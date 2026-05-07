// Package proxy — LocalForwarder is a localhost-only HTTP CONNECT proxy that
// optionally chains connections through a remote exit-node proxy.
// It is used by the desktop agent so any system application that respects
// HTTP/HTTPS proxy settings (http_proxy / HTTPS_PROXY) can route its traffic
// through the mesh exit node without any authentication.
package proxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"
)

// LocalForwarder is an HTTP CONNECT proxy that listens on 127.0.0.1 and
// optionally chains all connections through a remote upstream exit-node proxy.
// No authentication is required because it is localhost-only.
type LocalForwarder struct {
	addr string

	mu       sync.RWMutex
	upstream string // "host:port" or "" for direct
}

// NewLocalForwarder creates a LocalForwarder bound to addr (e.g. "127.0.0.1:8889").
func NewLocalForwarder(addr string) *LocalForwarder {
	return &LocalForwarder{addr: addr}
}

// SetUpstream configures the upstream exit-node proxy to chain through.
// host is the mesh IP of the exit node; port is its proxy port (typically 8888).
// Pass host="" or port=0 to clear (direct mode).
func (f *LocalForwarder) SetUpstream(host string, port int) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if host == "" || port == 0 {
		f.upstream = ""
	} else {
		f.upstream = fmt.Sprintf("%s:%d", host, port)
	}
	slog.Info("local forwarder: upstream changed", "upstream", f.upstream)
}

// Upstream returns the current upstream proxy address (thread-safe).
func (f *LocalForwarder) Upstream() string {
	f.mu.RLock()
	defer f.mu.RUnlock()
	return f.upstream
}

// Active returns true if an upstream exit node is currently configured.
func (f *LocalForwarder) Active() bool {
	return f.Upstream() != ""
}

// Start begins serving; blocks until ctx is cancelled.
func (f *LocalForwarder) Start(ctx context.Context) error {
	srv := &http.Server{
		Addr:              f.addr,
		Handler:           f,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()
	slog.Info("local forwarder listening", "addr", f.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("local forwarder: %w", err)
	}
	return nil
}

// ServeHTTP implements http.Handler; only CONNECT is supported.
func (f *LocalForwarder) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT supported", http.StatusMethodNotAllowed)
		return
	}

	if _, _, err := net.SplitHostPort(r.Host); err != nil {
		http.Error(w, "invalid target address", http.StatusBadRequest)
		return
	}

	upstream := f.Upstream()
	var (
		targetConn net.Conn
		err        error
	)

	if upstream != "" {
		targetConn, err = dialViaProxy(upstream, r.Host)
		slog.Debug("local forwarder: chaining through exit node", "upstream", upstream, "target", r.Host)
	} else {
		targetConn, err = net.DialTimeout("tcp", r.Host, 10*time.Second)
	}

	if err != nil {
		slog.Warn("local forwarder: dial failed", "target", r.Host, "upstream", upstream, "err", err)
		http.Error(w, "gateway error: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijack not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()

	const maxTunnel = 2 * time.Hour
	deadline := time.Now().Add(maxTunnel)
	clientConn.SetDeadline(deadline)
	targetConn.SetDeadline(deadline)

	if _, err := clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n")); err != nil {
		return
	}

	var wg sync.WaitGroup
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			clientConn.Close()
			targetConn.Close()
		})
	}

	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeAll()
		io.Copy(targetConn, clientConn) //nolint:errcheck
	}()
	go func() {
		defer wg.Done()
		defer closeAll()
		io.Copy(clientConn, targetConn) //nolint:errcheck
	}()
	wg.Wait()
}

// dialViaProxy opens a TCP connection to proxyAddr and sends a CONNECT request
// for target, returning the tunnel connection ready to use.
func dialViaProxy(proxyAddr, target string) (net.Conn, error) {
	conn, err := net.DialTimeout("tcp", proxyAddr, 10*time.Second)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxyAddr, err)
	}

	req := &http.Request{
		Method:     http.MethodConnect,
		Host:       target,
		URL:        &url.URL{Host: target},
		Header:     make(http.Header),
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
	}
	if err := req.Write(conn); err != nil {
		conn.Close()
		return nil, fmt.Errorf("write CONNECT to proxy: %w", err)
	}

	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, req)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("read CONNECT response from proxy: %w", err)
	}
	resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		conn.Close()
		return nil, fmt.Errorf("upstream CONNECT rejected: %s", resp.Status)
	}

	return conn, nil
}
