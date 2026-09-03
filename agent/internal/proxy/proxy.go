// Package proxy implements the HTTP CONNECT forward proxy for mesh egress.
// It is adapted from the vpn-core internal/proxy package but operates
// standalone — JWT validation uses a local JWKS provider without DB access.
package proxy

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/goastian/midorivpn-agent/internal/httpx"
	"github.com/goastian/midorivpn-agent/internal/logredact"
	"github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jwt"
)

// Server is an HTTP CONNECT proxy that authenticates via JWT.
type Server struct {
	addr    string
	jwksURL string // if empty, skip JWT validation (dev mode)

	keysMu sync.RWMutex
	keySet jwk.Set

	// per-user concurrency limit
	mu       sync.Mutex
	active   map[string]int
	maxConns int
	jwksHTTP *http.Client
}

// New creates a Server bound to addr (e.g. ":8888").
func New(addr, jwksURL string) *Server {
	return &Server{
		addr:     addr,
		jwksURL:  jwksURL,
		keySet:   jwk.NewSet(),
		active:   make(map[string]int),
		maxConns: 20,
		jwksHTTP: httpx.NewClient(15 * time.Second),
	}
}

// Start begins serving and refreshes the JWKS at regular intervals.
// It returns when ctx is cancelled.
func (s *Server) Start(ctx context.Context) error {
	defer s.jwksHTTP.CloseIdleConnections()
	if s.jwksURL != "" {
		if err := s.refreshKeys(ctx); err != nil {
			slog.Warn("proxy: initial JWKS fetch failed, auth will reject until keys load", "operation", "authentik_jwks", "code", "refresh_failed")
		}
		go s.keyRefreshLoop(ctx)
	}

	srv := httpx.NewTunnelServer(s.addr, s)

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	slog.Info("mesh proxy listening", "addr", s.addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		return fmt.Errorf("proxy: %w", err)
	}
	return nil
}

func (s *Server) keyRefreshLoop(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.refreshKeys(ctx); err != nil {
				slog.Warn("proxy: JWKS refresh failed", "operation", "authentik_jwks", "code", "refresh_failed")
			}
		}
	}
}

func (s *Server) refreshKeys(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, s.jwksURL, nil)
	if err != nil {
		return httpx.NewRemoteError("authentik_jwks", "request_build_failed", 0, 0, err)
	}
	resp, err := s.jwksHTTP.Do(req)
	if err != nil {
		return httpx.NewRemoteError("authentik_jwks", "transport_failed", 0, 0, err)
	}
	defer resp.Body.Close()
	body, err := httpx.ReadBody(resp.Body, httpx.MaxResponseBytes)
	if err != nil {
		code := "response_read_failed"
		responseBytes := 0
		if errors.Is(err, httpx.ErrResponseTooLarge) {
			code = "response_too_large"
			responseBytes = httpx.MaxResponseBytes + 1
		}
		return httpx.NewRemoteError("authentik_jwks", code, resp.StatusCode, responseBytes, err)
	}
	if resp.StatusCode != http.StatusOK {
		return httpx.NewRemoteError("authentik_jwks", "provider_rejected", resp.StatusCode, len(body), nil)
	}
	set, err := jwk.Parse(body)
	if err != nil {
		return httpx.NewRemoteError("authentik_jwks", "response_invalid", resp.StatusCode, len(body), err)
	}
	s.keysMu.Lock()
	s.keySet = set
	s.keysMu.Unlock()
	return nil
}

// ServeHTTP handles incoming requests. Only CONNECT is supported.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT is supported", http.StatusMethodNotAllowed)
		return
	}

	sub, err := s.authenticate(r)
	if err != nil {
		slog.Info("proxy auth failed", "remote", logredact.HostPort(r.RemoteAddr), "target", logredact.HostPort(r.Host), "code", "token_validation_failed")
		w.Header().Set("Proxy-Authenticate", `Basic realm="midorivpn"`)
		http.Error(w, "proxy authentication required", http.StatusProxyAuthRequired)
		return
	}

	if !s.acquireSlot(sub) {
		http.Error(w, "too many concurrent connections", http.StatusTooManyRequests)
		return
	}
	defer s.releaseSlot(sub)

	_, _, err = net.SplitHostPort(r.Host)
	if err != nil {
		http.Error(w, "invalid target address", http.StatusBadRequest)
		return
	}

	targetConn, err := net.DialTimeout("tcp", r.Host, 10*time.Second)
	if err != nil {
		http.Error(w, "failed to connect to target", http.StatusBadGateway)
		return
	}
	defer targetConn.Close()

	const maxTunnel = 2 * time.Hour
	deadline := time.Now().Add(maxTunnel)
	targetConn.SetDeadline(deadline)

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}
	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		return
	}
	defer clientConn.Close()
	clientConn.SetDeadline(deadline)

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	slog.Info("proxy tunnel established", "user", logredact.User(sub), "target", logredact.HostPort(r.Host))

	var (
		wg        sync.WaitGroup
		bytesUp   int64
		bytesDown int64
		closeOnce sync.Once
	)
	closeAll := func() {
		closeOnce.Do(func() {
			targetConn.Close()
			clientConn.Close()
		})
	}

	start := time.Now()
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeAll()
		bytesUp, _ = io.Copy(targetConn, clientConn)
	}()
	go func() {
		defer wg.Done()
		defer closeAll()
		bytesDown, _ = io.Copy(clientConn, targetConn)
	}()
	wg.Wait()

	slog.Info("proxy tunnel closed",
		"user", logredact.User(sub),
		"target", logredact.HostPort(r.Host),
		"duration_s", int(time.Since(start).Seconds()),
		"bytes_up", bytesUp,
		"bytes_down", bytesDown,
	)
}

func (s *Server) authenticate(r *http.Request) (string, error) {
	// In dev mode (no JWKS URL), accept any request.
	if s.jwksURL == "" {
		return "anonymous", nil
	}

	header := r.Header.Get("Proxy-Authorization")
	if header == "" {
		return "", fmt.Errorf("missing Proxy-Authorization header")
	}

	parts := strings.SplitN(header, " ", 2)
	if len(parts) != 2 {
		return "", fmt.Errorf("invalid format")
	}

	var tokenStr string
	switch strings.ToLower(parts[0]) {
	case "bearer":
		tokenStr = parts[1]
	case "basic":
		decoded, err := base64.StdEncoding.DecodeString(parts[1])
		if err != nil {
			return "", fmt.Errorf("invalid base64")
		}
		idx := strings.IndexByte(string(decoded), ':')
		if idx < 0 {
			return "", fmt.Errorf("invalid basic format")
		}
		tokenStr = string(decoded[idx+1:])
	default:
		return "", fmt.Errorf("unsupported scheme: %s", parts[0])
	}

	s.keysMu.RLock()
	ks := s.keySet
	s.keysMu.RUnlock()

	tok, err := jwt.Parse([]byte(tokenStr),
		jwt.WithKeySet(ks),
		jwt.WithValidate(true),
		jwt.WithAcceptableSkew(30*time.Second),
	)
	if err != nil {
		return "", fmt.Errorf("invalid token: %w", err)
	}

	sub, _ := tok.Subject()
	if sub == "" {
		return "", fmt.Errorf("empty sub claim")
	}
	return sub, nil
}

func (s *Server) acquireSlot(sub string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active[sub] >= s.maxConns {
		return false
	}
	s.active[sub]++
	return true
}

func (s *Server) releaseSlot(sub string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.active[sub]--
	if s.active[sub] <= 0 {
		delete(s.active, sub)
	}
}
