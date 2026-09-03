package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"sync"
	"time"

	"github.com/goastian/midorivpn-agent/internal/httpx"
	masquego "github.com/quic-go/masque-go"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/yosida95/uritemplate/v3"
)

// MasqueRelay adapts the local WireGuard UDP endpoint to an authenticated
// RFC 9298 CONNECT-UDP session over HTTP/3.
type MasqueRelay struct {
	udp        *net.UDPConn
	conn       *masquego.Conn
	mu         sync.RWMutex
	clientAddr *net.UDPAddr
	cancel     context.CancelFunc
	done       chan struct{}
	closeOnce  sync.Once
}

func StartMasqueRelay(ctx context.Context, proxyTemplate, target, token string) (*MasqueRelay, string, error) {
	if proxyTemplate == "" || target == "" || token == "" {
		return nil, "", fmt.Errorf("MASQUE URI template, target and tunnel token are required")
	}
	template, err := uritemplate.New(proxyTemplate)
	if err != nil {
		return nil, "", fmt.Errorf("parse MASQUE URI template: %w", err)
	}
	expandedTemplate, err := template.Expand(uritemplate.Values{
		"target_host": uritemplate.String("127.0.0.1"),
		"target_port": uritemplate.String("1"),
	})
	if err != nil {
		return nil, "", fmt.Errorf("expand MASQUE URI template: %w", err)
	}
	proxyURL, err := url.Parse(expandedTemplate)
	if err != nil || proxyURL.Scheme != "https" || proxyURL.Hostname() == "" {
		return nil, "", fmt.Errorf("MASQUE URI template must use an absolute HTTPS URL")
	}
	if _, err := net.ResolveUDPAddr("udp", target); err != nil {
		return nil, "", fmt.Errorf("resolve MASQUE target: %w", err)
	}

	relayCtx, cancel := context.WithCancel(context.Background())
	request, err := masquego.NewRequest(relayCtx, template, target)
	if err != nil {
		cancel()
		return nil, "", fmt.Errorf("create CONNECT-UDP request: %w", err)
	}
	request.Header().Set("Authorization", "Bearer "+token)
	transport := masquego.Transport{
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS13,
			NextProtos: []string{http3.NextProtoH3},
			ServerName: proxyURL.Hostname(),
		},
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: 10 * time.Second,
			MaxIdleTimeout:       5 * time.Minute,
			KeepAlivePeriod:      30 * time.Second,
			EnableDatagrams:      true,
			InitialPacketSize:    1350,
		},
		// masque-go passes URL.Host directly to quic.DialAddr. Unlike an HTTP
		// client, quic.DialAddr doesn't infer the default port for an HTTPS URL,
		// so templates such as https://vpn.example/masque must explicitly be
		// normalized to host:443 at the transport boundary.
		DialAddr: func(dialCtx context.Context, _ string, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(dialCtx, masqueProxyAddress(proxyURL), tlsConf, quicConf)
		},
	}

	type dialResult struct {
		conn     *masquego.Conn
		response *http.Response
		err      error
	}
	resultCh := make(chan dialResult, 1)
	go func() {
		conn, response, dialErr := transport.Dial(request)
		resultCh <- dialResult{conn: conn, response: response, err: dialErr}
	}()
	var result dialResult
	select {
	case result = <-resultCh:
	case <-ctx.Done():
		cancel()
		return nil, "", fmt.Errorf("dial MASQUE relay: %w", ctx.Err())
	}
	if result.err != nil {
		cancel()
		status := 0
		if result.response != nil {
			status = result.response.StatusCode
			if result.response.Body != nil {
				result.response.Body.Close()
			}
		}
		return nil, "", httpx.NewRemoteError("masque_relay", "handshake_failed", status, 0, result.err)
	}

	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		cancel()
		_ = result.conn.Close()
		return nil, "", fmt.Errorf("listen local UDP relay: %w", err)
	}
	relay := &MasqueRelay{udp: udp, conn: result.conn, cancel: cancel, done: make(chan struct{})}
	go relay.run(relayCtx)
	return relay, udp.LocalAddr().String(), nil
}

func masqueProxyAddress(proxyURL *url.URL) string {
	if proxyURL.Port() != "" {
		return proxyURL.Host
	}
	return net.JoinHostPort(proxyURL.Hostname(), "443")
}

func (r *MasqueRelay) Close() {
	r.closeOnce.Do(func() {
		r.cancel()
		_ = r.udp.Close()
		_ = r.conn.Close()
		<-r.done
	})
}

func (r *MasqueRelay) run(ctx context.Context) {
	defer close(r.done)
	defer r.udp.Close()
	defer r.conn.Close()

	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := r.udp.ReadFromUDP(buf)
			if err != nil {
				r.cancel()
				return
			}
			r.mu.Lock()
			r.clientAddr = addr
			r.mu.Unlock()
			if _, err := r.conn.WriteTo(buf[:n], nil); err != nil {
				r.cancel()
				return
			}
		}
	}()

	buf := make([]byte, 65535)
	for ctx.Err() == nil {
		n, _, err := r.conn.ReadFrom(buf)
		if err != nil {
			return
		}
		r.mu.RLock()
		addr := r.clientAddr
		r.mu.RUnlock()
		if addr != nil {
			_, _ = r.udp.WriteToUDP(buf[:n], addr)
		}
	}
}
