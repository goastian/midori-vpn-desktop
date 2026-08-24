package tunnel

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/coder/websocket"
)

// WSSRelay adapts a local UDP WireGuard endpoint to the authenticated WSS
// relay provided by a Core. The WireGuard engine only sees a loopback UDP peer.
type WSSRelay struct {
	udp        *net.UDPConn
	conn       *websocket.Conn
	mu         sync.RWMutex
	clientAddr *net.UDPAddr
	cancel     context.CancelFunc
	done       chan struct{}
	closeOnce  sync.Once
}

func StartWSSRelay(ctx context.Context, endpoint, token string) (*WSSRelay, string, error) {
	if endpoint == "" || token == "" {
		return nil, "", fmt.Errorf("WSS endpoint and tunnel token are required")
	}
	conn, _, err := websocket.Dial(ctx, endpoint, &websocket.DialOptions{HTTPHeader: http.Header{"Authorization": []string{"Bearer " + token}}})
	if err != nil {
		return nil, "", fmt.Errorf("dial WSS relay: %w", err)
	}
	udp, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		conn.Close(websocket.StatusInternalError, "local UDP unavailable")
		return nil, "", fmt.Errorf("listen local UDP relay: %w", err)
	}
	// The request context is only for the initial dial. The relay must outlive
	// the local RPC request that created it and is stopped explicitly by Close.
	relayCtx, cancel := context.WithCancel(context.Background())
	r := &WSSRelay{udp: udp, conn: conn, cancel: cancel, done: make(chan struct{})}
	go r.run(relayCtx)
	return r, udp.LocalAddr().String(), nil
}

func (r *WSSRelay) Close() {
	r.closeOnce.Do(func() {
		r.cancel()
		_ = r.udp.Close()
		_ = r.conn.Close(websocket.StatusNormalClosure, "relay closed")
		<-r.done
	})
}

func (r *WSSRelay) run(ctx context.Context) {
	defer close(r.done)
	defer r.udp.Close()
	defer r.conn.Close(websocket.StatusNormalClosure, "relay closed")

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
			writeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
			err = r.conn.Write(writeCtx, websocket.MessageBinary, append([]byte(nil), buf[:n]...))
			cancel()
			if err != nil {
				r.cancel()
				return
			}
		}
	}()

	for ctx.Err() == nil {
		typ, reader, err := r.conn.Reader(ctx)
		if err != nil {
			return
		}
		if typ != websocket.MessageBinary {
			continue
		}
		packet, err := io.ReadAll(io.LimitReader(reader, 65535))
		if err != nil || len(packet) == 0 {
			continue
		}
		r.mu.RLock()
		addr := r.clientAddr
		r.mu.RUnlock()
		if addr != nil {
			_, _ = r.udp.WriteToUDP(packet, addr)
		}
	}
}
