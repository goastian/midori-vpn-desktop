package tunnel

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func TestWSSRelayForwardsDatagramsAndAuthorization(t *testing.T) {
	authHeader := make(chan string, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authHeader <- r.Header.Get("Authorization")
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.Close(websocket.StatusNormalClosure, "done")
		ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
		defer cancel()
		typ, payload, err := conn.Read(ctx)
		if err == nil && typ == websocket.MessageBinary {
			_ = conn.Write(ctx, websocket.MessageBinary, payload)
		}
	}))
	defer server.Close()

	endpoint := "ws" + strings.TrimPrefix(server.URL, "http")
	relay, localEndpoint, err := StartWSSRelay(context.Background(), endpoint, "test-token")
	if err != nil {
		t.Fatalf("StartWSSRelay() error = %v", err)
	}
	defer relay.Close()

	select {
	case got := <-authHeader:
		if got != "Bearer test-token" {
			t.Fatalf("Authorization = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("relay did not connect to WSS server")
	}

	client, err := net.Dial("udp", localEndpoint)
	if err != nil {
		t.Fatalf("dial local relay: %v", err)
	}
	defer client.Close()
	if _, err := client.Write([]byte("wireguard-datagram")); err != nil {
		t.Fatalf("write datagram: %v", err)
	}
	_ = client.SetDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 64)
	n, err := client.Read(buf)
	if err != nil {
		t.Fatalf("read echoed datagram: %v", err)
	}
	if got := string(buf[:n]); got != "wireguard-datagram" {
		t.Fatalf("echoed datagram = %q", got)
	}
}
