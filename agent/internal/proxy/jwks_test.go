package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/httpx"
)

func TestJWKSResponseIsStrictlyBoundedAndRedacted(t *testing.T) {
	secret := "provider-jwks-secret"
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(secret + strings.Repeat("x", httpx.MaxResponseBytes)))
	}))
	defer server.Close()

	proxy := New("127.0.0.1:0", server.URL)
	proxy.jwksHTTP = server.Client()
	err := proxy.refreshKeys(context.Background())
	var remoteErr *httpx.RemoteError
	if !errors.As(err, &remoteErr) || remoteErr.Code != "response_too_large" {
		t.Fatalf("refreshKeys() error = %#v", err)
	}
	if strings.Contains(err.Error(), secret) {
		t.Fatalf("provider body leaked through error: %q", err.Error())
	}
}
