package rpc

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/proxy"
)

type publicIPRoundTripFunc func(*http.Request) (*http.Response, error)

func (fn publicIPRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return fn(request)
}

func publicIPTestServer(body string, status int) *Server {
	return &Server{
		localFwd: proxy.NewLocalForwarder("127.0.0.1:0"),
		publicIPClient: &http.Client{Transport: publicIPRoundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{
				StatusCode: status,
				Body:       io.NopCloser(strings.NewReader(body)),
				Header:     make(http.Header),
			}, nil
		})},
	}
}

func TestPublicIPAcceptsValidatedAddress(t *testing.T) {
	recorder := httptest.NewRecorder()
	publicIPTestServer("2001:4860:4860::8888\n", http.StatusOK).handlePublicIP(
		recorder,
		httptest.NewRequest(http.MethodGet, "/public-ip", nil),
	)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), `"ip":"2001:4860:4860::8888"`) {
		t.Fatalf("unexpected response: status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestPublicIPRejectsInvalidPrivateAndOversizedResponses(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
	}{
		{name: "invalid", body: "provider-message-not-an-ip"},
		{name: "private", body: "10.0.0.1"},
		{name: "oversized", body: strings.Repeat("A", 65)},
	} {
		t.Run(test.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			publicIPTestServer(test.body, http.StatusOK).handlePublicIP(
				recorder,
				httptest.NewRequest(http.MethodGet, "/public-ip", nil),
			)
			if recorder.Code != http.StatusBadGateway {
				t.Fatalf("status = %d, want %d", recorder.Code, http.StatusBadGateway)
			}
			if strings.Contains(recorder.Body.String(), test.body) {
				t.Fatalf("provider response leaked: %s", recorder.Body.String())
			}
		})
	}
}
