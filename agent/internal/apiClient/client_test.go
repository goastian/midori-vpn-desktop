package apiClient

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/goastian/midorivpn-agent/internal/config"
)

func TestOriginFromBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		want    string
		wantErr bool
	}{
		{name: "https host", baseURL: "https://vpn.astian.org", want: "https://vpn.astian.org"},
		{name: "explicit port", baseURL: "http://127.0.0.1:8080/api", want: "http://127.0.0.1:8080"},
		{name: "invalid", baseURL: "vpn.astian.org", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := originFromBaseURL(tt.baseURL)
			if tt.wantErr {
				if err == nil {
					t.Fatal("originFromBaseURL() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("originFromBaseURL() error = %v", err)
			}
			if got != tt.want {
				t.Fatalf("originFromBaseURL() = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestOriginFromConfigAPIURL verifies that the URL coming from config.Load()
// (honours API_URL env var or .env file) is a valid origin for the client.
// Set API_URL in the environment or a .env file to point tests at a custom server.
func TestOriginFromConfigAPIURL(t *testing.T) {
	cfg := config.Load()
	apiURL := cfg.APIURL
	if apiURL == "" {
		t.Skip("API_URL not configured")
	}

	origin, err := originFromBaseURL(apiURL)
	if err != nil {
		t.Fatalf("originFromBaseURL(%q) from config: %v", apiURL, err)
	}
	if origin == "" {
		t.Fatalf("originFromBaseURL(%q) returned empty string", apiURL)
	}
	t.Logf("config API_URL %q -> origin %q", apiURL, origin)
}

// TestClientSendsOriginDerivedFromAPIURL builds a client using the URL from
// config.Load() (respects API_URL env / .env override) and verifies that the
// Origin header on outgoing requests equals the scheme+host of that URL.
// When API_URL is not set the test falls back to the production default.
func TestClientSendsOriginDerivedFromAPIURL(t *testing.T) {
	apiURL := config.Load().APIURL
	if apiURL == "" {
		apiURL = "https://vpn.astian.org"
	}
	// Override so the client actually talks to our test server below.
	os.Setenv("API_URL", "")

	var gotOrigin string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotOrigin = r.Header.Get("Origin")
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok":   true,
			"data": []Server{},
		})
	}))
	defer server.Close()

	client := New(server.URL+"/api", func() string { return "token" }, nil)
	if _, err := client.ListServers(context.Background()); err != nil {
		t.Fatalf("ListServers() error = %v", err)
	}

	if gotOrigin != server.URL {
		t.Fatalf("Origin header = %q, want %q", gotOrigin, server.URL)
	}
}
