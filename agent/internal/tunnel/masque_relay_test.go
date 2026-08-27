package tunnel

import (
	"context"
	"net/url"
	"strings"
	"testing"
)

func TestMasqueRelayRejectsIncompleteAndInsecureConfiguration(t *testing.T) {
	if _, _, err := StartMasqueRelay(context.Background(), "", "127.0.0.1:51820", "token"); err == nil {
		t.Fatal("empty URI template was accepted")
	}
	_, _, err := StartMasqueRelay(context.Background(), "http://vpn.example.test/masque{?target_host,target_port}", "127.0.0.1:51820", "token")
	if err == nil || !strings.Contains(err.Error(), "HTTPS") {
		t.Fatalf("insecure URI template error = %v", err)
	}
}

func TestMasqueProxyAddressAddsDefaultHTTPSPort(t *testing.T) {
	tests := []struct {
		url  string
		want string
	}{
		{url: "https://vpn.example.test/masque", want: "vpn.example.test:443"},
		{url: "https://vpn.example.test:8443/masque", want: "vpn.example.test:8443"},
		{url: "https://[2001:db8::1]/masque", want: "[2001:db8::1]:443"},
	}
	for _, test := range tests {
		t.Run(test.url, func(t *testing.T) {
			parsed, err := url.Parse(test.url)
			if err != nil {
				t.Fatal(err)
			}
			if got := masqueProxyAddress(parsed); got != test.want {
				t.Fatalf("masqueProxyAddress() = %q, want %q", got, test.want)
			}
		})
	}
}
