package tunnel

import (
	"context"
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
