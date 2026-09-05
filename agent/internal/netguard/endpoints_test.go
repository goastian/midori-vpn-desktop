//go:build linux

package netguard

import (
	"reflect"
	"testing"
)

func TestGuardEndpointsIncludesRecoveryCandidatesOnce(t *testing.T) {
	scope := Scope{
		Endpoint: "edge.example:51820",
		APIURL:   "https://control.example/api/v1",
		RecoveryEndpoints: []string{
			"edge.example:51820",
			"edge-two.example:443",
			"edge-two.example:443",
		},
	}
	want := []string{"edge.example:51820", "control.example:443", "edge-two.example:443"}
	if got := guardEndpoints(scope); !reflect.DeepEqual(got, want) {
		t.Fatalf("guardEndpoints() = %#v, want %#v", got, want)
	}
}
