package rpc

import (
	"context"
	"testing"
	"time"

	"github.com/goastian/midorivpn-agent/internal/apiClient"
)

func TestListServersCachedReturnsFreshClone(t *testing.T) {
	s := &Server{
		serversCache:   []apiClient.Server{{ID: "a", Name: "alpha"}},
		serversCacheAt: time.Now(),
	}

	got, err := s.listServersCached(context.Background(), false)
	if err != nil {
		t.Fatalf("listServersCached returned error: %v", err)
	}
	got[0].Name = "mutated"

	if s.serversCache[0].Name != "alpha" {
		t.Fatalf("fresh cache result was not cloned: %#v", s.serversCache[0])
	}
}

func TestListServersCachedReturnsStaleCloneWhenRefreshAlreadyActive(t *testing.T) {
	s := &Server{
		serversCache:         []apiClient.Server{{ID: "a", Name: "alpha"}},
		serversCacheAt:       time.Now().Add(-10 * time.Minute),
		serversRefreshActive: true,
	}

	got, err := s.listServersCached(context.Background(), false)
	if err != nil {
		t.Fatalf("listServersCached returned error: %v", err)
	}
	if len(got) != 1 || got[0].Name != "alpha" {
		t.Fatalf("unexpected stale cache result: %#v", got)
	}

	got[0].Name = "mutated"
	if s.serversCache[0].Name != "alpha" {
		t.Fatalf("stale cache result was not cloned: %#v", s.serversCache[0])
	}
}

func TestCloneServersHandlesNil(t *testing.T) {
	if cloneServers(nil) != nil {
		t.Fatal("expected nil clone for nil input")
	}
}
