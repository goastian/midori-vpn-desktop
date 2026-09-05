package sysstate

import (
	"context"
	"reflect"
	"testing"
)

func TestRevertAllUsesLIFOAndClearsRegistry(t *testing.T) {
	registry := &Registry{}
	var reverted []string
	registry.Record("first", func(context.Context) { reverted = append(reverted, "first") })
	registry.Record("second", func(context.Context) { reverted = append(reverted, "second") })

	registry.RevertAll(context.Background())
	registry.RevertAll(context.Background())

	if want := []string{"second", "first"}; !reflect.DeepEqual(reverted, want) {
		t.Fatalf("revert order = %v, want %v", reverted, want)
	}
}

func TestRevertByPrefixKeepsUnrelatedMutations(t *testing.T) {
	registry := &Registry{}
	var reverted []string
	for _, name := range []string{"dns:primary", "firewall:default", "dns:fallback"} {
		name := name
		registry.Record(name, func(context.Context) { reverted = append(reverted, name) })
	}

	registry.RevertByPrefix(context.Background(), "dns:")
	if want := []string{"dns:fallback", "dns:primary"}; !reflect.DeepEqual(reverted, want) {
		t.Fatalf("selected revert order = %v, want %v", reverted, want)
	}

	registry.RevertAll(context.Background())
	if want := []string{"dns:fallback", "dns:primary", "firewall:default"}; !reflect.DeepEqual(reverted, want) {
		t.Fatalf("final revert order = %v, want %v", reverted, want)
	}
}

func TestRevertContinuesAfterPanicAndRetainsNewMutations(t *testing.T) {
	registry := &Registry{}
	var reverted []string
	registry.Record("survivor", func(context.Context) { reverted = append(reverted, "survivor") })
	registry.Record("panics", func(context.Context) { panic("expected test panic") })
	registry.Record("records-next", func(context.Context) {
		reverted = append(reverted, "records-next")
		registry.Record("next-cycle", func(context.Context) { reverted = append(reverted, "next-cycle") })
	})

	registry.RevertAll(context.Background())
	registry.RevertAll(context.Background())

	if want := []string{"records-next", "survivor", "next-cycle"}; !reflect.DeepEqual(reverted, want) {
		t.Fatalf("reverted = %v, want %v", reverted, want)
	}
}

func TestHasAnyPrefix(t *testing.T) {
	if !hasAnyPrefix("nat:nft:eth0", []string{"dns:", "nat:"}) {
		t.Fatal("expected matching prefix")
	}
	if hasAnyPrefix("firewall:default", nil) {
		t.Fatal("empty prefix set must not match")
	}
}
