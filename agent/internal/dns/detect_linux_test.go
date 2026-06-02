//go:build linux

package dns

import "testing"

func TestKindString(t *testing.T) {
	cases := []struct {
		k    Kind
		want string
	}{
		{KindNone, "none"},
		{KindResolved, "resolved"},
		{KindResolvconf, "resolvconf"},
	}
	for _, c := range cases {
		if got := c.k.String(); got != c.want {
			t.Errorf("Kind(%d).String() = %q, want %q", c.k, got, c.want)
		}
	}
}

func TestKindNeedsExtraCaps(t *testing.T) {
	if KindResolved.NeedsExtraCaps() {
		t.Error("resolved must not require extra caps")
	}
	if !KindResolvconf.NeedsExtraCaps() {
		t.Error("resolvconf must require extra caps")
	}
	if KindNone.NeedsExtraCaps() {
		t.Error("none must not require extra caps")
	}
}

func TestDetectReturnsBackend(t *testing.T) {
	// Detect is environment-sensitive; we just verify it returns a usable
	// backend and that the kind is one of the Linux-supported values.
	b := Detect()
	if b == nil {
		t.Fatal("Detect returned nil")
	}
	switch b.Kind() {
	case KindResolved, KindResolvconf:
		// ok
	default:
		t.Errorf("unexpected backend kind on Linux: %s", b.Kind())
	}
}

func TestTrimSpace(t *testing.T) {
	cases := map[string]string{
		"  hi  ":  "hi",
		"\t1.1.1.1\n": "1.1.1.1",
		"":          "",
		"x":         "x",
	}
	for in, want := range cases {
		if got := trimSpace(in); got != want {
			t.Errorf("trimSpace(%q) = %q, want %q", in, got, want)
		}
	}
}
