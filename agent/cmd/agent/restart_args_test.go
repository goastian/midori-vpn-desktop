package main

import (
	"slices"
	"testing"
)

func TestRestartArgsReusesCurrentBrowserTab(t *testing.T) {
	got := restartArgs([]string{"agent", "--port", "7071", "--open-ui"})
	if slices.Contains(got, "--open-ui") {
		t.Fatalf("restart retained --open-ui: %v", got)
	}
	if !slices.Contains(got, "--background") {
		t.Fatalf("restart did not become background-only: %v", got)
	}
}

func TestRestartArgsDoesNotDuplicateBackground(t *testing.T) {
	got := restartArgs([]string{"agent", "--background"})
	if count := len(got); count != 3 || got[2] != "--resume-session" {
		t.Fatalf("unexpected restart args: %v", got)
	}
}

func TestRestartPreservesSessionAndParentExactlyOnce(t *testing.T) {
	got := restartArgs([]string{"agent", "--background", "--resume-session", "--parent-pid", "42"})
	if len(got) != 5 || got[3] != "--parent-pid" || got[4] != "42" {
		t.Fatalf("restart args: %v", got)
	}
}
