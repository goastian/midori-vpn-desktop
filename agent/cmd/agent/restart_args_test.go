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
	if count := len(got); count != 2 {
		t.Fatalf("unexpected restart args: %v", got)
	}
}
