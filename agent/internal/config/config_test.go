package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDefaultAPIURL(t *testing.T) {
	// Ensure no stray env var overrides the test.
	t.Setenv("API_URL", "")

	cfg := Load()
	if cfg.APIURL != "https://vpn.astian.org" {
		t.Fatalf("default APIURL = %q, want %q", cfg.APIURL, "https://vpn.astian.org")
	}
}

func TestAPIURLFromEnvVar(t *testing.T) {
	t.Setenv("API_URL", "https://test.vpn.example.com")
	defer os.Unsetenv("API_URL")

	cfg := Load()
	if cfg.APIURL != "https://test.vpn.example.com" {
		t.Fatalf("APIURL from env = %q, want %q", cfg.APIURL, "https://test.vpn.example.com")
	}
}

func TestAPIURLFromDotEnvFile(t *testing.T) {
	dir := t.TempDir()

	// Write a .env-style config file.
	envFile := filepath.Join(dir, "config.env")
	content := "API_URL=https://staging.vpn.example.com\n# comment line\nACCOUNT_URL=https://staging.vpn.example.com\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	var cfg Config
	cfg = defaults()
	applyDotenv(&cfg, envFile)

	if cfg.APIURL != "https://staging.vpn.example.com" {
		t.Fatalf("APIURL from dotenv = %q, want %q", cfg.APIURL, "https://staging.vpn.example.com")
	}
	if cfg.AccountURL != "https://staging.vpn.example.com" {
		t.Fatalf("AccountURL from dotenv = %q, want %q", cfg.AccountURL, "https://staging.vpn.example.com")
	}
}

func TestDotEnvIgnoresComments(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "config.env")
	content := "# this is a comment\n  # indented comment\nAPI_URL=https://env.example.com\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := defaults()
	applyDotenv(&cfg, envFile)
	if cfg.APIURL != "https://env.example.com" {
		t.Fatalf("APIURL = %q, want %q", cfg.APIURL, "https://env.example.com")
	}
}

func TestDotEnvQuotedValues(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "config.env")
	content := `API_URL="https://quoted.example.com"` + "\n" +
		`AUTHENTIK_CLIENT_ID='my-client-id'` + "\n"
	if err := os.WriteFile(envFile, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}

	cfg := defaults()
	applyDotenv(&cfg, envFile)
	if cfg.APIURL != "https://quoted.example.com" {
		t.Fatalf("APIURL from quoted dotenv = %q, want %q", cfg.APIURL, "https://quoted.example.com")
	}
	if cfg.AuthentikClientID != "my-client-id" {
		t.Fatalf("AuthentikClientID from quoted dotenv = %q, want %q", cfg.AuthentikClientID, "my-client-id")
	}
}

func TestDotEnvMissingFileIsNoop(t *testing.T) {
	cfg := defaults()
	before := cfg.APIURL
	applyDotenv(&cfg, "/nonexistent/path/config.env")
	if cfg.APIURL != before {
		t.Fatalf("applyDotenv on missing file changed APIURL to %q", cfg.APIURL)
	}
}

func TestEnvVarTakesPrecedenceOverDotEnv(t *testing.T) {
	dir := t.TempDir()
	envFile := filepath.Join(dir, "config.env")
	if err := os.WriteFile(envFile, []byte("API_URL=https://from-file.example.com\n"), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("API_URL", "https://from-env.example.com")

	// Simulate Load() resolution order: defaults → dotenv → env.
	cfg := defaults()
	applyDotenv(&cfg, envFile)
	applyEnv(&cfg)

	if cfg.APIURL != "https://from-env.example.com" {
		t.Fatalf("env var did not take precedence: got %q", cfg.APIURL)
	}
}

func TestValidate(t *testing.T) {
	t.Run("valid default config passes", func(t *testing.T) {
		cfg := defaults()
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() on defaults failed: %v", err)
		}
	})

	t.Run("empty API_URL fails", func(t *testing.T) {
		cfg := defaults()
		cfg.APIURL = ""
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected Validate() to fail with empty APIURL")
		}
	})
}
