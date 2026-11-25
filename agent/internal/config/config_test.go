package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestProductionConfigIsComplete(t *testing.T) {
	cfg := productionConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("production configuration must be usable without a config file: %v", err)
	}
	if cfg.APIURL != "https://vpn.astian.org" {
		t.Fatalf("production APIURL = %q", cfg.APIURL)
	}
}

func TestProductionOIDCIdentityMatchesMidoriVPN(t *testing.T) {
	cfg := productionConfig()
	for name, check := range map[string]struct{ got, want string }{
		"issuer":        {cfg.AuthentikIssuer, "https://accounts.astian.org/"},
		"client":        {cfg.AuthentikClientID, "60mBgw8BHTvKRPYVhDTJGoKEt30QYG3b7Sv0RFNd"},
		"authorization": {cfg.AuthentikAuthURL, "https://accounts.astian.org/application/o/authorize/"},
		"token":         {cfg.AuthentikTokenURL, "https://accounts.astian.org/application/o/token/"},
		"userinfo":      {cfg.AuthentikUserinfoURL, "https://accounts.astian.org/application/o/userinfo/"},
		"jwks":          {cfg.AuthentikJWKSURL, "https://accounts.astian.org/application/o/midori-vpn/jwks/"},
		"callback":      {cfg.AuthentikRedirectURI, "http://127.0.0.1:7071/oauth/callback"},
	} {
		t.Run(name, func(t *testing.T) {
			if check.got != check.want {
				t.Fatalf("production OIDC %s = %q, want %q", name, check.got, check.want)
			}
		})
	}
}

func TestLoadPreservesOIDCUserAndEnvironmentOverrides(t *testing.T) {
	for _, key := range knownKeys() {
		t.Setenv(key, "")
	}
	t.Chdir(t.TempDir())
	configRoot := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", configRoot)
	userDir := filepath.Join(configRoot, "midorivpn")
	if err := os.Mkdir(userDir, 0700); err != nil {
		t.Fatal(err)
	}
	content := "AUTHENTIK_CLIENT_ID=operator-public-client\n" +
		"AUTHENTIK_ISSUER=https://accounts.example.test/\n" +
		"AUTHENTIK_JWKS_URL=https://accounts.example.test/application/o/custom/jwks/\n" +
		"AUTHENTIK_REDIRECT_URI=http://127.0.0.1:7071/oauth/callback\n"
	if err := os.WriteFile(filepath.Join(userDir, "config.env"), []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	fromFile := Load()
	if fromFile.AuthentikClientID != "operator-public-client" ||
		fromFile.AuthentikIssuer != "https://accounts.example.test/" ||
		fromFile.AuthentikJWKSURL != "https://accounts.example.test/application/o/custom/jwks/" {
		t.Fatalf("user OIDC config did not override production defaults: %#v", fromFile)
	}

	t.Setenv("AUTHENTIK_CLIENT_ID", "environment-public-client")
	t.Setenv("AUTHENTIK_JWKS_URL", "https://accounts.example.test/application/o/environment/jwks/")
	fromEnv := Load()
	if fromEnv.AuthentikClientID != "environment-public-client" ||
		fromEnv.AuthentikJWKSURL != "https://accounts.example.test/application/o/environment/jwks/" ||
		fromEnv.AuthentikIssuer != fromFile.AuthentikIssuer ||
		fromEnv.AuthentikRedirectURI != fromFile.AuthentikRedirectURI {
		t.Fatalf("environment OIDC precedence changed: %#v", fromEnv)
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

	var cfg Config
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

	var cfg Config
	applyDotenv(&cfg, envFile)
	if cfg.APIURL != "https://quoted.example.com" {
		t.Fatalf("APIURL from quoted dotenv = %q, want %q", cfg.APIURL, "https://quoted.example.com")
	}
	if cfg.AuthentikClientID != "my-client-id" {
		t.Fatalf("AuthentikClientID from quoted dotenv = %q, want %q", cfg.AuthentikClientID, "my-client-id")
	}
}

func TestDotEnvMissingFileIsNoop(t *testing.T) {
	var cfg Config
	cfg.APIURL = "https://initial.example.com"
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

	// Simulate Load() resolution order: dotenv → env.
	var cfg Config
	applyDotenv(&cfg, envFile)
	applyEnv(&cfg)

	if cfg.APIURL != "https://from-env.example.com" {
		t.Fatalf("env var did not take precedence: got %q", cfg.APIURL)
	}
}

func TestValidate(t *testing.T) {
	t.Run("valid complete config passes", func(t *testing.T) {
		cfg := Config{
			APIURL:               "https://vpn.example.com",
			AuthentikIssuer:      "https://auth.example.com/app/",
			AuthentikClientID:    "test-client-id",
			AuthentikAuthURL:     "https://auth.example.com/authorize/",
			AuthentikTokenURL:    "https://auth.example.com/token/",
			AuthentikUserinfoURL: "https://auth.example.com/userinfo/",
			AuthentikJWKSURL:     "https://auth.example.com/app/jwks/",
			AuthentikRedirectURI: "http://127.0.0.1:7071/oauth/callback",
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Validate() on complete config failed: %v", err)
		}
	})

	t.Run("empty API_URL fails", func(t *testing.T) {
		cfg := Config{
			AuthentikIssuer:      "https://auth.example.com/app/",
			AuthentikClientID:    "test-client-id",
			AuthentikAuthURL:     "https://auth.example.com/authorize/",
			AuthentikTokenURL:    "https://auth.example.com/token/",
			AuthentikUserinfoURL: "https://auth.example.com/userinfo/",
			AuthentikJWKSURL:     "https://auth.example.com/app/jwks/",
			AuthentikRedirectURI: "http://127.0.0.1:7071/oauth/callback",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected Validate() to fail with empty APIURL")
		}
	})

	t.Run("public callback is rejected", func(t *testing.T) {
		cfg := Config{
			APIURL:               "https://vpn.example.com",
			AuthentikIssuer:      "https://auth.example.com/app/",
			AuthentikClientID:    "test-client-id",
			AuthentikAuthURL:     "https://auth.example.com/authorize/",
			AuthentikTokenURL:    "https://auth.example.com/token/",
			AuthentikUserinfoURL: "https://auth.example.com/userinfo/",
			AuthentikJWKSURL:     "https://auth.example.com/app/jwks/",
			AuthentikRedirectURI: "https://vpn.example.com/auth/callback",
		}
		if err := cfg.Validate(); err == nil {
			t.Fatal("expected Validate() to reject a non-loopback OAuth callback")
		}
	})
}
