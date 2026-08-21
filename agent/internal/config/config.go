// Package config loads layered runtime configuration for the agent.
//
// Resolution order (later wins):
//  1. Hardcoded defaults (production endpoints).
//  2. Embedded build-time defaults (`.env` baked into binary, optional).
//  3. /etc/midorivpn/config.env (system-wide override, packaged).
//  4. $XDG_CONFIG_HOME/midorivpn/config.env (per-user override).
//  5. Process environment variables.
//
// Keys mirror the browser extension (.env) so admins can use the same
// vocabulary across components: API_URL, AUTHENTIK_*, ACCOUNT_URL.
package config

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Config is the resolved runtime configuration.
type Config struct {
	// APIURL is the vpn-core base URL. Its origin is also sent as the Origin
	// header for vpn-core CSRF validation.
	APIURL                string
	AccountURL            string
	AuthentikIssuer       string
	AuthentikClientID     string
	AuthentikClientSecret string
	AuthentikAuthURL      string
	AuthentikTokenURL     string
	AuthentikUserinfoURL  string
	AuthentikJWKSURL      string
	AuthentikRedirectURI  string
}

// defaults returns the hardcoded production fallback configuration.
// These values are intentionally identical to the extension's .env defaults
// so that misconfiguration in one place doesn't desync deployments.
func defaults() Config {
	return Config{
		APIURL:                "https://vpn.astian.org",
		AccountURL:            "https://vpn.astian.org",
		AuthentikIssuer:       "https://accounts.astian.org/application/o/midori-vpn/",
		AuthentikClientID:     "60mBgw8BHTvKRPYVhDTJGoKEt30QYG3b7Sv0RFNd",
		AuthentikClientSecret: "",
		AuthentikAuthURL:      "https://accounts.astian.org/application/o/authorize/",
		AuthentikTokenURL:     "https://accounts.astian.org/application/o/token/",
		AuthentikUserinfoURL:  "https://accounts.astian.org/application/o/userinfo/",
		AuthentikJWKSURL:      "https://accounts.astian.org/application/o/midori-vpn/jwks/",
		// Desktop redirect_uri is fixed to the agent's local callback. Must be
		// pre-registered as an allowed redirect URI in the Authentik client.
		AuthentikRedirectURI: "http://127.0.0.1:7071/oauth/callback",
	}
}

// Load reads, in order: defaults → /etc/midorivpn/config.env →
// $XDG_CONFIG_HOME/midorivpn/config.env → process environment.
// It never returns an error for missing files (those are normal).
func Load() Config {
	cfg := defaults()

	// System-wide override (packaged at /etc/midorivpn/config.env).
	applyDotenv(&cfg, "/etc/midorivpn/config.env")

	// Per-user override.
	if userPath, err := userConfigPath(); err == nil {
		applyDotenv(&cfg, userPath)
	}

	// Process env always wins.
	applyEnv(&cfg)

	return cfg
}

// userConfigPath returns $XDG_CONFIG_HOME/midorivpn/config.env or
// $HOME/.config/midorivpn/config.env.
func userConfigPath() (string, error) {
	if x := os.Getenv("XDG_CONFIG_HOME"); x != "" {
		return filepath.Join(x, "midorivpn", "config.env"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".config", "midorivpn", "config.env"), nil
}

// applyDotenv parses a `KEY=VALUE` file and applies recognised keys.
// Unknown keys are ignored. Lines starting with `#` are comments.
// Quoted values (single or double) are unquoted.
func applyDotenv(cfg *Config, path string) {
	f, err := os.Open(path) //nolint:gosec // operator-controlled config path
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		eq := strings.IndexByte(line, '=')
		if eq <= 0 {
			continue
		}
		key := strings.TrimSpace(line[:eq])
		val := strings.TrimSpace(line[eq+1:])
		val = unquote(val)
		assign(cfg, key, val)
	}
}

// applyEnv overlays process environment variables onto cfg.
func applyEnv(cfg *Config) {
	for _, k := range knownKeys() {
		if v, ok := os.LookupEnv(k); ok && v != "" {
			assign(cfg, k, v)
		}
	}
}

func assign(cfg *Config, key, val string) {
	switch key {
	case "API_URL":
		cfg.APIURL = val
	case "ACCOUNT_URL":
		cfg.AccountURL = val
	case "AUTHENTIK_ISSUER":
		cfg.AuthentikIssuer = val
	case "AUTHENTIK_CLIENT_ID":
		cfg.AuthentikClientID = val
	case "AUTHENTIK_CLIENT_SECRET":
		cfg.AuthentikClientSecret = val
	case "AUTHENTIK_AUTHORIZATION_URL", "AUTHENTIK_AUTH_URL":
		cfg.AuthentikAuthURL = val
	case "AUTHENTIK_TOKEN_URL":
		cfg.AuthentikTokenURL = val
	case "AUTHENTIK_USERINFO_URL":
		cfg.AuthentikUserinfoURL = val
	case "AUTHENTIK_JWKS_URL":
		cfg.AuthentikJWKSURL = val
	case "AUTHENTIK_REDIRECT_URI":
		cfg.AuthentikRedirectURI = val
	}
}

func knownKeys() []string {
	return []string{
		"API_URL",
		"ACCOUNT_URL",
		"AUTHENTIK_ISSUER",
		"AUTHENTIK_CLIENT_ID",
		"AUTHENTIK_CLIENT_SECRET",
		"AUTHENTIK_AUTHORIZATION_URL",
		"AUTHENTIK_AUTH_URL",
		"AUTHENTIK_TOKEN_URL",
		"AUTHENTIK_USERINFO_URL",
		"AUTHENTIK_JWKS_URL",
		"AUTHENTIK_REDIRECT_URI",
	}
}

func unquote(s string) string {
	if len(s) >= 2 {
		first, last := s[0], s[len(s)-1]
		if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
			return s[1 : len(s)-1]
		}
	}
	return s
}

// Validate returns an error if any required field is empty. Useful in tests
// or for fail-fast startup; the agent itself can still boot with defaults.
func (c Config) Validate() error {
	missing := []string{}
	check := func(name, v string) {
		if v == "" {
			missing = append(missing, name)
		}
	}
	check("API_URL", c.APIURL)
	check("AUTHENTIK_ISSUER", c.AuthentikIssuer)
	check("AUTHENTIK_CLIENT_ID", c.AuthentikClientID)
	check("AUTHENTIK_AUTH_URL", c.AuthentikAuthURL)
	check("AUTHENTIK_TOKEN_URL", c.AuthentikTokenURL)
	check("AUTHENTIK_REDIRECT_URI", c.AuthentikRedirectURI)
	if len(missing) > 0 {
		return fmt.Errorf("config missing required keys: %s", strings.Join(missing, ", "))
	}
	return nil
}
