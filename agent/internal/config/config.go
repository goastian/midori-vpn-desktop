// Package config loads layered runtime configuration for the agent.
//
// Resolution order (later wins):
//  1. The public production identity used by MidoriVPN Control.
//  2. Local .env/config.env files for development.
//  3. /etc/midorivpn/config.env (system-wide deployment override).
//  4. $XDG_CONFIG_HOME/midorivpn/config.env (per-user override).
//  5. Process environment variables.
//
// Keys mirror the browser extension (.env) so admins can use the same
// vocabulary across components: API_URL, AUTHENTIK_*, ACCOUNT_URL.
package config

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
)

// Config is the resolved runtime configuration.
type Config struct {
	// APIURL is the vpn-core base URL. Its origin is also sent as the Origin
	// header for vpn-core CSRF validation.
	APIURL               string
	AccountURL           string
	AuthentikIssuer      string
	AuthentikClientID    string
	AuthentikAuthURL     string
	AuthentikTokenURL    string
	AuthentikUserinfoURL string
	AuthentikJWKSURL     string
	AuthentikRedirectURI string
}

// Load reads configuration in hierarchical order:
//  1. Local .env / config.env (working directory)
//  2. /etc/midorivpn/config.env (system-wide)
//  3. $XDG_CONFIG_HOME/midorivpn/config.env (user-specific)
//  4. Process environment variables (highest priority)
func Load() Config {
	cfg := productionConfig()

	// Local directory .env and config.env
	applyDotenv(&cfg, ".env")
	applyDotenv(&cfg, "config.env")

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

// productionConfig contains public OIDC metadata only. It intentionally holds
// no client secret: this is the same PKCE public client and provider metadata
// discovered by MidoriVPN Control. Packaged desktops therefore work without a
// per-machine configuration file while development/deployment overrides remain
// available through the normal precedence chain.
func productionConfig() Config {
	return Config{
		APIURL:               "https://vpn.dorrejo.com",
		AccountURL:           "https://vpn.dorrejo.com",
		AuthentikIssuer:      "https://accounts.astian.org/",
		AuthentikClientID:    "Wbc5hsIaK6kDp4cCFvzTtgAnEc5qNfWWARMmYXTn",
		AuthentikAuthURL:     "https://accounts.astian.org/application/o/authorize/",
		AuthentikTokenURL:    "https://accounts.astian.org/application/o/token/",
		AuthentikUserinfoURL: "https://accounts.astian.org/application/o/userinfo/",
		AuthentikJWKSURL:     "https://accounts.astian.org/application/o/elrealplatano/jwks/",
		AuthentikRedirectURI: "http://127.0.0.1:7071/oauth/callback",
	}
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

// Validate returns an error if any required field is empty. The agent calls
// this during startup so an incomplete installation never contacts an
// unintended environment.
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
	check("AUTHENTIK_USERINFO_URL", c.AuthentikUserinfoURL)
	check("AUTHENTIK_JWKS_URL", c.AuthentikJWKSURL)
	check("AUTHENTIK_REDIRECT_URI", c.AuthentikRedirectURI)
	if len(missing) > 0 {
		return fmt.Errorf("config missing required keys: %s", strings.Join(missing, ", "))
	}
	redirect, err := url.Parse(c.AuthentikRedirectURI)
	if err != nil || redirect.Scheme != "http" || redirect.Hostname() != "127.0.0.1" || redirect.Port() == "" || redirect.Path != "/oauth/callback" || redirect.User != nil || redirect.RawQuery != "" || redirect.Fragment != "" {
		return fmt.Errorf("AUTHENTIK_REDIRECT_URI must be http://127.0.0.1:<port>/oauth/callback")
	}
	return nil
}
