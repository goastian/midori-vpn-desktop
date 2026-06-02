// Package logredact provides small helpers to keep sensitive values (DNS
// servers, client/peer IPs, hostnames, usernames, HTTP bodies) out of the
// agent's structured logs by default.
//
// Verbose, unredacted logging can be re-enabled at runtime by setting the
// environment variable MIDORIVPN_AGENT_DEBUG_LOGS=1. Without that opt-in,
// all helpers return a fingerprint-style summary instead of the raw value.
package logredact

import (
	"crypto/sha256"
	"encoding/hex"
	"net"
	"os"
	"strings"
	"sync"
)

var verboseOnce sync.Once
var verbose bool

// Verbose reports whether unredacted logging has been opted into via the
// MIDORIVPN_AGENT_DEBUG_LOGS environment variable. The value is cached on
// first access.
func Verbose() bool {
	verboseOnce.Do(func() {
		v := strings.TrimSpace(os.Getenv("MIDORIVPN_AGENT_DEBUG_LOGS"))
		verbose = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
	})
	return verbose
}

// IP masks the host portion of an IP address. IPv4 keeps the first octet
// ("10.0.0.5" -> "10.x.x.x"); IPv6 keeps the first hextet. Inputs that are
// not parseable IPs are passed through Generic.
func IP(s string) string {
	if Verbose() {
		return s
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return Generic(s)
	}
	if v4 := ip.To4(); v4 != nil {
		return itoa(int(v4[0])) + ".x.x.x"
	}
	parts := strings.Split(ip.To16().String(), ":")
	if len(parts) == 0 {
		return "ipv6:redacted"
	}
	return parts[0] + ":x:x:x:x:x:x:x"
}

// IPs applies IP to each element.
func IPs(ss []string) []string {
	if Verbose() {
		return ss
	}
	out := make([]string, len(ss))
	for i, s := range ss {
		out[i] = IP(s)
	}
	return out
}

// HostPort masks the host portion of a "host:port" pair, preserving the port
// so connection issues remain diagnosable. Bare hostnames (no port) are
// returned via Host.
func HostPort(s string) string {
	if Verbose() {
		return s
	}
	if s == "" {
		return ""
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Host(s)
	}
	return Host(host) + ":" + port
}

// Host returns a coarse hostname summary: top-level domain plus a fingerprint
// of the full value. IP literals are routed through IP.
func Host(s string) string {
	if Verbose() {
		return s
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if ip := net.ParseIP(s); ip != nil {
		return IP(s)
	}
	dot := strings.LastIndex(s, ".")
	suffix := ""
	if dot >= 0 && dot < len(s)-1 {
		suffix = "." + s[dot+1:]
	}
	return "***" + suffix + "#" + fingerprint(s)
}

// User masks a username or email-like identifier, retaining only the first
// character and (for emails) the domain.
func User(s string) string {
	if Verbose() {
		return s
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	at := strings.IndexByte(s, '@')
	if at <= 0 {
		if len(s) == 1 {
			return "*"
		}
		return s[:1] + "***#" + fingerprint(s)
	}
	local := s[:at]
	domain := s[at:]
	first := "*"
	if len(local) > 0 {
		first = local[:1]
	}
	return first + "***" + domain
}

// Body summarises an arbitrary byte payload as "<len>B sha256:<8 hex>".
func Body(b []byte) string {
	if Verbose() {
		return string(b)
	}
	sum := sha256.Sum256(b)
	return itoa(len(b)) + "B sha256:" + hex.EncodeToString(sum[:4])
}

// Generic returns a length+fingerprint summary for an opaque string value.
func Generic(s string) string {
	if Verbose() {
		return s
	}
	if s == "" {
		return ""
	}
	return "len=" + itoa(len(s)) + " sha256:" + fingerprint(s)
}

func fingerprint(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:4])
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
