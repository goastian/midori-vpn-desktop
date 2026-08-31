//go:build linux

// Package ikev2 runs a private strongSwan 6 charon instance for one EAP-TLS
// connection. Configuration and device keys exist only in the runtime
// directory and no system-wide strongSwan connection is created.
package ikev2

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/goastian/midorivpn-agent/internal/devicepki"
	"golang.org/x/sys/unix"
)

const (
	interfaceName   = "midorivpn-ike"
	xfrmInterfaceID = "42"
	connectionName  = "midori-client"
	childName       = "midori-full"
)

var safeServerName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
var safeCertificateID = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)

type Config struct {
	Endpoint   string
	ServerName string
	Credential *devicepki.Credential
	Timeout    time.Duration
}

type Client struct {
	charon            *exec.Cmd
	charonDone        chan error
	charonOutput      *boundedOutput
	files             *devicepki.RuntimeFiles
	swanctl           string
	swanctlDirectory  string
	configPath        string
	swanctlConfigPath string
	closeOnce         sync.Once
}

const charonDiagnosticLimit = 16 * 1024

// boundedOutput retains only the latest strongSwan diagnostics. charon can run
// for hours, so attaching an unbounded buffer would leak memory over time.
type boundedOutput struct {
	mu    sync.Mutex
	limit int
	data  []byte
}

func newBoundedOutput(limit int) *boundedOutput { return &boundedOutput{limit: limit} }

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	written := len(p)
	if b.limit <= 0 {
		return written, nil
	}
	if len(p) >= b.limit {
		b.data = append(b.data[:0], p[len(p)-b.limit:]...)
		return written, nil
	}
	overflow := len(b.data) + len(p) - b.limit
	if overflow > 0 {
		copy(b.data, b.data[overflow:])
		b.data = b.data[:len(b.data)-overflow]
	}
	b.data = append(b.data, p...)
	return written, nil
}

func (b *boundedOutput) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return strings.TrimSpace(string(b.data))
}

func Start(ctx context.Context, config Config) (*Client, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	charonVersionPath, err := findExecutable("/usr/libexec/ipsec/charon", "/usr/lib/ipsec/charon")
	if err != nil {
		return nil, errors.New("strongSwan 6 is not installed")
	}
	charonPath, err := findExecutable("/usr/sbin/charon-systemd", "/usr/libexec/ipsec/charon-systemd")
	if err != nil {
		return nil, errors.New("strongSwan charon-systemd is not installed")
	}
	swanctlPath, err := findExecutable("/usr/sbin/swanctl", "/usr/bin/swanctl")
	if err != nil {
		return nil, errors.New("strongSwan swanctl is not installed")
	}
	files, err := config.Credential.Materialize()
	if err != nil {
		return nil, err
	}
	client := &Client{
		files: files, swanctl: swanctlPath, charonDone: make(chan error, 1),
		charonOutput: newBoundedOutput(charonDiagnosticLimit),
	}
	if err := client.prepareRuntime(config); err != nil {
		client.Close()
		return nil, err
	}
	if err := requireVersion(ctx, charonVersionPath, client.configPath); err != nil {
		client.Close()
		return nil, err
	}
	if err := createXFRMInterface(); err != nil {
		client.Close()
		return nil, err
	}
	client.charon = exec.Command(charonPath)
	client.charon.Env = append(os.Environ(), "STRONGSWAN_CONF="+client.configPath)
	if err := setNetworkCapsInheritable(); err != nil {
		client.Close()
		return nil, fmt.Errorf("prepare strongSwan network capabilities: %w", err)
	}
	client.charon.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}}
	client.charon.Stdout = client.charonOutput
	client.charon.Stderr = client.charonOutput
	if err := client.charon.Start(); err != nil {
		client.Close()
		return nil, fmt.Errorf("start strongSwan charon: %w", err)
	}
	go func() { client.charonDone <- client.charon.Wait() }()
	if err := client.waitForVICI(ctx, config.Timeout); err != nil {
		client.Close()
		return nil, err
	}
	if _, err := client.runSwanctl(ctx, config.Timeout, "--load-all", "--file", client.swanctlConfigPath); err != nil {
		client.Close()
		return nil, fmt.Errorf("load strongSwan connection: %w", err)
	}
	if _, err := client.runSwanctl(ctx, config.Timeout, "--initiate", "--ike", connectionName, "--child", childName); err != nil {
		client.Close()
		return nil, fmt.Errorf("complete IKEv2 EAP-TLS handshake: %w", err)
	}
	if err := client.waitForAssignedIP(ctx, 3*time.Second); err != nil {
		client.Close()
		return nil, err
	}
	return client, nil
}

func validateConfig(config Config) error {
	if config.Credential == nil || !safeCertificateID.MatchString(config.Credential.CertificateID) ||
		config.Credential.Identity != "urn:midorivpn:device:"+config.Credential.CertificateID {
		return errors.New("IKEv2 device credential is required")
	}
	host, port, err := net.SplitHostPort(config.Endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("IKEv2 endpoint must be a host and port")
	}
	if net.ParseIP(host) == nil && !validDNSName(host) {
		return errors.New("IKEv2 endpoint host is invalid")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return errors.New("IKEv2 endpoint port is invalid")
	}
	if !validDNSName(config.ServerName) {
		return errors.New("IKEv2 server certificate name must be a DNS name")
	}
	return nil
}

func validDNSName(value string) bool {
	if !safeServerName.MatchString(value) || net.ParseIP(value) != nil || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
	}
	return true
}

func (c *Client) prepareRuntime(config Config) error {
	credentialRoot := filepath.Join(c.files.Directory, "swanctl")
	for _, directory := range []string{"private", "x509", "x509ca"} {
		if err := os.MkdirAll(filepath.Join(credentialRoot, directory), 0o700); err != nil {
			return fmt.Errorf("create strongSwan credential directory: %w", err)
		}
	}
	paths := []struct {
		from string
		to   string
	}{
		{c.files.PrivateKeyPath, filepath.Join(credentialRoot, "private", "device.key")},
		{c.files.CertificatePath, filepath.Join(credentialRoot, "x509", "device.crt")},
		{c.files.CAPath, filepath.Join(credentialRoot, "x509ca", "client-ca.pem")},
	}
	for _, path := range paths {
		if err := os.Rename(path.from, path.to); err != nil {
			return fmt.Errorf("prepare strongSwan credential: %w", err)
		}
	}
	configPath := filepath.Join(c.files.Directory, "strongswan.conf")
	swanctlPath := filepath.Join(credentialRoot, "swanctl.conf")
	viciSocket := filepath.Join(c.files.Directory, "charon.vici")
	strongswanConfig := buildStrongSwanConfig(viciSocket)
	swanctlConfig := buildSwanctlConfig(config)
	if err := os.WriteFile(configPath, []byte(strongswanConfig), 0o600); err != nil {
		return fmt.Errorf("write strongSwan runtime configuration: %w", err)
	}
	if err := os.WriteFile(swanctlPath, []byte(swanctlConfig), 0o600); err != nil {
		return fmt.Errorf("write swanctl runtime configuration: %w", err)
	}
	c.configPath = configPath
	c.swanctlDirectory = credentialRoot
	c.swanctlConfigPath = swanctlPath
	return nil
}

func buildStrongSwanConfig(viciSocket string) string {
	return fmt.Sprintf(`charon {
  load_modular = no
  load = random nonce x509 revocation constraints pubkey pem openssl pkcs1 pkcs8 gmp kdf gcm drbg kernel-netlink socket-default vici eap-identity eap-tls
  initiator_only = yes
  port = 0
  port_nat_t = 0
  install_routes = yes
  install_virtual_ip = yes
  install_virtual_ip_on = %s
  plugins {
    kernel-netlink { install_routes_xfrmi = yes }
    vici { socket = unix://%s }
  }
}
charon-systemd {
  filelog {
    stderr {
      default = 2
      flush_line = yes
    }
  }
}
swanctl {
  socket = unix://%s
}
`, interfaceName, viciSocket, viciSocket)
}

func buildSwanctlConfig(config Config) string {
	host, port, _ := net.SplitHostPort(config.Endpoint)
	// strongSwan parses a URN containing ':' as KEY_ID, while the certificate
	// carries that value as a URI SAN. These identity types do not match during
	// EAP-TLS certificate selection. Use the certificate's exact subject DN,
	// which remains uniquely bound to the same random certificate identifier.
	eapIdentity := "O=MidoriVPN, CN=device:" + config.Credential.CertificateID
	return fmt.Sprintf(`connections {
  %s {
    version = 2
    remote_addrs = %s
    remote_port = %s
    vips = 0.0.0.0
    proposals = aes256gcm16-prfsha384-ecp384,aes128gcm16-prfsha256-ecp256
    fragmentation = yes
    mobike = yes
    encap = yes
    local {
      auth = eap
      id = "%s"
      eap_id = "%s"
      certs = device.crt
    }
    remote {
      auth = pubkey
      id = %s
      cacerts = client-ca.pem
    }
    children {
      %s {
        local_ts = dynamic
        remote_ts = 0.0.0.0/0
        if_id_in = %s
        if_id_out = %s
        esp_proposals = aes256gcm16-ecp384,aes128gcm16-ecp256
        dpd_action = clear
        close_action = none
        start_action = none
      }
    }
  }
}
secrets {
  private-device { file = device.key }
}
`, connectionName, host, port, eapIdentity, eapIdentity, config.ServerName, childName, xfrmInterfaceID, xfrmInterfaceID)
}

func (c *Client) waitForVICI(ctx context.Context, configuredTimeout time.Duration) error {
	timeout := configuredTimeout
	if timeout <= 0 || timeout > 10*time.Second {
		timeout = 10 * time.Second
	}
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	socket := filepath.Join(c.files.Directory, "charon.vici")
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case err := <-c.charonDone:
			diagnostic := c.charonOutput.String()
			if diagnostic != "" {
				diagnostic = ": " + diagnostic
			}
			if err == nil {
				return errors.New("strongSwan charon exited during startup" + diagnostic)
			}
			return fmt.Errorf("strongSwan charon exited during startup: %w%s", err, diagnostic)
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("strongSwan VICI socket startup timed out")
		case <-ticker.C:
			if info, err := os.Stat(socket); err == nil && info.Mode()&os.ModeSocket != 0 {
				return nil
			}
		}
	}
}

func (c *Client) runSwanctl(parent context.Context, timeout time.Duration, arguments ...string) (string, error) {
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	uri := "unix://" + filepath.Join(c.files.Directory, "charon.vici")
	arguments = append(arguments, "--uri", uri)
	command := exec.CommandContext(ctx, c.swanctl, arguments...)
	command.Env = append(os.Environ(), "STRONGSWAN_CONF="+c.configPath, "SWANCTL_DIR="+c.swanctlDirectory)
	output, err := command.CombinedOutput()
	if ctx.Err() != nil {
		return "", c.withCharonDiagnostic(ctx.Err())
	}
	if err != nil {
		commandOutput := strings.TrimSpace(string(output))
		if commandOutput == "" {
			return "", c.withCharonDiagnostic(err)
		}
		return "", c.withCharonDiagnostic(fmt.Errorf("%w: %s", err, commandOutput))
	}
	return string(output), nil
}

func (c *Client) withCharonDiagnostic(err error) error {
	if c.charonOutput == nil {
		return err
	}
	diagnostic := c.charonOutput.String()
	if diagnostic == "" {
		return err
	}
	return fmt.Errorf("%w: %s", err, diagnostic)
}

func (c *Client) waitForAssignedIP(ctx context.Context, timeout time.Duration) error {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		if c.AssignedIP() != "" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("IKEv2 gateway did not assign a virtual IP")
		case <-ticker.C:
		}
	}
}

func createXFRMInterface() error {
	_ = deleteXFRMInterface()
	if _, err := runIP("link", "add", interfaceName, "type", "xfrm", "if_id", xfrmInterfaceID); err != nil {
		return fmt.Errorf("create IKEv2 XFRM interface: %w", err)
	}
	if _, err := runIP("link", "set", interfaceName, "up"); err != nil {
		_ = deleteXFRMInterface()
		return fmt.Errorf("activate IKEv2 XFRM interface: %w", err)
	}
	return nil
}

func deleteXFRMInterface() error {
	_, err := runIP("link", "delete", interfaceName)
	return err
}

func runIP(arguments ...string) ([]byte, error) {
	ipPath, err := findExecutable("/usr/sbin/ip", "/usr/bin/ip")
	if err != nil {
		return nil, err
	}
	if err := setNetworkCapsInheritable(); err != nil {
		return nil, fmt.Errorf("prepare ip network capabilities: %w", err)
	}
	command := exec.Command(ipPath, arguments...)
	command.Env = []string{"PATH=/usr/sbin:/usr/bin:/sbin:/bin"}
	command.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_NET_ADMIN}}
	output, err := command.CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(output)))
	}
	return output, nil
}

func setNetworkCapsInheritable() error {
	var header unix.CapUserHeader
	header.Version = unix.LINUX_CAPABILITY_VERSION_3
	var data [2]unix.CapUserData
	if err := unix.Capget(&header, &data[0]); err != nil {
		return err
	}
	data[0].Inheritable |= 1<<unix.CAP_NET_ADMIN | 1<<unix.CAP_NET_RAW
	return unix.Capset(&header, &data[0])
}

func requireVersion(ctx context.Context, binary, configPath string) error {
	versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	command := exec.CommandContext(versionCtx, binary, "--version")
	command.Env = append(os.Environ(), "STRONGSWAN_CONF="+configPath)
	output, err := command.CombinedOutput()
	if err != nil {
		return fmt.Errorf("read strongSwan version: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 2 || fields[0] != "strongSwan" {
		return errors.New("unrecognized strongSwan version output")
	}
	parts := strings.Split(fields[1], ".")
	major, majorErr := strconv.Atoi(parts[0])
	if majorErr != nil || major < 6 {
		return fmt.Errorf("strongSwan 6 or newer is required (found %s)", fields[1])
	}
	return nil
}

func findExecutable(paths ...string) (string, error) {
	for _, path := range paths {
		if info, err := os.Stat(path); err == nil && !info.IsDir() && info.Mode()&0o111 != 0 {
			return path, nil
		}
	}
	return "", errors.New("executable not found")
}

func (c *Client) InterfaceName() string { return interfaceName }

func (c *Client) AssignedIP() string {
	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return ""
	}
	addresses, err := iface.Addrs()
	if err != nil {
		return ""
	}
	for _, address := range addresses {
		ip, network, err := net.ParseCIDR(address.String())
		if err == nil && ip.To4() != nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
			return (&net.IPNet{IP: ip, Mask: network.Mask}).String()
		}
	}
	return ""
}

func (c *Client) ByteCounters() (tx, rx int64, ok bool) {
	txValue, txErr := os.ReadFile(filepath.Join("/sys/class/net", interfaceName, "statistics/tx_bytes"))
	rxValue, rxErr := os.ReadFile(filepath.Join("/sys/class/net", interfaceName, "statistics/rx_bytes"))
	if txErr != nil || rxErr != nil {
		return 0, 0, false
	}
	tx, txErr = strconv.ParseInt(strings.TrimSpace(string(txValue)), 10, 64)
	rx, rxErr = strconv.ParseInt(strings.TrimSpace(string(rxValue)), 10, 64)
	return tx, rx, txErr == nil && rxErr == nil
}

func (c *Client) Close() {
	c.closeOnce.Do(func() {
		if c.swanctl != "" && c.files != nil && c.configPath != "" {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			_, _ = c.runSwanctl(ctx, 3*time.Second, "--terminate", "--ike", connectionName)
			cancel()
		}
		if c.charon != nil && c.charon.Process != nil {
			_ = c.charon.Process.Signal(syscall.SIGTERM)
			select {
			case <-c.charonDone:
			case <-time.After(3 * time.Second):
				_ = c.charon.Process.Kill()
			}
		}
		_ = deleteXFRMInterface()
		if c.files != nil {
			_ = c.files.Close()
		}
	})
}
