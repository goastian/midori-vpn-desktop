//go:build linux

// Package openvpn runs the distribution OpenVPN 2.7 client with a narrow,
// generated configuration and requires a kernel DCO network device.
package openvpn

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
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

const interfaceName = "midorivpn-ovpn"

var safeServerName = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)

type Config struct {
	Endpoint   string
	ServerName string
	Credential *devicepki.Credential
	Timeout    time.Duration
}

type Client struct {
	mu        sync.RWMutex
	cmd       *exec.Cmd
	files     *devicepki.RuntimeFiles
	dns       []string
	dcoActive bool
	done      chan error
	closeOnce sync.Once
}

func Start(ctx context.Context, config Config) (*Client, error) {
	if err := validateConfig(config); err != nil {
		return nil, err
	}
	openvpnPath, err := exec.LookPath("openvpn")
	if err != nil {
		return nil, errors.New("OpenVPN 2.7 is not installed")
	}
	if err := requireVersion(ctx, openvpnPath); err != nil {
		return nil, err
	}
	files, err := config.Credential.Materialize()
	if err != nil {
		return nil, err
	}
	client := &Client{files: files, done: make(chan error, 1)}
	managementSocket := filepath.Join(files.Directory, "management.sock")
	args := buildArgs(config, files, managementSocket)
	client.cmd = exec.Command(openvpnPath, args...)
	client.cmd.SysProcAttr = &syscall.SysProcAttr{AmbientCaps: []uintptr{unix.CAP_NET_ADMIN, unix.CAP_NET_RAW}}
	reader, writer, err := os.Pipe()
	if err != nil {
		_ = files.Close()
		return nil, fmt.Errorf("create OpenVPN log pipe: %w", err)
	}
	client.cmd.Stdout = writer
	client.cmd.Stderr = writer
	if err := client.cmd.Start(); err != nil {
		_ = reader.Close()
		_ = writer.Close()
		_ = files.Close()
		return nil, fmt.Errorf("start OpenVPN: %w", err)
	}
	_ = writer.Close()
	initialized := make(chan struct{}, 1)
	go client.consumeOutput(reader, initialized)
	go func() { client.done <- client.cmd.Wait() }()

	timeout := config.Timeout
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-initialized:
		if err := client.verifyDCO(); err != nil {
			client.Close()
			return nil, err
		}
		return client, nil
	case err := <-client.done:
		_ = files.Close()
		if err == nil {
			return nil, errors.New("OpenVPN exited before completing the handshake")
		}
		return nil, fmt.Errorf("OpenVPN exited before completing the handshake: %w", err)
	case <-ctx.Done():
		client.Close()
		return nil, ctx.Err()
	case <-timer.C:
		client.Close()
		return nil, errors.New("OpenVPN handshake timed out")
	}
}

func validateConfig(config Config) error {
	if config.Credential == nil {
		return errors.New("OpenVPN device credential is required")
	}
	host, port, err := net.SplitHostPort(config.Endpoint)
	if err != nil || strings.TrimSpace(host) == "" {
		return errors.New("OpenVPN endpoint must be a host and port")
	}
	parsedPort, err := strconv.Atoi(port)
	if err != nil || parsedPort < 1 || parsedPort > 65535 {
		return errors.New("OpenVPN endpoint port is invalid")
	}
	if !safeServerName.MatchString(config.ServerName) || net.ParseIP(config.ServerName) != nil {
		return errors.New("OpenVPN server certificate name must be a DNS name")
	}
	return nil
}

func buildArgs(config Config, files *devicepki.RuntimeFiles, managementSocket string) []string {
	host, port, _ := net.SplitHostPort(config.Endpoint)
	return []string{
		"--client",
		"--dev", interfaceName,
		"--dev-type", "tun",
		"--topology", "subnet",
		"--proto", "udp",
		"--remote", host, port,
		"--nobind",
		"--remote-cert-tls", "server",
		"--verify-x509-name", config.ServerName, "name",
		"--tls-version-min", "1.3",
		"--data-ciphers", "AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305",
		"--auth", "SHA256",
		"--allow-compression", "no",
		"--auth-nocache",
		"--ca", files.CAPath,
		"--cert", files.CertificatePath,
		"--key", files.PrivateKeyPath,
		"--management", managementSocket, "unix",
		"--management-log-cache", "50",
		"--machine-readable-output",
		"--verb", "3",
	}
}

func requireVersion(ctx context.Context, binary string) error {
	versionCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	output, err := exec.CommandContext(versionCtx, binary, "--version").Output()
	if err != nil {
		return fmt.Errorf("read OpenVPN version: %w", err)
	}
	fields := strings.Fields(string(output))
	if len(fields) < 2 || fields[0] != "OpenVPN" {
		return errors.New("unrecognized OpenVPN version output")
	}
	parts := strings.Split(fields[1], ".")
	major, majorErr := strconv.Atoi(parts[0])
	minor := 0
	if len(parts) > 1 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if majorErr != nil || major < 2 || major == 2 && minor < 7 {
		return fmt.Errorf("OpenVPN 2.7 or newer is required (found %s)", fields[1])
	}
	if !strings.Contains(string(output), "[DCO]") {
		return errors.New("installed OpenVPN was built without DCO support")
	}
	return nil
}

func (c *Client) consumeOutput(reader io.ReadCloser, initialized chan<- struct{}) {
	defer reader.Close()
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 4096), 256*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.Contains(line, "Initialization Sequence Completed") {
			select {
			case initialized <- struct{}{}:
			default:
			}
		}
		if strings.Contains(line, "DCO device ") && strings.Contains(line, " opened") {
			c.mu.Lock()
			c.dcoActive = true
			c.mu.Unlock()
		}
		for _, token := range strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == '\'' || r == ' ' }) {
			ip := net.ParseIP(strings.TrimSpace(token))
			if ip == nil || ip.IsLoopback() || ip.IsUnspecified() {
				continue
			}
			if strings.Contains(line, "dhcp-option DNS "+token) {
				c.addDNS(ip.String())
			}
		}
	}
}

func (c *Client) addDNS(value string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, existing := range c.dns {
		if existing == value {
			return
		}
	}
	c.dns = append(c.dns, value)
}

func (c *Client) verifyDCO() error {
	c.mu.RLock()
	active := c.dcoActive
	c.mu.RUnlock()
	if !active {
		return errors.New("OpenVPN connected without opening a DCO device")
	}
	if _, err := net.InterfaceByName(interfaceName); err != nil {
		return fmt.Errorf("verify OpenVPN DCO interface: %w", err)
	}
	return nil
}

func (c *Client) InterfaceName() string { return interfaceName }

func (c *Client) DNS() []string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return append([]string(nil), c.dns...)
}

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
		if err == nil && !ip.IsLoopback() && !ip.IsLinkLocalUnicast() {
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
		if c.cmd != nil && c.cmd.Process != nil {
			_ = c.cmd.Process.Signal(syscall.SIGTERM)
			select {
			case <-c.done:
			case <-time.After(5 * time.Second):
				_ = c.cmd.Process.Kill()
				select {
				case <-c.done:
				case <-time.After(time.Second):
				}
			}
		}
		if c.files != nil {
			_ = c.files.Close()
		}
	})
}
