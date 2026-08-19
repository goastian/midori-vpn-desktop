package tunnel

import (
	"context"
	"fmt"
	"net"
	"os"
	"time"
)

type OpenVpnDcoDriver struct {
	dcoAvailable bool
}

func NewOpenVpnDcoDriver() *OpenVpnDcoDriver {
	// Detect if ovpn-dco kernel module is available in Linux
	dco := false
	if _, err := os.Stat("/sys/module/ovpn_dco"); err == nil {
		dco = true
	}
	return &OpenVpnDcoDriver{dcoAvailable: dco}
}

func (o *OpenVpnDcoDriver) Name() string {
	if o.dcoAvailable {
		return "openvpn-dco-kernel"
	}
	return "openvpn-compat"
}

func (o *OpenVpnDcoDriver) Protocol() Protocol {
	return ProtocolOpenVPN
}

func (o *OpenVpnDcoDriver) Capabilities() DriverCapabilities {
	return DriverCapabilities{
		SupportsIPv6:        true,
		SupportsObfuscation: false,
		SupportsDCO:         o.dcoAvailable,
		HardwareAccel:       o.dcoAvailable,
	}
}

func (o *OpenVpnDcoDriver) Connect(ctx context.Context, cfg *TunnelConfig) (*Session, error) {
	return &Session{
		ID:          fmt.Sprintf("ovpn-%s-%d", cfg.ServerID, time.Now().Unix()),
		Protocol:    ProtocolOpenVPN,
		Driver:      o.Name(),
		ConnectedAt: time.Now(),
		LocalIP:     cfg.AssignedIP,
		Endpoint:    fmt.Sprintf("%s:%d", cfg.ServerHost, 1194),
	}, nil
}

func (o *OpenVpnDcoDriver) Disconnect(ctx context.Context) error {
	return nil
}

func (o *OpenVpnDcoDriver) Stats(ctx context.Context) (*Stats, error) {
	return &Stats{
		LastHandshake: time.Now(),
		RTT:           55 * time.Millisecond,
		PacketLoss:    0.0,
	}, nil
}

func (o *OpenVpnDcoDriver) Probe(ctx context.Context, endpointHost string) (*ProbeResult, error) {
	start := time.Now()
	target := net.JoinHostPort(endpointHost, "1194")
	conn, err := net.DialTimeout("udp", target, 1500*time.Millisecond)
	if err != nil {
		return &ProbeResult{
			Protocol:  ProtocolOpenVPN,
			Available: false,
			Error:     err.Error(),
		}, err
	}
	defer conn.Close()

	rtt := time.Since(start)
	return &ProbeResult{
		Protocol:  ProtocolOpenVPN,
		Available: true,
		Latency:   rtt,
	}, nil
}
