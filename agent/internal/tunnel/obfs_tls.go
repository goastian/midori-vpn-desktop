package tunnel

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

type ObfsTLSDriver struct {
	customPath string
}

func NewObfsTLSDriver(customPath string) *ObfsTLSDriver {
	if customPath == "" {
		customPath = "/tunnel/wss"
	}
	return &ObfsTLSDriver{customPath: customPath}
}

func (o *ObfsTLSDriver) Name() string {
	return "obfs-tls-wss"
}

func (o *ObfsTLSDriver) Protocol() Protocol {
	return ProtocolObfsTLS
}

func (o *ObfsTLSDriver) Capabilities() DriverCapabilities {
	return DriverCapabilities{
		SupportsIPv6:        true,
		SupportsObfuscation: true,
		SupportsDCO:         false,
		HardwareAccel:       false,
	}
}

func (o *ObfsTLSDriver) Connect(ctx context.Context, cfg *TunnelConfig) (*Session, error) {
	return &Session{
		ID:          fmt.Sprintf("obfs-%s-%d", cfg.ServerID, time.Now().Unix()),
		Protocol:    ProtocolObfsTLS,
		Driver:      o.Name(),
		ConnectedAt: time.Now(),
		LocalIP:     cfg.AssignedIP,
		Endpoint:    fmt.Sprintf("https://%s:443%s", cfg.ServerHost, o.customPath),
	}, nil
}

func (o *ObfsTLSDriver) Disconnect(ctx context.Context) error {
	return nil
}

func (o *ObfsTLSDriver) Stats(ctx context.Context) (*Stats, error) {
	return &Stats{
		LastHandshake: time.Now(),
		RTT:           45 * time.Millisecond,
		PacketLoss:    0.0,
	}, nil
}

func (o *ObfsTLSDriver) Probe(ctx context.Context, endpointHost string) (*ProbeResult, error) {
	start := time.Now()
	target := net.JoinHostPort(endpointHost, "443")

	tlsDialer := &tls.Dialer{
		Config: &tls.Config{
			ServerName: endpointHost,
			MinVersion: tls.VersionTLS12,
		},
	}

	conn, err := tlsDialer.DialContext(ctx, "tcp", target)
	if err != nil {
		return &ProbeResult{
			Protocol:  ProtocolObfsTLS,
			Available: false,
			Error:     err.Error(),
		}, err
	}
	defer conn.Close()

	rtt := time.Since(start)
	return &ProbeResult{
		Protocol:  ProtocolObfsTLS,
		Available: true,
		Latency:   rtt,
	}, nil
}
