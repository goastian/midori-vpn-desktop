package tunnel

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"
)

type SmartSelectorConfig struct {
	ProbeTimeout      time.Duration
	PreferredProtocol Protocol
	AllowFallback     bool
}

type SmartProtocolSelector struct {
	registry *Registry
	cfg      SmartSelectorConfig
}

func NewSmartProtocolSelector(registry *Registry, cfg SmartSelectorConfig) *SmartProtocolSelector {
	if cfg.ProbeTimeout == 0 {
		cfg.ProbeTimeout = 1500 * time.Millisecond
	}
	return &SmartProtocolSelector{
		registry: registry,
		cfg:      cfg,
	}
}

// SelectBestDriver executes parallel probing and selects the optimal tunnel driver
// based on network latency, handshake success, and firewall resistance (zero content inspection).
func (s *SmartProtocolSelector) SelectBestDriver(ctx context.Context, endpointHost string) (Driver, *ProbeResult, error) {
	drivers := s.registry.List()
	if len(drivers) == 0 {
		return nil, nil, ErrNoSuitableDriver
	}

	// 1. Direct override if a specific protocol was requested and exists
	if s.cfg.PreferredProtocol != "" && s.cfg.PreferredProtocol != ProtocolSmart {
		if d, ok := s.registry.Get(s.cfg.PreferredProtocol); ok {
			slog.Info("smart-protocol: using preferred protocol override", "protocol", s.cfg.PreferredProtocol)
			return d, &ProbeResult{Protocol: s.cfg.PreferredProtocol, Available: true}, nil
		}
	}

	// 2. Parallel probing of available protocols
	probeCtx, cancel := context.WithTimeout(ctx, s.cfg.ProbeTimeout)
	defer cancel()

	results := make(chan *ProbeResult, len(drivers))
	var wg sync.WaitGroup

	for _, d := range drivers {
		wg.Add(1)
		go func(driver Driver) {
			defer wg.Done()
			res, err := driver.Probe(probeCtx, endpointHost)
			if err != nil {
				results <- &ProbeResult{
					Protocol:  driver.Protocol(),
					Available: false,
					Error:     err.Error(),
				}
				return
			}
			results <- res
		}(d)
	}

	wg.Wait()
	close(results)

	probeMap := make(map[Protocol]*ProbeResult)
	for r := range results {
		probeMap[r.Protocol] = r
	}

	// 3. Smart Protocol Cascade:
	// Priority 1: Direct UDP WireGuard (Lowest latency, maximum throughput)
	if res, ok := probeMap[ProtocolWireGuard]; ok && res.Available {
		if d, found := s.registry.Get(ProtocolWireGuard); found {
			slog.Info("smart-protocol: wireguard direct UDP probe successful", "rtt_ms", res.Latency.Milliseconds())
			return d, res, nil
		}
	}

	// Priority 2: Obfuscated TLS 443 / WSS (Firewall & DPI bypass)
	if res, ok := probeMap[ProtocolObfsTLS]; ok && res.Available {
		if d, found := s.registry.Get(ProtocolObfsTLS); found {
			slog.Warn("smart-protocol: UDP blocked, fallback to Obfs TLS 443", "rtt_ms", res.Latency.Milliseconds())
			return d, res, nil
		}
	}

	// Priority 3: MASQUE HTTP/3 (QUIC-based multiplexing)
	if res, ok := probeMap[ProtocolMASQUE]; ok && res.Available {
		if d, found := s.registry.Get(ProtocolMASQUE); found {
			slog.Info("smart-protocol: connecting via MASQUE HTTP/3", "rtt_ms", res.Latency.Milliseconds())
			return d, res, nil
		}
	}

	// Priority 4: OpenVPN DCO (Compatibility fallback)
	if res, ok := probeMap[ProtocolOpenVPN]; ok && res.Available {
		if d, found := s.registry.Get(ProtocolOpenVPN); found {
			slog.Warn("smart-protocol: fallback to OpenVPN DCO compatibility mode")
			return d, res, nil
		}
	}

	return nil, nil, fmt.Errorf("%w: all probe candidates failed", ErrNoSuitableDriver)
}
