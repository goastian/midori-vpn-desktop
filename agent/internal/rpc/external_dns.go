package rpc

import (
	"fmt"

	"github.com/goastian/midorivpn-agent/internal/dns"
)

func (s *Server) applyExternalDNS(iface string, servers []string) error {
	s.externalDNSMu.Lock()
	defer s.externalDNSMu.Unlock()
	if s.externalDNSApplied && s.externalDNS != nil {
		_ = s.externalDNS.Restore()
		s.externalDNSApplied = false
	}
	if s.externalDNS == nil {
		s.externalDNS = dns.Detect()
	}
	if err := s.externalDNS.Apply(iface, servers); err != nil {
		return fmt.Errorf("dns apply (%s): %w", s.externalDNS.Kind(), err)
	}
	s.externalDNSApplied = true
	return nil
}

func (s *Server) restoreExternalDNS() {
	s.externalDNSMu.Lock()
	defer s.externalDNSMu.Unlock()
	if s.externalDNSApplied && s.externalDNS != nil {
		_ = s.externalDNS.Restore()
	}
	s.externalDNSApplied = false
}

func (s *Server) currentDNSStatus() (dns.Kind, bool) {
	s.externalDNSMu.Lock()
	defer s.externalDNSMu.Unlock()
	if s.externalDNSApplied && s.externalDNS != nil {
		return s.externalDNS.Kind(), true
	}
	return s.wgMgr.DNSBackendKind(), s.wgMgr.DNSProtected()
}
