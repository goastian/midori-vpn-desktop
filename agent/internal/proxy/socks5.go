package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"
)

type SOCKS5Server struct {
	addr              string
	allowedSourceNets []*net.IPNet
	maxConnections    int
	limit             chan struct{}
}

type SOCKS5Option func(*SOCKS5Server)

func WithAllowedSourceCIDRs(cidrs []string) SOCKS5Option {
	return func(s *SOCKS5Server) {
		s.allowedSourceNets = parseCIDRs(cidrs)
	}
}

func WithMaxConnections(n int) SOCKS5Option {
	return func(s *SOCKS5Server) {
		if n > 0 {
			s.maxConnections = n
		}
	}
}

func NewSOCKS5(addr string, opts ...SOCKS5Option) *SOCKS5Server {
	s := &SOCKS5Server{addr: addr, maxConnections: 128}
	for _, opt := range opts {
		opt(s)
	}
	s.limit = make(chan struct{}, s.maxConnections)
	return s
}

func MeshSourceCIDRs(meshIP string) []string {
	ip := net.ParseIP(meshIP)
	if ip == nil {
		return nil
	}
	if ip.To4() != nil {
		switch {
		case cidrContains("100.64.0.0/10", ip):
			return []string{"100.64.0.0/10"}
		case ip.IsPrivate():
			return []string{privateIPv4CIDR(ip)}
		default:
			return []string{ip.String() + "/32"}
		}
	}
	if cidrContains("fd00::/8", ip) {
		return []string{"fd00::/8"}
	}
	return []string{ip.String() + "/128"}
}

func SourceCIDRsForIPs(ips []string) []string {
	cidrs := make([]string, 0, len(ips))
	for _, raw := range ips {
		ip := net.ParseIP(raw)
		if ip == nil {
			continue
		}
		if ip.To4() != nil {
			cidrs = append(cidrs, ip.String()+"/32")
		} else {
			cidrs = append(cidrs, ip.String()+"/128")
		}
	}
	return cidrs
}

func (s *SOCKS5Server) Start(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.addr)
	if err != nil {
		return fmt.Errorf("socks5 listen: %w", err)
	}
	defer ln.Close()
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	slog.Info("mesh socks5 proxy listening", "addr", s.addr, "source_filters", len(s.allowedSourceNets))
	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		if !s.allowConn(conn) {
			slog.Warn("mesh socks5 rejected remote source", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
			continue
		}
		select {
		case s.limit <- struct{}{}:
			go func() {
				defer func() { <-s.limit }()
				s.handle(ctx, conn)
			}()
		default:
			slog.Warn("mesh socks5 rejected connection: limit reached", "remote", conn.RemoteAddr().String())
			_ = conn.Close()
		}
	}
}

func (s *SOCKS5Server) handle(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))

	buf := make([]byte, 262)
	if _, err := io.ReadFull(conn, buf[:2]); err != nil || buf[0] != 0x05 {
		return
	}
	nMethods := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nMethods]); err != nil {
		return
	}
	if _, err := conn.Write([]byte{0x05, 0x00}); err != nil {
		return
	}

	host, port, cmd, err := readSOCKS5Request(conn)
	if err != nil {
		_ = writeSOCKS5Reply(conn, 0x01, nil)
		return
	}
	_ = conn.SetDeadline(time.Now().Add(2 * time.Hour))

	switch cmd {
	case 0x01:
		s.handleConnect(conn, net.JoinHostPort(host, strconv.Itoa(port)))
	case 0x03:
		s.handleUDPAssociate(ctx, conn)
	default:
		_ = writeSOCKS5Reply(conn, 0x07, nil)
	}
}

func (s *SOCKS5Server) handleConnect(client net.Conn, target string) {
	upstream, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		_ = writeSOCKS5Reply(client, 0x05, nil)
		return
	}
	defer upstream.Close()
	if err := writeSOCKS5Reply(client, 0x00, upstream.LocalAddr()); err != nil {
		return
	}

	var wg sync.WaitGroup
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			_ = client.Close()
			_ = upstream.Close()
		})
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		defer closeAll()
		_, _ = io.Copy(upstream, client)
	}()
	go func() {
		defer wg.Done()
		defer closeAll()
		_, _ = io.Copy(client, upstream)
	}()
	wg.Wait()
}

func (s *SOCKS5Server) handleUDPAssociate(ctx context.Context, control net.Conn) {
	udpConn, err := net.ListenUDP("udp", s.udpListenAddr())
	if err != nil {
		_ = writeSOCKS5Reply(control, 0x01, nil)
		return
	}
	defer udpConn.Close()
	if err := writeSOCKS5Reply(control, 0x00, udpConn.LocalAddr()); err != nil {
		return
	}

	done := make(chan struct{})
	go func() {
		_, _ = io.Copy(io.Discard, control)
		close(done)
	}()

	buf := make([]byte, 65535)
	for {
		_ = udpConn.SetReadDeadline(time.Now().Add(30 * time.Second))
		n, clientAddr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-done:
				return
			default:
				continue
			}
		}
		if !s.allowIP(clientAddr.IP) {
			slog.Warn("mesh socks5 rejected UDP source", "remote", clientAddr.String())
			continue
		}
		target, payload, err := parseUDPRequest(buf[:n])
		if err != nil {
			continue
		}
		go relayUDP(udpConn, clientAddr, target, payload)
	}
}

func (s *SOCKS5Server) allowConn(conn net.Conn) bool {
	host, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		return false
	}
	return s.allowIP(net.ParseIP(host))
}

func (s *SOCKS5Server) allowIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	if len(s.allowedSourceNets) == 0 {
		return true
	}
	for _, n := range s.allowedSourceNets {
		if n.Contains(ip) {
			return true
		}
	}
	return false
}

func (s *SOCKS5Server) udpListenAddr() *net.UDPAddr {
	host, _, err := net.SplitHostPort(s.addr)
	if err != nil || host == "" {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	ip := net.ParseIP(host)
	if ip == nil || ip.IsUnspecified() {
		return &net.UDPAddr{IP: net.IPv4zero, Port: 0}
	}
	return &net.UDPAddr{IP: ip, Port: 0}
}

func parseCIDRs(cidrs []string) []*net.IPNet {
	nets := make([]*net.IPNet, 0, len(cidrs))
	for _, cidr := range cidrs {
		_, n, err := net.ParseCIDR(cidr)
		if err == nil {
			nets = append(nets, n)
		}
	}
	return nets
}

func cidrContains(cidr string, ip net.IP) bool {
	_, n, err := net.ParseCIDR(cidr)
	return err == nil && n.Contains(ip)
}

func privateIPv4CIDR(ip net.IP) string {
	switch {
	case cidrContains("10.0.0.0/8", ip):
		return "10.0.0.0/8"
	case cidrContains("172.16.0.0/12", ip):
		return "172.16.0.0/12"
	case cidrContains("192.168.0.0/16", ip):
		return "192.168.0.0/16"
	default:
		return ip.String() + "/32"
	}
}

func readSOCKS5Request(conn net.Conn) (string, int, byte, error) {
	h := make([]byte, 4)
	if _, err := io.ReadFull(conn, h); err != nil {
		return "", 0, 0, err
	}
	if h[0] != 0x05 {
		return "", 0, 0, fmt.Errorf("invalid version")
	}
	host, err := readSOCKS5Addr(conn, h[3])
	if err != nil {
		return "", 0, 0, err
	}
	p := make([]byte, 2)
	if _, err := io.ReadFull(conn, p); err != nil {
		return "", 0, 0, err
	}
	return host, int(binary.BigEndian.Uint16(p)), h[1], nil
}

func readSOCKS5Addr(r io.Reader, atyp byte) (string, error) {
	switch atyp {
	case 0x01:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil
	case 0x03:
		l := []byte{0}
		if _, err := io.ReadFull(r, l); err != nil {
			return "", err
		}
		name := make([]byte, int(l[0]))
		if _, err := io.ReadFull(r, name); err != nil {
			return "", err
		}
		return string(name), nil
	case 0x04:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", err
		}
		return net.IP(ip).String(), nil
	default:
		return "", fmt.Errorf("unsupported address type")
	}
}

func writeSOCKS5Reply(conn net.Conn, rep byte, addr net.Addr) error {
	host := net.IPv4zero
	port := 0
	if tcp, ok := addr.(*net.TCPAddr); ok {
		host = tcp.IP.To4()
		port = tcp.Port
	}
	if udp, ok := addr.(*net.UDPAddr); ok {
		host = udp.IP.To4()
		port = udp.Port
	}
	if host == nil {
		host = net.IPv4zero
	}
	resp := []byte{0x05, rep, 0x00, 0x01, host[0], host[1], host[2], host[3], 0x00, 0x00}
	binary.BigEndian.PutUint16(resp[8:10], uint16(port))
	_, err := conn.Write(resp)
	return err
}

func parseUDPRequest(packet []byte) (string, []byte, error) {
	if len(packet) < 10 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return "", nil, fmt.Errorf("invalid udp header")
	}
	atyp := packet[3]
	offset := 4
	var host string
	switch atyp {
	case 0x01:
		if len(packet) < offset+4+2 {
			return "", nil, fmt.Errorf("short ipv4 packet")
		}
		host = net.IP(packet[offset : offset+4]).String()
		offset += 4
	case 0x03:
		if len(packet) < offset+1 {
			return "", nil, fmt.Errorf("short domain packet")
		}
		l := int(packet[offset])
		offset++
		if len(packet) < offset+l+2 {
			return "", nil, fmt.Errorf("short domain payload")
		}
		host = string(packet[offset : offset+l])
		offset += l
	case 0x04:
		if len(packet) < offset+16+2 {
			return "", nil, fmt.Errorf("short ipv6 packet")
		}
		host = net.IP(packet[offset : offset+16]).String()
		offset += 16
	default:
		return "", nil, fmt.Errorf("unsupported address type")
	}
	port := int(binary.BigEndian.Uint16(packet[offset : offset+2]))
	offset += 2
	return net.JoinHostPort(host, strconv.Itoa(port)), packet[offset:], nil
}

func relayUDP(relay *net.UDPConn, client *net.UDPAddr, target string, payload []byte) {
	upstream, err := net.DialTimeout("udp", target, 10*time.Second)
	if err != nil {
		return
	}
	defer upstream.Close()
	_ = upstream.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := upstream.Write(payload); err != nil {
		return
	}
	resp := make([]byte, 65535)
	n, err := upstream.Read(resp)
	if err != nil {
		return
	}
	header := []byte{0, 0, 0, 1, 0, 0, 0, 0, 0, 0}
	_, _ = relay.WriteToUDP(append(header, resp[:n]...), client)
}
