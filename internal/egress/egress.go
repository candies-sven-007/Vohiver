// Package egress ports the one idea from MDD that makes VoWiFi work
// from mainland China: never dial the ePDG directly.
//
// MDD evidence (mdd-sim-gateway, branch slim-reader-vowifi, 2026-11-03):
//   - engine/outer_transport.py: "Explicit SOCKS5 UDP transport for the
//     isolated country service. There is no direct fallback. SWu uses
//     one association for IKE/500 and another for NAT-T/4500; proxy
//     mode never opens a raw ESP socket."
//   - control/app/egress.py: a per-country exit; a line behind a
//     country exit resolves its ePDG through that exit, not through
//     the gateway host's resolver.
//   - README: each SIM's ePDG traffic goes via its selected country
//     exit; if the exit is down, nothing leaks out direct.
//
// This package implements only the SOCKS5 UDP ASSOCIATE transport
// (RFC 1928) in Go, so a future IKE client can use it for UDP 500
// and UDP 4500 without ever opening a direct socket to the ePDG.
// It does NOT implement IKEv2, EAP-AKA or IMS: those are the next
// steps, and the fastest route for them is to reuse an existing
// implementation (MDD's SWu IKE / VoCat's IKE+IMS) rather than
// writing a new IKE stack from scratch on a 382MiB stick.
//
// No direct fallback: if the proxy URL is empty or the ASSOCIATE
// fails, Dial returns an error. Callers must not fall back to a
// direct UDP dial on that error.
package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"strings"
	"time"
)

// Proxy is a parsed socks5://host:port URL with optional credentials.
// Credentials are never logged by this package.
type Proxy struct {
	Host     string
	Port     string
	Username string
	Password string
	HasAuth  bool
}

// ParseProxy parses a socks5:// URL. It rejects any other scheme,
// a missing host/port, or a path/query/fragment, exactly like MDD's
// ProxyEndpoint.parse.
func ParseProxy(raw string) (Proxy, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "socks5" || u.Hostname() == "" || u.Port() == "" ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" {
		return Proxy{}, errors.New("egress: expected socks5://host:port with optional credentials")
	}
	p := Proxy{Host: u.Hostname(), Port: u.Port()}
	if u.User != nil {
		p.Username = u.User.Username()
		p.Password, p.HasAuth = u.User.Password()
		// A username without a password is still an auth attempt.
		if p.Username != "" {
			p.HasAuth = true
		}
	}
	return p, nil
}

// Conn is a UDP connection to one target, carried over a SOCKS5
// UDP relay. It implements net.Conn for a single destination.
type Conn struct {
	tcp    net.Conn
	udp    *net.UDPConn
	target *net.UDPAddr
}

func (c *Conn) Read(b []byte) (int, error) {
	buf := make([]byte, len(b)+10)
	n, _, err := c.udp.ReadFromUDP(buf)
	if err != nil {
		return 0, err
	}
	// SOCKS5 UDP header: RSV(2) FRAG(1) ATYP(1) DST.ADDR(4) DST.PORT(2).
	if n < 10 || buf[0] != 0 || buf[1] != 0 || buf[2] != 0 || buf[3] != 1 {
		return 0, errors.New("egress: invalid SOCKS5 UDP reply header")
	}
	n -= 10
	copy(b, buf[10:10+n])
	return n, nil
}

func (c *Conn) Write(b []byte) (int, error) {
	hdr := make([]byte, 10)
	hdr[3] = 1 // ATYP IPv4
	copy(hdr[4:8], c.target.IP.To4())
	binary.BigEndian.PutUint16(hdr[8:10], uint16(c.target.Port))
	pkt := append(hdr, b...)
	if _, err := c.udp.Write(pkt); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *Conn) Close() error {
	if c.udp != nil {
		c.udp.Close()
	}
	if c.tcp != nil {
		return c.tcp.Close()
	}
	return nil
}

func (c *Conn) LocalAddr() net.Addr  { return c.udp.LocalAddr() }
func (c *Conn) RemoteAddr() net.Addr { return c.target }
func (c *Conn) SetDeadline(t time.Time) error {
	if err := c.udp.SetDeadline(t); err != nil {
		return err
	}
	return c.tcp.SetDeadline(t)
}
func (c *Conn) SetReadDeadline(t time.Time) error  { return c.udp.SetReadDeadline(t) }
func (c *Conn) SetWriteDeadline(t time.Time) error { return c.udp.SetWriteDeadline(t) }

// Dial returns a Conn to targetIP:targetPort via proxy, using a
// SOCKS5 UDP ASSOCIATE. It never dials the target directly.
func Dial(proxyURL, targetIP string, targetPort int, timeout time.Duration) (*Conn, error) {
	if strings.TrimSpace(proxyURL) == "" {
		return nil, errors.New("egress: no proxy configured; direct dial is not allowed")
	}
	p, err := ParseProxy(proxyURL)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(targetIP)
	if ip == nil || ip.To4() == nil {
		return nil, fmt.Errorf("egress: target must be an IPv4 address, got %q", targetIP)
	}
	if targetPort <= 0 || targetPort > 65535 {
		return nil, fmt.Errorf("egress: invalid target port %d", targetPort)
	}
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	tcp, err := net.DialTimeout("tcp", net.JoinHostPort(p.Host, p.Port), timeout)
	if err != nil {
		return nil, err
	}
	defer func() {
		// The TCP association must stay open for the life of the
		// UDP relay; only close it on failure, before returning.
		if err != nil {
			tcp.Close()
		}
	}()
	if err = tcp.SetDeadline(time.Now().Add(timeout)); err != nil {
		return nil, err
	}
	// Greeting: VER=5, NMETHODS=1, METHOD=0 (no auth) or 2 (user/pass).
	greet := []byte{5, 1, 0}
	if p.HasAuth {
		greet[2] = 2
	}
	if _, err = tcp.Write(greet); err != nil {
		return nil, err
	}
	resp := make([]byte, 2)
	if _, err = io.ReadFull(tcp, resp); err != nil {
		return nil, err
	}
	if resp[0] != 5 || (resp[1] != 0 && resp[1] != 2) {
		return nil, fmt.Errorf("egress: SOCKS5 greeting rejected (method %d)", resp[1])
	}
	if resp[1] == 2 {
		// RFC 1929 username/password subnegotiation.
		auth := []byte{1, byte(len(p.Username))}
		auth = append(auth, p.Username...)
		auth = append(auth, byte(len(p.Password)))
		auth = append(auth, p.Password...)
		if _, err = tcp.Write(auth); err != nil {
			return nil, err
		}
		ar := make([]byte, 2)
		if _, err = io.ReadFull(tcp, ar); err != nil {
			return nil, err
		}
		if ar[1] != 0 {
			return nil, errors.New("egress: SOCKS5 authentication failed")
		}
	}
	// UDP ASSOCIATE: VER CMD RSV ATYP DST.ADDR DST.PORT, with a
	// zero address (the relay chooses its own relay address).
	req := []byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}
	if _, err = tcp.Write(req); err != nil {
		return nil, err
	}
	rep := make([]byte, 10)
	if _, err = io.ReadFull(tcp, rep); err != nil {
		return nil, err
	}
	if rep[0] != 5 || rep[1] != 0 || rep[3] != 1 {
		return nil, fmt.Errorf("egress: SOCKS5 UDP ASSOCIATE rejected (rep %d)", rep[1])
	}
	relayIP := net.IP(rep[4:8])
	relayPort := int(binary.BigEndian.Uint16(rep[8:10]))
	relay := &net.UDPAddr{IP: relayIP, Port: relayPort}
	udp, err := net.DialUDP("udp", nil, relay)
	if err != nil {
		return nil, err
	}
	if err = tcp.SetDeadline(time.Time{}); err != nil {
		udp.Close()
		return nil, err
	}
	return &Conn{tcp: tcp, udp: udp, target: &net.UDPAddr{IP: ip, Port: targetPort}}, nil
}
