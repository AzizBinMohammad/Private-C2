// Package pivot implements the operator-facing pivot primitives: a SOCKS5
// proxy and a local TCP port forward. Every outbound connection passes through
// a ScopeCheck before dialing, so a pivot cannot reach outside the engagement
// scope even though the operator chooses the destination at connection time.
package pivot

import (
	"context"
	"crypto/subtle"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

// ScopeCheck is called with the destination host before any dial.
type ScopeCheck func(ctx context.Context, host string) error

const (
	socksVersion      = 5
	socksNoAuth       = 0x00
	socksUserPass     = 0x02
	socksNoAcceptable = 0xFF

	cmdConnect = 0x01

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	repSuccess         = 0x00
	repNotAllowed      = 0x02
	repHostUnreach     = 0x04
	repCmdUnsupported  = 0x07
	repAtypUnsupported = 0x08
)

// SOCKS5Server is a running proxy. Close stops the listener and all active
// tunnels.
type SOCKS5Server struct {
	listener net.Listener
	username string
	password string
	check    ScopeCheck

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
}

// StartSOCKS5 binds the proxy and starts accepting. An empty listen address
// binds 127.0.0.1:0. Supplying a username enables RFC 1929 authentication.
func StartSOCKS5(listenAddr, username, password string, check ScopeCheck) (*SOCKS5Server, error) {
	if listenAddr == "" {
		listenAddr = "127.0.0.1:0"
	}
	if (username == "") != (password == "") {
		return nil, fmt.Errorf("socks authentication requires both a username and a password")
	}
	if username != "" && len(username) > 255 {
		return nil, fmt.Errorf("socks username is too long")
	}
	if len(password) > 255 {
		return nil, fmt.Errorf("socks password is too long")
	}
	if check == nil {
		return nil, fmt.Errorf("a scope check is required")
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	s := &SOCKS5Server{
		listener: ln,
		username: username,
		password: password,
		check:    check,
		conns:    make(map[net.Conn]struct{}),
		closed:   make(chan struct{}),
	}
	go s.accept()
	return s, nil
}

// Addr is the bound address, useful when the caller asked for port 0.
func (s *SOCKS5Server) Addr() string { return s.listener.Addr().String() }

// Close stops the listener and closes active tunnels.
func (s *SOCKS5Server) Close() error {
	s.once.Do(func() {
		close(s.closed)
		_ = s.listener.Close()
		s.mu.Lock()
		for c := range s.conns {
			_ = c.Close()
		}
		s.mu.Unlock()
	})
	s.wg.Wait()
	return nil
}

func (s *SOCKS5Server) accept() {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			select {
			case <-s.closed:
				return
			default:
				return
			}
		}
		s.track(conn, true)
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			defer s.track(conn, false)
			s.handle(conn)
		}()
	}
}

func (s *SOCKS5Server) track(c net.Conn, add bool) {
	s.mu.Lock()
	if add {
		s.conns[c] = struct{}{}
	} else {
		delete(s.conns, c)
	}
	s.mu.Unlock()
}

func (s *SOCKS5Server) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(30 * time.Second))

	if err := s.negotiate(conn); err != nil {
		return
	}
	target, err := readConnectRequest(conn)
	if err != nil {
		return
	}

	if err := s.check(context.Background(), target.host); err != nil {
		_ = writeReply(conn, repNotAllowed)
		return
	}

	upstream, err := net.DialTimeout("tcp", target.addr(), 15*time.Second)
	if err != nil {
		_ = writeReply(conn, repHostUnreach)
		return
	}
	defer upstream.Close()

	if err := writeReply(conn, repSuccess); err != nil {
		return
	}
	_ = conn.SetDeadline(time.Time{})
	relay(conn, upstream)
}

func (s *SOCKS5Server) negotiate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != socksVersion || header[1] == 0 {
		return fmt.Errorf("unsupported socks greeting")
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return err
	}

	want := byte(socksNoAuth)
	if s.username != "" {
		want = socksUserPass
	}
	if !containsByte(methods, want) {
		_, _ = conn.Write([]byte{socksVersion, socksNoAcceptable})
		return fmt.Errorf("no acceptable socks authentication method")
	}
	if _, err := conn.Write([]byte{socksVersion, want}); err != nil {
		return err
	}
	if want == socksUserPass {
		return s.authenticate(conn)
	}
	return nil
}

func (s *SOCKS5Server) authenticate(conn net.Conn) error {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return err
	}
	if header[0] != 0x01 {
		return fmt.Errorf("unsupported authentication version")
	}
	username := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, username); err != nil {
		return err
	}
	plen := make([]byte, 1)
	if _, err := io.ReadFull(conn, plen); err != nil {
		return err
	}
	password := make([]byte, int(plen[0]))
	if _, err := io.ReadFull(conn, password); err != nil {
		return err
	}

	userOK := subtle.ConstantTimeCompare(username, []byte(s.username)) == 1
	passOK := subtle.ConstantTimeCompare(password, []byte(s.password)) == 1
	if !userOK || !passOK {
		_, _ = conn.Write([]byte{0x01, 0x01})
		return fmt.Errorf("socks authentication failed")
	}
	_, err := conn.Write([]byte{0x01, 0x00})
	return err
}

type destination struct {
	host string
	port int
}

func (d destination) addr() string { return net.JoinHostPort(d.host, fmt.Sprint(d.port)) }

func readConnectRequest(conn net.Conn) (destination, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(conn, header); err != nil {
		return destination{}, err
	}
	if header[0] != socksVersion {
		return destination{}, fmt.Errorf("unsupported socks request version")
	}
	if header[1] != cmdConnect {
		_ = writeReply(conn, repCmdUnsupported)
		return destination{}, fmt.Errorf("unsupported socks command %d", header[1])
	}

	var host string
	switch header[3] {
	case atypIPv4:
		buf := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return destination{}, err
		}
		host = net.IP(buf).String()
	case atypIPv6:
		buf := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return destination{}, err
		}
		host = net.IP(buf).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return destination{}, err
		}
		buf := make([]byte, int(lenBuf[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return destination{}, err
		}
		host = string(buf)
	default:
		_ = writeReply(conn, repAtypUnsupported)
		return destination{}, fmt.Errorf("unsupported socks address type %d", header[3])
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return destination{}, err
	}
	return destination{host: host, port: int(binary.BigEndian.Uint16(portBuf))}, nil
}

func writeReply(conn net.Conn, rep byte) error {
	_, err := conn.Write([]byte{socksVersion, rep, 0, atypIPv4, 0, 0, 0, 0, 0, 0})
	return err
}

func containsByte(haystack []byte, needle byte) bool {
	for _, b := range haystack {
		if b == needle {
			return true
		}
	}
	return false
}

func relay(a, b net.Conn) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		closeWrite(a)
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		closeWrite(b)
		done <- struct{}{}
	}()
	<-done
	<-done
}

func closeWrite(c net.Conn) {
	if cw, ok := c.(interface{ CloseWrite() error }); ok {
		_ = cw.CloseWrite()
	}
}

// PortForward listens locally and relays each connection to target.
type PortForward struct {
	listener net.Listener
	target   string
	check    ScopeCheck

	mu     sync.Mutex
	conns  map[net.Conn]struct{}
	wg     sync.WaitGroup
	closed chan struct{}
	once   sync.Once
}

// StartPortForward binds listenAddr and relays to target (host:port). The
// target host is scope-checked before each dial.
func StartPortForward(listenAddr, target string, check ScopeCheck) (*PortForward, error) {
	if listenAddr == "" {
		return nil, fmt.Errorf("a listen address is required")
	}
	host, _, err := net.SplitHostPort(target)
	if err != nil || host == "" {
		return nil, fmt.Errorf("target must be host:port: %w", err)
	}
	if check == nil {
		return nil, fmt.Errorf("a scope check is required")
	}

	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return nil, err
	}
	p := &PortForward{
		listener: ln,
		target:   target,
		check:    check,
		conns:    make(map[net.Conn]struct{}),
		closed:   make(chan struct{}),
	}
	go p.accept(host)
	return p, nil
}

// Addr is the bound address.
func (p *PortForward) Addr() string { return p.listener.Addr().String() }

// Close stops the listener and active relays.
func (p *PortForward) Close() error {
	p.once.Do(func() {
		close(p.closed)
		_ = p.listener.Close()
		p.mu.Lock()
		for c := range p.conns {
			_ = c.Close()
		}
		p.mu.Unlock()
	})
	p.wg.Wait()
	return nil
}

func (p *PortForward) accept(targetHost string) {
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			return
		}
		p.mu.Lock()
		p.conns[conn] = struct{}{}
		p.mu.Unlock()
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			defer conn.Close()
			defer func() {
				p.mu.Lock()
				delete(p.conns, conn)
				p.mu.Unlock()
			}()
			if err := p.check(context.Background(), targetHost); err != nil {
				return
			}
			upstream, err := net.DialTimeout("tcp", p.target, 15*time.Second)
			if err != nil {
				return
			}
			defer upstream.Close()
			relay(conn, upstream)
		}()
	}
}
