package listener

import (
	"context"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/azizbinmohammad/private-c2/server/c2/profile"
)

// DNSListener implements an authoritative DNS server that encodes C2 data
// in TXT, CNAME, A, and AAAA records and decodes data from subdomains.
type DNSListener struct {
	BaseListener
	profile      *profile.C2Profile
	udpConn      *net.UDPConn
	tcpListener  net.Listener
	cancelFunc   context.CancelFunc
	reassembly   map[string]*dnsReassemblyBuffer
	reassemblyMu sync.Mutex
	rateLimit    map[string]time.Time
	rateMu       sync.Mutex
	rateInterval time.Duration
}

// dnsReassemblyBuffer holds chunks for reassembling multi-packet DNS data.
type dnsReassemblyBuffer struct {
	chunks    map[uint16][]byte
	total     uint16
	createdAt time.Time
}

// DNSListenerConfig holds the configuration for a DNS listener.
type DNSListenerConfig struct {
	ID           string
	BindAddr     string
	EngagementID string
	Profile      *profile.C2Profile
	RateInterval time.Duration
}

// NewDNSListener creates a new authoritative DNS listener.
func NewDNSListener(cfg DNSListenerConfig) (*DNSListener, error) {
	p := cfg.Profile
	if p == nil {
		p = profile.DefaultProfile()
	}
	if p.DNSConfig.ParentDomain == "" {
		return nil, fmt.Errorf("DNS parent domain is required")
	}

	rateInterval := cfg.RateInterval
	if rateInterval == 0 {
		rateInterval = 50 * time.Millisecond
	}

	return &DNSListener{
		BaseListener: NewBaseListener(cfg.ID, "dns", cfg.BindAddr, cfg.EngagementID),
		profile:      p,
		reassembly:   make(map[string]*dnsReassemblyBuffer),
		rateLimit:    make(map[string]time.Time),
		rateInterval: rateInterval,
	}, nil
}

// Start begins listening on both UDP and TCP for DNS queries.
func (d *DNSListener) Start(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	d.cancelFunc = cancel
	d.SetActive(true)

	udpAddr, err := net.ResolveUDPAddr("udp", d.bindAddr)
	if err != nil {
		return fmt.Errorf("resolving UDP address: %w", err)
	}

	d.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listening UDP on %s: %w", d.bindAddr, err)
	}

	tcpAddr, err := net.ResolveTCPAddr("tcp", d.bindAddr)
	if err != nil {
		d.udpConn.Close()
		return fmt.Errorf("resolving TCP address: %w", err)
	}

	d.tcpListener, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		d.udpConn.Close()
		return fmt.Errorf("listening TCP on %s: %w", d.bindAddr, err)
	}

	log.Printf("[dns] listener %s started on %s (domain: %s)", d.id, d.bindAddr, d.profile.DNSConfig.ParentDomain)

	// Reassembly garbage collection.
	go d.gcReassembly(ctx)

	// TCP handler.
	go d.serveTCP(ctx)

	// UDP handler (main loop).
	return d.serveUDP(ctx)
}

// Stop shuts down the DNS listener.
func (d *DNSListener) Stop() error {
	d.SetActive(false)
	if d.cancelFunc != nil {
		d.cancelFunc()
	}
	if d.udpConn != nil {
		d.udpConn.Close()
	}
	if d.tcpListener != nil {
		d.tcpListener.Close()
	}
	return nil
}

// ID returns the listener's unique identifier.
func (d *DNSListener) ID() string { return d.id }

// Type returns the listener type.
func (d *DNSListener) Type() string { return d.listenerType }

// Addr returns the listener's bind address.
func (d *DNSListener) Addr() string { return d.bindAddr }

// serveUDP reads DNS queries from the UDP connection.
func (d *DNSListener) serveUDP(ctx context.Context) error {
	buf := make([]byte, 4096)
	for {
		select {
		case <-ctx.Done():
			return nil
		default:
		}

		d.udpConn.SetReadDeadline(time.Now().Add(1 * time.Second))
		n, remoteAddr, err := d.udpConn.ReadFromUDP(buf)
		if err != nil {
			if ne, ok := err.(net.Error); ok && ne.Timeout() {
				continue
			}
			select {
			case <-ctx.Done():
				return nil
			default:
				log.Printf("[dns] UDP read error: %v", err)
				continue
			}
		}

		// Rate limiting per source IP.
		if !d.checkRate(remoteAddr.IP.String()) {
			continue
		}

		go d.handleDNSQuery(buf[:n], func(resp []byte) {
			d.udpConn.WriteToUDP(resp, remoteAddr)
		})
	}
}

// serveTCP accepts DNS queries over TCP.
func (d *DNSListener) serveTCP(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		conn, err := d.tcpListener.Accept()
		if err != nil {
			select {
			case <-ctx.Done():
				return
			default:
				log.Printf("[dns] TCP accept error: %v", err)
				continue
			}
		}

		go func(c net.Conn) {
			defer c.Close()
			c.SetDeadline(time.Now().Add(10 * time.Second))

			// TCP DNS: 2-byte length prefix then message.
			lengthBuf := make([]byte, 2)
			if _, err := c.Read(lengthBuf); err != nil {
				return
			}
			msgLen := binary.BigEndian.Uint16(lengthBuf)
			msg := make([]byte, msgLen)
			if _, err := c.Read(msg); err != nil {
				return
			}

			d.handleDNSQuery(msg, func(resp []byte) {
				respLen := make([]byte, 2)
				binary.BigEndian.PutUint16(respLen, uint16(len(resp)))
				c.Write(respLen)
				c.Write(resp)
			})
		}(conn)
	}
}

// handleDNSQuery parses a DNS query, extracts encoded data from the subdomain,
// and constructs a response with the C2 data encoded in the requested record type.
func (d *DNSListener) handleDNSQuery(query []byte, respond func([]byte)) {
	if len(query) < 12 {
		return
	}

	// Extract the queried name from the DNS question.
	name, qtype, offset := d.parseDNSQuestion(query)
	if name == "" {
		return
	}

	parentDomain := d.profile.DNSConfig.ParentDomain
	if !strings.HasSuffix(strings.ToLower(name), "."+strings.ToLower(parentDomain)) {
		return
	}

	// Extract encoded data from subdomain labels.
	subdomain := strings.TrimSuffix(strings.ToLower(name), "."+strings.ToLower(parentDomain))
	encodedData := strings.ReplaceAll(subdomain, ".", "")

	if encodedData != "" {
		decoded, err := base32.HexEncoding.WithPadding(base32.NoPadding).DecodeString(strings.ToUpper(encodedData))
		if err == nil && len(decoded) > 0 {
			// Extract session ID (first 8 bytes) and data payload.
			if len(decoded) >= 8 {
				sessionID := fmt.Sprintf("%x", decoded[:8])
				payload := decoded[8:]

				d.OnSession(sessionID, d.engagementID, map[string]string{
					"transport": "dns",
				})

				_, _ = d.OnData(sessionID, payload)
			}
		}
	}

	// Build DNS response.
	response := d.buildDNSResponse(query[:offset], name, qtype)
	respond(response)
}

// parseDNSQuestion extracts the queried name and type from a DNS question section.
func (d *DNSListener) parseDNSQuestion(query []byte) (string, uint16, int) {
	if len(query) < 12 {
		return "", 0, 0
	}

	offset := 12 // skip header
	var labels []string

	for offset < len(query) {
		length := int(query[offset])
		if length == 0 {
			offset++
			break
		}
		if offset+1+length > len(query) {
			return "", 0, 0
		}
		labels = append(labels, string(query[offset+1:offset+1+length]))
		offset += 1 + length
	}

	if offset+4 > len(query) {
		return "", 0, 0
	}

	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	offset += 4 // skip qtype and qclass

	return strings.Join(labels, "."), qtype, offset
}

// buildDNSResponse constructs a minimal DNS response.
func (d *DNSListener) buildDNSResponse(header []byte, name string, qtype uint16) []byte {
	// Build a minimal valid DNS response.
	resp := make([]byte, 0, 512)

	// Copy the transaction ID from the query header.
	if len(header) >= 2 {
		resp = append(resp, header[0], header[1])
	} else {
		resp = append(resp, 0, 0)
	}

	// Flags: standard response, no error.
	resp = append(resp, 0x81, 0x80)
	// QDCOUNT=1.
	resp = append(resp, 0, 1)
	// ANCOUNT=1.
	resp = append(resp, 0, 1)
	// NSCOUNT=0.
	resp = append(resp, 0, 0)
	// ARCOUNT=0.
	resp = append(resp, 0, 0)

	// Question section: encode the name.
	for _, label := range strings.Split(name, ".") {
		resp = append(resp, byte(len(label)))
		resp = append(resp, []byte(label)...)
	}
	resp = append(resp, 0) // null terminator
	qtypeBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(qtypeBytes, qtype)
	resp = append(resp, qtypeBytes...)
	resp = append(resp, 0, 1) // class IN

	// Answer section: pointer to name at offset 12.
	resp = append(resp, 0xc0, 0x0c)
	resp = append(resp, qtypeBytes...) // type
	resp = append(resp, 0, 1)          // class IN

	// TTL: 60 seconds.
	ttl := make([]byte, 4)
	binary.BigEndian.PutUint32(ttl, 60)
	resp = append(resp, ttl...)

	// RDATA based on query type.
	switch qtype {
	case 1: // A record
		resp = append(resp, 0, 4)       // rdlength
		resp = append(resp, 127, 0, 0, 1) // 127.0.0.1
	case 28: // AAAA record
		resp = append(resp, 0, 16) // rdlength
		resp = append(resp, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1) // ::1
	case 16: // TXT record
		txt := []byte("v=spf1 ~all")
		resp = append(resp, 0, byte(len(txt)+1)) // rdlength
		resp = append(resp, byte(len(txt)))       // txt-length
		resp = append(resp, txt...)
	case 5: // CNAME record
		cname := d.profile.DNSConfig.ParentDomain
		cnameEncoded := d.encodeDNSName(cname)
		rdLen := make([]byte, 2)
		binary.BigEndian.PutUint16(rdLen, uint16(len(cnameEncoded)))
		resp = append(resp, rdLen...)
		resp = append(resp, cnameEncoded...)
	default:
		resp = append(resp, 0, 4)
		resp = append(resp, 127, 0, 0, 1)
	}

	return resp
}

// encodeDNSName encodes a domain name for DNS wire format.
func (d *DNSListener) encodeDNSName(name string) []byte {
	var encoded []byte
	for _, label := range strings.Split(name, ".") {
		encoded = append(encoded, byte(len(label)))
		encoded = append(encoded, []byte(label)...)
	}
	encoded = append(encoded, 0)
	return encoded
}

// checkRate enforces per-source rate limiting.
func (d *DNSListener) checkRate(srcIP string) bool {
	d.rateMu.Lock()
	defer d.rateMu.Unlock()

	if lastSeen, ok := d.rateLimit[srcIP]; ok {
		if time.Since(lastSeen) < d.rateInterval {
			return false
		}
	}
	d.rateLimit[srcIP] = time.Now()
	return true
}

// gcReassembly cleans up stale reassembly buffers.
func (d *DNSListener) gcReassembly(ctx context.Context) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.reassemblyMu.Lock()
			cutoff := time.Now().Add(-2 * time.Minute)
			for k, buf := range d.reassembly {
				if buf.createdAt.Before(cutoff) {
					delete(d.reassembly, k)
				}
			}
			d.reassemblyMu.Unlock()

			d.rateMu.Lock()
			rateCutoff := time.Now().Add(-1 * time.Minute)
			for k, t := range d.rateLimit {
				if t.Before(rateCutoff) {
					delete(d.rateLimit, k)
				}
			}
			d.rateMu.Unlock()
		}
	}
}
