// Package api is a small HTTP client for the Private-C2 operator REST API.
//
// It centralises bearer-token authentication so that every operator-facing
// interface (the CLI today, the MCP server later) talks to the server the
// same way. Only the standard library is used.
package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// DefaultTimeout is the request timeout used when none is supplied.
const DefaultTimeout = 30 * time.Second

// StatusError reports a non-2xx HTTP response. Callers can test for specific
// codes with errors.As, e.g. to detect an expired session token.
type StatusError struct {
	Code int
	Body string
}

func (e *StatusError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("server returned %d %s", e.Code, http.StatusText(e.Code))
	}
	return fmt.Sprintf("server returned %d: %s", e.Code, e.Body)
}

// IsUnauthorized reports whether err is a 401 from the server.
func IsUnauthorized(err error) bool {
	var se *StatusError
	return errors.As(err, &se) && se.Code == http.StatusUnauthorized
}

// Client talks to a Private-C2 server's HTTP API.
type Client struct {
	baseURL string
	token   string
	http    *http.Client
}

// Option customises a Client.
type Option func(*Client)

// WithHTTPClient replaces the underlying http.Client.
func WithHTTPClient(hc *http.Client) Option {
	return func(c *Client) {
		if hc != nil {
			c.http = hc
		}
	}
}

// WithToken seeds the client with an already-issued bearer token, skipping Login.
func WithToken(token string) Option {
	return func(c *Client) { c.token = token }
}

// New returns a Client for the given base URL (e.g. "http://127.0.0.1:8080").
func New(baseURL string, opts ...Option) *Client {
	c := &Client{
		baseURL: strings.TrimRight(baseURL, "/"),
		http:    &http.Client{Timeout: DefaultTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// BaseURL returns the normalised base URL.
func (c *Client) BaseURL() string { return c.baseURL }

// Token returns the current bearer token ("" if not authenticated).
func (c *Client) Token() string { return c.token }

// SetToken sets the bearer token directly.
func (c *Client) SetToken(token string) { c.token = token }

// Login exchanges credentials for a bearer token and stores it.
func (c *Client) Login(username, password string) error {
	var out struct {
		Token string `json:"token"`
	}
	if err := c.do(http.MethodPost, "/api/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, &out); err != nil {
		return fmt.Errorf("login as %q: %w", username, err)
	}
	if out.Token == "" {
		return fmt.Errorf("login as %q: server returned an empty token", username)
	}
	c.token = out.Token
	return nil
}

// Get performs an authenticated GET and decodes the JSON response into out.
// A nil out discards the body.
func (c *Client) Get(path string, out interface{}) error {
	return c.do(http.MethodGet, path, nil, out)
}

// Post performs an authenticated POST with a JSON body and decodes the response.
func (c *Client) Post(path string, body, out interface{}) error {
	return c.do(http.MethodPost, path, body, out)
}

// Delete performs an authenticated DELETE and decodes the response.
func (c *Client) Delete(path string, out interface{}) error {
	return c.do(http.MethodDelete, path, nil, out)
}

// GetBytes performs an authenticated GET and returns the raw response body.
// Use it for endpoints that do not return JSON (e.g. artifact downloads).
func (c *Client) GetBytes(path string) ([]byte, error) {
	req, err := c.newRequest(http.MethodGet, path, nil)
	if err != nil {
		return nil, err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	return data, nil
}

func (c *Client) do(method, path string, body, out interface{}) error {
	req, err := c.newRequest(method, path, body)
	if err != nil {
		return err
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("connection error: %w", err)
	}
	defer resp.Body.Close()

	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("reading response: %w", err)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return &StatusError{Code: resp.StatusCode, Body: strings.TrimSpace(string(data))}
	}
	if out == nil || len(data) == 0 {
		return nil
	}
	if err := json.Unmarshal(data, out); err != nil {
		return fmt.Errorf("decoding response: %w", err)
	}
	return nil
}

func (c *Client) newRequest(method, path string, body interface{}) (*http.Request, error) {
	var reader io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return nil, fmt.Errorf("encoding request: %w", err)
		}
		reader = bytes.NewReader(encoded)
	}

	req, err := http.NewRequest(method, c.baseURL+path, reader)
	if err != nil {
		return nil, fmt.Errorf("building request: %w", err)
	}
	if c.token != "" {
		req.Header.Set("Authorization", "Bearer "+c.token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req, nil
}
