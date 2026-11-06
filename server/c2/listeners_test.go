package c2

import (
	"crypto/tls"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/tlsutil"
)

func testListenerTLS(t *testing.T) *tls.Config {
	t.Helper()
	cfg, err := tlsutil.ServerTLSConfig("", "", "")
	if err != nil {
		t.Fatalf("server TLS config: %v", err)
	}
	return cfg
}

func TestStartListener_DuplicateIDRejected(t *testing.T) {
	srv := NewImplantServer()
	cfg := ListenerConfig{
		ID:        "duplicate",
		Type:      ListenerTypeMTLS,
		BindAddr:  "127.0.0.1",
		Port:      0,
		TLSConfig: testListenerTLS(t),
	}

	first, err := srv.StartListener(cfg)
	if err != nil {
		t.Fatalf("first StartListener: %v", err)
	}
	defer srv.StopListener(first.ID)

	if _, err := srv.StartListener(cfg); err == nil {
		t.Fatal("second StartListener with the same ID succeeded")
	}

	// The first listener must still be the one in the registry.
	if got, ok := srv.GetListener(first.ID); !ok || got.Port != first.Port {
		t.Fatalf("first listener was disturbed: got %+v, want %+v", got, first)
	}
}

func TestStopListener_ClosesActiveConnections(t *testing.T) {
	srv := NewImplantServer()
	info, err := srv.StartListener(ListenerConfig{
		ID:        "stop-test",
		Type:      ListenerTypeMTLS,
		BindAddr:  "127.0.0.1",
		Port:      0,
		TLSConfig: testListenerTLS(t),
	})
	if err != nil {
		t.Fatalf("StartListener: %v", err)
	}

	addr := net.JoinHostPort(info.BindAddr, fmt.Sprintf("%d", info.Port))
	conn, err := tls.Dial("tcp", addr, &tls.Config{InsecureSkipVerify: true}) //nolint:gosec // test only
	if err != nil {
		t.Fatalf("dial %s: %v", addr, err)
	}
	defer conn.Close()

	// Wait until the listener observes the connection.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if got, ok := srv.GetListener(info.ID); ok && got.ActiveConnections > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if err := srv.StopListener(info.ID); err != nil {
		t.Fatalf("StopListener: %v", err)
	}

	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection still readable after listener stop")
	}
}
