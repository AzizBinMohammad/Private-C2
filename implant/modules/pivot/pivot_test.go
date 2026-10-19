package pivot

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"
)

func startEcho(t *testing.T) net.Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	return ln
}

func allowAll(context.Context, string) error { return nil }

func TestSOCKS5ConnectRelays(t *testing.T) {
	echo := startEcho(t)
	server, err := StartSOCKS5("127.0.0.1:0", "", "", allowAll)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))

	mustWrite(t, conn, []byte{5, 1, 0})
	reply := make([]byte, 2)
	mustRead(t, conn, reply)
	if reply[0] != 5 || reply[1] != 0 {
		t.Fatalf("greeting reply = %v", reply)
	}

	mustWrite(t, conn, connectRequest(echo.Addr().String()))
	rep := make([]byte, 10)
	mustRead(t, conn, rep)
	if rep[1] != 0 {
		t.Fatalf("connect reply = %v", rep)
	}

	mustWrite(t, conn, []byte("hello pivot"))
	got := make([]byte, len("hello pivot"))
	mustRead(t, conn, got)
	if string(got) != "hello pivot" {
		t.Fatalf("relayed %q", got)
	}
}

func TestSOCKS5Authentication(t *testing.T) {
	echo := startEcho(t)

	server, err := StartSOCKS5("127.0.0.1:0", "operator", "s3cret", allowAll)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	t.Run("wrong password", func(t *testing.T) {
		conn := dialSOCKS(t, server.Addr())
		defer conn.Close()
		mustWrite(t, conn, []byte{5, 1, 2})
		reply := make([]byte, 2)
		mustRead(t, conn, reply)
		if reply[1] != 2 {
			t.Fatalf("method reply = %v", reply)
		}
		mustWrite(t, conn, []byte{1, 8, 'o', 'p', 'e', 'r', 'a', 't', 'o', 'r', 5, 'w', 'r', 'o', 'n', 'g'})
		auth := make([]byte, 2)
		mustRead(t, conn, auth)
		if auth[1] != 1 {
			t.Fatalf("auth reply = %v", auth)
		}
	})

	t.Run("correct password", func(t *testing.T) {
		conn := dialSOCKS(t, server.Addr())
		defer conn.Close()
		mustWrite(t, conn, []byte{5, 1, 2})
		reply := make([]byte, 2)
		mustRead(t, conn, reply)
		mustWrite(t, conn, []byte{1, 8, 'o', 'p', 'e', 'r', 'a', 't', 'o', 'r', 6, 's', '3', 'c', 'r', 'e', 't'})
		auth := make([]byte, 2)
		mustRead(t, conn, auth)
		if auth[1] != 0 {
			t.Fatalf("auth reply = %v", auth)
		}
		mustWrite(t, conn, connectRequest(echo.Addr().String()))
		rep := make([]byte, 10)
		mustRead(t, conn, rep)
		if rep[1] != 0 {
			t.Fatalf("connect reply = %v", rep)
		}
	})
}

func TestSOCKS5ScopeDenied(t *testing.T) {
	echo := startEcho(t)
	server, err := StartSOCKS5("127.0.0.1:0", "", "", func(context.Context, string) error {
		return fmt.Errorf("outside engagement scope")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	conn := dialSOCKS(t, server.Addr())
	defer conn.Close()
	mustWrite(t, conn, []byte{5, 1, 0})
	reply := make([]byte, 2)
	mustRead(t, conn, reply)
	mustWrite(t, conn, connectRequest(echo.Addr().String()))
	rep := make([]byte, 10)
	mustRead(t, conn, rep)
	if rep[1] != repNotAllowed {
		t.Fatalf("connect reply = %v, want not allowed", rep)
	}
}

func TestPortForwardRelays(t *testing.T) {
	echo := startEcho(t)
	fwd, err := StartPortForward("127.0.0.1:0", echo.Addr().String(), allowAll)
	if err != nil {
		t.Fatal(err)
	}
	defer fwd.Close()

	conn, err := net.Dial("tcp", fwd.Addr())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	mustWrite(t, conn, []byte("forwarded"))
	got := make([]byte, len("forwarded"))
	mustRead(t, conn, got)
	if string(got) != "forwarded" {
		t.Fatalf("relayed %q", got)
	}
}

func dialSOCKS(t *testing.T, addr string) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	return conn
}

func connectRequest(addr string) []byte {
	host, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	ip := net.ParseIP(host).To4()
	if ip == nil {
		panic("test target is not IPv4")
	}
	var port uint16
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	req := []byte{5, 1, 0, 1, ip[0], ip[1], ip[2], ip[3], 0, 0}
	binary.BigEndian.PutUint16(req[8:], port)
	return req
}

func mustWrite(t *testing.T, conn net.Conn, data []byte) {
	t.Helper()
	if _, err := conn.Write(data); err != nil {
		t.Fatalf("write: %v", err)
	}
}

func mustRead(t *testing.T, conn net.Conn, buf []byte) {
	t.Helper()
	if _, err := io.ReadFull(conn, buf); err != nil {
		t.Fatalf("read: %v", err)
	}
}
