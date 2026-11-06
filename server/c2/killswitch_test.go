package c2

import (
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

func registerWithEngagement(t *testing.T, conn net.Conn, engagementID string) string {
	t.Helper()
	reg := makeRegisterData()
	reg.EngagementID = engagementID
	sendMsg(t, conn, "register", reg)
	ack := recvMsg(t, conn)
	if ack.Type != "register_ack" {
		t.Fatalf("expected register_ack, got %q", ack.Type)
	}
	var ackData protocol.RegisterAckData
	if err := json.Unmarshal(ack.Data, &ackData); err != nil {
		t.Fatalf("unmarshal ack: %v", err)
	}
	return ackData.SessionID
}

func TestKillEngagement_ClosesSessionsAndBlocksTasking(t *testing.T) {
	srv := NewImplantServer()
	serverConn, clientConn := net.Pipe()
	defer clientConn.Close()
	go srv.HandleConnection(serverConn)

	sessionID := registerWithEngagement(t, clientConn, "eng-1")
	if _, err := srv.QueueTask(sessionID, protocol.TaskShell, "id"); err != nil {
		t.Fatalf("QueueTask before kill: %v", err)
	}

	if closed := srv.KillEngagement("eng-1", "test kill"); closed != 1 {
		t.Fatalf("KillEngagement closed %d sessions, want 1", closed)
	}
	if killed, reason := srv.IsEngagementKilled("eng-1"); !killed || reason != "test kill" {
		t.Fatalf("IsEngagementKilled = (%v,%q)", killed, reason)
	}
	if srv.GetSession(sessionID) != nil {
		t.Fatal("session still live after kill switch")
	}
	if _, err := srv.QueueTask(sessionID, protocol.TaskShell, "id"); !errors.Is(err, ErrEngagementKilled) && !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("QueueTask after kill = %v, want ErrEngagementKilled or ErrSessionNotFound", err)
	}

	_ = clientConn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := clientConn.Read(make([]byte, 1)); err == nil {
		t.Fatal("connection still readable after kill switch")
	}
}

func TestKillEngagement_IgnoresEmptyID(t *testing.T) {
	srv := NewImplantServer()
	if closed := srv.KillEngagement("", "no engagement"); closed != 0 {
		t.Fatalf("KillEngagement(\"\") closed %d sessions", closed)
	}
	if killed, _ := srv.IsEngagementKilled(""); killed {
		t.Fatal("empty engagement ID was marked killed")
	}
}
