package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/azizbinmohammad/private-c2/pkg/protocol"
)

func TestRegisterNegotiatesV2(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	gotRegister := make(chan protocol.RegisterData, 1)
	go func() {
		msg, err := readMessage(serverConn)
		if err != nil {
			return
		}
		var reg protocol.RegisterData
		if err := json.Unmarshal(msg.Data, &reg); err == nil {
			gotRegister <- reg
		}
		ack, _ := json.Marshal(protocol.RegisterAckData{
			SessionID:       "session-1",
			Interval:        5000,
			HeartbeatMs:     1500,
			ProtocolVersion: protocol.Version2,
			SessionToken:    "token-1",
		})
		_ = sendMessage(serverConn, &protocol.Message{Type: "register_ack", Data: ack})
	}()

	result, err := register(clientConn, protocol.RegisterData{ImplantID: "implant-1"}, "eng-1", 5*time.Second, 0.2)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if result.SessionID != "session-1" || result.SessionToken != "token-1" {
		t.Fatalf("unexpected register result: %+v", result)
	}
	if result.ProtocolVersion != protocol.Version2 {
		t.Fatalf("negotiated version = %d, want 2", result.ProtocolVersion)
	}
	if result.Heartbeat != 1500*time.Millisecond {
		t.Fatalf("heartbeat = %v, want 1.5s", result.Heartbeat)
	}

	select {
	case reg := <-gotRegister:
		if reg.ProtocolVersion != protocol.Version2 {
			t.Errorf("register protocol version = %d", reg.ProtocolVersion)
		}
		if reg.EngagementID != "eng-1" || reg.SleepMs != 5000 || reg.JitterPct != 20 {
			t.Errorf("register v2 fields = %+v", reg)
		}
		if len(reg.Transports) != 1 || reg.Transports[0] != "mtls" {
			t.Errorf("register transports = %v", reg.Transports)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("server did not receive register")
	}
}

func TestRegisterLegacyAckFallsBackToV1(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = readMessage(serverConn)
		ack, _ := json.Marshal(protocol.RegisterAckData{SessionID: "legacy", Interval: 5000})
		_ = sendMessage(serverConn, &protocol.Message{Type: "register_ack", Data: ack})
	}()

	result, err := register(clientConn, protocol.RegisterData{ImplantID: "implant-1"}, "", 5*time.Second, 0)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if result.ProtocolVersion != protocol.Version1 {
		t.Fatalf("negotiated version = %d, want 1", result.ProtocolVersion)
	}
	if result.SessionToken != "" {
		t.Fatalf("legacy ack produced a token: %q", result.SessionToken)
	}
	if result.Heartbeat != 5*time.Second {
		t.Fatalf("heartbeat fallback = %v, want 5s", result.Heartbeat)
	}
}

func TestRegisterHonorsKillInstruction(t *testing.T) {
	clientConn, serverConn := net.Pipe()
	defer clientConn.Close()
	defer serverConn.Close()

	go func() {
		_, _ = readMessage(serverConn)
		ack, _ := json.Marshal(protocol.RegisterAckData{
			SessionID:       "session-1",
			ProtocolVersion: protocol.Version2,
			Kill:            true,
			KillReason:      "engagement ended",
		})
		_ = sendMessage(serverConn, &protocol.Message{Type: "register_ack", Data: ack})
	}()

	result, err := register(clientConn, protocol.RegisterData{ImplantID: "implant-1"}, "", 5*time.Second, 0)
	if err != nil {
		t.Fatalf("register: %v", err)
	}
	if !result.Kill || result.KillReason != "engagement ended" {
		t.Fatalf("kill instruction not propagated: %+v", result)
	}
}
