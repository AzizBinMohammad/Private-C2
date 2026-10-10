package engagement

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestCheckRemoteKillSwitch_200_ContinueOperation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	killed, err := CheckRemoteKillSwitch(context.Background(), srv.URL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if killed {
		t.Error("HTTP 200 should return false (continue operation)")
	}
}

func TestCheckRemoteKillSwitch_Non200_Kill(t *testing.T) {
	for _, code := range []int{
		http.StatusForbidden,
		http.StatusInternalServerError,
		http.StatusServiceUnavailable,
	} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(code)
		}))

		killed, err := CheckRemoteKillSwitch(context.Background(), srv.URL)
		srv.Close()
		if err != nil {
			t.Fatalf("code %d: unexpected error: %v", code, err)
		}
		if !killed {
			t.Errorf("HTTP %d should return true (kill)", code)
		}
	}
}

func TestCheckRemoteKillSwitch_Unreachable_FailClosed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	url := srv.URL
	srv.Close()

	killed, err := CheckRemoteKillSwitch(context.Background(), url)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !killed {
		t.Error("unreachable endpoint should return true (fail-closed)")
	}
}

func TestCheckRemoteKillSwitch_EmptyURL_NilBehavior(t *testing.T) {
	killed, err := CheckRemoteKillSwitch(context.Background(), "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if killed {
		t.Error("empty URL should return false (no kill switch configured)")
	}
}
