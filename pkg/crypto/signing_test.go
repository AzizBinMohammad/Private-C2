package crypto

import (
	"testing"
)

func TestSignVerifyRoundTrip(t *testing.T) {
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	message := []byte("important message")
	sig := Sign(kp.PrivateKey, message)

	if err := Verify(kp.PublicKey, message, sig); err != nil {
		t.Fatalf("Verify should succeed: %v", err)
	}
}

func TestTamperedMessageFailsVerify(t *testing.T) {
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	message := []byte("original message")
	sig := Sign(kp.PrivateKey, message)

	tampered := []byte("tampered message")
	if err := Verify(kp.PublicKey, tampered, sig); err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for tampered message, got %v", err)
	}
}

func TestWrongKeyFailsVerify(t *testing.T) {
	kp1, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair 1: %v", err)
	}

	kp2, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair 2: %v", err)
	}

	message := []byte("message from kp1")
	sig := Sign(kp1.PrivateKey, message)

	if err := Verify(kp2.PublicKey, message, sig); err != ErrInvalidSignature {
		t.Fatalf("expected ErrInvalidSignature for wrong key, got %v", err)
	}
}

func TestSignatureNotEmpty(t *testing.T) {
	kp, err := GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	sig := Sign(kp.PrivateKey, []byte("test"))
	if len(sig) == 0 {
		t.Fatal("signature should not be empty")
	}
}
