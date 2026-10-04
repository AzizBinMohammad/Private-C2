package crypto

import (
	"bytes"
	"testing"
)

func TestEncryptDecryptRoundTrip(t *testing.T) {
	key, err := RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}

	ctx := NewCipherContext(key)

	plaintext := []byte("hello, world")
	ciphertext, err := ctx.Encrypt(plaintext)
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	if bytes.Equal(plaintext, ciphertext) {
		t.Fatal("ciphertext should differ from plaintext")
	}

	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt: %v", err)
	}

	if !bytes.Equal(plaintext, decrypted) {
		t.Fatalf("round-trip mismatch: got %q, want %q", decrypted, plaintext)
	}
}

func TestEncryptDecryptEmptyPlaintext(t *testing.T) {
	key, err := RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}

	ctx := NewCipherContext(key)

	ciphertext, err := ctx.Encrypt([]byte{})
	if err != nil {
		t.Fatalf("Encrypt empty: %v", err)
	}

	decrypted, err := ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("Decrypt empty: %v", err)
	}

	if len(decrypted) != 0 {
		t.Fatalf("expected empty plaintext, got %d bytes", len(decrypted))
	}
}

func TestReplayDetection(t *testing.T) {
	key, err := RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}

	ctx := NewCipherContext(key)

	ciphertext, err := ctx.Encrypt([]byte("test"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = ctx.Decrypt(ciphertext)
	if err != nil {
		t.Fatalf("first Decrypt: %v", err)
	}

	_, err = ctx.Decrypt(ciphertext)
	if err != ErrReplayDetected {
		t.Fatalf("expected ErrReplayDetected, got %v", err)
	}
}

func TestDifferentKeysFailDecrypt(t *testing.T) {
	key1, err := RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}
	key2, err := RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}

	ctx1 := NewCipherContext(key1)
	ctx2 := NewCipherContext(key2)

	ciphertext, err := ctx1.Encrypt([]byte("secret"))
	if err != nil {
		t.Fatalf("Encrypt: %v", err)
	}

	_, err = ctx2.Decrypt(ciphertext)
	if err == nil {
		t.Fatal("expected decryption to fail with wrong key")
	}
}

func TestDeriveKeyDeterminism(t *testing.T) {
	material := []byte("deterministic input material")

	k1 := DeriveKey(material)
	k2 := DeriveKey(material)

	if k1 != k2 {
		t.Fatal("DeriveKey should be deterministic for the same input")
	}

	k3 := DeriveKey([]byte("different material"))
	if k1 == k3 {
		t.Fatal("DeriveKey should produce different output for different input")
	}
}

func TestRandomSymmetricKeyUniqueness(t *testing.T) {
	keys := make(map[[32]byte]struct{})
	const n = 100
	for i := 0; i < n; i++ {
		key, err := RandomSymmetricKey()
		if err != nil {
			t.Fatalf("RandomSymmetricKey: %v", err)
		}
		if _, exists := keys[key]; exists {
			t.Fatal("RandomSymmetricKey produced a duplicate key")
		}
		keys[key] = struct{}{}
	}
}
