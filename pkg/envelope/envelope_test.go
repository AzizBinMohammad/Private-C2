package envelope

import (
	"bytes"
	"testing"

	"github.com/azizbinmohammad/private-c2/pkg/crypto"
)

func TestSealOpenRoundTrip(t *testing.T) {
	sigKP, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	key, err := crypto.RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}

	sealCipher := crypto.NewCipherContext(key)
	openCipher := crypto.NewCipherContext(key)

	payload := []byte("secret payload data")
	sealed, err := Seal(payload, sigKP.PrivateKey, sealCipher)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	opened, err := Open(sealed, sigKP.PublicKey, openCipher)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(payload, opened) {
		t.Fatalf("round-trip mismatch: got %q, want %q", opened, payload)
	}
}

func TestTamperedCiphertextFails(t *testing.T) {
	sigKP, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	key, err := crypto.RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}

	sealCipher := crypto.NewCipherContext(key)
	openCipher := crypto.NewCipherContext(key)

	sealed, err := Seal([]byte("test"), sigKP.PrivateKey, sealCipher)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Tamper with a byte in the ciphertext portion (after the signature)
	if len(sealed) > SignatureSize+1 {
		sealed[SignatureSize+1] ^= 0xFF
	}

	_, err = Open(sealed, sigKP.PublicKey, openCipher)
	if err == nil {
		t.Fatal("Open should fail with tampered ciphertext")
	}
}

func TestWrongSigningKeyFails(t *testing.T) {
	sigKP1, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair 1: %v", err)
	}

	sigKP2, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair 2: %v", err)
	}

	key, err := crypto.RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}

	sealCipher := crypto.NewCipherContext(key)
	openCipher := crypto.NewCipherContext(key)

	sealed, err := Seal([]byte("test"), sigKP1.PrivateKey, sealCipher)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Verify with wrong public key
	_, err = Open(sealed, sigKP2.PublicKey, openCipher)
	if err == nil {
		t.Fatal("Open should fail with wrong signing key")
	}
}

func TestWrongEncryptionKeyFails(t *testing.T) {
	sigKP, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	key1, err := crypto.RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey 1: %v", err)
	}
	key2, err := crypto.RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey 2: %v", err)
	}

	sealCipher := crypto.NewCipherContext(key1)
	openCipher := crypto.NewCipherContext(key2)

	sealed, err := Seal([]byte("test"), sigKP.PrivateKey, sealCipher)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	// Signature verification will pass (signature is over the ciphertext),
	// but decryption with the wrong key should fail
	_, err = Open(sealed, sigKP.PublicKey, openCipher)
	if err == nil {
		t.Fatal("Open should fail with wrong encryption key")
	}
}

func TestSealOpenLargePayload(t *testing.T) {
	sigKP, err := crypto.GenerateEd25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateEd25519KeyPair: %v", err)
	}

	key, err := crypto.RandomSymmetricKey()
	if err != nil {
		t.Fatalf("RandomSymmetricKey: %v", err)
	}

	sealCipher := crypto.NewCipherContext(key)
	openCipher := crypto.NewCipherContext(key)

	payload := make([]byte, 1<<20) // 1 MB
	for i := range payload {
		payload[i] = byte(i % 256)
	}

	sealed, err := Seal(payload, sigKP.PrivateKey, sealCipher)
	if err != nil {
		t.Fatalf("Seal: %v", err)
	}

	opened, err := Open(sealed, sigKP.PublicKey, openCipher)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}

	if !bytes.Equal(payload, opened) {
		t.Fatal("large payload round-trip mismatch")
	}
}
