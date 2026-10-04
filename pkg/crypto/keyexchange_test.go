package crypto

import (
	"testing"
)

func TestGenerateX25519KeyPair(t *testing.T) {
	kp, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair: %v", err)
	}

	var zero [32]byte
	if kp.PrivateKey == zero {
		t.Fatal("private key should not be zero")
	}
	if kp.PublicKey == zero {
		t.Fatal("public key should not be zero")
	}
}

func TestSharedSecretAgreement(t *testing.T) {
	alice, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (alice): %v", err)
	}

	bob, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (bob): %v", err)
	}

	secretAB, err := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret (alice->bob): %v", err)
	}

	secretBA, err := ComputeSharedSecret(bob.PrivateKey, alice.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret (bob->alice): %v", err)
	}

	if secretAB != secretBA {
		t.Fatal("shared secrets should agree between both parties")
	}
}

func TestDifferentKeyPairsDifferentSecrets(t *testing.T) {
	alice, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (alice): %v", err)
	}

	bob, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (bob): %v", err)
	}

	carol, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair (carol): %v", err)
	}

	secretAB, err := ComputeSharedSecret(alice.PrivateKey, bob.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret (alice->bob): %v", err)
	}

	secretAC, err := ComputeSharedSecret(alice.PrivateKey, carol.PublicKey)
	if err != nil {
		t.Fatalf("ComputeSharedSecret (alice->carol): %v", err)
	}

	if secretAB == secretAC {
		t.Fatal("shared secrets with different peers should differ")
	}
}

func TestKeyPairUniqueness(t *testing.T) {
	kp1, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair 1: %v", err)
	}

	kp2, err := GenerateX25519KeyPair()
	if err != nil {
		t.Fatalf("GenerateX25519KeyPair 2: %v", err)
	}

	if kp1.PublicKey == kp2.PublicKey {
		t.Fatal("two generated key pairs should have different public keys")
	}
}
