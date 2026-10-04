package crypto

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
)

var ErrInvalidSignature = errors.New("invalid signature")

type Ed25519KeyPair struct {
	PrivateKey ed25519.PrivateKey
	PublicKey  ed25519.PublicKey
}

func GenerateEd25519KeyPair() (*Ed25519KeyPair, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return &Ed25519KeyPair{PrivateKey: priv, PublicKey: pub}, nil
}

func Sign(privateKey ed25519.PrivateKey, message []byte) []byte {
	return ed25519.Sign(privateKey, message)
}

func Verify(publicKey ed25519.PublicKey, message, signature []byte) error {
	if !ed25519.Verify(publicKey, message, signature) {
		return ErrInvalidSignature
	}
	return nil
}
