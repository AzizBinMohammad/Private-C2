package crypto

import (
	"crypto/rand"
	"errors"

	"golang.org/x/crypto/curve25519"
)

var ErrKeyExchangeFailed = errors.New("key exchange failed")

type X25519KeyPair struct {
	PrivateKey [32]byte
	PublicKey  [32]byte
}

func GenerateX25519KeyPair() (*X25519KeyPair, error) {
	var priv [32]byte
	if _, err := rand.Read(priv[:]); err != nil {
		return nil, err
	}

	pub, err := curve25519.X25519(priv[:], curve25519.Basepoint)
	if err != nil {
		return nil, err
	}

	kp := &X25519KeyPair{}
	copy(kp.PrivateKey[:], priv[:])
	copy(kp.PublicKey[:], pub)
	return kp, nil
}

func ComputeSharedSecret(privateKey [32]byte, peerPublicKey [32]byte) ([32]byte, error) {
	shared, err := curve25519.X25519(privateKey[:], peerPublicKey[:])
	if err != nil {
		return [32]byte{}, ErrKeyExchangeFailed
	}
	return DeriveKey(shared), nil
}
