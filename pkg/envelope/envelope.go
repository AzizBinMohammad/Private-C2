package envelope

import (
	"crypto/ed25519"
	"errors"

	"github.com/azizbinmohammad/private-c2/pkg/crypto"
)

const SignatureSize = ed25519.SignatureSize

var ErrInvalidEnvelope = errors.New("invalid envelope format")

type SignedEnvelope struct {
	Signature []byte
	Payload   []byte
}

func Seal(payload []byte, signingKey ed25519.PrivateKey, cipher *crypto.CipherContext) ([]byte, error) {
	compressed, err := Compress(payload)
	if err != nil {
		return nil, err
	}

	encrypted, err := cipher.Encrypt(compressed)
	if err != nil {
		return nil, err
	}

	signature := crypto.Sign(signingKey, encrypted)

	envelope := make([]byte, 0, len(signature)+len(encrypted))
	envelope = append(envelope, signature...)
	envelope = append(envelope, encrypted...)

	return envelope, nil
}

func Open(data []byte, verifyKey ed25519.PublicKey, cipher *crypto.CipherContext) ([]byte, error) {
	if len(data) < SignatureSize {
		return nil, ErrInvalidEnvelope
	}

	signature := data[:SignatureSize]
	ciphertext := data[SignatureSize:]

	if err := crypto.Verify(verifyKey, ciphertext, signature); err != nil {
		return nil, err
	}

	compressed, err := cipher.Decrypt(ciphertext)
	if err != nil {
		return nil, err
	}

	return Decompress(compressed)
}
