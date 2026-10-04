package crypto

import (
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"sync"

	"golang.org/x/crypto/chacha20poly1305"
)

var (
	ErrDecryptFailed = errors.New("decryption failed")
	ErrReplayDetected = errors.New("replay detected: ciphertext already seen")
)

type CipherContext struct {
	key    [chacha20poly1305.KeySize]byte
	replay sync.Map
}

func NewCipherContext(key [32]byte) *CipherContext {
	return &CipherContext{key: key}
}

func DeriveKey(material []byte) [32]byte {
	return sha256.Sum256(material)
}

func RandomSymmetricKey() ([32]byte, error) {
	var seed [64]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return [32]byte{}, err
	}
	return DeriveKey(seed[:]), nil
}

func (c *CipherContext) Encrypt(plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(c.key[:])
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}

	return aead.Seal(nonce, nonce, plaintext, nil), nil
}

func (c *CipherContext) Decrypt(ciphertext []byte) ([]byte, error) {
	digest := sha256.Sum256(ciphertext)
	if _, loaded := c.replay.LoadOrStore(digest, struct{}{}); loaded {
		return nil, ErrReplayDetected
	}

	aead, err := chacha20poly1305.NewX(c.key[:])
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aead.NonceSize() {
		return nil, ErrDecryptFailed
	}

	nonce := ciphertext[:aead.NonceSize()]
	data := ciphertext[aead.NonceSize():]

	plaintext, err := aead.Open(nil, nonce, data, nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	return plaintext, nil
}
