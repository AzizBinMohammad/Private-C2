package httpapi

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// loadLootKey resolves the AES-256 key in this order:
//  1. PC2_LOOT_KEY (hex or base64, 32 bytes)
//  2. <loot-dir>/loot.key
//  3. a newly generated key written to <loot-dir>/loot.key with mode 0600
//
// Key rotation is a deliberate operator action: replace the key and re-encrypt
// existing blobs, or keep the old key readable by moving files aside.
func (lh *lootHandler) loadLootKey() ([]byte, error) {
	lh.keyOnce.Do(func() {
		lh.key, lh.keyErr = loadLootKey(lh.dir)
	})
	return lh.key, lh.keyErr
}

func loadLootKey(dir string) ([]byte, error) {
	if raw := strings.TrimSpace(os.Getenv("PC2_LOOT_KEY")); raw != "" {
		key, err := decodeLootKey(raw)
		if err != nil {
			return nil, fmt.Errorf("PC2_LOOT_KEY: %w", err)
		}
		return key, nil
	}

	path := filepath.Join(dir, "loot.key")
	if data, err := os.ReadFile(path); err == nil {
		return decodeLootKey(strings.TrimSpace(string(data)))
	}

	key := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		return nil, fmt.Errorf("generate loot key: %w", err)
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, []byte(hex.EncodeToString(key)), 0600); err != nil {
		return nil, fmt.Errorf("write loot key: %w", err)
	}
	return key, nil
}

func decodeLootKey(raw string) ([]byte, error) {
	if len(raw) == 64 {
		if key, err := hex.DecodeString(raw); err == nil {
			return key, nil
		}
	}
	if key, err := base64.StdEncoding.DecodeString(raw); err == nil && len(key) == 32 {
		return key, nil
	}
	return nil, fmt.Errorf("key must be 32 bytes encoded as hex or base64")
}

func (lh *lootHandler) seal(plain []byte) ([]byte, error) {
	key, err := lh.loadLootKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(lootMagic)+len(nonce)+len(plain)+gcm.Overhead())
	out = append(out, lootMagic...)
	out = append(out, nonce...)
	return gcm.Seal(out, nonce, plain, []byte(lootMagic)), nil
}

func (lh *lootHandler) open(sealed []byte) ([]byte, error) {
	if !bytes.HasPrefix(sealed, []byte(lootMagic)) {
		// Legacy plaintext blobs from before encryption was enabled.
		return sealed, nil
	}
	key, err := lh.loadLootKey()
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	rest := sealed[len(lootMagic):]
	if len(rest) < gcm.NonceSize() {
		return nil, fmt.Errorf("loot blob is truncated")
	}
	nonce, ciphertext := rest[:gcm.NonceSize()], rest[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, []byte(lootMagic))
}

func (lh *lootHandler) readArtifact(path string) ([]byte, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return lh.open(sealed)
}
