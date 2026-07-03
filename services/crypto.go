package services

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"io"

	"github.com/hedwi/certhub-server/config"
)

var encryptionKey []byte

// InitCrypto loads the encryption key from config. Empty key is allowed only in dev mode.
func InitCrypto() error {
	if config.Cfg.Security.EncryptionKey == "" {
		encryptionKey = nil
		return nil
	}
	key, err := config.DecodeEncryptionKey(config.Cfg.Security.EncryptionKey)
	if err != nil {
		return err
	}
	if len(key) != 32 {
		return fmt.Errorf("encryption key must be 32 bytes")
	}
	encryptionKey = key
	return nil
}

// Encrypt encrypts plaintext with AES-256-GCM. Returns plaintext unchanged when encryption is disabled.
func Encrypt(plaintext []byte) ([]byte, error) {
	if len(encryptionKey) == 0 {
		return plaintext, nil
	}
	block, err := aes.NewCipher(encryptionKey)
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
	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	out := make([]byte, base64.StdEncoding.EncodedLen(len(ciphertext)))
	base64.StdEncoding.Encode(out, ciphertext)
	return out, nil
}

// Decrypt decrypts data encrypted by Encrypt.
func Decrypt(data []byte) ([]byte, error) {
	if len(encryptionKey) == 0 {
		return data, nil
	}
	raw := make([]byte, base64.StdEncoding.DecodedLen(len(data)))
	n, err := base64.StdEncoding.Decode(raw, data)
	if err != nil {
		return nil, err
	}
	raw = raw[:n]

	block, err := aes.NewCipher(encryptionKey)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext too short")
	}
	nonce, ciphertext := raw[:gcm.NonceSize()], raw[gcm.NonceSize():]
	return gcm.Open(nil, nonce, ciphertext, nil)
}
