package aes

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"

	"github.com/LetsFocus/encryptia/pkg"
	"github.com/LetsFocus/encryptia/pkg/utils"
)

type GCM struct {
}

func NewGCM() pkg.Cryptographer {
	return &GCM{}
}

func (a *GCM) Encrypt(plaintext []byte, key ...string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("encryption key cannot be empty")
	}

	block, err := aes.NewCipher([]byte(key[0]))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(nonce, nonce, plaintext, nil)
	return utils.Base64Encode(ciphertext), nil
}

func (a *GCM) Decrypt(ciphertext string, key ...string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("decryption key cannot be empty")
	}

	ciphertextBytes, err := utils.Base64Decode(ciphertext)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher([]byte(key[0]))
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(ciphertextBytes) < nonceSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := ciphertextBytes[:nonceSize], ciphertextBytes[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertextBytes, nil)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}
