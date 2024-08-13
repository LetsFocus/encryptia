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

type CTR struct {
}

func NewCTR() pkg.Cryptographer {
	return &CTR{}
}

func (a *CTR) Encrypt(plaintext []byte, key ...string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("encryption key cannot be empty")
	}

	block, err := aes.NewCipher([]byte(key[0]))
	if err != nil {
		return "", err
	}

	nonce := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}

	stream := cipher.NewCTR(block, nonce)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	result := append(nonce, ciphertext...)
	return utils.Base64Encode(result), nil
}

func (a *CTR) Decrypt(ciphertext string, key ...string) (string, error) {
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

	if len(ciphertextBytes) < aes.BlockSize {
		return "", errors.New("ciphertext too short")
	}

	nonce, ciphertextBytes := ciphertextBytes[:aes.BlockSize], ciphertextBytes[aes.BlockSize:]
	stream := cipher.NewCTR(block, nonce)

	plaintext := make([]byte, len(ciphertextBytes))
	stream.XORKeyStream(plaintext, ciphertextBytes)

	return string(plaintext), nil
}
