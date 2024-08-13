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

type OFB struct {
}

func NewOFB() pkg.Cryptographer {
	return &OFB{}
}

func (a *OFB) Encrypt(plaintext []byte, key ...string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("encryption key cannot be empty")
	}

	block, err := aes.NewCipher([]byte(key[0]))
	if err != nil {
		return "", err
	}

	iv := make([]byte, aes.BlockSize)
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewOFB(block, iv)
	ciphertext := make([]byte, len(plaintext))
	stream.XORKeyStream(ciphertext, plaintext)

	result := append(iv, ciphertext...)
	return utils.Base64Encode(result), nil
}

func (a *OFB) Decrypt(ciphertext string, key ...string) (string, error) {
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

	iv, ciphertextBytes := ciphertextBytes[:aes.BlockSize], ciphertextBytes[aes.BlockSize:]
	stream := cipher.NewOFB(block, iv)

	plaintext := make([]byte, len(ciphertextBytes))
	stream.XORKeyStream(plaintext, ciphertextBytes)

	return string(plaintext), nil
}
