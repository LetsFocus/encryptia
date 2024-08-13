package aes

import (
	"crypto/aes"
	"errors"

	"github.com/LetsFocus/encryptia/pkg"
	"github.com/LetsFocus/encryptia/pkg/utils"
)

type ECB struct {
}

func NewECB() pkg.Cryptographer {
	return &ECB{}
}

func (a *ECB) Encrypt(plaintext []byte, key ...string) (string, error) {
	if len(key) == 0 {
		return "", errors.New("encryption key cannot be empty")
	}

	block, err := aes.NewCipher([]byte(key[0]))
	if err != nil {
		return "", err
	}

	if len(plaintext)%aes.BlockSize != 0 {
		return "", errors.New("plaintext is not a multiple of the block size")
	}

	ciphertext := make([]byte, len(plaintext))
	for i := 0; i < len(plaintext); i += aes.BlockSize {
		block.Encrypt(ciphertext[i:i+aes.BlockSize], plaintext[i:i+aes.BlockSize])
	}

	return utils.Base64Encode(ciphertext), nil
}

func (a *ECB) Decrypt(ciphertext string, key ...string) (string, error) {
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

	if len(ciphertextBytes)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}

	plaintext := make([]byte, len(ciphertextBytes))
	for i := 0; i < len(ciphertextBytes); i += aes.BlockSize {
		block.Decrypt(plaintext[i:i+aes.BlockSize], ciphertextBytes[i:i+aes.BlockSize])
	}

	return string(plaintext), nil
}
