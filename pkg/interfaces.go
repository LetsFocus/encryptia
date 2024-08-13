package pkg

type Cryptographer interface {
	Encrypt(plaintext []byte, key ...string) (string, error)
	Decrypt(ciphertext string, key ...string) (string, error)
}
