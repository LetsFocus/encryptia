package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestOFMEncrypt(t *testing.T) {
	tests := []struct {
		name        string
		plaintext   string
		key         string
		expectError bool
	}{
		{
			name:        "Valid encryption",
			plaintext:   "Hello, World!",
			key:         "thisis32bitlongpassphraseimusing",
			expectError: false,
		},
		{
			name:        "Invalid key length (too short)",
			plaintext:   "Hello, World!",
			key:         "shortkey",
			expectError: true,
		},
		{
			name:        "Empty plaintext",
			plaintext:   "",
			key:         "thisis32bitlongpassphraseimusing",
			expectError: false,
		},
		{
			name:        "Empty key",
			plaintext:   "Hello, World!",
			key:         "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		tt := tt

		t.Run(tt.name, func(t *testing.T) {
			ofb := NewOFB()

			// Test encryption
			encrypted, err := ofb.Encrypt([]byte(tt.plaintext), tt.key)
			if tt.expectError {
				assert.Error(t, err, "Expected an error but got none")
			} else {
				assert.NoError(t, err, "Expected no error but got one")
				assert.NotEmpty(t, encrypted, "Expected non-empty ciphertext")
			}
		})
	}
}

func TestOFBDecrypt(t *testing.T) {
	ofb := NewOFB()

	cipharText, _ := ofb.Encrypt([]byte("Hello, World!"), "thisis32bitlongpassphraseimusing")

	tests := []struct {
		name         string
		ciphertext   string
		key          string
		expectError  bool
		expectedText string
	}{
		{
			name:         "Valid decryption",
			ciphertext:   cipharText,
			key:          "thisis32bitlongpassphraseimusing",
			expectError:  false,
			expectedText: "Hello, World!",
		},
		{
			name:         "Invalid key length (too short)",
			ciphertext:   "Base64EncodedCiphertextHere",
			key:          "shortkey",
			expectError:  true,
			expectedText: "",
		},
		{
			name:         "Empty key",
			ciphertext:   "Base64EncodedCiphertextHere",
			key:          "",
			expectError:  true,
			expectedText: "",
		},
		{
			name:         "Tampered ciphertext",
			ciphertext:   "Base64EncodedTamperedCiphertext",
			key:          "thisis32bitlongpassphraseimusing!",
			expectError:  true,
			expectedText: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			decrypted, err := ofb.Decrypt(tt.ciphertext, tt.key)
			if tt.expectError {
				assert.Error(t, err, "Expected an error but got none")
				assert.Empty(t, decrypted, "Expected empty plaintext due to error")
			} else {
				assert.NoError(t, err, "Decryption failed")
				assert.Equal(t, tt.expectedText, decrypted, "Decrypted text does not match expected plaintext")
			}
		})
	}
}
