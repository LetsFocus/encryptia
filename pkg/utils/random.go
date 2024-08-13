package utils

import (
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"math/big"
)

const (
	letterBytes = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	lowerCase   = "abcdefghijklmnopqrstuvwxyz"
	upperCase   = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	digits      = "0123456789"
	special     = "!@#$%^&*()-_=+[]{}|;:,.<>?/"
	allChars    = lowerCase + upperCase + digits + special
)

// GenerateRandomString generates a random string of the specified length using the provided character set.
func GenerateRandomString(length int) (string, error) {
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(letterBytes))))
		if err != nil {
			return "", err
		}

		result[i] = letterBytes[num.Int64()]
	}

	return string(result), nil
}

// GenerateRandomInt generates a random integer between min and max-1.
func GenerateRandomInt(min, max int64) (int64, error) {
	if max <= min {
		return 0, errors.New("max must be greater than min")
	}

	n, err := rand.Int(rand.Reader, big.NewInt(max-min))
	if err != nil {
		return 0, err
	}

	return n.Int64() + min, nil
}

// GenerateRandomFloat generates a random float64 between 0 and 1.
func GenerateRandomFloat() (float64, error) {
	newInt := big.NewInt(1 << 53)
	n, err := rand.Int(rand.Reader, newInt)
	if err != nil {
		return 0, err
	}

	return float64(n.Int64()) / float64(1<<53), nil
}

// GenerateUUID generates a random UUID (version 4).
func GenerateUUID() (string, error) {
	uuid := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, uuid); err != nil {
		return "", err
	}

	// Set the version to 4 (pseudo-random)
	uuid[6] = (uuid[6] & 0x0f) | 0x40
	// Set the variant to RFC4122
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	return fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:]), nil
}

// GenerateRandomBool generates a random boolean value.
func GenerateRandomBool() (bool, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(2))
	if err != nil {
		return false, err
	}

	return n.Int64() == 1, nil
}

// GenerateSecurePassword generates a secure password with the specified length.
func GenerateSecurePassword(length int) (string, error) {
	if length < 8 {
		return "", errors.New("password length should be at least 8 characters")
	}

	password := make([]byte, length)

	// Ensure at least one character from each set is included
	categories := []string{lowerCase, upperCase, digits, special}
	for i, category := range categories {
		char, err := generateRandomCharFromSet(category)
		if err != nil {
			return "", err
		}

		password[i] = char
	}

	// Fill the rest with random characters from all character sets
	for i := len(categories); i < length; i++ {
		char, err := generateRandomCharFromSet(allChars)
		if err != nil {
			return "", err
		}

		password[i] = char
	}

	// Shuffle to ensure randomness
	password, err := GenerateRandomPermutationBytes(password)
	if err != nil {
		return "", err
	}

	return string(password), nil
}

// generateRandomCharFromSet generates a random character from the given set.
func generateRandomCharFromSet(charSet string) (byte, error) {
	index, err := rand.Int(rand.Reader, big.NewInt(int64(len(charSet))))
	if err != nil {
		return 0, err
	}

	return charSet[index.Int64()], nil
}

// GenerateRandomPermutationBytes returns a shuffled byte slice using crypto/rand.
func GenerateRandomPermutationBytes(input []byte) ([]byte, error) {
	n := len(input)
	for i := n - 1; i > 0; i-- {
		j, err := cryptoRandInt(i + 1)
		if err != nil {
			return nil, err
		}
		input[i], input[j] = input[j], input[i]
	}

	return input, nil
}

// cryptoRandInt returns a random int in the range [0, max).
func cryptoRandInt(max int) (int, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(int64(max)))
	if err != nil {
		return 0, err
	}
	return int(n.Int64()), nil
}
