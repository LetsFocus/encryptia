package utils

import "encoding/base64"

// Base64Encode encodes data to a Base64 encoded string.
func Base64Encode(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

// Base64Decode decodes a Base64 encoded string to its original form.
func Base64Decode(encoded string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(encoded)
}
