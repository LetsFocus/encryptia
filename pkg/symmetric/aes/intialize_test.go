package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNew(t *testing.T) {
	tests := []struct {
		name         string
		mode         string
		expectErr    bool
		expectedType string
	}{
		{
			name:         "Valid GCM mode",
			mode:         ModeGCM,
			expectErr:    false,
			expectedType: "*aes.GCM", // Replace with actual type
		},
		{
			name:         "Valid CTR mode",
			mode:         ModeCTR,
			expectErr:    false,
			expectedType: "*aes.CTR", // Replace with actual type
		},
		{
			name:         "Valid CFB mode",
			mode:         ModeCFB,
			expectErr:    false,
			expectedType: "*aes.CFB", // Replace with actual type
		},
		{
			name:         "Valid OFB mode",
			mode:         ModeOFB,
			expectErr:    false,
			expectedType: "*aes.OFB", // Replace with actual type
		},
		{
			name:         "Valid ECB mode",
			mode:         ModeECB,
			expectErr:    false,
			expectedType: "*aes.ECB", // Replace with actual type
		},
		{
			name:         "Invalid mode",
			mode:         "invalid",
			expectErr:    true,
			expectedType: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cryptographer, err := New(tt.mode)
			if tt.expectErr {
				assert.Error(t, err, "Expected an error but got none")
				assert.Nil(t, cryptographer, "Expected nil Cryptographer due to error")
			} else {
				assert.NoError(t, err, "Unexpected error occurred")
				assert.NotNil(t, cryptographer, "Cryptographer should not be nil")
				assert.IsType(t, getExpectedType(tt.expectedType), cryptographer, "Incorrect Cryptographer type")
			}
		})
	}
}

// Helper function to get the expected type for assertions
func getExpectedType(typeName string) interface{} {
	switch typeName {
	case "*aes.GCM":
		return NewGCM()
	case "*aes.CTR":
		return NewCTR()
	case "*aes.CFB":
		return &CFB{}
	case "*aes.OFB":
		return &OFB{}
	case "*aes.ECB":
		return &ECB{}
	default:
		return nil
	}
}
