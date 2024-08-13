package aes

import (
	"errors"
	"github.com/LetsFocus/encryptia/pkg"
)

const (
	ModeGCM = "GCM"
	ModeCTR = "CTR"
	ModeCFB = "CFB"
	ModeOFB = "OFB"
	ModeECB = "ECB"
)

// New creates the appropriate AES mode based on the input mode string.
func New(mode string) (pkg.Cryptographer, error) {
	switch mode {
	case ModeGCM:
		return NewGCM(), nil
	case ModeCTR:
		return NewCTR(), nil
	case ModeCFB:
		return NewCFB(), nil
	case ModeOFB:
		return NewOFB(), nil
	case ModeECB:
		return NewECB(), nil
	default:
		return nil, errors.New("unsupported AES mode")
	}
}
