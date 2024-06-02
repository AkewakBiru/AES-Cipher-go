package utils

import (
	"bytes"
	"errors"
)

// Implementation of PKCS #7 as per RFC 2315
type Padder struct {
	blockSize uint8
}

func NewPadder(blockSize uint8) *Padder {
	return &Padder{blockSize: blockSize}
}

func paddingError(msg string) error {
	return errors.New(msg)
}

func (p *Padder) Pad(input []byte) ([]byte, error) {
	if p.blockSize < 16 || p.blockSize > 255 {
		return nil, paddingError("blocksize error")
	}

	if len(input)%int(p.blockSize) == 0 {
		return input, nil
	}

	paddingBytes := int(p.blockSize) - (len(input) % int(p.blockSize))
	padded := bytes.Repeat([]byte{byte(paddingBytes)}, paddingBytes)
	return append(input, padded...), nil
}

func (p *Padder) Unpad(input []byte) ([]byte, error) {
	if p.blockSize < 16 || p.blockSize > 255 {
		return nil, paddingError("blocksize error")
	}

	if len(input) == 0 {
		return input, paddingError("empty array")
	}

	padded, ok := isPadded(input, input[len(input)-1])
	if !ok {
		return input, nil
	}
	count := int(p.blockSize) - (padded % int(p.blockSize))
	return input[:len(input)-count], nil
}

func isPadded(input []byte, val byte) (int, bool) {
	// if the last byte is not between (0x0-0xF), it's not padded
	if val > 0xF {
		return -1, false
	}
	if input[len(input)-int(val)] == val {
		for i := len(input) - int(val); i < len(input); i++ {
			if input[i] != val {
				return -1, false
			}
		}
		return len(input) - int(val), true
	}
	return -1, false
}
