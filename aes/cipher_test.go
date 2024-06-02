package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// checks for error handling
func TestCipherSpecError(t *testing.T) {
	var testCases = []struct {
		errName string
		mode    Mode
		key     []byte
		iv      []byte
	}{
		{
			"invalid keysize",
			ECB,
			[]byte("thisis a test"),
			[]byte("thisisasample_iv"),
		},
		{
			"initialization vector must be 16 bytes long",
			CBC,
			[]byte("this_isa_testkey"),
			[]byte("thisisample_iv"),
		},
		{
			"nonce must be 8 bytes long",
			CTR,
			[]byte("this_isa_testkey"),
			[]byte("thisisample_nonce"),
		},
	}

	for _, c := range testCases {
		_, err := NewCipherWithCodec(c.key, ECB, c.iv)
		if err != nil {
			assert.EqualError(t, err, c.errName)
		}
	}
}
