package aes

import (
	"testing"

	"github.com/AkewakBiru/AES-Cipher-go/utils"

	"github.com/stretchr/testify/assert"
)

// checks if encryption/decryption works with basic plaintext blocks
func TestCbcBasic(t *testing.T) {
	testCases := []struct {
		desc  string
		plain []byte
	}{
		{
			"1 block",
			[]byte("simpleteststring"),
		},
		{
			"Empty block",
			[]byte(""),
		},
		{
			"1 block without padding",
			[]byte("1"),
		},
		{
			"2 blocks without padding",
			[]byte("simple teststring"),
		},
	}

	key := []byte("this_isa_testkey")
	iv := []byte("thisisasample_iv")
	cipher, err := NewCipherWithCodec(key, ECB, iv)
	if err != nil {
		t.Error(err)
		return
	}

	for _, c := range testCases {
		enc, err := cipher.Encrypt(c.plain)
		if err != nil {
			assert.EqualError(t, err, "empty plaintext array")
		} else {
			dec, err := cipher.Decrypt(enc)
			if err != nil {
				t.Error(err)
			}
			assert.Equal(t, dec, c.plain)
		}
	}
}

// tests enc/dec of a big content
func TestCbcBigFile(t *testing.T) {
	plain, err := utils.ReadFile("../test")
	if err != nil {
		t.Error(err)
		return
	}

	key := []byte("this_isa_testkey")
	iv := []byte("thisisasample_iv")
	cipher, err := NewCipherWithCodec(key, CBC, iv)
	if err != nil {
		t.Error(err)
		return
	}

	enc, err := cipher.Encrypt(plain)
	if err != nil {
		t.Error(err)
		return
	}

	dec, err := cipher.Decrypt(enc)
	if err != nil {
		t.Error(err)
		return
	}

	assert.Equal(t, plain, dec)
}
