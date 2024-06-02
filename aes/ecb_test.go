package aes

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

// checks if encryption/decryption works with basic plaintext blocks
func TestEcbBasic(t *testing.T) {
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
	cipher, err := NewCipher(key)
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
func TestEcbBigFile(t *testing.T) {
	key := []byte("this_isa_testkey")
	iv := []byte("thisisasample_iv")
	cipher, err := NewCipherWithCodec(key, CBC, iv)
	if err != nil {
		t.Error(err)
		return
	}

	if err := EncryptFile(cipher, "../test", "out"); err != nil {
		t.Error(err)
		return
	}
	if err := DecryptFile(cipher, "out", "orig"); err != nil {
		t.Error(err)
		return
	}
	_, same, err := CompareFiles("../test", "orig")
	if err != nil {
		t.Error(err)
		return
	}
	if !same {
		t.Fail()
	}
	RemoveFiles("out", "orig")
}
