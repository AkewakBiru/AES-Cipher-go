package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPad(t *testing.T) {
	testCases := []struct {
		name     string
		c        []byte
		expected []byte
	}{
		{
			name:     "basic test",
			c:        []byte("test123"),
			expected: []byte("test123\x09\x09\x09\x09\x09\x09\x09\x09\x09"),
		},
		{
			name:     "another test",
			c:        []byte("test1\n"),
			expected: []byte("test1\n\n\n\n\n\n\n\n\n\n\n"),
		},
	}

	padder := NewPadder(16)

	for _, c := range testCases {
		padded, err := padder.Pad(c.c)
		if err != nil {
			t.Error(err)
			continue
		}
		assert.Equal(t, c.expected, padded)
		unpadded, err := padder.Unpad(c.expected)
		if err != nil {
			t.Error(err)
			continue
		}
		assert.Equal(t, c.c, unpadded)
	}
}
