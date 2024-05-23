package aes

import (
	"aes/utils"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
)

type Encryption interface {
	Encrypt([]byte, []byte) []byte
	Decrypt([]byte, []byte) []byte
}

type Mode int

const (
	ECB Mode = iota
	CBC
	CTR
)

type Cipher struct {
	mode Mode
	iv   []byte
}

var factor = [][]byte{
	{0x02, 0x03, 0x01, 0x01},
	{0x01, 0x02, 0x03, 0x01},
	{0x01, 0x01, 0x02, 0x03},
	{0x03, 0x01, 0x01, 0x02},
}

var invfactor = [][]byte{
	{0x0e, 0x0b, 0x0d, 0x09},
	{0x09, 0x0e, 0x0b, 0x0d},
	{0x0d, 0x09, 0x0e, 0x0b},
	{0x0b, 0x0d, 0x09, 0x0e},
}

// a new cipher with ECB mode is created when mode isn't specified
func NewCipher() *Cipher {
	return &Cipher{mode: ECB}
}

func NewCipherWithMode(mode Mode, iv []byte) (*Cipher, error) {
	if mode != ECB && len(iv) != 16 {
		return nil, errors.New("initialization vector must be 16 bytes long")
	}
	return &Cipher{mode: mode, iv: iv}, nil
}

// Checks if the length is not divisible by 16, and pads the last block
func CreateBlocks(input []byte) ([][]uint32, error) {
	padder := utils.NewPadder(16)
	padded, err := padder.Pad(input)
	if err != nil {
		log.Fatal(err)
	}

	block := make([][]uint32, len(padded)/16)

	j := 0
	for i := 0; i < len(padded); i += 16 {
		// block[j] = make([]uint32, 4)
		block[j] = utils.ByteArrayToUintArray(padded[i : i+16])
		// block[j][0] = binary.BigEndian.Uint32(padded[i : i+4])
		// block[j][1] = binary.BigEndian.Uint32(padded[i+4 : i+8])
		// block[j][2] = binary.BigEndian.Uint32(padded[i+8 : i+12])
		// block[j][3] = binary.BigEndian.Uint32(padded[i+12:])
		j++
	}

	for _, b := range block {
		if len(b) != 4 {
			return nil, errors.New("invalid block")
		}
	}
	return block, nil
}

func (cipher *Cipher) Encrypt(input []byte, key []byte) []byte {
	switch cipher.mode {
	case ECB:
		return encryptEcb(input, key)
	case CBC:
		return encryptCbc(input, key, cipher.iv)
	default:
		fmt.Fprint(os.Stderr, "Encryption Mode not found")
	}
	return nil
}

func (cipher *Cipher) Decrypt(input []byte, key []byte) []byte {
	switch cipher.mode {
	case ECB:
		return decryptEcb(input, key)
	case CBC:
		return decryptCbc(input, key, cipher.iv)
	default:
		fmt.Fprint(os.Stderr, "Decryption Mode not found")
	}
	return nil
}

func Xor(a []uint32, b []uint32) []uint32 {
	if len(a) != len(b) || len(a) != 4 {
		log.Fatal("operands for XOR of different size/ block not 16 bytes")
	}
	return []uint32{a[0] ^ b[0], a[1] ^ b[1], a[2] ^ b[2], a[3] ^ b[3]}
}

func SubByte(input []uint32) []uint32 {
	for i := 0; i < 4; i++ {
		input[i] = SubWord(input[i])
	}
	return input
}

func InvSubByte(input []uint32) []uint32 {
	for i := 0; i < 4; i++ {
		input[i] = InvSubWord(input[i])
	}
	return input
}

func MixCols(input []uint32, factor [][]byte) []uint32 {
	var part = utils.New2DSlice(4, 4)

	for i := 0; i < len(input); i++ {
		tmp := make([]byte, 4)
		binary.BigEndian.PutUint32(tmp, input[i])
		part[i] = tmp
	}

	r := make([]uint32, 4)
	var g utils.Gfield
	for i := 0; i < 4; i++ {
		for j := 0; j < 4; j++ {
			r[i] |= uint32(g.AccMul(utils.Gfield(factor[j][0]), utils.Gfield(part[i][0]))^
				g.AccMul(utils.Gfield(factor[j][1]), utils.Gfield(part[i][1]))^
				g.AccMul(utils.Gfield(factor[j][2]), utils.Gfield(part[i][2]))^
				g.AccMul(utils.Gfield(factor[j][3]), utils.Gfield(part[i][3]))) << (24 - 8*j)
		}
	}
	return r
}

func ShiftRows(arr []uint32) []uint32 {
	res := make([]uint32, 4)

	for i := 0; i < 4; i++ {
		res[i] = arr[i]&0xff000000 |
			arr[(i+1)%4]&0xff0000 |
			arr[(i+2)%4]&0xff00 |
			arr[(i+3)%4]&0xff
	}
	return res
}

func InvShiftRows(arr []uint32) []uint32 {
	res := make([]uint32, 4)

	for i := 0; i < 4; i++ {
		res[i] = arr[i]&0xff000000 |
			arr[(i+3)%4]&0xff0000 |
			arr[(i+2)%4]&0xff00 |
			arr[(i+1)%4]&0xff
	}
	return res
}
