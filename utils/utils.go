package utils

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"math"
)

func checkPrime(num uint32) (uint32, bool) {
	if num <= 2 {
		return num, num == 2
	}

	lim := uint32(math.Ceil(math.Sqrt(float64(num))))
	for i := uint32(2); i <= lim; i++ {
		if num%i == 0 {
			return 0, false
		}
	}
	return num, true
}

// 63 09 cd 60
// ca 53 60 70
// b7 d0 e0 e1
// 04 51 e7 8c

// 63cab704 0953d051 cd60e0e7 ba70e18c
// 6353e08c 0960e104 cd70b751 bacad0e7

// checks if a number is a prime number or power of a prime number.
//
// returns the base, exponent and a boolean showing if it is a prime power or not
func IsPrimePower(num uint32) (uint32, uint32, bool) {
	if _, ok := checkPrime(num); ok {
		return num, 1, true
	}

	var sieve []uint32
	lim := uint32(math.Ceil(math.Sqrt(float64(num))))

	for i := uint32(2); i <= lim; i++ {
		res, isPrime := checkPrime(i)
		if isPrime {
			sieve = append(sieve, res)
		}
	}

	for _, i := range sieve {
		tmp := num
		ct := uint32(0)
		for tmp%i == 0 {
			if tmp == i {
				return i, ct + 1, true
			}
			tmp = tmp / i
			ct++
		}
	}
	return 0, 0, false
}

func New2DSlice(row int, col int) [][]byte {
	matrix := make([][]byte, row)

	for i := 0; i < row; i++ {
		matrix[i] = make([]byte, col)
	}
	return matrix
}

func EncodeToBytes(input string) []byte {
	encoded := make([]byte, hex.EncodedLen(len(input)))

	hex.Encode(encoded, []byte(input))
	return encoded
}

func GetHex(input []byte) string {
	return hex.EncodeToString(input)
}

func printBlock(block []uint32) []byte {
	res := make([][]byte, 4)
	for i := 0; i < len(block); i++ {
		tmp := make([]byte, 4)
		binary.BigEndian.PutUint32(tmp, block[i])
		res[i] = tmp
	}
	return bytes.Join(res, []byte(""))
}

func UintToByteArray(input [][]uint32) []byte {
	bytes := make([]byte, len(input)*16)

	for i := 0; i < len(input); i++ {
		for j := 0; j < len(input[i]); j++ {
			binary.BigEndian.PutUint32(bytes[16*i+4*j:], input[i][j])
		}
	}
	return bytes
}

func ByteArrayToUintArray(input []byte) []uint32 {
	res := make([]uint32, 4)
	res[0] = binary.BigEndian.Uint32(input[:4])
	res[1] = binary.BigEndian.Uint32(input[4:8])
	res[2] = binary.BigEndian.Uint32(input[8:12])
	res[3] = binary.BigEndian.Uint32(input[12:])
	return res
}
