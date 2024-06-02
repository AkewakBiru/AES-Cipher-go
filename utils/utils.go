package utils

import (
	"encoding/binary"
)

func New2DSlice(row int, col int) [][]byte {
	matrix := make([][]byte, row)

	for i := 0; i < row; i++ {
		matrix[i] = make([]byte, col)
	}
	return matrix
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
