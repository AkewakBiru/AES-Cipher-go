package aes

import (
	"aes/utils"
	"log"
)

func encryptEcb(in []byte, key []byte) []byte {
	keys := GenerateKeys(key)

	blocks, err := CreateBlocks(in)
	if err != nil {
		log.Fatal(err)
	}

	var res = make([][]uint32, len(blocks))
	for j, v := range blocks {
		res[j] = make([]uint32, 4)
		var block []uint32
		for i := 0; i < 11; i++ {
			k := keys[i]
			if i == 0 {
				block = Xor(k, v)
			} else if i == 10 {
				block = Xor(k, ShiftRows(SubByte(block)))
			} else {
				block = Xor(k, MixCols(ShiftRows(SubByte(block)), factor))
			}
		}
		res[j] = block
	}

	return utils.UintToByteArray(res)
}

func decryptEcb(input []byte, key []byte) []byte {
	keys := GenerateKeys(key)

	blocks, err := CreateBlocks(input)
	if err != nil {
		log.Fatal(err)
	}

	var res = make([][]uint32, len(blocks))
	for j, v := range blocks {
		res[j] = make([]uint32, 4)
		var block []uint32

		for i := 10; i >= 0; i-- {
			k := keys[i]
			if i == 10 {
				block = Xor(k, v)
			} else if i == 0 {
				block = Xor(k, InvSubByte(InvShiftRows(block)))
			} else {
				block = MixCols(Xor(k, InvSubByte(InvShiftRows(block))), invfactor)
			}
		}
		res[j] = block
	}

	padder := utils.NewPadder(16)
	padded, err := padder.Unpad(utils.UintToByteArray(res))
	if err != nil {
		log.Fatal(err)
	}
	return padded
}
