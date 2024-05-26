package aes

import (
	"aes/utils"
)

func encryptCbc(in []byte, key []byte, iv []byte) ([]byte, error) {
	keys := GenerateKeys(key)

	blocks, err := CreateBlocks(in)
	if err != nil {
		return nil, err
	}

	var res = make([][]uint32, len(blocks))
	for j, v := range blocks {
		res[j] = make([]uint32, 4)
		var block []uint32
		if j == 0 {
			block = Xor(utils.ByteArrayToUintArray(iv), v)
		} else {
			block = Xor(v, res[j-1])
		}
		for i := 0; i < 11; i++ {
			k := keys[i]
			if i == 0 {
				block = Xor(k, block)
			} else if i == 10 {
				block = Xor(k, ShiftRows(SubByte(block)))
			} else {
				block = Xor(k, MixCols(ShiftRows(SubByte(block)), factor))
			}
		}
		res[j] = block
	}

	return utils.UintToByteArray(res), nil
}

func decryptCbc(input []byte, key []byte, iv []byte) ([]byte, error) {
	keys := GenerateKeys(key)

	blocks, err := CreateBlocks(input)
	if err != nil {
		return nil, err
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
		if j == 0 {
			res[j] = Xor(block, utils.ByteArrayToUintArray(iv))
		} else {
			res[j] = Xor(block, blocks[j-1])
		}
	}

	padder := utils.NewPadder(16)
	padded, err := padder.Unpad(utils.UintToByteArray(res))
	if err != nil {
		return nil, err
	}
	return padded, nil
}
