package aes

import (
	"aes/utils"
)

// the (counter+nonce) is iv in this case
// TODO: Think of a way to parallelize this
func encryptCtr(in []byte, key []byte, iv []byte) ([]byte, error) {
	keys := GenerateKeys(key)
	blocks, err := CreateBlocks(in)
	if err != nil {
		return nil, err
	}

	var res = make([][]uint32, len(blocks))
	iv = append(iv, "00000000"...)
	idx := len(iv) - 1
	for j, v := range blocks {
		res[j] = make([]uint32, 4)
		var block []uint32
		for i := 0; i < 11; i++ {
			k := keys[i]
			if i == 0 {
				block = Xor(k, utils.ByteArrayToUintArray(iv))
			} else if i == 10 {
				block = Xor(k, ShiftRows(SubByte(block)))
			} else {
				block = Xor(k, MixCols(ShiftRows(SubByte(block)), factor))
			}
		}
		if idx >= 255 {
			idx--
		}
		iv[idx]++
		res[j] = Xor(block, v)
	}

	return utils.UintToByteArray(res), nil
}

func decryptCtr(input []byte, key []byte, iv []byte) ([]byte, error) {
	keys := GenerateKeys(key)

	blocks, err := CreateBlocks(input)
	if err != nil {
		return nil, err
	}

	var res = make([][]uint32, len(blocks))
	iv = append(iv, "00000000"...)
	idx := len(iv) - 1
	for j, v := range blocks {
		res[j] = make([]uint32, 4)
		var block []uint32
		for i := 0; i < 11; i++ {
			k := keys[i]
			if i == 0 {
				block = Xor(k, utils.ByteArrayToUintArray(iv))
			} else if i == 10 {
				block = Xor(k, ShiftRows(SubByte(block)))
			} else {
				block = Xor(k, MixCols(ShiftRows(SubByte(block)), factor))
			}
		}
		if idx >= 255 {
			idx--
		}
		iv[idx]++
		res[j] = Xor(block, v)
	}

	padder := utils.NewPadder(16)
	padded, err := padder.Unpad(utils.UintToByteArray(res))
	if err != nil {
		return nil, err
	}
	return padded, nil
}
