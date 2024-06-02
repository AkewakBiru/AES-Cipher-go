package aes

import (
	"encoding/binary"
	"sync"

	"github.com/AkewakBiru/AES-Cipher-go/utils"
)

type Block struct {
	idx  int
	data []uint32
}

type Iv struct {
	mu sync.RWMutex
	iv []byte
}

func worker(jobs chan Block, out chan Block, keys [][]uint32, iv *Iv) {
	for job := range jobs {
		var block []uint32
		for i := 0; i < 11; i++ {
			k := keys[i]
			if i == 0 {
				iv.mu.Lock()
				binary.BigEndian.PutUint64(iv.iv[(len(iv.iv)/2):], uint64(job.idx))
				block = Xor(k, utils.ByteArrayToUintArray(iv.iv))
				iv.mu.Unlock()
			} else if i == 10 {
				block = Xor(k, ShiftRows(SubByte(block)))
			} else {
				block = Xor(k, MixCols(ShiftRows(SubByte(block)), factor))
			}
		}
		res := Xor(block, job.data)
		out <- Block{data: res, idx: job.idx}
	}
}

// @param: in -> input to en/decrypt
// @param: key -> en/decryption key
// @param: secret -> combn of nonce + counter
// @param: isPlain -> is the input plaintext=true or ciphertext=false
func performCtr(in []byte, key []byte, secret []byte, isPlain bool) ([]byte, error) {
	keys := GenerateKeys(key)
	blocks, err := CreateBlocks(in)
	if err != nil {
		return nil, err
	}

	tmp := append(secret, "00000000"...)
	iv := Iv{iv: tmp, mu: sync.RWMutex{}}

	jobs := make(chan Block, len(blocks))
	output := make(chan Block, len(blocks))

	// for a block size of greater than 1024 being n, spawn n / 1024 routines
	if len(blocks) > 1024 {
		for i := 0; i < len(blocks)/1024; i++ {
			go worker(jobs, output, keys, &iv)
		}
	} else {
		go worker(jobs, output, keys, &iv)
	}

	for idx, block := range blocks {
		jobs <- Block{idx: idx, data: block}
	}
	close(jobs)

	res := make([][]uint32, len(blocks))
	for i := 0; i < len(blocks); i++ {
		d := <-output
		res[d.idx] = d.data
	}
	close(output)

	if !isPlain {
		padder := utils.NewPadder(16)
		unpadded, err := padder.Unpad(utils.UintToByteArray(res))
		if err != nil {
			return nil, err
		}
		return unpadded, nil
	}
	return utils.UintToByteArray(res), nil
}

// the (counter+nonce) is iv in this case
func performCtrBoring(in []byte, key []byte, iv []byte, isPlain bool) ([]byte, error) {
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

	if !isPlain {
		padder := utils.NewPadder(16)
		padded, err := padder.Unpad(utils.UintToByteArray(res))
		if err != nil {
			return nil, err
		}
		return padded, nil
	}
	return utils.UintToByteArray(res), nil
}
