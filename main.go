package main

import (
	f "aes/aes"
	"fmt"
)

func main() {
	cipher := f.Cipher

	plain := []byte("thisisiasdkfkasf1")
	key := []byte("[hisisatest!)i+-")

	enc := cipher.Encrypt(plain, key)
	dec := cipher.Decrypt(enc, key)

	fmt.Println(plain, "\n", dec)
}
