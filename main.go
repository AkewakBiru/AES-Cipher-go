package main

import (
	f "aes/aes"
	"fmt"
)

func main() {
	cipher, err := f.NewCipherWithMode(f.ECB, []byte("this is a test!!"))
	if err != nil {
		panic(err)
	}

	plain := []byte("thisisiasdkfkasf1")
	key := []byte("[hisisatest!)i+-")

	enc := cipher.Encrypt(plain, key)
	dec := cipher.Decrypt(enc, key)

	fmt.Println(plain)
	fmt.Println(string(enc))
	fmt.Println(string(dec))
}
