package main

import (
	f "aes/aes"
	"fmt"
)

func main() {
	cipher, err := f.NewCipherWithMode(f.CTR, []byte("this is "))
	if err != nil {
		panic(err)
	}

	plain := []byte(`this is a test`)
	key := []byte("[hisisatest!)i+-")

	enc, _ := cipher.Encrypt(plain, key)
	dec, _ := cipher.Decrypt(enc, key)

	fmt.Println(plain)
	fmt.Println(string(enc))
	fmt.Println(string(dec))
}
