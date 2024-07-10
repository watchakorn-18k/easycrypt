package main

import "github.com/watchakorn-18k/easycrypt"

func main() {
	secretKey := "password"
	text := "wk18k"
	// Encrypt the plaintext
	encrypted, err := easycrypt.Encrypt(secretKey, text)
	if err != nil {
		panic(err)
	}
	println("encrypted: ", encrypted)

	// Decrypt the encrypted text
	decrypted, err := easycrypt.Decrypt(secretKey, encrypted)
	if err != nil {
		panic(err)
	}
	println("decrypted: ", decrypted)
}
