// Package main demonstrates how to use the easycrypt package to encrypt and decrypt text.
package main

import "github.com/watchakorn-18k/easycrypt"

func main() {
	// Define the secret key and plaintext to be encrypted
	secretKey := "password"
	text := "wk18k"

	// Encrypt the plaintext
	// The Encrypt function takes a passphrase and plaintext string and returns the encrypted text encoded in base64.
	// If encryption fails, an error is returned.
	encrypted, err := easycrypt.Encrypt(secretKey, text)
	if err != nil {
		panic(err)
	}
	println("encrypted: ", encrypted)

	// Decrypt the encrypted text
	// The Decrypt function takes a passphrase and the base64 encoded encrypted text, and returns the decrypted plaintext.
	// If decryption fails, an error is returned.
	decrypted, err := easycrypt.Decrypt(secretKey, encrypted)
	if err != nil {
		panic(err)
	}
	println("decrypted: ", decrypted)
}
