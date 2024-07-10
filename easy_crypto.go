package easycrypt

import (
	"fmt"

	"github.com/watchakorn-18k/easycrypt/easycrypt"
)

// Encrypt encrypts the given plaintext using AES encryption with the provided passphrase
func Encrypt(key, plaintext string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	} else if plaintext == "" {
		return "", fmt.Errorf("plaintext cannot be empty")
	}
	return easycrypt.Encrypt(key, plaintext)
}

// Decrypt decrypts the given base64 encoded ciphertext using AES encryption with the provided passphrase
func Decrypt(key, cryptoText string) (string, error) {
	if key == "" {
		return "", fmt.Errorf("key cannot be empty")
	} else if cryptoText == "" {
		return "", fmt.Errorf("ciphertext cannot be empty")
	}
	return easycrypt.Decrypt(key, cryptoText)
}
