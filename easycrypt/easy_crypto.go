// Package easycrypt provides simple functions for encrypting and decrypting text using AES encryption.
package easycrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"unicode/utf8"
)

// generateKey generates a 32-byte key from a passphrase using SHA-256
func generateKey(passphrase string) []byte {
	hash := sha256.Sum256([]byte(passphrase))
	return hash[:]
}

// Encrypt encrypts the given plaintext using AES encryption with the provided passphrase.
//
// The passphrase is used to generate a 32-byte key using SHA-256.
// The plaintext is encrypted using AES in CFB mode and the result is encoded in base64.
//
// Example:
//
//	passphrase := "your-passphrase"
//	plaintext := "your-plaintext"
//	encryptedText, err := easycrypt.Encrypt(passphrase, plaintext)
//	if err != nil {
//	    fmt.Println("Encryption error:", err)
//	    return
//	}
//	fmt.Println("Encrypted Text:", encryptedText)
func Encrypt(passphrase, plaintext string) (string, error) {
	key := generateKey(passphrase)
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	ciphertext := make([]byte, aes.BlockSize+len(plaintext))
	iv := ciphertext[:aes.BlockSize]
	if _, err := io.ReadFull(rand.Reader, iv); err != nil {
		return "", err
	}

	stream := cipher.NewCFBEncrypter(block, iv)
	stream.XORKeyStream(ciphertext[aes.BlockSize:], []byte(plaintext))

	return base64.URLEncoding.EncodeToString(ciphertext), nil
}

// Decrypt decrypts the given base64 encoded ciphertext using AES encryption with the provided passphrase.
//
// The passphrase is used to generate a 32-byte key using SHA-256.
// The ciphertext is decoded from base64 and decrypted using AES in CFB mode.
//
// Example:
//
//	passphrase := "your-passphrase"
//	encryptedText := "your-encrypted-text"
//	decryptedText, err := easycrypt.Decrypt(passphrase, encryptedText)
//	if err != nil {
//	    fmt.Println("Decryption error:", err)
//	    return
//	}
//	fmt.Println("Decrypted Text:", decryptedText)
func Decrypt(passphrase, cryptoText string) (string, error) {
	key := generateKey(passphrase)
	ciphertext, err := base64.URLEncoding.DecodeString(cryptoText)
	if err != nil {
		return "", err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	if len(ciphertext) < aes.BlockSize {
		return "", fmt.Errorf("ciphertext too short")
	}

	iv := ciphertext[:aes.BlockSize]
	ciphertext = ciphertext[aes.BlockSize:]

	plaintext := make([]byte, len(ciphertext))
	stream := cipher.NewCFBDecrypter(block, iv)
	stream.XORKeyStream(plaintext, ciphertext)

	// check plaintext is length == 0
	if len(plaintext) == 0 {
		return "", fmt.Errorf("decryption failed")
	}

	// check plaintext can be decoded as UTF-8 string
	if !utf8.Valid(plaintext) {
		return "", fmt.Errorf("invalid UTF-8 sequence")
	}

	return string(plaintext), nil
}
