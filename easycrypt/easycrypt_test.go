package easycrypt

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptDecrypt(t *testing.T) {
	secretKey := "password"
	wrongSecretKey := "wrongpassword"
	plaintext := "wk18k"

	// Encrypt the plaintext
	t.Run("Encrypt", func(t *testing.T) {
		encrypted, err := Encrypt(secretKey, plaintext)
		assert.NoError(t, err, "Failed to encrypt")
		assert.NotEmpty(t, encrypted, "Encrypted text is empty")
	})

	// Decrypt the encrypted text
	t.Run("Decrypt", func(t *testing.T) {
		encrypted, err := Encrypt(secretKey, plaintext)
		assert.NoError(t, err, "Failed to encrypt")
		decrypted, err := Decrypt(secretKey, encrypted)
		assert.NoError(t, err, "Failed to decrypt")
		assert.Equal(t, plaintext, decrypted, "Decrypted text does not match the original plaintext")
	})

	// Decrypt the encrypted text with wrong secret key
	t.Run("DecryptWrongSecretKey", func(t *testing.T) {
		encrypted, err := Encrypt(secretKey, plaintext)
		assert.NoError(t, err, "Failed to encrypt")
		decrypted, err := Decrypt(wrongSecretKey, encrypted)
		assert.Error(t, err, "Decryption should fail")
		assert.Empty(t, decrypted, "Decrypted text should be empty")
	})
}
