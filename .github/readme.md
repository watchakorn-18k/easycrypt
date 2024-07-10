

<div align="center">

# EasyCrypt

  <a href="https://goreportcard.com/report/github.com/watchakorn-18k/easycrypt">
    <img src="https://img.shields.io/badge/%F0%9F%93%9D%20goreport-A%2B-75C46B?style=flat-square">
  </a>


</div>

🔐 EasyCrypt is a Go package that provides straightforward encryption and decryption functionality using AES encryption with a passphrase.

## Project Origin

🤖 This project originated from ChatGPT, but I injected some creative ideas to bring this code to life. So, while I won't claim to be the creator, let's just have fun with it! 😎

## Installation

To use EasyCrypt, ensure you have Go installed and configured. Use the following command to install the package:

```sh
go get github.com/watchakorn-18k/easycrypt
```

## Usage

Import EasyCrypt in your Go code:

```go
import (
	"fmt"
	"log"

	"github.com/watchakorn-18k/easycrypt"
)
```

### Functions

#### generateKey

```go
func generateKey(passphrase string) []byte
```

Generates a 32-byte key from a passphrase using SHA-256.

#### Encrypt

```go
func Encrypt(passphrase, plaintext string) (string, error)
```

Encrypts the provided plaintext using AES encryption with the given passphrase. Returns the base64 URL encoded ciphertext and any encountered error.

#### Decrypt

```go
func Decrypt(passphrase, cryptoText string) (string, error)
```

Decrypts the base64 encoded ciphertext using AES encryption with the provided passphrase. Returns the plaintext and any encountered error.

### Example

```go
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
```

## License

This project is licensed under the Unlicense license
