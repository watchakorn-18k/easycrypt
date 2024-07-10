# EasyCrypto

EasyCrypto is a Go package that provides straightforward encryption and decryption functionality using AES encryption with a passphrase.

## Project Origin

🤖 This project originated from ChatGPT, but I injected some creative ideas to bring this code to life. So, while I won't claim to be the creator, let's just have fun with it! 😎

## Installation

To use EasyCrypto, ensure you have Go installed and configured. Use the following command to install the package:

```sh
go get github.com/watchakorn-18k/easycrypto
```

## Usage

Import EasyCrypto in your Go code:

```go
import (
	"fmt"
	"log"

	"github.com/watchakorn-18k/easycrypto"
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

import (
	"fmt"
	"log"
	"github.com/watchakorn-18k/easycrypto"
)

func main() {
	secretKey := "password"
	text := "wk18k"
	// Encrypt the plaintext
	encrypted, err := easycrypto.Encrypt(secretKey, text)
	if err != nil {
		panic(err)
	}
	println("encrypted: ", encrypted)
	// Decrypt the encrypted text
	decrypted, err := easycrypto.Decrypt(secretKey, encrypted)
	if err != nil {
		panic(err)
	}
	println("decrypted: ", decrypted)
}
```

## License

This project is licensed under the MIT License - see the LICENSE file for details.
