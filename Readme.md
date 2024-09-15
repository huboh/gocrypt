# gocrypt

`gocrypt` is a simple Go package that provides utility functions to securely encrypt and decrypt data using AES-256-GCM (an authenticated encryption mode with associated data). It derives keys of 256 bits(32 bytes) size cryptographically using the `scrypt` key derivation function from a user-provided secret and random salt.

## Installation

To install the `gocrypt` package, run:

```bash
go get github.com/huboh/gocrypt
```

## Usage

### Encrypting Data

You can encrypt a message by calling the Encrypt function. This function takes a message and a secret as input and returns the concatenation of the encryption components `[IV... || salt... || cipherText...]`.

```go
package main

import (
  "fmt"
  "log"

  "github.com/huboh/gocrypt"
)

func main() {
  secret := []byte("secret")
  message := []byte("confidential!!!")

  encrypted, err := gocrypt.Encrypt(message, secret)
  if err != nil {
    log.Fatalf("encryption failed: %v", err)
  }

  fmt.Printf("encrypted message: %x\n", encrypted)
}
```

### Decrypting Data

```go
package main

import (
  "fmt"
  "log"

  "github.com/huboh/gocrypt"
)

func main() {
  secret := []byte("secret")
  encrypted := []byte("/* encrypted data here */")

  decrypted, err := gocrypt.Decrypt(encrypted, secret)
  if err != nil {
    log.Fatalf("decryption failed: %v", err)
  }

  fmt.Printf("decrypted message: %s\n", string(decrypted))
}
```

## License

This package is provided under MIT license.
