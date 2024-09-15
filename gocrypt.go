// Package gocrypt provides utility functions for encrypting and decrypting data
// using AES-256-GCM with a cryptographically derived key from a given secret and a randomly generated salt.
package gocrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"

	"golang.org/x/crypto/scrypt"
)

const (
	ivSize      = 12      // Initialization Vector size in bytes for AES-GCM (96 bits)
	keySize     = 32      // AES key length in bytes. For AES-256, key length is 32 bytes (256 bits).
	saltSize    = 16      // Salt size in bytes
	authTagSize = 16      // Authentication tag size in bytes (128 bits)
	n           = 1 << 14 // Number of iterations for cryptographic key derivation.
	r           = 8       // Block size for scrypt
	p           = 1       // Parallelization factor for scrypt
)

// Encrypt encrypts the message using AES-256-GCM, deriving the encryption key
// cryptographically from the provided secret and a randomly generated salt.
//
// The resulting output is a concatenation of the components in a single byte slice:
//
//	[IV... || salt... || cipherText...]
//
// Ensuring all necessary components are bundled together for decryption
func Encrypt(message []byte, secret []byte) ([]byte, error) {
	iv, err := generateIV()
	if err != nil {
		return nil, err
	}

	salt, err := generateSalt()
	if err != nil {
		return nil, err
	}

	key, err := deriveKey(secret, salt)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES block: %w", err)
	}

	gcmBlock, err := cipher.NewGCMWithTagSize(block, authTagSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM block: %w", err)
	}

	cipherTxt := gcmBlock.Seal(nil, iv, message, nil)

	return append(iv, append(salt, cipherTxt...)...), nil
}

// Decrypt decrypts the encryption using AES-256-GCM, the decryption key is derived
// cryptographically from the secret and the salt extracted as a component from the encryption.
//
// The `encryption` byte slice is expected to contain the IV, salt, and cipherText, concatenated as follows:
//
//	[IV... || salt... || cipherText...]
func Decrypt(encryption []byte, secret []byte) ([]byte, error) {
	var (
		iv        = encryption[:ivSize]
		salt      = encryption[ivSize:(ivSize + saltSize)]
		cipherTxt = encryption[(ivSize + saltSize):]
	)

	key, err := deriveKey(secret, salt)
	if err != nil {
		return nil, fmt.Errorf("could not derive key: %w", err)
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES block: %w", err)
	}

	gcmBlock, err := cipher.NewGCMWithTagSize(block, authTagSize)
	if err != nil {
		return nil, fmt.Errorf("failed to create AES-GCM block: %w", err)
	}

	return gcmBlock.Open(
		nil,
		iv,
		cipherTxt,
		nil,
	)
}

func randomBytes(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		return nil, err
	}

	return b, nil
}

func generateIV() ([]byte, error) {
	return randomBytes(ivSize)
}

func generateSalt() ([]byte, error) {
	return randomBytes(saltSize)
}

// deriveKey cryptographically derives a key from the secret and salt.
func deriveKey(secret []byte, salt []byte) ([]byte, error) {
	k, err := scrypt.Key(secret, salt, n, r, p, keySize)
	if err != nil {
		return nil, fmt.Errorf("could not derive key: %w", err)
	}

	return k, nil
}
