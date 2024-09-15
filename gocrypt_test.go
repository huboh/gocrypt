package gocrypt

import (
	"bytes"
	"testing"
)

var (
	secret    = []byte("0eb01db9dea18a2af1586c73a2bbdc0ecbc19f8efe92c9fdfb11d1f76c8704d9")
	blackHole []byte
)

func TestEncryptDecrypt(t *testing.T) {
	type testCase struct {
		name    string
		secret  []byte
		message []byte
	}

	testCases := []testCase{
		{
			name:    "empty message",
			secret:  secret,
			message: []byte(""),
		},
		{
			name:    "short message",
			secret:  []byte("mySecretKey123456"),
			message: []byte("short"),
		},
		{
			name:    "long message",
			secret:  secret,
			message: []byte("A really long message that spans multiple lines and has enough data to see if encryption still works properly"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encrypted, err := Encrypt(tc.message, tc.secret)
			if err != nil {
				t.Fatalf("error encrypting message: %v", err)
			}

			decrypted, err := Decrypt(encrypted, tc.secret)
			if err != nil {
				t.Fatalf("error decrypting message: %v", err)
			}

			if !bytes.Equal(tc.message, decrypted) {
				t.Errorf("decrypted message (%s) does not match original message (%s)", string(decrypted), string(tc.message))
			}
		})
	}
}

func TestInvalidDecryption(t *testing.T) {
	message := []byte("message")
	wrongSecret := []byte("wrong_secret")
	correctSecret := secret

	encrypted, err := Encrypt(message, correctSecret)
	if err != nil {
		t.Fatalf("error encrypting message: %v", err)
	}

	_, err = Decrypt(encrypted, wrongSecret)
	if err == nil {
		t.Fatal("expected an error when decrypting with the wrong secret, but got none")
	}
}

func TestEncryptSameValueDiffOutput(t *testing.T) {
	m := []byte("sensitive data")

	encrypted1, err := Encrypt(m, secret)
	if err != nil {
		t.Fatalf("error encrypting message: %v", err)
	}

	encrypted2, err := Encrypt(m, secret)
	if err != nil {
		t.Fatalf("error encrypting message: %v", err)
	}

	if bytes.Equal(encrypted1, encrypted2) {
		t.Error("encrypted outputs should be different due to random salts and IVs")
	}
}

func BenchmarkEncryption(b *testing.B) {
	m := []byte("Benchmarking encryption performance")

	for i := 0; i < b.N; i++ {
		encryption, err := Encrypt(m, secret)
		if err != nil {
			b.Fatalf("error encrypting message: %v", err)
		}

		blackHole = encryption
	}
}

func BenchmarkDecryption(b *testing.B) {
	m := []byte("Benchmarking decryption performance")
	encryption, err := Encrypt(m, secret)
	if err != nil {
		b.Fatalf("Error encrypting message: %v", err)
	}

	for i := 0; i < b.N; i++ {
		data, err := Decrypt(encryption, secret)
		if err != nil {
			b.Fatalf("error decrypting message: %v", err)
		}

		blackHole = data
	}
}
