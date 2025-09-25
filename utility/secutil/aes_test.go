package secutil

import (
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEncryptAndDecrypt(t *testing.T) {
	expected := make([]byte, 32)
	if n, err := rand.Read(expected); err != nil {
		t.Fatal(err)
	} else if n != len(expected) {
		t.Fatalf("unexpected length: %d", n)
	}
	ap := NewAESPassword("password")

	ciphertext, err := ap.Encrypt(expected)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := ap.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, expected, actual)
}
