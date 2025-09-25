package secutil

import (
	"context"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/nsuiteio/trial-mpc-key-export/utility/logutil"
)

func TestRsaEncryptionPublicKey_MarshalAndUnmarshal(t *testing.T) {
	ctx := logutil.Setup(context.Background(), t.Name())

	prvkey, err := GenerateEncryptionKeyPair(ctx, EncryptionKeyTypeRSA)
	if err != nil {
		t.Fatal(err)
	}
	pubkey := prvkey.PublicKey()

	bs := pubkey.MarshalToBytes()
	assert.Greater(t, len(bs), 0)
	t.Logf("public key: %d\n%s", len(bs), string(bs))

	actual, err := EncryptionPublicKeyFromBytes(bs)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, pubkey, actual)
}

func TestRsaEncryptionPrivateKey_MarshalAndUnmarshal(t *testing.T) {
	ctx := logutil.Setup(context.Background(), t.Name())

	prvkey, err := GenerateEncryptionKeyPair(ctx, EncryptionKeyTypeRSA)
	if err != nil {
		t.Fatal(err)
	}

	bs := prvkey.MarshalToBytes()
	assert.Greater(t, len(bs), 0)
	t.Logf("private key: %d\n%s", len(bs), string(bs))

	actual, err := EncryptionPrivateKeyFromBytes(bs)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, prvkey, actual)
}

func TestRsaEncryption_EncryptAndDecrypt(t *testing.T) {
	ctx := logutil.Setup(context.Background(), t.Name())

	prvkey, err := GenerateEncryptionKeyPair(ctx, EncryptionKeyTypeRSA)
	if err != nil {
		t.Fatal(err)
	}
	pubkey := prvkey.PublicKey()

	plaintext := genMsg(10240)
	ciphertext, err := pubkey.Encrypt(plaintext)
	if err != nil {
		t.Fatal(err)
	}
	assert.Greater(t, len(ciphertext), 0)
	assert.NotEqual(t, plaintext, ciphertext)

	actual, err := prvkey.Decrypt(ciphertext)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, plaintext, actual)
}

func TestSplitBytesToModuled(t *testing.T) {
	testCases := []struct {
		name         string
		originalSize int
		moduledSize  int
	}{
		{
			name:         "originalSize < moduledSize",
			originalSize: 1024,
			moduledSize:  1025,
		},
		{
			name:         "originalSize = moduledSize",
			originalSize: 1024,
			moduledSize:  1024,
		},
		{
			name:         "割り切れる",
			originalSize: 1024,
			moduledSize:  512,
		},
		{
			name:         "割り切れない",
			originalSize: 1024,
			moduledSize:  513,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				original := genMsg(tc.originalSize)
				var rebuilt []byte
				if err := splitBytesToModuled(
					original, tc.moduledSize,
					func(moduled []byte) error {
						rebuilt = append(rebuilt, moduled...)
						return nil
					},
				); err != nil {
					t.Fatal(err)
				}
				assert.Equal(t, original, rebuilt)
			},
		)
	}
}

func genMsg(length int) []byte {
	msg := make([]byte, length)
	if n, err := rand.Read(msg); err != nil {
		panic(err)
	} else if n != length {
		panic("short read")
	}
	return msg
}
