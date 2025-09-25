package secutil

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"fmt"
	"io"

	"golang.org/x/crypto/argon2"

	"github.com/nsuiteio/trial-mpc-key-export/utility/errutil"
)

const (
	aesKeySize  = 32 // AES-256
	aesSaltSize = 16
)

type (
	EncryptionKey interface {
		Encrypt(plaintext []byte) ([]byte, error)
		Decrypt(ciphertext []byte) ([]byte, error)
	}

	aesPassword string
	aesKey      []byte
)

func NewAESPassword(password string) (EncryptionKey, error) {
	if len(password) == 0 {
		err := fmt.Errorf("password is empty")
		return nil, errutil.Wrap(err)
	}
	ap := aesPassword(password)
	return &ap, nil
}

func NewAESKey(key []byte) (EncryptionKey, error) {
	if len(key) != aesKeySize {
		err := fmt.Errorf("invalid key size: %v", len(key))
		return nil, errutil.Wrap(err)
	}
	ak := aesKey(key)
	return &ak, nil
}

func (ap *aesPassword) deriveKey(salt []byte) (EncryptionKey, error) {
	if ap == nil {
		err := fmt.Errorf("password is nil")
		return nil, errutil.Wrap(err)
	}
	password := []byte(*ap)
	key := argon2.IDKey(password, salt, 4, 64*1024, 2, aesKeySize)
	return NewAESKey(key)
}

func (ap *aesPassword) Encrypt(plaintext []byte) ([]byte, error) {
	if ap == nil {
		err := fmt.Errorf("password is nil")
		return nil, errutil.Wrap(err)
	}

	salt := make([]byte, aesSaltSize)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return nil, err
	}

	key, err := ap.deriveKey(salt)
	if err != nil {
		return nil, errutil.Wrap(err)
	}

	encrypted, err := key.Encrypt(plaintext)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	ciphertext := make([]byte, aesSaltSize+len(encrypted))
	copy(ciphertext[:aesSaltSize], salt)
	copy(ciphertext[aesSaltSize:], encrypted)

	return ciphertext, nil
}

func (ap *aesPassword) Decrypt(ciphertext []byte) (
	[]byte,
	error,
) {
	if ap == nil {
		err := fmt.Errorf("password is nil")
		return nil, errutil.Wrap(err)
	}

	if len(ciphertext) < aesSaltSize {
		err := fmt.Errorf("ciphertext too short")
		return nil, errutil.Wrap(err)
	}

	salt := ciphertext[:aesSaltSize]
	encrypted := ciphertext[aesSaltSize:]

	key, err := ap.deriveKey(salt)
	if err != nil {
		return nil, errutil.Wrap(err)
	}

	return key.Decrypt(encrypted)
}

func (ak *aesKey) Encrypt(
	plain []byte,
) ([]byte, error) {
	if ak == nil {
		err := fmt.Errorf("key is nil")
		return nil, errutil.Wrap(err)
	}
	key := []byte(*ak)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, errutil.Wrap(err)
	}
	ciphertext := gcm.Seal(nonce, nonce, plain, nil)
	return ciphertext, nil
}

func (ak *aesKey) Decrypt(
	encrypted []byte,
) ([]byte, error) {
	if ak == nil {
		err := fmt.Errorf("key is nil")
		return nil, errutil.Wrap(err)
	}
	key := []byte(*ak)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		err := fmt.Errorf("ciphertext too short")
		return nil, errutil.Wrap(err)
	}
	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	return plain, nil
}
