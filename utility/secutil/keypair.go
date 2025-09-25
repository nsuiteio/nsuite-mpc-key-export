package secutil

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"io"

	"github.com/nsuiteio/trial-mpc-key-export/utility/errutil"
)

type (
	EncryptionKeyPairType int

	EncryptionPublicKey interface {
		MarshalToBytes() []byte
		UnmarshalFromBytes([]byte) error

		Encrypt(plaintext []byte) ([]byte, error)
	}
	EncryptionPrivateKey interface {
		MarshalToBytes() []byte
		UnmarshalFromBytes([]byte) error

		PublicKey() EncryptionPublicKey
		Decrypt(ciphertext []byte) ([]byte, error)
	}

	rsaEncryptionPublicKey struct {
		pubkey *rsa.PublicKey
	}

	rsaEncryptionPrivateKey struct {
		prvkey *rsa.PrivateKey
	}
)

const (
	EncryptionKeyPairTypeRSA EncryptionKeyPairType = iota
)

func GenerateEncryptionKeyPair(
	ctx context.Context,
	keyType EncryptionKeyPairType,
) (EncryptionPrivateKey, error) {
	switch keyType {
	case EncryptionKeyPairTypeRSA:
		return generateRSAEncryptionKeyPair(ctx)
	}
	err := fmt.Errorf("unsupported encryption key type: %d", keyType)
	return nil, errutil.Wrap(err)
}

func generateRSAEncryptionKeyPair(
	_ context.Context,
) (EncryptionPrivateKey, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	prv := &rsaEncryptionPrivateKey{
		prvkey: key,
	}
	return prv, nil
}

func EncryptionPublicKeyFromBytes(
	src []byte,
) (EncryptionPublicKey, error) {
	if len(src) < 2 {
		err := fmt.Errorf("invalid public key bytes")
		return nil, errutil.Wrap(err)
	}
	keyType := EncryptionKeyPairType(src[0])
	switch keyType {
	case EncryptionKeyPairTypeRSA:
		pub := new(rsaEncryptionPublicKey)
		if err := pub.UnmarshalFromBytes(src); err != nil {
			return nil, errutil.Wrap(err)
		}
		return pub, nil
	}
	err := fmt.Errorf("unsupported encryption key type: %d", keyType)
	return nil, errutil.Wrap(err)
}

func EncryptionPrivateKeyFromBytes(
	src []byte,
) (EncryptionPrivateKey, error) {
	if len(src) < 2 {
		err := fmt.Errorf("invalid private key bytes")
		return nil, errutil.Wrap(err)
	}
	keyType := EncryptionKeyPairType(src[0])
	switch keyType {
	case EncryptionKeyPairTypeRSA:
		prv := new(rsaEncryptionPrivateKey)
		if err := prv.UnmarshalFromBytes(src); err != nil {
			return nil, errutil.Wrap(err)
		}
		return prv, nil
	}
	err := fmt.Errorf("unsupported encryption key type: %d", keyType)
	return nil, errutil.Wrap(err)
}

func (pub *rsaEncryptionPublicKey) Encrypt(
	plaintext []byte,
) ([]byte, error) {
	hash := sha256.New()
	mSize := pub.pubkey.Size() - 2*hash.Size() - 2
	var result []byte
	if err := splitBytesToModuled(
		plaintext,
		mSize,
		func(plain []byte) error {
			bs, err := rsa.EncryptOAEP(
				hash,
				rand.Reader,
				pub.pubkey,
				plain,
				nil,
			)
			if err != nil {
				return errutil.Wrap(err)
			}
			result = append(result, bs...)
			return nil
		},
	); err != nil {
		return nil, errutil.Wrap(err)
	}
	return result, nil
}

func (pub *rsaEncryptionPublicKey) MarshalToBytes() []byte {
	pubBs := x509.MarshalPKCS1PublicKey(pub.pubkey)
	bs := make([]byte, 0, len(pubBs)+1)
	bs = append(bs, byte(EncryptionKeyPairTypeRSA))
	bs = append(bs, pubBs...)
	return bs
}

func (pub *rsaEncryptionPublicKey) UnmarshalFromBytes(
	src []byte,
) error {
	if len(src) < 2 {
		err := fmt.Errorf("invalid public key bytes")
		return errutil.Wrap(err)
	}
	keyType := EncryptionKeyPairType(src[0])
	if keyType != EncryptionKeyPairTypeRSA {
		err := fmt.Errorf("invalid public key type: %d", keyType)
		return errutil.Wrap(err)
	}
	pubkey, err := x509.ParsePKCS1PublicKey(src[1:])
	if err != nil {
		return errutil.Wrap(err)
	}
	pub.pubkey = pubkey
	return nil
}

func (prv *rsaEncryptionPrivateKey) Decrypt(
	ciphertext []byte,
) ([]byte, error) {
	hash := sha256.New()
	var result []byte
	if err := splitBytesToModuled(
		ciphertext,
		prv.prvkey.Size(),
		func(cypher []byte) error {
			bs, err := rsa.DecryptOAEP(
				hash,
				rand.Reader,
				prv.prvkey,
				cypher,
				nil,
			)
			if err != nil {
				return errutil.Wrap(err)
			}
			result = append(result, bs...)
			return nil
		},
	); err != nil {
		return nil, errutil.Wrap(err)
	}
	return result, nil
}

func (prv *rsaEncryptionPrivateKey) PublicKey() EncryptionPublicKey {
	pub := &rsaEncryptionPublicKey{
		pubkey: &prv.prvkey.PublicKey,
	}
	return pub
}

func (prv *rsaEncryptionPrivateKey) MarshalToBytes() []byte {
	prvBs := x509.MarshalPKCS1PrivateKey(prv.prvkey)
	bs := make([]byte, 0, len(prvBs)+1)
	bs = append(bs, byte(EncryptionKeyPairTypeRSA))
	bs = append(bs, prvBs...)
	return bs
}

func (prv *rsaEncryptionPrivateKey) UnmarshalFromBytes(
	src []byte,
) error {
	if len(src) < 2 {
		err := fmt.Errorf("invalid private key bytes")
		return errutil.Wrap(err)
	}
	keyType := EncryptionKeyPairType(src[0])
	if keyType != EncryptionKeyPairTypeRSA {
		err := fmt.Errorf("invalid private key type: %d", keyType)
		return errutil.Wrap(err)
	}
	prvkey, err := x509.ParsePKCS1PrivateKey(src[1:])
	if err != nil {
		return errutil.Wrap(err)
	}
	prv.prvkey = prvkey
	return nil
}

func splitBytesToModuled(
	src []byte,
	moduledSize int,
	proc func([]byte) error,
) error {
	source := bytes.NewReader(src)
	buf := make([]byte, moduledSize)
	for {
		n, err := source.Read(buf)
		if err != nil {
			if err == io.EOF {
				break
			}
			return errutil.Wrap(err)
		}
		part := buf
		if n < moduledSize {
			part = buf[:n]
		}
		if err := proc(part); err != nil {
			return errutil.Wrap(err)
		}
	}
	return nil
}
