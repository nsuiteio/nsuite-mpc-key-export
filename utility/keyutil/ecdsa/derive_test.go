package ecdsa

import (
	"context"
	"encoding/hex"
	"testing"

	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/stretchr/testify/assert"

	"github.com/nsuiteio/nst-mpc-key-export/utility/keyutil"
)

func TestDeriveKey_DerivePrvKey(t *testing.T) {
	ctx := context.Background()

	const masterPrivKeyBase58 = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi"

	masterPrvKey, err := hdkeychain.NewKeyFromString(masterPrivKeyBase58)
	if err != nil {
		t.Fatal(err)
	}
	rootPrvKey, err := masterPrvKey.ECPrivKey()
	if err != nil {
		t.Fatal(err)
	}

	chainCode := new(keyutil.ChainCode).SetBytes(masterPrvKey.ChainCode())

	testCases := []struct {
		path           string
		expectedPrvKey string
	}{
		{
			path:           "m/",
			expectedPrvKey: masterPrivKeyBase58,
		},
		{
			path:           "m/0",
			expectedPrvKey: "xprv9uHRZZhbkedL37eZEnyrNsQPFZYRAvjy5rt6M1nbEkLSo378x1CQQLo2xxBvREwiK6kqf7GRNvsNEchwibzXaV6i5GcsgyjBeRguXhKsi4R",
		},
		{
			path:           "m/0/1",
			expectedPrvKey: "xprv9ww7sMFLzJMzy7bV1qs7nGBxgKYrgcm3HcJvGb4yvNhT9vxXC7eX7WVULzCfxucFEn2TsVvJw25hH9d4mchywguGQCZvRgsiRaTY1HCqN8G",
		},
		{
			path:           "m/0/1/2",
			expectedPrvKey: "xprv9xrdP7iD2L1YZCgR9AecDgpDMZSTzP5KCfUykGXgjBxLgp1VFHsEeL3conzGAkbc1MigG1o8YqmfEA2jtkPdf4vwMaGJC2YSDbBTPAjfRUi",
		},
		{
			path:           "m/0/1/2/2",
			expectedPrvKey: "xprvA2J8Hq4eiP7xCEBP7gzRJGJnd9CHTkEU6eTNMrZ6YR7H5boik8daFtDZxmJDfdMSKHwroCfAfsBKWWidRfBQjpegy6kzXSkQGGoMdWKz5Xh",
		},
		{
			path:           "m/0/1/2/2/1000000000",
			expectedPrvKey: "xprvA3XhazxncJqJsQcG85Gg61qwPQKiobAnWjuPpjKhExprZjfse6nErRwTMwGe6uGWXPSykZSTiYb2TXAm7Qhwj8KgRd2XaD21Styu6h6AwFz",
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.path, func(t *testing.T) {
				hdpath, err := new(keyutil.DerivePath).Parse(tc.path)
				if err != nil {
					t.Fatal(err)
				}
				deriveKey := new(DeriveKey)
				deriveKey.Init(chainCode[:], hdpath...)
				prvKey, err := deriveKey.DerivePrvKey(ctx, rootPrvKey)
				if err != nil {
					t.Fatal(err)
				}
				childKey, err := hdkeychain.NewKeyFromString(tc.expectedPrvKey)
				if err != nil {
					t.Fatal(err)
				}
				expectedPrvKey, err := childKey.ECPrivKey()
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(
					t,
					hex.EncodeToString(expectedPrvKey.Serialize()),
					hex.EncodeToString(prvKey.Serialize()),
				)
			},
		)
	}
}

func TestDeriveKey_DerivePubKey(t *testing.T) {
	ctx := context.Background()

	const masterPubKeyBase58 = "xpub661MyMwAqRbcFtXgS5sYJABqqG9YLmC4Q1Rdap9gSE8NqtwybGhePY2gZ29ESFjqJoCu1Rupje8YtGqsefD265TMg7usUDFdp6W1EGMcet8"

	masterPubKey, err := hdkeychain.NewKeyFromString(masterPubKeyBase58)
	if err != nil {
		t.Fatal(err)
	}
	rootPubKey, err := masterPubKey.ECPubKey()
	if err != nil {
		t.Fatal(err)
	}

	chainCode := new(keyutil.ChainCode).SetBytes(masterPubKey.ChainCode())

	testCases := []struct {
		path           string
		expectedPubKey string
	}{
		{
			path:           "m/",
			expectedPubKey: masterPubKeyBase58,
		}, {
			path:           "m/0",
			expectedPubKey: "xpub68Gmy5EVb2BdFbj2LpWrk1M7obNuaPTpT5oh9QCCo5sRfqSHVYWex97WpDZzszdzHzxXDAzPLVSwybe4uPYkSk4G3gnrPqqkV9RyNzAcNJ1",
		},
		{
			path:           "m/0/1",
			expectedPubKey: "xpub6AvUGrnEpfvJBbfx7sQ89Q8hEMPM65UteqEX4yUbUiES2jHfjexmfJoxCGSwFMZiPBaKQT1RiKWrKfuDV4vpgVs4Xn8PpPTR2i79rwHd4Zr",
		},
		{
			path:           "m/0/1/2",
			expectedPubKey: "xpub6BqyndF6rhZqmgktFCBcapkwubGxPqoAZtQaYewJHXVKZcLdnqBVC8N6f6FSHWUghjuTLeubWyQWfJdk2G3tGgvgj3qngo4vLTnnSjAZckv",
		},
		{
			path:           "m/0/1/2/2",
			expectedPubKey: "xpub6FHUhLbYYkgFQiFrDiXRfQFXBB2msCxKTsNyAExi6keFxQ8sHfwpogY3p3s1ePSpUqLNYks5T6a3JqpCGszt4kxbyq7tUoFP5c8KWyiDtPp",
		},
		{
			path:           "m/0/1/2/2/1000000000",
			expectedPubKey: "xpub6GX3zWVgSgPc5tgjE6ogT9nfwSADD3tdsxpzd7jJoJMqSY12Be6VQEFwDCp6wAQoZsH2iq5nNocHEaVDxBcobPrkZCjYW3QUmoDYzMFBDu9",
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.path, func(t *testing.T) {
				hdpath, err := new(keyutil.DerivePath).Parse(tc.path)
				if err != nil {
					t.Fatal(err)
				}
				deriveKey := new(DeriveKey)
				deriveKey.Init(chainCode[:], hdpath...)
				pubKey, err := deriveKey.DerivePubKey(ctx, rootPubKey)
				if err != nil {
					t.Fatal(err)
				}
				childKey, err := hdkeychain.NewKeyFromString(tc.expectedPubKey)
				if err != nil {
					t.Fatal(err)
				}
				expectedPubKey, err := childKey.ECPubKey()
				if err != nil {
					t.Fatal(err)
				}
				assert.Equal(
					t,
					hex.EncodeToString(expectedPubKey.SerializeCompressed()),
					hex.EncodeToString(pubKey.SerializeCompressed()),
				)
			},
		)
	}
}
