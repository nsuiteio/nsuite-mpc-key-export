package derive

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// BIP32 公式テストベクタ1（chaincode・秘密鍵は xprv を base58 デコードした生値）。
// nst-tss-lib ecdsautil/derivation_test.go・nst-core derive_ecdsa_test.go と同一の
// 外部ベクタで、3リポジトリの導出実装が一致することを保証する。
const (
	bip32RootChainCodeHex = "873dff81c02f525623fd1fe5167eac3a55a049de3d314bb42ee227ffed37d508"
	bip32RootPrvHex       = "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	bs, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return bs
}

// ECDSA 子秘密鍵導出が BIP32 公式ベクタと一致すること。
func TestDeriveECDSAPrivateKey_BIP32Vectors(t *testing.T) {
	rootPrv := secp256k1.PrivKeyFromBytes(mustHex(t, bip32RootPrvHex))

	cases := []struct {
		path        []uint32
		expectedPrv string
	}{
		{
			[]uint32{0},
			"4e2cdcf2f14e802810e878cf9e6411fc4e712edf19a06bcfcc5d5572e489a3b7",
		},
		{
			[]uint32{0, 1},
			"472e3788b980839678da16b6a285113a1edb579114b62f9efe628335049fca83",
		},
		{
			[]uint32{0, 1, 2},
			"ce619e3b282d0cd38a0abde918cc0ba03a8aa6991a76c6fbcc820052b416a61d",
		},
		{
			[]uint32{0, 1, 2, 2},
			"0eefe0c18fdb28656d98a422ef7bf7e9e1ad55b4c4646cdd75b3b73d3923564a",
		},
		{
			[]uint32{0, 1, 2, 2, 1000000000},
			"c1ea7b9eb90adb5f483e4143b6e9194c6a195268c96aab4a644fa0a9c454ff4b",
		},
	}
	for _, tc := range cases {
		key := NewKey(mustHex(t, bip32RootChainCodeHex), tc.path...)
		child, err := key.DeriveECDSAPrivateKey(rootPrv)
		if err != nil {
			t.Fatalf("path %v: %v", tc.path, err)
		}
		got := hex.EncodeToString(child.Serialize())
		if got != tc.expectedPrv {
			t.Errorf("path %v: got %s want %s", tc.path, got, tc.expectedPrv)
		}
	}
}

// ECDSA 公開鍵導出が「子秘密鍵の公開鍵」と一致すること（往復整合）。
func TestDeriveECDSAPublicKey_RoundTrip(t *testing.T) {
	rootPrv := secp256k1.PrivKeyFromBytes(mustHex(t, bip32RootPrvHex))
	for _, path := range [][]uint32{{0}, {0, 1, 2, 2, 1000000000}} {
		key := NewKey(mustHex(t, bip32RootChainCodeHex), path...)
		childPrv, err := key.DeriveECDSAPrivateKey(rootPrv)
		if err != nil {
			t.Fatal(err)
		}
		childPub, err := key.DeriveECDSAPublicKey(rootPrv.PubKey())
		if err != nil {
			t.Fatal(err)
		}
		if got, want := hex.EncodeToString(childPub.SerializeCompressed()),
			hex.EncodeToString(childPrv.PubKey().SerializeCompressed()); got != want {
			t.Errorf("path %v: pub mismatch got %s want %s", path, got, want)
		}
	}
}

// EdDSA 公開鍵導出が Fireblocks recovery の公開ベクタと一致すること。
func TestDeriveEdDSAPublicKey_FireblocksVector(t *testing.T) {
	const (
		fpubChainCodeHex = "5d90bd21d2273a25d0aea082716bdc4529e007823260ad3479182f6672c25cc4"
		fpubPubHex       = "50cfee85dabebed78f43e94a1b7afd13c20461ad66efa083779bdeffd22269d9"
		wantChildPubHex  = "cdff9320114119fd2add3a20b5cf852470dc08d4cefb31874304d3813a0ad51f"
	)
	rootPub, err := edwards.ParsePubKey(mustHex(t, fpubPubHex))
	if err != nil {
		t.Fatal(err)
	}
	key := NewKey(mustHex(t, fpubChainCodeHex), 44, 501, 0, 0, 0)
	childPub, err := key.DeriveEdDSAPublicKey(rootPub)
	if err != nil {
		t.Fatal(err)
	}
	if got := hex.EncodeToString(childPub.Serialize()); got != wantChildPubHex {
		t.Errorf("got %s want %s", got, wantChildPubHex)
	}
}

// EdDSA 子秘密鍵導出が「子秘密鍵の公開鍵 == 導出した子公開鍵」を満たすこと（往復整合）。
// DeriveEdDSAPublicKey は Fireblocks ベクタで外部検証済みのため、この往復整合により
// 子秘密鍵の正当性が推移的に保証される。
func TestDeriveEdDSAPrivateKey_RoundTrip(t *testing.T) {
	rootPrv, err := edwards.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	rootPub := rootPrv.PubKey()
	for _, path := range [][]uint32{{44, 501, 0, 0, 0}, {44, 501, 0, 0, 7}} {
		key := NewKey(bip32ChainCodeForTest(t), path...)
		childPrv, err := key.DeriveEdDSAPrivateKey(rootPrv)
		if err != nil {
			t.Fatal(err)
		}
		childPub, err := key.DeriveEdDSAPublicKey(rootPub)
		if err != nil {
			t.Fatal(err)
		}
		if got, want := hex.EncodeToString(childPrv.PubKey().Serialize()),
			hex.EncodeToString(childPub.Serialize()); got != want {
			t.Errorf("path %v: got %s want %s", path, got, want)
		}
	}
}

func bip32ChainCodeForTest(t *testing.T) []byte {
	return mustHex(t, bip32RootChainCodeHex)
}

// hardened index（>= 2^31）は拒否されること。
func TestDerive_HardenedRejected(t *testing.T) {
	rootPrv := secp256k1.PrivKeyFromBytes(mustHex(t, bip32RootPrvHex))
	key := NewKey(mustHex(t, bip32RootChainCodeHex), 0x80000000)
	if _, err := key.DeriveECDSAPrivateKey(rootPrv); err == nil {
		t.Error("expected error for hardened index")
	}
}
