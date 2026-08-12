package derive

import (
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// nst-core（go/feature/mpc derive_ecdsa.go / derive_eddsa.go / keyshare_rootpub.go）
// の実装で独立に生成した交差検証ベクタ。root 鍵 → chaincode 自己計算 → 固定パス →
// 最終アドレスまでの全パイプラインが N Suite のアドレス発行実装と一致することを
// 保証する（本パッケージの実装を期待値生成に使っていない）。
func TestECDSAChild_NSuiteCrossImplVector(t *testing.T) {
	root := secp256k1.PrivKeyFromBytes(mustHex(t, bip32RootPrvHex))

	cases := []struct {
		index uint32
		want  string
	}{
		{0, "0x6069EB711Ea5f43df9d9C20328ea550c2D8bf8eE"},
		{1, "0x5402856aea9898EeA1024e59DdC9edF6981b264c"},
		{5, "0x47e5D031b9368810D4d5a777296a9F70c0e966E4"},
	}
	for _, tc := range cases {
		_, addr, err := ECDSAChild(root, tc.index)
		if err != nil {
			t.Fatalf("index %d: %v", tc.index, err)
		}
		if addr != tc.want {
			t.Errorf("index %d: got %s want %s", tc.index, addr, tc.want)
		}
	}
}

func TestEdDSAChild_NSuiteCrossImplVector(t *testing.T) {
	scalar := make([]byte, 32)
	scalar[31] = 0x2a
	root, _, err := edwards.PrivKeyFromScalar(scalar)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		index uint32
		want  string
	}{
		{0, "G7NUmA82Nn5UtHcb2Zqf387ooRM9VR4ccSWDwRuDnKKe"},
		{3, "35CQygCGS6chBzqneU2N54zRxA6vPWnaP6XaTbysAMNH"},
	}
	for _, tc := range cases {
		_, addr, err := EdDSAChild(root, tc.index)
		if err != nil {
			t.Fatalf("index %d: %v", tc.index, err)
		}
		if addr != tc.want {
			t.Errorf("index %d: got %s want %s", tc.index, addr, tc.want)
		}
	}
}

// NewKey は 32 バイト以外の chaincode を拒否する（黙ってゼロ埋め・切り捨てしない）。
func TestNewKey_InvalidChainCodeLength(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33} {
		if _, err := NewKey(make([]byte, n), 0); err == nil {
			t.Errorf("length %d: expected error", n)
		}
	}
	if _, err := NewKey(make([]byte, 32), 0); err != nil {
		t.Errorf("length 32: unexpected error: %v", err)
	}
}
