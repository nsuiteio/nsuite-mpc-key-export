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
//
// ベクタ生成元: nst-core commit e95690686dc34a089eca9ed7abcfa068d327d65a。
// 導出関連 4 ファイル（derive_ecdsa.go / derive_eddsa.go / keyshare_rootpub.go /
// keyshare_derivation.go）は nst-core origin/develop
// (34ad6bf56192d4f3bc134e4bd0525d7daddad782) と同一内容であることを確認済み。
// EdDSA の公開鍵シリアライズは両実装とも dcrd edwards/v2 の 32 バイト形式
// （Serialize == SerializeCompressed）。
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

// NewKey は path を内部コピーし、呼び出し元スライスの後続変更に影響されない。
func TestNewKey_CopiesPath(t *testing.T) {
	rootPrv := secp256k1.PrivKeyFromBytes(mustHex(t, bip32RootPrvHex))
	path := []uint32{0}
	key, err := NewKey(mustHex(t, bip32RootChainCodeHex), path...)
	if err != nil {
		t.Fatal(err)
	}
	before, err := key.DeriveECDSAPrivateKey(rootPrv)
	if err != nil {
		t.Fatal(err)
	}
	path[0] = 1 // 呼び出し元がスライスを書き換えても導出結果は変わらないこと
	after, err := key.DeriveECDSAPrivateKey(rootPrv)
	if err != nil {
		t.Fatal(err)
	}
	if string(before.Serialize()) != string(after.Serialize()) {
		t.Error("NewKey must copy the path slice")
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
