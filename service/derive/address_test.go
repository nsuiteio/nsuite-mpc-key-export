package derive

import (
	"encoding/hex"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// 有名な既知ベクタ: 秘密鍵 0x0000...0001 の EVM アドレス（EIP-55 チェックサム済み）。
// アドレス整形（Keccak256 + EIP-55）を導出ロジックと独立に検証する。
func TestEVMAddress_KnownVector(t *testing.T) {
	one := make([]byte, 32)
	one[31] = 1
	prv := secp256k1.PrivKeyFromBytes(one)
	const want = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"
	if got := EVMAddress(prv.PubKey()); got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

// Solana アドレスは ed25519 公開鍵 32 バイトの base58。Fireblocks ベクタの子公開鍵から
// 期待アドレスを算出（base58 整形を独立検証）。
func TestSolanaAddress_FireblocksChildPub(t *testing.T) {
	childPubBytes, err := hex.DecodeString(
		"cdff9320114119fd2add3a20b5cf852470dc08d4cefb31874304d3813a0ad51f")
	if err != nil {
		t.Fatal(err)
	}
	pub, err := edwards.ParsePubKey(childPubBytes)
	if err != nil {
		t.Fatal(err)
	}
	const want = "Es8cMivoZYEsCfKBYvZEkgeyYN3saNpzfkoagUBCLy5p"
	if got := SolanaAddress(pub); got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

// 高レベル API: root 秘密鍵と index から chaincode を自己計算し、
// 固定パス m/44/60/0/0/index で子秘密鍵とアドレスを返すこと（アドレスは
// 返却された子公開鍵と整合すること）。
func TestECDSAChild_SelfConsistent(t *testing.T) {
	root := secp256k1.PrivKeyFromBytes(mustHex(t, bip32RootPrvHex))
	childPrv, addr, err := ECDSAChild(root, 3)
	if err != nil {
		t.Fatal(err)
	}
	if want := EVMAddress(childPrv.PubKey()); addr != want {
		t.Errorf("address mismatch: got %s want %s", addr, want)
	}
	// index が変われば別の鍵になること。
	other, _, err := ECDSAChild(root, 4)
	if err != nil {
		t.Fatal(err)
	}
	if hex.EncodeToString(
		childPrv.Serialize(),
	) == hex.EncodeToString(
		other.Serialize(),
	) {
		t.Error("different index must yield different key")
	}
}

func TestEdDSAChild_SelfConsistent(t *testing.T) {
	root, err := edwards.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	childPrv, addr, err := EdDSAChild(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	if want := SolanaAddress(childPrv.PubKey()); addr != want {
		t.Errorf("address mismatch: got %s want %s", addr, want)
	}
}
