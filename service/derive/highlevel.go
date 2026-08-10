package derive

import (
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// N Suite の HDPath は BIP44 由来の固定 5 段 m/44/{coinType}/0/0/{index}。
// coinType は curve で一意（ECDSA=ETH=60, EdDSA=SOL=501）。すべて非 hardened。
const (
	coinTypeETH uint32 = 60
	coinTypeSOL uint32 = 501
)

// chainCodeFromPub は N Suite root 公開鍵から chaincode を導出する。
// nst-core keyshare_rootpub.go と同じく Keccak256(Keccak256(圧縮 root 公開鍵))。
func chainCodeFromPub(compressedPub []byte) []byte {
	return keccak256(keccak256(compressedPub))
}

// ECDSAChild は再構成した ECDSA root 秘密鍵と index から、
// 固定パス m/44/60/0/0/index の子秘密鍵と EVM アドレスを返す。
func ECDSAChild(
	root *secp256k1.PrivateKey, index uint32,
) (*secp256k1.PrivateKey, string, error) {
	chainCode := chainCodeFromPub(root.PubKey().SerializeCompressed())
	key := NewKey(chainCode, 44, coinTypeETH, 0, 0, index)
	childPrv, err := key.DeriveECDSAPrivateKey(root)
	if err != nil {
		return nil, "", err
	}
	return childPrv, EVMAddress(childPrv.PubKey()), nil
}

// EdDSAChild は再構成した EdDSA root 秘密鍵と index から、
// 固定パス m/44/501/0/0/index の子秘密鍵と Solana アドレスを返す。
func EdDSAChild(
	root *edwards.PrivateKey, index uint32,
) (*edwards.PrivateKey, string, error) {
	chainCode := chainCodeFromPub(root.PubKey().SerializeCompressed())
	key := NewKey(chainCode, 44, coinTypeSOL, 0, 0, index)
	childPrv, err := key.DeriveEdDSAPrivateKey(root)
	if err != nil {
		return nil, "", err
	}
	return childPrv, SolanaAddress(childPrv.PubKey()), nil
}
