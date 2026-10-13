// Package derive は、MPC から再構成した root 秘密鍵から、HDPath（BIP32 CKD の
// 非 hardened 導出）によって個別アドレスの子秘密鍵・子公開鍵を導出する。
//
// 導出アルゴリズムは nst-tss-lib の ecdsautil/eddsautil derivation.go
// （tss-lib/v2/crypto/ckd の移植）と等価で、外部の公開ベクタ（BIP32 公式ベクタ、
// Fireblocks recovery）で検証している。root 秘密鍵・子秘密鍵などの鍵素材は
// ログに出力しない。
package derive

import (
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"math/big"

	tssCommon "github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/nsuiteio/nsuite-mpc-key-export/utility/errutil"
)

// hardenedKeyStart 以上の index は hardened 導出を意味し、MPC では非対応。
const hardenedKeyStart uint32 = 0x80000000

// Key は chaincode と導出パスを保持する導出器。
type Key struct {
	chainCode [32]byte
	path      []uint32
}

// NewKey は chaincode（32 バイト）と導出パスから Key を作る。
// chaincode が 32 バイト以外の場合は、黙ってゼロ埋め・切り捨てせずエラーを返す。
func NewKey(chainCode []byte, path ...uint32) (*Key, error) {
	if len(chainCode) != 32 {
		err := fmt.Errorf("invalid chaincode length: %d", len(chainCode))
		return nil, errutil.Wrap(err)
	}
	// 呼び出し元スライスの後続変更に影響されないよう path をコピーする。
	k := &Key{path: append([]uint32(nil), path...)}
	copy(k.chainCode[:], chainCode)
	return k, nil
}

// derived は導出途中の公開鍵点と chaincode を保持する。
type derived struct {
	point     *crypto.ECPoint
	chainCode [32]byte
}

// keyDerivationDelta は、公開鍵の階層を辿って各段の IL を曲線位数 N で mod 加算し、
// 累積した delta（= 子スカラー - root スカラー）と最終的な子公開鍵点を返す。
// ECDSA/EdDSA で公開鍵のシリアライズと IL の扱いが異なるため関数で切り替える。
func (k *Key) keyDerivationDelta(
	rootPoint *crypto.ECPoint,
	deriveChild func(uint32, *derived) (*big.Int, *derived, error),
) (*big.Int, *crypto.ECPoint, error) {
	mod := tssCommon.ModInt(rootPoint.Curve().Params().N)
	child := &derived{point: rootPoint, chainCode: k.chainCode}
	kdd := big.NewInt(0)
	for _, index := range k.path {
		il, next, err := deriveChild(index, child)
		if err != nil {
			return nil, nil, errutil.Wrap(err)
		}
		child = next
		kdd = mod.Add(kdd, il)
	}
	return kdd, child.point, nil
}

// --- ECDSA (secp256k1) ---

// DeriveECDSAPrivateKey は root 秘密鍵から子秘密鍵を導出する。
// 子スカラー = (root スカラー + Σ IL) mod N。
func (k *Key) DeriveECDSAPrivateKey(
	rootPrv *secp256k1.PrivateKey,
) (*secp256k1.PrivateKey, error) {
	rootPoint, err := crypto.NewECPoint(
		tss.S256(), rootPrv.PubKey().X(), rootPrv.PubKey().Y(),
	)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	kdd, _, err := k.keyDerivationDelta(rootPoint, deriveChildECDSA)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	n := tss.S256().Params().N
	rootScalar := new(big.Int).SetBytes(rootPrv.Serialize())
	childScalar := new(big.Int).Add(rootScalar, kdd)
	childScalar.Mod(childScalar, n)
	if childScalar.Sign() == 0 {
		return nil, errutil.Wrap(fmt.Errorf("invalid derived private key"))
	}
	return secp256k1.PrivKeyFromBytes(padScalar(childScalar)), nil
}

// DeriveECDSAPublicKey は root 公開鍵から子公開鍵を導出する。
func (k *Key) DeriveECDSAPublicKey(
	rootPub *secp256k1.PublicKey,
) (*secp256k1.PublicKey, error) {
	rootPoint, err := crypto.NewECPoint(tss.S256(), rootPub.X(), rootPub.Y())
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	_, childPoint, err := k.keyDerivationDelta(rootPoint, deriveChildECDSA)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	x, y := new(secp256k1.FieldVal), new(secp256k1.FieldVal)
	x.SetByteSlice(childPoint.X().Bytes())
	y.SetByteSlice(childPoint.Y().Bytes())
	return secp256k1.NewPublicKey(x, y), nil
}

func deriveChildECDSA(index uint32, de *derived) (*big.Int, *derived, error) {
	if index >= hardenedKeyStart {
		return nil, nil, errutil.Wrap(
			fmt.Errorf("the index must be non-hardened: %d", index))
	}
	pub := serializeCompressedECDSA(de.point.X(), de.point.Y())
	il, childChainCode := hmacSHA512(de.chainCode[:], pub, index, false)
	ilNum := new(big.Int).SetBytes(il)

	n := tss.S256().Params().N
	if ilNum.Cmp(n) >= 0 || ilNum.Sign() == 0 {
		return nil, nil, errutil.Wrap(fmt.Errorf("invalid derived key"))
	}
	return addDelta(de.point, ilNum, childChainCode)
}

// --- EdDSA (ed25519 / edwards) ---

// DeriveEdDSAPrivateKey は root 秘密鍵から子秘密鍵を導出する。
// EdDSA の秘密鍵は生スカラーであり、子スカラー = (root スカラー + Σ IL) mod L。
func (k *Key) DeriveEdDSAPrivateKey(
	rootPrv *edwards.PrivateKey,
) (*edwards.PrivateKey, error) {
	rootPub := rootPrv.PubKey()
	rootPoint, err := crypto.NewECPoint(
		tss.Edwards(),
		rootPub.GetX(),
		rootPub.GetY(),
	)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	kdd, _, err := k.keyDerivationDelta(rootPoint, deriveChildEdDSA)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	n := tss.Edwards().Params().N
	rootScalar := rootPrv.GetD()
	childScalar := new(big.Int).Add(rootScalar, kdd)
	childScalar.Mod(childScalar, n)
	if childScalar.Sign() == 0 {
		return nil, errutil.Wrap(fmt.Errorf("invalid derived private key"))
	}
	prv, _, err := edwards.PrivKeyFromScalar(padScalar(childScalar))
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	return prv, nil
}

// DeriveEdDSAPublicKey は root 公開鍵から子公開鍵を導出する。
func (k *Key) DeriveEdDSAPublicKey(
	rootPub *edwards.PublicKey,
) (*edwards.PublicKey, error) {
	rootPoint, err := crypto.NewECPoint(
		tss.Edwards(),
		rootPub.GetX(),
		rootPub.GetY(),
	)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	_, childPoint, err := k.keyDerivationDelta(rootPoint, deriveChildEdDSA)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	return edwards.NewPublicKey(childPoint.X(), childPoint.Y()), nil
}

func deriveChildEdDSA(index uint32, de *derived) (*big.Int, *derived, error) {
	if index >= hardenedKeyStart {
		return nil, nil, errutil.Wrap(
			fmt.Errorf("the index must be non-hardened: %d", index))
	}
	pub := edwards.NewPublicKey(de.point.X(), de.point.Y()).Serialize()
	il, childChainCode := hmacSHA512(de.chainCode[:], pub, index, true)
	ilNum := new(big.Int).SetBytes(il)
	if ilNum.Sign() == 0 {
		return nil, nil, errutil.Wrap(fmt.Errorf("invalid derived key"))
	}
	ilNum.Mod(ilNum, tss.Edwards().Params().N)
	return addDelta(de.point, ilNum, childChainCode)
}

// --- 共通ヘルパ ---

// hmacSHA512 は HMAC-SHA512(key=chainCode, data=pub||index) を計算し、
// 前半 32 バイト（IL）と後半 32 バイト（子 chaincode）を返す。
// EdDSA では 32 バイト公開鍵の直後（data[32]）を 0 にしてから index を書く。
func hmacSHA512(
	chainCode, pub []byte, index uint32, eddsa bool,
) (il []byte, childChainCode []byte) {
	data := make([]byte, 37)
	copy(data, pub)
	if eddsa {
		data[32] = 0
	}
	binary.BigEndian.PutUint32(data[33:], index)
	h := hmac.New(sha512.New, chainCode)
	h.Write(data)
	sum := h.Sum(nil)
	return sum[:32], sum[32:]
}

// addDelta は親公開鍵点に delta*G を加算して子公開鍵点を作る。
func addDelta(
	point *crypto.ECPoint, ilNum *big.Int, childChainCode []byte,
) (*big.Int, *derived, error) {
	deltaG := crypto.ScalarBaseMult(point.Curve(), ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		return nil, nil, errutil.Wrap(fmt.Errorf("invalid child"))
	}
	childPoint, err := point.Add(deltaG)
	if err != nil {
		return nil, nil, errutil.Wrap(err)
	}
	next := &derived{point: childPoint}
	copy(next.chainCode[:], childChainCode)
	return ilNum, next, nil
}

// serializeCompressedECDSA は secp256k1 公開鍵を 33 バイト圧縮形式にする。
func serializeCompressedECDSA(x, y *big.Int) []byte {
	b := make([]byte, 33)
	if y.Bit(0) == 1 {
		b[0] = 0x03
	} else {
		b[0] = 0x02
	}
	xb := x.Bytes()
	copy(b[33-len(xb):], xb)
	return b
}

// padScalar は big.Int を 32 バイト左ゼロ詰めのバイト列にする。
func padScalar(v *big.Int) []byte {
	bs := v.Bytes()
	if len(bs) >= 32 {
		return bs
	}
	out := make([]byte, 32)
	copy(out[32-len(bs):], bs)
	return out
}
