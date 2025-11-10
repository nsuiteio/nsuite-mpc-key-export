package eddsa

import (
	"context"
	"crypto/hmac"
	"crypto/sha512"
	"encoding/binary"
	"fmt"
	"log/slog"
	"math/big"

	tssCommon "github.com/bnb-chain/tss-lib/v2/common"
	"github.com/bnb-chain/tss-lib/v2/crypto"
	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	gethCrypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/keyutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
)

type (
	DeriveKey struct {
		keyutil.DeriveKey
	}

	derivingExtended struct {
		ChainCode keyutil.ChainCode
		Point     *crypto.ECPoint
	}
)

func NewDeriveKey(
	pubkey *edwards.PublicKey,
	index uint32,
) *DeriveKey {
	pkbs := pubkey.SerializeCompressed()
	chainCode := gethCrypto.Keccak256(gethCrypto.Keccak256(pkbs))

	dk := new(DeriveKey)
	dk.Init(chainCode, 44, 501, 0, 0, index)
	return dk
}

func (dk *DeriveKey) DerivePubKey(
	ctx context.Context,
	publicKey *edwards.PublicKey,
) (*edwards.PublicKey, error) {
	path := dk.Path()
	logger := logutil.Get(ctx).With(
		slog.String("function", "DeriveKey.DerivePubKey"),
		slog.String("path", path.String()),
	)
	logger.Info("deriving public key")
	rootPub, err := crypto.NewECPoint(
		publicKey.Curve,
		publicKey.X,
		publicKey.Y,
	)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	_, cp, err := dk.getKeyDerivationDelta(rootPub)
	if err != nil {
		return nil, errutil.Wrap(err)
	}

	return edwards.NewPublicKey(cp.X(), cp.Y()), nil
}

func (dk *DeriveKey) UpdateKeyShare(
	ctx context.Context,
	shares ...*keygen.LocalPartySaveData,
) error {
	logger := logutil.Get(ctx).With(
		slog.String("function", "DeriveKey.UpdateKeyShare"),
		slog.String("chaincode", dk.ChainCodeHex()),
		slog.String("hdpath", dk.HDPath()),
		slog.Int("shares", len(shares)),
	)
	logger.Info("updating key shares")
	if len(shares) == 0 {
		return fmt.Errorf("no shares")
	}
	publicKey := shares[0].EDDSAPub
	kdd, childPub, err := dk.getKeyDerivationDelta(publicKey)
	if err != nil {
		return err
	}

	var keys []keygen.LocalPartySaveData
	for i := range shares {
		keys = append(keys, *shares[i])
	}
	if err := updatePublicKeyAndAdjustBigXj(
		(*big.Int)(kdd),
		keys,
		childPub,
	); err != nil {
		return err
	}
	for i := range shares {
		shares[i].EDDSAPub = keys[i].EDDSAPub
	}

	return nil
}

func updatePublicKeyAndAdjustBigXj(
	keyDerivationDelta *big.Int,
	keys []keygen.LocalPartySaveData,
	pubkey *crypto.ECPoint,
) error {
	n := pubkey.Curve().Params().N
	mod := tssCommon.ModInt(n)
	for k := range keys {
		xi := keys[k].Xi
		xi.Set(mod.Add(keyDerivationDelta, xi)) // Secrets の更新
		keys[k].EDDSAPub = &(*pubkey)           // 公開鍵の更新
	}
	return nil
}

func (dk *DeriveKey) getKeyDerivationDelta(
	ecpoint *crypto.ECPoint,
) (*keyutil.KeyDerivationDelta, *crypto.ECPoint, error) {
	rootKey := &derivingExtended{
		Point:     ecpoint,
		ChainCode: new(keyutil.ChainCode).SetBytes(dk.ChainCode()),
	}
	kdd, childKey, err := deriveChildKeyFromHierarchy(dk.Path(), rootKey)
	if err != nil {
		return nil, nil, errutil.Wrap(err)
	}
	return (*keyutil.KeyDerivationDelta)(kdd), childKey.Point, err
}

// ----------------------------------------------------------------
// Ported from tss-lib/v2/crypto/ckd
// ----------------------------------------------------------------

const (
	HardenedKeyStart = 0x80000000 // 2^31
)

func deriveChildKeyFromHierarchy(
	indicesHierarchy []uint32,
	rootKey *derivingExtended,
) (*big.Int, *derivingExtended, error) {
	child := rootKey
	mod := tssCommon.ModInt(tss.Edwards().Params().N)
	kdd := big.NewInt(0)
	for index := range indicesHierarchy {
		diff, nextKey, err := deriveChildKey(indicesHierarchy[index], child)
		if err != nil {
			return nil, nil, errutil.Wrap(err)
		}
		child = nextKey
		kdd = mod.Add(kdd, diff)
	}
	return kdd, child, nil
}

func deriveChildKey(
	index uint32,
	de *derivingExtended,
) (*big.Int, *derivingExtended, error) {
	if index >= HardenedKeyStart {
		err := fmt.Errorf("the index must be non-hardened: %v", index)
		return nil, nil, errutil.Wrap(err)
	}

	pk := edwards.NewPublicKey(de.Point.X(), de.Point.Y())
	pkPublicKeyBytes := pk.Serialize()

	data := make([]byte, 37)
	copy(data, pkPublicKeyBytes)
	data[32] = 0
	binary.BigEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, de.ChainCode.Bytes())
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)

	if ilNum.Sign() == 0 {
		err := fmt.Errorf("invalid derived key")
		return nil, nil, errutil.Wrap(err)
	}
	curve := tss.Edwards()
	ilNum.Mod(ilNum, curve.Params().N)

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err := fmt.Errorf("invalid child")
		return nil, nil, errutil.Wrap(err)
	}
	childCryptoPk, err := de.Point.Add(deltaG)
	if err != nil {
		err := fmt.Errorf("error adding delta G to parent key")
		return nil, nil, errutil.Wrap(err)
	}

	childPk := &derivingExtended{
		Point:     childCryptoPk,
		ChainCode: new(keyutil.ChainCode).SetBytes(childChainCode),
	}
	return ilNum, childPk, nil
}
