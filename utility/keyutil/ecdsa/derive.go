package ecdsa

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
	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
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
	pubkey *secp256k1.PublicKey,
	index uint32,
) *DeriveKey {
	pkbs := pubkey.SerializeCompressed()
	chainCode := gethCrypto.Keccak256(gethCrypto.Keccak256(pkbs))

	dk := new(DeriveKey)
	dk.Init(chainCode, 44, 60, 0, 0, index)
	return dk
}

func (dk *DeriveKey) DerivePrvKey(
	ctx context.Context,
	privateKey *secp256k1.PrivateKey,
) (*secp256k1.PrivateKey, error) {
	path := dk.Path()
	logger := logutil.Get(ctx).With(
		slog.String("function", "DeriveKey.DerivePrvKey"),
		slog.String("path", path.String()),
	)
	logger.Info("deriving private key")

	xprv := hdkeychain.NewExtendedKey(
		[]byte{0x04, 0x88, 0xad, 0xe4}, // mainnet
		privateKey.Serialize(),
		dk.ChainCode(),
		[]byte{0x00, 0x00, 0x00, 0x00},
		0,
		0,
		true,
	)
	logger.Info(
		"deriving as root",
		slog.String("root_prv", xprv.String()),
	)

	childPrv := xprv
	for _, node := range dk.Path() {
		cp, err := childPrv.Derive(node)
		if err != nil {
			return nil, err
		}
		childPrv = cp
	}
	logger.Debug(
		"derived",
		slog.String("child_prv", childPrv.String()),
	)

	privKey, err := childPrv.ECPrivKey()
	if err != nil {
		return nil, err
	}

	return privKey, nil
}

func (dk *DeriveKey) DerivePubKey(
	ctx context.Context,
	publicKey *secp256k1.PublicKey,
) (*secp256k1.PublicKey, error) {
	path := dk.Path()
	logger := logutil.Get(ctx).With(
		slog.String("function", "DeriveKey.DerivePubKey"),
		slog.String("path", path.String()),
	)
	logger.Info("deriving public key")
	rootPub, err := crypto.NewECPoint(
		tss.S256(),
		publicKey.X(),
		publicKey.Y(),
	)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	_, cp, err := dk.getKeyDerivationDelta(rootPub)
	if err != nil {
		return nil, errutil.Wrap(err)
	}

	toVal := func(v *big.Int) *secp256k1.FieldVal {
		fv := new(secp256k1.FieldVal)
		fv.SetByteSlice(v.Bytes())
		return fv
	}
	return secp256k1.NewPublicKey(toVal(cp.X()), toVal(cp.Y())), nil
}

func (dk *DeriveKey) UpdateKeyShare(
	ctx context.Context,
	shares ...*keygen.LocalPartySaveData,
) (*keyutil.KeyDerivationDelta, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "DeriveKey.UpdateKeyShare"),
		slog.String("chaincode", dk.ChainCodeHex()),
		slog.String("hdpath", dk.HDPath()),
		slog.Int("shares", len(shares)),
	)
	logger.Info("updating key shares")
	if len(shares) == 0 {
		return nil, fmt.Errorf("no shares")
	}
	publicKey := shares[0].ECDSAPub
	kdd, childPub, err := dk.getKeyDerivationDelta(publicKey)
	if err != nil {
		return nil, err
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
		return nil, err
	}
	for i := range shares {
		shares[i].ECDSAPub = keys[i].ECDSAPub
	}

	return kdd, nil
}

func updatePublicKeyAndAdjustBigXj(
	keyDerivationDelta *big.Int,
	keys []keygen.LocalPartySaveData,
	pubkey *crypto.ECPoint,
) error {
	var err error
	gDelta := crypto.ScalarBaseMult(pubkey.Curve(), keyDerivationDelta)
	for k := range keys {
		keys[k].ECDSAPub, err = crypto.NewECPoint(
			pubkey.Curve(),
			pubkey.X(),
			pubkey.Y(),
		)
		if err != nil {
			return errutil.Wrap(err)
		}
		// Suppose X_j has shamir shares X_j0,     X_j1,     ..., X_jn
		// So X_j + D has shamir shares  X_j0 + D, X_j1 + D, ..., X_jn + D
		for j := range keys[k].BigXj {
			keys[k].BigXj[j], err = keys[k].BigXj[j].Add(gDelta)
			if err != nil {
				return errutil.Wrap(err)
			}
		}
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

	pubKeyCompressed byte = 0x2

	PubKeyBytesLenCompressed = 33
)

func deriveChildKeyFromHierarchy(
	indicesHierarchy []uint32,
	rootKey *derivingExtended,
) (*big.Int, *derivingExtended, error) {
	child := rootKey
	mod := tssCommon.ModInt(rootKey.Point.Curve().Params().N)
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
	pk *derivingExtended,
) (*big.Int, *derivingExtended, error) {
	if index >= HardenedKeyStart {
		err := fmt.Errorf("the index must be non-hardened: %v", index)
		return nil, nil, errutil.Wrap(err)
	}

	pkPublicKeyBytes := serializeCompressed(pk.Point.X(), pk.Point.Y())

	data := make([]byte, 37)
	copy(data, pkPublicKeyBytes)
	binary.BigEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode.Bytes())
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)

	curve := pk.Point.Curve()
	n := curve.Params().N
	if ilNum.Cmp(n) >= 0 || ilNum.Sign() == 0 {
		// falling outside of the valid range for curve private keys
		err := fmt.Errorf("invalid derived key")
		return nil, nil, errutil.Wrap(err)
	}

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err := fmt.Errorf("invalid child")
		return nil, nil, errutil.Wrap(err)
	}
	childCryptoPk, err := pk.Point.Add(deltaG)
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

// SerializeCompressed serializes a public key 33-byte compressed format
func serializeCompressed(publicKeyX *big.Int, publicKeyY *big.Int) []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubKeyCompressed
	if isOdd(publicKeyY) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(b, 32, publicKeyX.Bytes())
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// PaddedAppend append src to dst, if less than size padding 0 at start
func paddedAppend(dst []byte, srcPaddedSize int, src []byte) []byte {
	return append(dst, paddedBytes(srcPaddedSize, src)...)
}

// PaddedBytes padding byte array to size length
func paddedBytes(size int, src []byte) []byte {
	offset := size - len(src)
	tmp := src
	if offset > 0 {
		tmp = make([]byte, size)
		copy(tmp[offset:], src)
	}
	return tmp
}
