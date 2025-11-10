package keyutil

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/ziputil"
)

func LocalDataFromBytesECDSA(
	ctx context.Context,
	data []byte,
) (*keygen.LocalPartySaveData, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "StoredData.FromBytes"),
	)
	str, err := ziputil.GunzipBytes(ctx, data)
	if err != nil {
		logger.Error(
			"failed to gunzip",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	}

	var result keygen.LocalPartySaveData
	if err := json.Unmarshal(str, &result); err != nil {
		logger.Error(
			"could not unmarshal json",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	} else if result.ECDSAPub == nil {
		err := fmt.Errorf("not ECDSA key share")
		return nil, errutil.Wrap(err)
	}
	result.ECDSAPub.SetCurve(tss.S256())
	for _, kbxj := range result.BigXj {
		kbxj.SetCurve(tss.S256())
	}
	return &result, nil
}

func LocalDataToBytesECDSA(
	ctx context.Context,
	localData *keygen.LocalPartySaveData,
) ([]byte, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "StoredData.ToBytes"),
	)
	str, err := json.Marshal(localData)
	if err != nil {
		logger.Error(
			"failed to marshal",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	}

	bytes, err := ziputil.GzipBytes(ctx, str)
	if err != nil {
		logger.Error(
			"failed to gzip",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	}
	return bytes, nil
}

func PubKeyFromShareECDSA(
	ctx context.Context,
	share *keygen.LocalPartySaveData,
) (*secp256k1.PublicKey, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "PubKeyFromShareECDSA"),
	)
	logger.Info("deriving public key from share")
	if share.ECDSAPub == nil {
		err := fmt.Errorf("share does not contain public key")
		return nil, errutil.Wrap(err)
	}
	ecPub := share.ECDSAPub.ToECDSAPubKey()
	x := new(secp256k1.FieldVal)
	if overflow := x.SetByteSlice(ecPub.X.Bytes()); overflow {
		err := fmt.Errorf("x coordinate is not on curve")
		return nil, errutil.Wrap(err)
	}
	y := new(secp256k1.FieldVal)
	if overflow := y.SetByteSlice(ecPub.Y.Bytes()); overflow {
		err := fmt.Errorf("y coordinate is not on curve")
		return nil, errutil.Wrap(err)
	}
	result := secp256k1.NewPublicKey(x, y)
	return result, nil
}
