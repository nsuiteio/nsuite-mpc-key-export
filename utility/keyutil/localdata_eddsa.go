package keyutil

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/ziputil"
)

func LocalDataFromBytesEdDSA(
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
	} else if result.EDDSAPub == nil {
		err := fmt.Errorf("not EdDSA key share")
		return nil, err
	}
	result.EDDSAPub.SetCurve(tss.Edwards())
	for _, kbxj := range result.BigXj {
		kbxj.SetCurve(tss.Edwards())
	}
	return &result, nil
}

func LocalDataToBytesEdDSA(
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
