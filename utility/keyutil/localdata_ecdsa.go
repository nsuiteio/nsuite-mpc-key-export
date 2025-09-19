package keyutil

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	"github.com/bnb-chain/tss-lib/v2/tss"
	"github.com/nsuiteio/trial-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/trial-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/trial-mpc-key-export/utility/ziputil"
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
		logger.Error("failed to gunzip",
			slog.String("error", err.Error()))
		return nil, errutil.Wrap(err)
	}

	var result keygen.LocalPartySaveData
	if err := json.Unmarshal(str, &result); err != nil {
		logger.Error("could not unmarshal json",
			slog.String("error", err.Error()))
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
