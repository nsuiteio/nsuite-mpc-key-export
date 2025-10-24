package reconstruct

import (
	"context"
	"encoding/json"
	"log/slog"

	ecdsa "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsa "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/keyutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/ziputil"
)

type (
	keyStruct struct {
		ECDSA []byte `json:"ecdsa"`
		EdDSA []byte `json:"eddsa"`
	}
)

func LoadFromZip(
	ctx context.Context,
	privateKey secutil.EncryptionPrivateKey,
	path string,
) ([]*ecdsa.LocalPartySaveData, []*eddsa.LocalPartySaveData, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "LoadFromZip"),
		slog.String("path", path),
	)
	logger.Info("reading zip file")

	encyptedKeyShares, err := ziputil.UnzipFile(ctx, path)
	if err != nil {
		return nil, nil, errutil.Wrap(err)
	}

	var keySharesECDSA []*ecdsa.LocalPartySaveData
	var keySharesEdDSA []*eddsa.LocalPartySaveData
	for k, bs := range encyptedKeyShares {
		logger.Info("decrypting key share", slog.String("key", k))
		var keys keyStruct
		if err := json.Unmarshal(bs, &keys); err != nil {
			return nil, nil, errutil.Wrap(err)
		}
		if plainBs, err := privateKey.Decrypt(keys.ECDSA); err != nil {
			return nil, nil, errutil.Wrap(err)
		} else if keyShare, err := keyutil.LocalDataFromBytesECDSA(
			ctx,
			plainBs,
		); err != nil {
			keySharesECDSA = append(keySharesECDSA, keyShare)
		}
		if plainBs, err := privateKey.Decrypt(keys.EdDSA); err != nil {
			return nil, nil, errutil.Wrap(err)
		} else if plainKeyShare, err := keyutil.LocalDataFromBytesEdDSA(
			ctx,
			plainBs,
		); err != nil {
			keySharesEdDSA = append(keySharesEdDSA, plainKeyShare)
		}
	}

	return keySharesECDSA, keySharesEdDSA, nil
}
