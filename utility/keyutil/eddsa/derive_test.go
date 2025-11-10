package eddsa

import (
	"context"
	"log/slog"
	"testing"

	"github.com/btcsuite/btcd/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"

	"github.com/nsuiteio/nst-mpc-key-export/utility/keyutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/strutil"
)

func TestDerivePubKey(t *testing.T) {
	ctx := context.Background()
	logger := logutil.Get(ctx)

	// https://github.com/fireblocks/recovery/blob/09fce94ba6c6cffc5624a070ca51da36e4024ed6/packages/wallet-derivation/tests/index.test.ts#L77
	const fpub = "fpub8sZZXw2wbqVpURAAA9cCBpv2256rejFtCayHuRAzcYN1qciBxMVmB6UgiDAQTUZh5EP9JZciPQPjKAHyqPYHELqEHWkvo1sxreEJgLyfCJj"
	const childPub = "0xcdff9320114119fd2add3a20b5cf852470dc08d4cefb31874304d3813a0ad51f"

	rootFpub, err := parseFpub(fpub)
	if err != nil {
		t.Fatal(err)
	}
	rootPubKey := rootFpub.pubKey
	logger.Info(
		"rootPub",
		slog.String("serialized", strutil.ToHex(rootPubKey.Serialize())),
	)

	deriveKey := new(DeriveKey)
	deriveKey.Init(rootFpub.chainCode.Bytes(), 44, 501, 0, 0, 0)

	childPubKey, err := deriveKey.DerivePubKey(ctx, rootPubKey)
	if err != nil {
		t.Fatal(err)
	}
	assert.Equal(t, childPub, strutil.ToHex(childPubKey.Serialize()))
}

type Fpub struct {
	pubKey    *edwards.PublicKey
	chainCode keyutil.ChainCode
}

func parseFpub(src string) (*Fpub, error) {
	decoded := base58.Decode(src)
	chainCode := new(keyutil.ChainCode).SetBytes(decoded[13:45])
	keyData := decoded[45:78]
	pubKey, err := edwards.ParsePubKey(keyData[1:])
	if err != nil {
		return nil, err
	}
	return &Fpub{
		pubKey:    pubKey,
		chainCode: chainCode,
	}, nil
}
