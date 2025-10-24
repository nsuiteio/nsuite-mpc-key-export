package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"sync"

	ecdsa "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsa "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nsuiteio/nst-mpc-key-export/service/reconstruct"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/keyutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/qrutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/strutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/ziputil"
)

// App struct
type App struct {
	config *cfgutil.WailsJson

	ctx context.Context

	lockStorage sync.Mutex
	storage     cfgutil.Storage
}

// NewApp creates a new App application struct
func NewApp(config *cfgutil.WailsJson) *App {
	return &App{config: config}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = logutil.Setup(ctx, a.config.Name)
}

func (a *App) ChooseKeyShares(password string) (string, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "ChooseKeyShares"),
	)

	akey, err := secutil.NewAESPassword(password)
	if err != nil {
		return "", err
	}

	privateKey, ok, err := a.loadKeyPair(ctx, akey)
	if err != nil {
		return "", err
	}
	if !ok {
		err := fmt.Errorf("key pair not found")
		return "", err
	}

	file, err := runtime.OpenFileDialog(
		ctx, runtime.OpenDialogOptions{
			Title: "ファイルを選択してください",
			Filters: []runtime.FileFilter{
				{
					DisplayName: "ZIPファイル (*.zip)",
					Pattern:     "*.zip",
				},
			},
		},
	)
	if err != nil {
		return "", err
	}
	logger.Info("reading zip file", slog.String("file", file))
	encyptedKeyShares, err := ziputil.UnzipFile(ctx, file)
	if err != nil {
		return "", err
	}

	type keyStruct struct {
		ECDSA []byte `json:"ecdsa"`
		EdDSA []byte `json:"eddsa"`
	}
	var keySharesECDSA []*ecdsa.LocalPartySaveData
	var keySharesEdDSA []*eddsa.LocalPartySaveData
	for k, bs := range encyptedKeyShares {
		logger.Info("decrypting key share", slog.String("key", k))
		var keys keyStruct
		if err := json.Unmarshal(bs, &keys); err != nil {
			return "", err
		}
		if plainBs, err := privateKey.Decrypt(keys.ECDSA); err != nil {
			return "", err
		} else if keyShare, err := keyutil.LocalDataFromBytesECDSA(
			ctx,
			plainBs,
		); err != nil {
			keySharesECDSA = append(keySharesECDSA, keyShare)
		}
		if plainBs, err := privateKey.Decrypt(keys.EdDSA); err != nil {
			return "", err
		} else if plainKeyShare, err := keyutil.LocalDataFromBytesEdDSA(
			ctx,
			plainBs,
		); err != nil {
			keySharesEdDSA = append(keySharesEdDSA, plainKeyShare)
		}
	}

	const threshold = 3

	if prvkey, err := reconstruct.ReconstructECDSA(
		ctx,
		threshold,
		keySharesECDSA,
	); err != nil {
		return "", err
	} else if err := a.saveECDSA(ctx, akey, prvkey); err != nil {
		return "", err
	}

	if prvkey, err := reconstruct.ReconstructEdDSA(
		ctx,
		threshold,
		keySharesEdDSA,
	); err != nil {
		return "", err
	} else if err := a.saveEdDSA(ctx, akey, prvkey); err != nil {
		return "", err
	}

	return "OK", nil
}

func (a *App) GenerateKeyPair(password string, force bool) (string, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "GenerateKeyPair"),
	)

	akey, err := secutil.NewAESPassword(password)
	if err != nil {
		return "", err
	}
	if !force {
		if _, ok, err := a.loadKeyPair(ctx, akey); err != nil {
			return "", err
		} else if ok {
			err := fmt.Errorf("key pair already exists")
			return "", err
		}
	}

	privateKey, err := secutil.GenerateEncryptionKeyPair(
		ctx,
		secutil.EncryptionKeyPairTypeRSA,
	)
	if err != nil {
		return "", err
	}

	if err := a.saveKeyPair(ctx, akey, privateKey); err != nil {
		return "", err
	}

	pubkeyBs := privateKey.PublicKey().MarshalToBytes()
	logger.Info(
		"generated key pair",
		slog.String("public_key", strutil.ToHex(pubkeyBs)),
	)
	png, err := qrutil.GenerateQRCodePNG(pubkeyBs)
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(png)

	return "data:image/png;base64," + b64, nil
}

//////// Access to storage

const (
	pathEncryptionKey = "encryption.key"
	pathECDSA         = "ecdsa.key"
	pathEdDSA         = "eddsa.key"
)

func (a *App) getStorage(ctx context.Context) (cfgutil.Storage, error) {
	if a.storage != nil {
		return a.storage, nil
	}
	a.lockStorage.Lock()
	defer a.lockStorage.Unlock()
	if a.storage == nil {
		storage, err := cfgutil.NewSecStorage(ctx, a.config.Name)
		if err != nil {
			return nil, errutil.Wrap(err)
		}
		a.storage = storage
	}
	return a.storage, nil
}

func (a *App) saveKeyPair(
	ctx context.Context,
	ekey secutil.EncryptionKey,
	keyPair secutil.EncryptionPrivateKey,
) error {
	plainBs := keyPair.MarshalToBytes()
	encriptedBs, err := ekey.Encrypt(plainBs)
	if err != nil {
		return errutil.Wrap(err)
	}
	storage, err := a.getStorage(ctx)
	if err != nil {
		return errutil.Wrap(err)
	}
	return storage.Save(ctx, encriptedBs, pathEncryptionKey)
}

func (a *App) loadKeyPair(
	ctx context.Context,
	ekey secutil.EncryptionKey,
) (secutil.EncryptionPrivateKey, bool, error) {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	plainBs, ok, err := storage.Load(ctx, pathEncryptionKey)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	if !ok {
		return nil, false, nil
	}
	bs, err := ekey.Decrypt(plainBs)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	pk, err := secutil.EncryptionPrivateKeyFromBytes(bs)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	return pk, true, nil
}

func (a *App) saveECDSA(
	ctx context.Context,
	ekey secutil.EncryptionKey,
	prvkey *secp256k1.PrivateKey,
) error {
	plainBs := prvkey.Serialize()
	bs, err := ekey.Encrypt(plainBs)
	if err != nil {
		return errutil.Wrap(err)
	}
	storage, err := a.getStorage(ctx)
	if err != nil {
		return errutil.Wrap(err)
	}
	return storage.Save(ctx, bs, pathECDSA)
}

func (a *App) loadECDSA(
	ctx context.Context,
	ekey secutil.EncryptionKey,
) (*secp256k1.PrivateKey, bool, error) {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	plainBs, ok, err := storage.Load(ctx, pathECDSA)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	if !ok {
		return nil, false, nil
	}
	bs, err := ekey.Decrypt(plainBs)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	prvkey := secp256k1.PrivKeyFromBytes(bs)
	return prvkey, true, nil
}

func (a *App) saveEdDSA(
	ctx context.Context,
	ekey secutil.EncryptionKey,
	prvkey *edwards.PrivateKey,
) error {
	plainBs := prvkey.Serialize()
	bs, err := ekey.Encrypt(plainBs)
	if err != nil {
		return errutil.Wrap(err)
	}
	storage, err := a.getStorage(ctx)
	if err != nil {
		return errutil.Wrap(err)
	}
	return storage.Save(ctx, bs, pathEdDSA)
}

func (a *App) loadEdDSA(
	ctx context.Context,
	ekey secutil.EncryptionKey,
) (*edwards.PrivateKey, bool, error) {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	plainBs, ok, err := storage.Load(ctx, pathEdDSA)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	if !ok {
		return nil, false, nil
	}
	bs, err := ekey.Decrypt(plainBs)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	prvkey, _, err := edwards.PrivKeyFromScalar(bs)
	if err != nil {
		return nil, false, errutil.Wrap(err)
	}
	return prvkey, true, nil
}
