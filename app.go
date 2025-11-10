package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"fmt"
	"log/slog"
	"sync"

	ecdsa "github.com/bnb-chain/tss-lib/v2/ecdsa/keygen"
	eddsa "github.com/bnb-chain/tss-lib/v2/eddsa/keygen"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nsuiteio/nst-mpc-key-export/service/reconstruct"
	"github.com/nsuiteio/nst-mpc-key-export/service/storage"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/keyutil"
	keyutil_ecdsa "github.com/nsuiteio/nst-mpc-key-export/utility/keyutil/ecdsa"
	keyutil_eddsa "github.com/nsuiteio/nst-mpc-key-export/utility/keyutil/eddsa"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/qrutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/strutil"
)

// App struct
type App struct {
	config *cfgutil.WailsJson

	ctx context.Context

	lockStorage sync.Mutex
	storage     *storage.Storage
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

	strg, err := a.getStorage(ctx)
	if err != nil {
		return "", err
	}

	privateKey, ok, err := strg.LoadKeyPair(ctx, akey)
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
	keySharesECDSA, keySharesEdDSA, err := reconstruct.LoadFromZip(
		ctx,
		privateKey,
		file,
	)
	if err != nil {
		return "", err
	}
	logger.Info(
		"loaded key shares",
		slog.Int("ecdsa_shares", len(keySharesECDSA)),
		slog.Int("eddsa_shares", len(keySharesEdDSA)),
	)

	if err := strg.SaveECDSA(ctx, akey, keySharesECDSA); err != nil {
		return "", err
	}

	if err := strg.SaveEdDSA(ctx, akey, keySharesEdDSA); err != nil {
		return "", err
	}

	return "OK", nil
}

func (a *App) CheckKeyPair() (bool, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "CheckKeyPair"),
	)
	logger.Info("started")
	strg, err := a.getStorage(ctx)
	if err != nil {
		return false, err
	}
	ok, err := strg.IsKeyPairExists(ctx)
	if err != nil {
		return false, err
	}
	return ok, nil
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
		strg, err := a.getStorage(ctx)
		if err != nil {
			return "", err
		}
		if _, ok, err := strg.LoadKeyPair(ctx, akey); err != nil {
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

	strg, err := a.getStorage(ctx)
	if err != nil {
		return "", err
	}
	if err := strg.SaveKeyPair(ctx, akey, privateKey); err != nil {
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

func (a *App) GetPrivateKey(
	password string,
	keyType string,
	index int32,
) (string, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "GetPrivateKey"),
		slog.String("key_type", keyType),
		slog.Int("index", int(index)),
	)
	logger.Info("started")

	akey, err := secutil.NewAESPassword(password)
	if err != nil {
		return "", err
	}

	strg, err := a.getStorage(ctx)
	if err != nil {
		return "", err
	}

	// TODO: derive by index

	const threshold = 3

	switch keyType {
	case "ECDSA":
		keys, ok, err := strg.LoadECDSA(ctx, akey)
		if err != nil {
			return "", err
		}
		if !ok {
			err := fmt.Errorf("ECDSA key not found")
			return "", err
		}
		logger.Info(
			"loaded ECDSA key",
			slog.Int("key_count", len(keys)),
		)
		prvkey, err := reconstruct.ReconstructECDSA(ctx, threshold, keys)
		if err != nil {
			return "", err
		}
		return strutil.ToHex(prvkey.Serialize()), nil
	case "EdDSA":
		keys, ok, err := strg.LoadEdDSA(ctx, akey)
		if err != nil {
			return "", err
		}
		if !ok {
			err := fmt.Errorf("EdDSA key not found")
			return "", err
		}
		logger.Info(
			"loaded EdDSA key",
			slog.Int("key_count", len(keys)),
		)
		prvkey, err := reconstruct.ReconstructEdDSA(ctx, threshold, keys)
		if err != nil {
			return "", err
		}
		return strutil.ToHex(prvkey.Serialize()), nil
	}
	return "", fmt.Errorf("unknown key type")
}

func (a *App) getStorage(ctx context.Context) (*storage.Storage, error) {
	if a.storage != nil {
		return a.storage, nil
	}
	a.lockStorage.Lock()
	defer a.lockStorage.Unlock()
	if a.storage == nil {
		userData, err := cfgutil.NewUserData(ctx, a.config.Name)
		if err != nil {
			return nil, errutil.Wrap(err)
		}
		a.storage = &storage.Storage{UserData: userData}
	}
	return a.storage, nil
}

func (a *App) deriveECDSA(
	ctx context.Context,
	akey secutil.EncryptionKey,
	index uint32,
) ([]*ecdsa.LocalPartySaveData, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "deriveECDSA"),
		slog.Int("index", int(index)),
	)
	strg, err := a.getStorage(ctx)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	keys, ok, err := strg.LoadECDSA(ctx, akey)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	if !ok {
		err := fmt.Errorf("ECDSA key not found")
		return nil, errutil.Wrap(err)
	}
	logger.Info(
		"loaded ECDSA key",
		slog.Int("key_count", len(keys)),
	)
	if len(keys) < 1 {
		err := fmt.Errorf("no ECDSA key found")
		return nil, errutil.Wrap(err)
	}

	pubkey, err := keyutil.PubKeyFromShareECDSA(ctx, keys[0])
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	dk := keyutil_ecdsa.NewDeriveKey(pubkey, index)
	if _, err := dk.UpdateKeyShare(ctx, keys...); err != nil {
		return nil, errutil.Wrap(err)
	}

	return keys, nil
}

func (a *App) deriveEdDSA(
	ctx context.Context,
	akey secutil.EncryptionKey,
	index uint32,
) ([]*eddsa.LocalPartySaveData, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "deriveEdDSA"),
		slog.Int("index", int(index)),
	)
	strg, err := a.getStorage(ctx)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	keys, ok, err := strg.LoadEdDSA(ctx, akey)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	if !ok {
		err := fmt.Errorf("EdDSA key not found")
		return nil, errutil.Wrap(err)
	}
	logger.Info(
		"loaded EdDSA key",
		slog.Int("key_count", len(keys)),
	)
	if len(keys) < 1 {
		err := fmt.Errorf("no EdDSA key found")
		return nil, errutil.Wrap(err)
	}

	pubkey, err := keyutil.PubKeyFromShareEdDSA(ctx, keys[0])
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	dk := keyutil_eddsa.NewDeriveKey(pubkey, index)
	if err := dk.UpdateKeyShare(ctx, keys...); err != nil {
		return nil, errutil.Wrap(err)
	}

	return keys, nil
}
