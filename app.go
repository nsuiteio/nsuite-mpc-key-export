package main

import (
	"context"
	_ "embed"
	"encoding/base64"
	"log/slog"
	"sync"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nsuiteio/nst-mpc-key-export/service/reconstruct"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/qrutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
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

// Reconstruct sample keyshares
func (a *App) Reconstruct() (string, error) {
	ecdsaBs, err := reconstruct.SampleECDSA(a.ctx)
	if err != nil {
		return "", err
	}
	eddsaBs, err := reconstruct.SampleEdDSA(a.ctx)
	if err != nil {
		return "", err
	}

	if err := a.saveECDSA(a.ctx, ecdsaBs); err != nil {
		return "", err
	}
	if err := a.saveEdDSA(a.ctx, eddsaBs); err != nil {
		return "", err
	}

	return "OK", nil
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

	encryptedPrivateKey, err := a.loadKeyPair(ctx)
	if err != nil {
		return "", err
	}
	privateKeyBs, err := akey.Decrypt(encryptedPrivateKey)
	if err != nil {
		return "", err
	}
	privateKey, err := secutil.EncryptionPrivateKeyFromBytes(privateKeyBs)
	if err != nil {
		return "", err
	}

	keyShares := make(map[string][]byte)
	for k, encryptedKeyShare := range encyptedKeyShares {
		logger.Info("decrypting key share", slog.String("key", k))
		plainKeyShare, err := privateKey.Decrypt(encryptedKeyShare)
		if err != nil {
			return "", err
		}
		keyShares[k] = plainKeyShare
	}

	// parse KeySahres

	return "OK", nil
}

func (a *App) GenerateKeyPair(password string) (string, error) {
	ctx := a.ctx

	akey, err := secutil.NewAESPassword(password)
	if err != nil {
		return "", err
	}
	privateKey, err := secutil.GenerateEncryptionKeyPair(
		ctx,
		secutil.EncryptionKeyPairTypeRSA,
	)
	if err != nil {
		return "", err
	}
	plainData := privateKey.MarshalToBytes()
	encriptedData, err := akey.Encrypt(plainData)
	if err != nil {
		return "", err
	}

	if err := a.saveKeyPair(ctx, encriptedData); err != nil {
		return "", err
	}

	pubkey := privateKey.PublicKey()
	bs, err := qrutil.GenerateQRCodePNG(pubkey.MarshalToBytes())
	if err != nil {
		return "", err
	}
	b64 := base64.StdEncoding.EncodeToString(bs)

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

func (a *App) saveKeyPair(ctx context.Context, bs []byte) error {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return errutil.Wrap(err)
	}
	return storage.Save(ctx, bs, pathEncryptionKey)
}

func (a *App) loadKeyPair(ctx context.Context) ([]byte, error) {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	return storage.Load(ctx, pathEncryptionKey)
}

func (a *App) saveECDSA(ctx context.Context, bs []byte) error {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return errutil.Wrap(err)
	}
	return storage.Save(ctx, bs, pathECDSA)
}

func (a *App) loadECDSA(ctx context.Context) ([]byte, error) {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	return storage.Load(ctx, pathECDSA)
}

func (a *App) saveEdDSA(ctx context.Context, bs []byte) error {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return errutil.Wrap(err)
	}
	return storage.Save(ctx, bs, pathEdDSA)
}

func (a *App) loadEdDSA(ctx context.Context) ([]byte, error) {
	storage, err := a.getStorage(ctx)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	return storage.Load(ctx, pathEdDSA)
}
