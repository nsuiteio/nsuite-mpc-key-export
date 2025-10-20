package main

import (
	"bytes"
	"context"
	_ "embed"
	"encoding/base64"
	"io"

	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"

	"github.com/nsuiteio/nst-mpc-key-export/service/reconstruct"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
)

// App struct
type App struct {
	config *cfgutil.WailsJson

	ctx context.Context
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

// Reconstruct returns sample private key
func (a *App) Reconstruct() (string, error) {
	ecdsaBs, err := reconstruct.SampleECDSA(a.ctx)
	if err != nil {
		return "", err
	}
	eddsaBs, err := reconstruct.SampleEdDSA(a.ctx)
	if err != nil {
		return "", err
	}

	storage, err := cfgutil.NewSecStorage(a.ctx, a.config.Name)
	if err != nil {
		return "", err
	}
	if err := storage.Save(a.ctx, ecdsaBs, "ecdsa.key"); err != nil {
		return "", err
	}
	if err := storage.Save(a.ctx, eddsaBs, "eddsa.key"); err != nil {
		return "", err
	}

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

	storage, err := cfgutil.NewSecStorage(ctx, a.config.Name)
	if err != nil {
		return "", err
	}
	if err := storage.Save(ctx, encriptedData, "encryption.key"); err != nil {
		return "", err
	}

	pubkey := privateKey.PublicKey()
	qrc, err := qrcode.New(string(pubkey.MarshalToBytes()))
	if err != nil {
		return "", err
	}

	var buf bytes.Buffer
	// bytes.Buffer を io.WriterCloser に変換
	wc := struct {
		io.Writer
		io.Closer
	}{
		Writer: &buf,
		Closer: io.NopCloser(nil), // 空の Close 実装
	}
	wr := standard.NewWithWriter(wc)
	if err := qrc.Save(wr); err != nil {
		return "", err
	}
	if err := wr.Close(); err != nil {
		return "", err
	}

	bs := buf.Bytes()
	b64 := base64.StdEncoding.EncodeToString(bs)

	return "data:image/png;base64," + b64, nil
}
