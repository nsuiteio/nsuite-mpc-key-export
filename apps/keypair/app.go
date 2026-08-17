package main

import (
	"context"
	"encoding/base64"
	"log/slog"
	"os"

	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nsuiteio/nst-mpc-key-export/service/exportpubkey"
	"github.com/nsuiteio/nst-mpc-key-export/service/keypairfile"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/qrutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
)

// App は受取用キーペア生成アプリ（担当者A用）。
// 鍵素材はユーザーが明示的に選んだファイルにのみ書き出し、
// アプリ自身は何も永続化しない。
type App struct {
	config *cfgutil.WailsJson

	ctx context.Context

	// ダイアログはテストから差し替え可能にするため関数フィールドで持つ
	saveFileDialog func(
		ctx context.Context, opts runtime.SaveDialogOptions,
	) (string, error)
	openFileDialog func(
		ctx context.Context, opts runtime.OpenDialogOptions,
	) (string, error)
}

// NewApp creates a new App application struct
func NewApp(config *cfgutil.WailsJson) *App {
	return &App{
		config:         config,
		saveFileDialog: runtime.SaveFileDialog,
		openFileDialog: runtime.OpenFileDialog,
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = logutil.Setup(ctx, a.config.Name)
}

// GeneratedKeyPair は鍵ペアの公開鍵情報。すべて同一の公開鍵から生成される。
type GeneratedKeyPair struct {
	QRImage      string `json:"qrImage"`
	Fingerprint  string `json:"fingerprint"`
	PublicKeyHex string `json:"publicKeyHex"`
	FilePath     string `json:"filePath"`
}

// GenerateKeyPair は受取用キーペアを新規生成し、ユーザーが選んだ保存先へ
// キーペアファイルとして書き出す。保存がキャンセルされた場合は何も残さず
// nil を返す（フロント側は無操作として扱う）。
func (a *App) GenerateKeyPair() (*GeneratedKeyPair, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "GenerateKeyPair"),
	)

	privateKey, err := secutil.GenerateEncryptionKeyPair(
		ctx,
		secutil.EncryptionKeyPairTypeRSA,
	)
	if err != nil {
		return nil, err
	}

	path, err := a.saveFileDialog(
		ctx, runtime.SaveDialogOptions{
			Title:           "キーペアファイルの保存先を選択してください",
			DefaultFilename: keypairfile.DefaultFileName,
			Filters: []runtime.FileFilter{
				{
					DisplayName: "キーペアファイル (*" +
						keypairfile.Extension + ")",
					Pattern: "*" + keypairfile.Extension,
				},
			},
		},
	)
	if err != nil {
		return nil, err
	}
	// 保存ダイアログのキャンセルは空文字で返る。鍵はどこにも残さず破棄する。
	if path == "" {
		return nil, nil
	}

	// 鍵素材はユーザーが選んだファイルにのみ書き出す（所有者のみ読み書き可）
	if err := os.WriteFile(
		path, keypairfile.Encode(privateKey), 0600,
	); err != nil {
		return nil, errutil.Wrap(err)
	}
	logger.Info(
		"saved key pair file",
		slog.String("path", path),
	)

	return buildKeyPairInfo(privateKey, path)
}

// ShowKeyPairFile は保存済みキーペアファイルを選択して読み込み、
// 公開鍵情報（QR・フィンガープリント・hex）を再表示する。
// 2回目以降のエクスポートで公開鍵を再提示するために使う。
func (a *App) ShowKeyPairFile() (*GeneratedKeyPair, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "ShowKeyPairFile"),
	)

	path, err := a.openFileDialog(
		ctx, runtime.OpenDialogOptions{
			Title: "キーペアファイルを選択してください",
			Filters: []runtime.FileFilter{
				{
					DisplayName: "キーペアファイル (*" +
						keypairfile.Extension + ")",
					Pattern: "*" + keypairfile.Extension,
				},
			},
		},
	)
	if err != nil {
		return nil, err
	}
	if path == "" {
		return nil, nil
	}

	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	privateKey, err := keypairfile.Decode(bs)
	if err != nil {
		return nil, err
	}
	logger.Info(
		"loaded key pair file",
		slog.String("path", path),
	)

	return buildKeyPairInfo(privateKey, path)
}

// buildKeyPairInfo は公開鍵情報を単一の鍵スナップショットから組み立てる。
// QR・フィンガープリント・hex は同一の pubkeyBs から生成し、別々の読み直しに
// よる鍵不一致を防ぐ。QR ペイロードは hex 文字列（モバイル側パーサーの期待
// 形式。生バイナリはスキャナの文字列経由で不可逆に破損するため不可）。
func buildKeyPairInfo(
	privateKey secutil.EncryptionPrivateKey,
	path string,
) (*GeneratedKeyPair, error) {
	pubkeyBs := privateKey.PublicKey().MarshalToBytes()
	payload := exportpubkey.Payload(pubkeyBs)
	png, err := qrutil.GenerateQRCodePNG([]byte(payload))
	if err != nil {
		return nil, err
	}
	b64 := base64.StdEncoding.EncodeToString(png)

	return &GeneratedKeyPair{
		QRImage: "data:image/png;base64," + b64,
		Fingerprint: exportpubkey.FormatFingerprint(
			exportpubkey.Fingerprint(pubkeyBs),
		),
		PublicKeyHex: payload,
		FilePath:     path,
	}, nil
}
