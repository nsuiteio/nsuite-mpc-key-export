package main

import (
	"context"
	"fmt"
	"log/slog"
	"sync"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nsuiteio/nst-mpc-key-export/service/derive"
	"github.com/nsuiteio/nst-mpc-key-export/service/exportpubkey"
	"github.com/nsuiteio/nst-mpc-key-export/service/keypairfile"
	"github.com/nsuiteio/nst-mpc-key-export/service/reconstruct"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/strutil"
)

// App はウォレット秘密鍵復元アプリ（エクスポート実行者用）。
// エクスポート準備担当者のキーペアファイルと
// 暗号化ウォレット秘密鍵ファイル（zip）を入力に、
// メモリ上でのみroot鍵を復元する。復元結果は一切永続化せず、
// アプリを終了するとすべて消える。
type App struct {
	config *cfgutil.WailsJson

	ctx context.Context

	// ダイアログはテストから差し替え可能にするため関数フィールドで持つ
	openFileDialog func(
		ctx context.Context, opts runtime.OpenDialogOptions,
	) (string, error)

	// 復元セッション（メモリ上のみ）
	lock      sync.Mutex
	keyPair   secutil.EncryptionPrivateKey
	rootECDSA *secp256k1.PrivateKey
	rootEdDSA *edwards.PrivateKey
	// generation はキーペアを選び直すたびに増える世代番号。
	// 進行中のzip復元がキーペア変更前のセッションへ結果を書き戻す
	// レースを防ぐ。
	generation uint64
}

// NewApp creates a new App application struct
func NewApp(config *cfgutil.WailsJson) *App {
	return &App{
		config:         config,
		openFileDialog: runtime.OpenFileDialog,
	}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = logutil.Setup(ctx, a.config.Name)
}

// KeyPairInfo は選択したキーペアファイルの公開鍵情報。
// フィンガープリントをキーペア生成時の記録と目視照合するために返す。
type KeyPairInfo struct {
	Fingerprint string `json:"fingerprint"`
	FilePath    string `json:"filePath"`
}

// ChooseKeyPairFile はエクスポート準備担当者のキーペアファイルを選択して
// 読み込む。選び直した場合、前のキーペアで復元したroot鍵は破棄する
// （鍵とファイルの対応を取り違えたまま導出させないため）。
func (a *App) ChooseKeyPairFile() (*KeyPairInfo, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "ChooseKeyPairFile"),
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
	// 選択キャンセルは空文字で返る。何もせずnilを返す。
	if path == "" {
		return nil, nil
	}

	privateKey, err := keypairfile.Load(path)
	if err != nil {
		return nil, err
	}

	a.lock.Lock()
	a.keyPair = privateKey
	a.rootECDSA = nil
	a.rootEdDSA = nil
	a.generation++
	a.lock.Unlock()

	logger.Info(
		"loaded key pair file",
		slog.String("path", path),
	)

	pubkeyBs := privateKey.PublicKey().MarshalToBytes()
	return &KeyPairInfo{
		Fingerprint: exportpubkey.FormatFingerprint(
			exportpubkey.Fingerprint(pubkeyBs),
		),
		FilePath: path,
	}, nil
}

// ChooseKeyShares は暗号化ウォレット秘密鍵ファイル（zip）を選択し、
// キーペアで復号してroot鍵をメモリ上に復元する。
// 成功時は"OK"、キャンセル時は空文字を返す。
func (a *App) ChooseKeyShares() (string, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "ChooseKeyShares"),
	)

	a.lock.Lock()
	keyPair := a.keyPair
	generation := a.generation
	a.lock.Unlock()
	if keyPair == nil {
		err := fmt.Errorf("key pair file is not selected")
		return "", err
	}

	file, err := a.openFileDialog(
		ctx, runtime.OpenDialogOptions{
			Title: "暗号化ウォレット秘密鍵ファイル（zip）を選択してください",
			Filters: []runtime.FileFilter{
				{
					DisplayName: "暗号化ウォレット秘密鍵ファイル (*.zip)",
					Pattern:     "*.zip",
				},
			},
		},
	)
	if err != nil {
		return "", err
	}
	// ファイル選択ダイアログのキャンセルは空文字で返る。エラーではなく
	// 「何もしなかった」として空文字を返し、フロント側で無視させる。
	if file == "" {
		return "", nil
	}

	// 新しいzipを選択した時点で既存のroot鍵を破棄する。以降の復元が
	// 失敗した場合に、前回復元した別のzip由来の鍵を取り出せてしまう
	// 状態を残さないため。
	a.lock.Lock()
	if a.generation == generation {
		a.rootECDSA = nil
		a.rootEdDSA = nil
	}
	a.lock.Unlock()

	keySharesECDSA, keySharesEdDSA, err := reconstruct.LoadFromZip(
		ctx,
		keyPair,
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

	const threshold = 3

	rootECDSA, err := reconstruct.ReconstructECDSA(
		ctx,
		threshold,
		keySharesECDSA,
	)
	if err != nil {
		return "", err
	}
	rootEdDSA, err := reconstruct.ReconstructEdDSA(
		ctx,
		threshold,
		keySharesEdDSA,
	)
	if err != nil {
		return "", err
	}

	a.lock.Lock()
	defer a.lock.Unlock()
	// 復元中にキーペアが選び直されていた場合は結果を書き戻さない
	// （別のキーペアの表示のまま、古いzipの鍵を導出させないため）。
	if a.generation != generation {
		err := fmt.Errorf(
			"key pair selection changed during restore",
		)
		return "", err
	}
	a.rootECDSA = rootECDSA
	a.rootEdDSA = rootEdDSA

	return "OK", nil
}

// GetPrivateKey は復元済みのroot鍵から、指定されたcurve種別とHDPath indexで
// 子秘密鍵を導出しhex文字列で返す。鍵素材はログに出力しない。
// expectedAddressにはDeriveAddressで確認済みのアドレスを渡す。導出結果の
// アドレスと一致しない場合（確認と異なるindex/curveの指定など）は
// 秘密鍵を返さずエラーにする。
func (a *App) GetPrivateKey(
	keyType string,
	index int32,
	expectedAddress string,
) (string, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "GetPrivateKey"),
		slog.String("key_type", keyType),
		slog.Int("index", int(index)),
	)
	logger.Info("started")

	prvBytes, address, err := a.deriveChild(keyType, index)
	if err != nil {
		return "", err
	}
	if address != expectedAddress {
		err := fmt.Errorf(
			"derived address does not match the confirmed address",
		)
		return "", err
	}
	logger.Info("derived child private key")
	return strutil.ToHex(prvBytes), nil
}

// DeriveAddress は復元済みのroot鍵から、指定されたcurve種別とHDPath indexで
// 子アドレス（ECDSA=EVM, EdDSA=Solana）を導出して返す。取り出し前の宛先確認と、
// 復元リハーサル（N Suite上のウォレットアドレスとの一致確認）に使う。
func (a *App) DeriveAddress(
	keyType string,
	index int32,
) (string, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "DeriveAddress"),
		slog.String("key_type", keyType),
		slog.Int("index", int(index)),
	)
	logger.Info("started")

	_, address, err := a.deriveChild(keyType, index)
	if err != nil {
		return "", err
	}
	// アドレスはアカウントを識別できる情報のためログに値は出さない。
	logger.Info("derived address")
	return address, nil
}

// deriveChild は復元済みroot鍵からindexで子秘密鍵とアドレスを導出する共通処理。
func (a *App) deriveChild(
	keyType string,
	index int32,
) ([]byte, string, error) {
	if index < 0 {
		err := fmt.Errorf("index must be non-negative: %d", index)
		return nil, "", err
	}

	a.lock.Lock()
	rootECDSA := a.rootECDSA
	rootEdDSA := a.rootEdDSA
	a.lock.Unlock()

	switch keyType {
	case "ECDSA":
		if rootECDSA == nil {
			return nil, "", fmt.Errorf("ECDSA key not restored")
		}
		child, address, err := derive.ECDSAChild(
			rootECDSA, uint32(index),
		)
		if err != nil {
			return nil, "", errutil.Wrap(err)
		}
		return child.Serialize(), address, nil
	case "EdDSA":
		if rootEdDSA == nil {
			return nil, "", fmt.Errorf("EdDSA key not restored")
		}
		child, address, err := derive.EdDSAChild(
			rootEdDSA, uint32(index),
		)
		if err != nil {
			return nil, "", errutil.Wrap(err)
		}
		return child.Serialize(), address, nil
	}
	return nil, "", fmt.Errorf("unknown key type")
}
