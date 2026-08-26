package main

import (
	"context"
	"fmt"
	"log/slog"
	"math"
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

// App はウォレット秘密鍵復元アプリ（担当者B用）。
// 担当者Aのキーペアファイルと担当者Bのエクスポートzipを入力に、
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
// フィンガープリントを鍵ペア生成時の記録と目視照合するために返す。
type KeyPairInfo struct {
	Fingerprint string `json:"fingerprint"`
	FilePath    string `json:"filePath"`
}

// ChooseKeyPairFile は担当者Aのキーペアファイルを選択して読み込む。
// 選び直した場合、前のキーペアで復元したroot鍵は破棄する
// （鍵とzipの対応を取り違えたまま導出させないため）。
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

// ChooseKeyShares はエクスポートzipを選択し、キーペアで復号して
// root鍵をメモリ上に復元する。成功時は"OK"、キャンセル時は空文字を返す。
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
			Title: "エクスポートzipファイルを選択してください",
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
// バックアップ検証（N Suite上のウォレットアドレスとの一致確認）に使う。
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

// AddressEntry はアドレス一覧の1件分（HDPath indexとアドレスの組）。
type AddressEntry struct {
	Index   int32  `json:"index"`
	Address string `json:"address"`
}

// deriveAddressesMaxCount は一括導出の1回あたり上限。フロントは8件ずつ
// 要求するが、不正な呼び出しで大量導出させないための防御。
const deriveAddressesMaxCount = 100

// DeriveAddresses は復元済みのroot鍵から、startIndexからcount件分の
// 子アドレスを一括導出して返す。取り出し対象をアドレス一覧から
// 選択させるための表示用で、秘密鍵は返さない。
func (a *App) DeriveAddresses(
	keyType string,
	startIndex int32,
	count int32,
) ([]AddressEntry, error) {
	ctx := a.ctx
	logger := logutil.Get(ctx).With(
		slog.String("function", "DeriveAddresses"),
		slog.String("key_type", keyType),
		slog.Int("start_index", int(startIndex)),
		slog.Int("count", int(count)),
	)
	logger.Info("started")

	if count < 1 || count > deriveAddressesMaxCount {
		err := fmt.Errorf(
			"count must be between 1 and %d: %d",
			deriveAddressesMaxCount, count,
		)
		return nil, err
	}
	if startIndex < 0 {
		err := fmt.Errorf(
			"start index must be non-negative: %d", startIndex,
		)
		return nil, err
	}
	// 終端index（startIndex + count - 1）のint32オーバーフローを拒否する。
	// 終端がちょうどMaxInt32になる場合は正常。
	if startIndex > math.MaxInt32-(count-1) {
		err := fmt.Errorf(
			"index range exceeds int32: start=%d count=%d",
			startIndex, count,
		)
		return nil, err
	}

	entries := make([]AddressEntry, 0, count)
	for i := int32(0); i < count; i++ {
		index := startIndex + i
		_, address, err := a.deriveChild(keyType, index)
		if err != nil {
			return nil, err
		}
		entries = append(entries, AddressEntry{
			Index:   index,
			Address: address,
		})
	}
	// アドレスはアカウントを識別できる情報のためログに値は出さない。
	logger.Info("derived addresses")
	return entries, nil
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
