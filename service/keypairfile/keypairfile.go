// Package keypairfile は、取出用キーペアをファイルとして保存・読込するための
// エンコード形式を提供する。
//
// キーペアファイルは平文で保存する（パスワード暗号化しない）。
// このツールの保管モデルは「取出用キーペア＝エクスポート準備担当者、
// 暗号化ウォレット秘密鍵ファイル＝エクスポート実行者」の分離保管を主たる統制と
// し、キーペア単体の漏洩ではウォレット秘密鍵を復元できない（暗号化ウォレット
// 秘密鍵ファイルが揃って初めて復元可能）。長期保管でのパスワード忘れによる
// 復元不能リスクを避けるため、あえて暗号化レイヤーを持たない。
//
// フォーマット: [Magic 8バイト][Version 1バイト][キーペアバイト列]
// キーペアバイト列は secutil.EncryptionPrivateKey.MarshalToBytes() の出力
// （[keyType 1バイト] + PKCS#1 DER）。
package keypairfile

import (
	"errors"
	"fmt"
	"os"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
)

// Magic はキーペアファイル先頭の識別子。zip等の別ファイルとの取り違えを
// 明確なエラーとして検出するために付与する。値は既存ファイルとの互換のため
// 変更しない（由来: NST MPC Receiving Keypair）。
const Magic = "NSTMPCRK"

// Version は現行のファイル形式バージョン。
const Version byte = 0x01

// Extension はキーペアファイルの推奨拡張子。
const Extension = ".nstkey"

// FileNamePrefix はキーペアファイル名の接頭辞。暗号化ウォレット秘密鍵
// ファイル（nsuite-mpc-export-<短縮FP>.zip）と接頭辞・フィンガープリント部を
// 揃えることで、2 つのファイルが対であることをファイル名だけで判別できる。
const FileNamePrefix = "nsuite-mpc-extraction-keypair-"

// BuildFileName は保存ダイアログの初期ファイル名を組み立てる。
// shortFingerprint には exportpubkey.ShortFingerprint の出力（hex 8 文字）を
// 渡す。hex のみなのでファイル名に使える文字だけで構成される。
func BuildFileName(shortFingerprint string) string {
	return FileNamePrefix + shortFingerprint + Extension
}

// MaxFileSize はキーペアファイルの上限サイズ。RSA-2048のキーペアは
// 2KB弱なので1MiBあれば十分で、取り違えた巨大ファイルの読み込みによる
// メモリ消費を防ぐ。
const MaxFileSize = 1 << 20

var (
	// ErrNotKeyPairFile は入力がキーペアファイル形式でない場合のエラー。
	ErrNotKeyPairFile = errors.New(
		"not a key pair file (magic mismatch)",
	)
	// ErrUnsupportedVersion は未対応バージョンのファイルを読んだ場合のエラー。
	ErrUnsupportedVersion = errors.New(
		"unsupported key pair file version",
	)
	// ErrFileTooLarge は上限サイズを超えるファイルを読んだ場合のエラー。
	ErrFileTooLarge = errors.New(
		"key pair file is too large",
	)
)

// Encode はキーペアをファイル保存用のバイト列にする。
func Encode(prv secutil.EncryptionPrivateKey) []byte {
	payload := prv.MarshalToBytes()
	bs := make([]byte, 0, len(Magic)+1+len(payload))
	bs = append(bs, []byte(Magic)...)
	bs = append(bs, Version)
	bs = append(bs, payload...)
	return bs
}

// Load はキーペアファイルを読み込んでキーペアに復元する。
// 読み込み前にサイズ上限を検査し、取り違えた巨大ファイルを弾く。
func Load(path string) (secutil.EncryptionPrivateKey, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	if info.Size() > MaxFileSize {
		err := fmt.Errorf(
			"%w: %d bytes",
			ErrFileTooLarge,
			info.Size(),
		)
		return nil, errutil.Wrap(err)
	}
	bs, err := os.ReadFile(path)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	return Decode(bs)
}

// Decode はファイルから読んだバイト列をキーペアに復元する。
func Decode(bs []byte) (secutil.EncryptionPrivateKey, error) {
	headerLen := len(Magic) + 1
	if len(bs) < headerLen {
		return nil, errutil.Wrap(ErrNotKeyPairFile)
	}
	if string(bs[:len(Magic)]) != Magic {
		return nil, errutil.Wrap(ErrNotKeyPairFile)
	}
	version := bs[len(Magic)]
	if version != Version {
		err := fmt.Errorf(
			"%w: %d",
			ErrUnsupportedVersion,
			version,
		)
		return nil, errutil.Wrap(err)
	}
	prv, err := secutil.EncryptionPrivateKeyFromBytes(bs[headerLen:])
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	return prv, nil
}
