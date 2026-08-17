// Package keypairfile は、受取用キーペアをファイルとして保存・読込するための
// エンコード形式を提供する。
//
// キーペアファイルは平文で保存する（パスワード暗号化しない）。
// このツールの保管モデルは「受取用キーペア＝担当者A、エクスポートzip＝担当者B」
// の分離保管を主たる統制とし、キーペア単体の漏洩ではウォレット秘密鍵を
// 復元できない（zipが揃って初めて復元可能）。長期保管でのパスワード忘れによる
// バックアップ喪失リスクを避けるため、あえて暗号化レイヤーを持たない。
//
// フォーマット: [Magic 8バイト][Version 1バイト][キーペアバイト列]
// キーペアバイト列は secutil.EncryptionPrivateKey.MarshalToBytes() の出力
// （[keyType 1バイト] + PKCS#1 DER）。
package keypairfile

import (
	"errors"
	"fmt"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
)

// Magic はキーペアファイル先頭の識別子。zip等の別ファイルとの取り違えを
// 明確なエラーとして検出するために付与する（NST MPC Receiving Keypair）。
const Magic = "NSTMPCRK"

// Version は現行のファイル形式バージョン。
const Version byte = 0x01

// Extension はキーペアファイルの推奨拡張子。
const Extension = ".nstkey"

// DefaultFileName は保存ダイアログの初期ファイル名。
const DefaultFileName = "receiving-keypair" + Extension

var (
	// ErrNotKeyPairFile は入力がキーペアファイル形式でない場合のエラー。
	ErrNotKeyPairFile = errors.New(
		"not a key pair file (magic mismatch)",
	)
	// ErrUnsupportedVersion は未対応バージョンのファイルを読んだ場合のエラー。
	ErrUnsupportedVersion = errors.New(
		"unsupported key pair file version",
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
