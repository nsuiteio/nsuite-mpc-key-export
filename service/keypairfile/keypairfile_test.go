package keypairfile

import (
	"bytes"
	"context"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/nsuiteio/nst-mpc-key-export/service/exportpubkey"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
)

func genKeyPair(t *testing.T) secutil.EncryptionPrivateKey {
	t.Helper()
	prv, err := secutil.GenerateEncryptionKeyPair(
		context.Background(),
		secutil.EncryptionKeyPairTypeRSA,
	)
	require.NoError(t, err)
	return prv
}

func TestEncodeDecode(t *testing.T) {
	t.Run("正常系_ラウンドトリップで同一鍵が復元される", func(t *testing.T) {
		prv := genKeyPair(t)

		encoded := Encode(prv)
		decoded, err := Decode(encoded)
		require.NoError(t, err)

		// 公開鍵バイト列の一致で同一鍵であることを確認する
		assert.Equal(
			t,
			prv.PublicKey().MarshalToBytes(),
			decoded.PublicKey().MarshalToBytes(),
		)

		// 復元した秘密鍵で実際に復号できることを確認する
		plain := []byte("mpc key export test payload")
		cipher, err := prv.PublicKey().Encrypt(plain)
		require.NoError(t, err)
		got, err := decoded.Decrypt(cipher)
		require.NoError(t, err)
		assert.Equal(t, plain, got)
	})

	t.Run("正常系_エンコード結果はマジックバイトで始まる", func(t *testing.T) {
		prv := genKeyPair(t)
		encoded := Encode(prv)
		assert.True(t, bytes.HasPrefix(encoded, []byte(Magic)))
	})

	t.Run("異常系_マジック不一致はErrNotKeyPairFile", func(t *testing.T) {
		// zipファイルの先頭バイト列（PK..）を模した取り違え入力
		zipLike := append(
			[]byte{0x50, 0x4B, 0x03, 0x04},
			bytes.Repeat([]byte{0x00}, 32)...,
		)
		_, err := Decode(zipLike)
		assert.ErrorIs(t, err, ErrNotKeyPairFile)
	})

	t.Run("異常系_短すぎる入力はErrNotKeyPairFile", func(t *testing.T) {
		_, err := Decode([]byte("NST"))
		assert.ErrorIs(t, err, ErrNotKeyPairFile)
	})

	t.Run("異常系_未対応バージョンはErrUnsupportedVersion", func(t *testing.T) {
		prv := genKeyPair(t)
		encoded := Encode(prv)
		encoded[len(Magic)] = 0xFF
		_, err := Decode(encoded)
		assert.ErrorIs(t, err, ErrUnsupportedVersion)
	})

	t.Run("正常系_Loadでファイルから読み込める", func(t *testing.T) {
		prv := genKeyPair(t)
		path := filepath.Join(t.TempDir(), "kp.nstkey")
		require.NoError(t, os.WriteFile(path, Encode(prv), 0600))

		decoded, err := Load(path)
		require.NoError(t, err)
		assert.Equal(
			t,
			prv.PublicKey().MarshalToBytes(),
			decoded.PublicKey().MarshalToBytes(),
		)
	})

	t.Run("異常系_上限サイズを超えるファイルはErrFileTooLarge", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "huge.nstkey")
		huge := make([]byte, MaxFileSize+1)
		copy(huge, []byte(Magic))
		require.NoError(t, os.WriteFile(path, huge, 0600))

		_, err := Load(path)
		assert.ErrorIs(t, err, ErrFileTooLarge)
	})

	t.Run("異常系_存在しないファイルのLoadはエラー", func(t *testing.T) {
		_, err := Load(
			filepath.Join(t.TempDir(), "missing.nstkey"),
		)
		assert.Error(t, err)
	})

	t.Run("異常系_ペイロード破損はエラー", func(t *testing.T) {
		prv := genKeyPair(t)
		encoded := Encode(prv)
		// ヘッダは保持しペイロードを破壊する
		corrupt := encoded[:len(Magic)+1]
		corrupt = append(corrupt, 0xDE, 0xAD)
		_, err := Decode(corrupt)
		assert.Error(t, err)
	})
}

func TestBuildFileName(t *testing.T) {
	t.Run("正常系_短縮フィンガープリント付きの名前を返す", func(t *testing.T) {
		assert.Equal(
			t,
			"nsuite-mpc-extraction-keypair-ABCD1234.nstkey",
			BuildFileName("ABCD1234"),
		)
	})

	// 暗号化ウォレット秘密鍵ファイル（nsuite-mpc-export-<FP>.zip）と
	// プレフィックス・フィンガープリント部を揃え、2ファイルが対であることを
	// ファイル名だけで判別できるようにしている。
	t.Run("正常系_公開鍵バイト列からの固定ベクタ", func(t *testing.T) {
		pubkeyBs, err := hex.DecodeString(
			"00306e73742d6d70632d6b65792d6578706f7274" +
				"2066696e6765727072696e74207465737420766563746f72",
		)
		require.NoError(t, err)

		short := exportpubkey.ShortFingerprint(
			exportpubkey.Fingerprint(pubkeyBs),
		)
		assert.Equal(
			t,
			"nsuite-mpc-extraction-keypair-F570C28F.nstkey",
			BuildFileName(short),
		)
	})

	t.Run("正常系_空の短縮値は短縮値なしの既定名になる", func(t *testing.T) {
		got := BuildFileName("")
		assert.Equal(t, "nsuite-mpc-extraction-keypair.nstkey", got)
		assert.NotContains(t, got, string(filepath.Separator))
	})

	t.Run("正常系_拡張子は既存の Extension と一致する", func(t *testing.T) {
		assert.Equal(
			t, Extension, filepath.Ext(BuildFileName("ABCD1234")),
		)
	})
}

// BuildFileName はファイル名を組み立てるため、想定外の入力でも
// パス区切りや親ディレクトリ参照を含む名前を作らないこと。
// 想定入力は exportpubkey.ShortFingerprint の出力（hex 8 文字）で、
// それ以外は短縮値を省いた安全な既定名にフォールバックする。
func TestBuildFileName_RejectsUnexpectedInput(t *testing.T) {
	const fallback = "nsuite-mpc-extraction-keypair" + Extension
	cases := map[string]string{
		"":                fallback,
		"ABCD123":         fallback, // 8 文字未満
		"ABCD12345":       fallback, // 8 文字超過
		"abcd1234":        fallback, // 小文字（ShortFingerprint は大文字を返す）
		"ABCD12G4":        fallback, // 非 hex
		"../../etc/passw": fallback,
		"AB/CD1234":       fallback,
	}
	for in, want := range cases {
		got := BuildFileName(in)
		assert.Equal(t, want, got, "BuildFileName(%q)", in)
		assert.NotContains(t, got, "/")
		assert.NotContains(t, got, `\`)
		assert.NotContains(t, got, "..")
	}
}
