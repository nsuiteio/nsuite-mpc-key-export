package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nsuiteio/nst-mpc-key-export/service/exportpubkey"
	"github.com/nsuiteio/nst-mpc-key-export/service/keypairfile"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	app := NewApp(&cfgutil.WailsJson{Name: "KeyPairGeneratorTest"})
	app.ctx = logutil.Setup(context.Background(), "test")
	return app
}

// stubSaveDialog は保存ダイアログを固定パス返却に差し替える。
func stubSaveDialog(app *App, path string) {
	app.saveFileDialog = func(
		_ context.Context, _ runtime.SaveDialogOptions,
	) (string, error) {
		return path, nil
	}
}

// stubOpenDialog はファイル選択ダイアログを固定パス返却に差し替える。
func stubOpenDialog(app *App, path string) {
	app.openFileDialog = func(
		_ context.Context, _ runtime.OpenDialogOptions,
	) (string, error) {
		return path, nil
	}
}

func TestGenerateKeyPair(t *testing.T) {
	t.Run("正常系_生成して選択先に保存し公開鍵情報を返す", func(t *testing.T) {
		app := newTestApp(t)
		path := filepath.Join(t.TempDir(), "receiving-keypair.nstkey")
		stubSaveDialog(app, path)

		got, err := app.GenerateKeyPair()
		require.NoError(t, err)
		require.NotNil(t, got)

		// 保存されたファイルがキーペアとして復元できる
		bs, err := os.ReadFile(path)
		require.NoError(t, err)
		prv, err := keypairfile.Decode(bs)
		require.NoError(t, err)

		// 返却された公開鍵情報が保存されたキーペアと一致する
		pubkeyBs := prv.PublicKey().MarshalToBytes()
		assert.Equal(t, exportpubkey.Payload(pubkeyBs), got.PublicKeyHex)
		assert.Equal(
			t,
			exportpubkey.FormatFingerprint(
				exportpubkey.Fingerprint(pubkeyBs),
			),
			got.Fingerprint,
		)
		assert.True(
			t,
			strings.HasPrefix(got.QRImage, "data:image/png;base64,"),
		)
		assert.Equal(t, path, got.FilePath)
	})

	t.Run("正常系_ファイルは所有者のみ読み書き可能な権限で保存される", func(t *testing.T) {
		app := newTestApp(t)
		path := filepath.Join(t.TempDir(), "receiving-keypair.nstkey")
		stubSaveDialog(app, path)

		_, err := app.GenerateKeyPair()
		require.NoError(t, err)

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})

	t.Run("正常系_保存キャンセルはnilを返しファイルを作らない", func(t *testing.T) {
		app := newTestApp(t)
		dir := t.TempDir()
		stubSaveDialog(app, "")

		got, err := app.GenerateKeyPair()
		require.NoError(t, err)
		assert.Nil(t, got)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Empty(t, entries)
	})

	t.Run("正常系_生成のたびに異なる鍵が生成される", func(t *testing.T) {
		app := newTestApp(t)
		dir := t.TempDir()
		path1 := filepath.Join(dir, "kp1.nstkey")
		path2 := filepath.Join(dir, "kp2.nstkey")

		stubSaveDialog(app, path1)
		got1, err := app.GenerateKeyPair()
		require.NoError(t, err)

		stubSaveDialog(app, path2)
		got2, err := app.GenerateKeyPair()
		require.NoError(t, err)

		assert.NotEqual(t, got1.PublicKeyHex, got2.PublicKeyHex)
	})
}

func TestShowKeyPairFile(t *testing.T) {
	t.Run("正常系_保存済みファイルの公開鍵情報を再表示できる", func(t *testing.T) {
		app := newTestApp(t)
		path := filepath.Join(t.TempDir(), "receiving-keypair.nstkey")
		stubSaveDialog(app, path)
		generated, err := app.GenerateKeyPair()
		require.NoError(t, err)

		stubOpenDialog(app, path)
		shown, err := app.ShowKeyPairFile()
		require.NoError(t, err)
		require.NotNil(t, shown)

		assert.Equal(t, generated.PublicKeyHex, shown.PublicKeyHex)
		assert.Equal(t, generated.Fingerprint, shown.Fingerprint)
		assert.Equal(t, generated.QRImage, shown.QRImage)
		assert.Equal(t, path, shown.FilePath)
	})

	t.Run("正常系_選択キャンセルはnilを返す", func(t *testing.T) {
		app := newTestApp(t)
		stubOpenDialog(app, "")

		got, err := app.ShowKeyPairFile()
		require.NoError(t, err)
		assert.Nil(t, got)
	})

	t.Run("異常系_キーペア以外のファイルは取り違えエラー", func(t *testing.T) {
		app := newTestApp(t)
		path := filepath.Join(t.TempDir(), "export.zip")
		require.NoError(
			t,
			os.WriteFile(path, []byte("PK\x03\x04dummy"), 0600),
		)
		stubOpenDialog(app, path)

		_, err := app.ShowKeyPairFile()
		assert.ErrorIs(t, err, keypairfile.ErrNotKeyPairFile)
	})
}
