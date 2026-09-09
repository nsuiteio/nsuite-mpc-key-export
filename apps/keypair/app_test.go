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

// testFileName はテストでの保存先ファイル名。保存ダイアログをスタブして
// いるため実装が組み立てる初期ファイル名とは独立だが、命名規則は合わせる。
const testFileName = "nsuite-mpc-extraction-keypair-ABCD1234.nstkey"

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

// captureSaveDialog は保存ダイアログを差し替え、渡されたオプションを
// 記録する。初期ファイル名（DefaultFilename）の検証に使う。
func captureSaveDialog(
	app *App, path string,
) *runtime.SaveDialogOptions {
	var captured runtime.SaveDialogOptions
	app.saveFileDialog = func(
		_ context.Context, opts runtime.SaveDialogOptions,
	) (string, error) {
		captured = opts
		return path, nil
	}
	return &captured
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
	// 保存ダイアログの初期ファイル名には、生成した公開鍵の短縮
	// フィンガープリントが入る。暗号化ウォレット秘密鍵ファイル
	// （nsuite-mpc-export-<短縮FP>.zip）と対であることを名前で判別できる。
	t.Run("正常系_初期ファイル名に短縮フィンガープリントが入る", func(t *testing.T) {
		app := newTestApp(t)
		path := filepath.Join(t.TempDir(), "saved.nstkey")
		opts := captureSaveDialog(app, path)

		got, err := app.GenerateKeyPair()
		require.NoError(t, err)
		require.NotNil(t, got)

		bs, err := os.ReadFile(path)
		require.NoError(t, err)
		prv, err := keypairfile.Decode(bs)
		require.NoError(t, err)
		short := exportpubkey.ShortFingerprint(
			exportpubkey.Fingerprint(prv.PublicKey().MarshalToBytes()),
		)

		assert.Equal(
			t,
			keypairfile.BuildFileName(short),
			opts.DefaultFilename,
		)
		assert.Regexp(
			t,
			`^nsuite-mpc-extraction-keypair-[0-9A-F]{8}\.nstkey$`,
			opts.DefaultFilename,
		)
	})

	t.Run("正常系_生成して選択先に保存し公開鍵情報を返す", func(t *testing.T) {
		app := newTestApp(t)
		path := filepath.Join(t.TempDir(), testFileName)
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
		// 表示の短縮はフロント側の責務。バックエンドは公開鍵すり替え検知に
		// 必要な全長（64桁）を返す。
		assert.Equal(
			t,
			exportpubkey.FormatFingerprint(
				exportpubkey.Fingerprint(pubkeyBs),
			),
			got.Fingerprint,
		)
		assert.Len(t, strings.ReplaceAll(got.Fingerprint, " ", ""), 64)
		assert.True(
			t,
			strings.HasPrefix(got.QRImage, "data:image/png;base64,"),
		)
		assert.Equal(t, path, got.FilePath)
	})

	t.Run("正常系_ファイルは所有者のみ読み書き可能な権限で保存される", func(t *testing.T) {
		app := newTestApp(t)
		path := filepath.Join(t.TempDir(), testFileName)
		stubSaveDialog(app, path)

		_, err := app.GenerateKeyPair()
		require.NoError(t, err)

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})

	t.Run("正常系_権限が緩い既存ファイルを上書きしても0600になる", func(t *testing.T) {
		app := newTestApp(t)
		path := filepath.Join(t.TempDir(), testFileName)
		// 既存の0644ファイル（過去に緩い権限で作られた想定）
		require.NoError(
			t,
			os.WriteFile(path, []byte("old content"), 0644),
		)
		stubSaveDialog(app, path)

		_, err := app.GenerateKeyPair()
		require.NoError(t, err)

		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0600), info.Mode().Perm())
	})

	t.Run("正常系_保存後に一時ファイルが残らない", func(t *testing.T) {
		app := newTestApp(t)
		dir := t.TempDir()
		path := filepath.Join(dir, testFileName)
		stubSaveDialog(app, path)

		_, err := app.GenerateKeyPair()
		require.NoError(t, err)

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		require.Len(t, entries, 1)
		assert.Equal(
			t, testFileName, entries[0].Name(),
		)
	})

	t.Run("異常系_保存失敗時は既存ファイルが無傷で残る", func(t *testing.T) {
		app := newTestApp(t)
		dir := t.TempDir()
		path := filepath.Join(dir, testFileName)

		// 有効な既存キーペアファイルを用意する
		stubSaveDialog(app, path)
		_, err := app.GenerateKeyPair()
		require.NoError(t, err)
		original, err := os.ReadFile(path)
		require.NoError(t, err)

		// ディレクトリを書き込み不可にして保存を失敗させる
		require.NoError(t, os.Chmod(dir, 0500))
		t.Cleanup(func() { _ = os.Chmod(dir, 0700) })

		_, err = app.GenerateKeyPair()
		require.Error(t, err)

		// 既存ファイルは切り詰められず無傷のまま
		require.NoError(t, os.Chmod(dir, 0700))
		got, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.Equal(t, original, got)
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
		path := filepath.Join(t.TempDir(), testFileName)
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
