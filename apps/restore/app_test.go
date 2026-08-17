package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nsuiteio/nst-mpc-key-export/internal/testfixture"
	"github.com/nsuiteio/nst-mpc-key-export/service/derive"
	"github.com/nsuiteio/nst-mpc-key-export/service/exportpubkey"
	"github.com/nsuiteio/nst-mpc-key-export/service/keypairfile"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/strutil"
)

func newTestApp(t *testing.T) *App {
	t.Helper()
	app := NewApp(&cfgutil.WailsJson{Name: "KeyRestoreTest"})
	app.ctx = logutil.Setup(context.Background(), "test")
	return app
}

// stubOpenDialog はファイル選択ダイアログを固定パス返却に差し替える。
func stubOpenDialog(app *App, path string) {
	app.openFileDialog = func(
		_ context.Context, _ runtime.OpenDialogOptions,
	) (string, error) {
		return path, nil
	}
}

// writeFixtureKeyPairFile はフィクスチャの受取用キーペアをファイルに書き出す。
func writeFixtureKeyPairFile(t *testing.T, dir string) string {
	t.Helper()
	prv, err := testfixture.RSAPrivateKey()
	require.NoError(t, err)
	path := filepath.Join(dir, "receiving-keypair.nstkey")
	require.NoError(
		t,
		os.WriteFile(path, keypairfile.Encode(prv), 0600),
	)
	return path
}

// writeFixtureZip はフィクスチャのエクスポートzipをファイルに書き出す。
func writeFixtureZip(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "keyshares.zip")
	require.NoError(t, testfixture.WriteKeyShareZip(path))
	return path
}

// restoreSession はキーペア選択→zip選択まで完了した状態のAppを作る。
func restoreSession(t *testing.T) *App {
	t.Helper()
	app := newTestApp(t)
	dir := t.TempDir()

	stubOpenDialog(app, writeFixtureKeyPairFile(t, dir))
	_, err := app.ChooseKeyPairFile()
	require.NoError(t, err)

	stubOpenDialog(app, writeFixtureZip(t, dir))
	result, err := app.ChooseKeyShares()
	require.NoError(t, err)
	require.Equal(t, "OK", result)
	return app
}

// fixtureECDSARoot はフィクスチャの期待root鍵（ECDSA）を返す。
func fixtureECDSARoot(t *testing.T) *secp256k1.PrivateKey {
	t.Helper()
	bs, err := strutil.FromHex(testfixture.SamplePrivateKeyECDSAHex)
	require.NoError(t, err)
	return secp256k1.PrivKeyFromBytes(bs)
}

func TestChooseKeyPairFile(t *testing.T) {
	t.Run("正常系_キーペアファイルを読み込み公開鍵情報を返す", func(t *testing.T) {
		app := newTestApp(t)
		path := writeFixtureKeyPairFile(t, t.TempDir())
		stubOpenDialog(app, path)

		got, err := app.ChooseKeyPairFile()
		require.NoError(t, err)
		require.NotNil(t, got)

		prv, err := testfixture.RSAPrivateKey()
		require.NoError(t, err)
		pubkeyBs := prv.PublicKey().MarshalToBytes()
		assert.Equal(
			t,
			exportpubkey.FormatFingerprint(
				exportpubkey.Fingerprint(pubkeyBs),
			),
			got.Fingerprint,
		)
		assert.Equal(t, path, got.FilePath)
	})

	t.Run("正常系_選択キャンセルはnilを返す", func(t *testing.T) {
		app := newTestApp(t)
		stubOpenDialog(app, "")

		got, err := app.ChooseKeyPairFile()
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

		_, err := app.ChooseKeyPairFile()
		assert.ErrorIs(t, err, keypairfile.ErrNotKeyPairFile)
	})

	t.Run("正常系_キーペアを選び直すと復元セッションはリセットされる", func(t *testing.T) {
		app := restoreSession(t)

		// 復元済みの状態でキーペアを選び直す
		stubOpenDialog(app, writeFixtureKeyPairFile(t, t.TempDir()))
		_, err := app.ChooseKeyPairFile()
		require.NoError(t, err)

		// 前のセッションのroot鍵では導出できない
		_, err = app.DeriveAddress("ECDSA", 0)
		assert.Error(t, err)
	})
}

func TestChooseKeyShares(t *testing.T) {
	t.Run("正常系_zipを復号しroot鍵を復元する", func(t *testing.T) {
		app := restoreSession(t)
		// restoreSession内で"OK"が返ることを確認済み。
		// 復元後は導出が可能になっている。
		_, err := app.DeriveAddress("ECDSA", 0)
		assert.NoError(t, err)
	})

	t.Run("異常系_キーペア未選択ではzipを選択できない", func(t *testing.T) {
		app := newTestApp(t)
		stubOpenDialog(app, writeFixtureZip(t, t.TempDir()))

		_, err := app.ChooseKeyShares()
		assert.Error(t, err)
	})

	t.Run("正常系_選択キャンセルは空文字を返す", func(t *testing.T) {
		app := newTestApp(t)
		dir := t.TempDir()
		stubOpenDialog(app, writeFixtureKeyPairFile(t, dir))
		_, err := app.ChooseKeyPairFile()
		require.NoError(t, err)

		stubOpenDialog(app, "")
		got, err := app.ChooseKeyShares()
		require.NoError(t, err)
		assert.Equal(t, "", got)
	})

	t.Run("異常系_別のキーペアではzipを復号できない", func(t *testing.T) {
		app := newTestApp(t)
		dir := t.TempDir()

		// zipの暗号化に使われたものとは別のキーペアを選択する
		other, err := secutil.GenerateEncryptionKeyPair(
			context.Background(),
			secutil.EncryptionKeyPairTypeRSA,
		)
		require.NoError(t, err)
		otherPath := filepath.Join(dir, "other.nstkey")
		require.NoError(
			t,
			os.WriteFile(
				otherPath, keypairfile.Encode(other), 0600,
			),
		)
		stubOpenDialog(app, otherPath)
		_, err = app.ChooseKeyPairFile()
		require.NoError(t, err)

		stubOpenDialog(app, writeFixtureZip(t, dir))
		_, err = app.ChooseKeyShares()
		assert.Error(t, err)
	})
}

func TestDeriveAddress(t *testing.T) {
	t.Run("正常系_ECDSAはderiveサービスと同じEVMアドレスを返す", func(t *testing.T) {
		app := restoreSession(t)

		got, err := app.DeriveAddress("ECDSA", 0)
		require.NoError(t, err)

		_, want, err := derive.ECDSAChild(fixtureECDSARoot(t), 0)
		require.NoError(t, err)
		assert.Equal(t, want, got)
	})

	t.Run("正常系_EdDSAはSolanaアドレスを返す", func(t *testing.T) {
		app := restoreSession(t)

		got, err := app.DeriveAddress("EdDSA", 1)
		require.NoError(t, err)
		assert.NotEmpty(t, got)
	})

	t.Run("異常系_復元前は導出できない", func(t *testing.T) {
		app := newTestApp(t)
		_, err := app.DeriveAddress("ECDSA", 0)
		assert.Error(t, err)
	})

	t.Run("異常系_不明なkeyTypeはエラー", func(t *testing.T) {
		app := restoreSession(t)
		_, err := app.DeriveAddress("RSA", 0)
		assert.Error(t, err)
	})

	t.Run("異常系_負のindexはエラー", func(t *testing.T) {
		app := restoreSession(t)
		_, err := app.DeriveAddress("ECDSA", -1)
		assert.Error(t, err)
	})
}

func TestGetPrivateKey(t *testing.T) {
	t.Run("正常系_確認済みアドレスと一致すれば子秘密鍵を返す", func(t *testing.T) {
		app := restoreSession(t)

		address, err := app.DeriveAddress("ECDSA", 0)
		require.NoError(t, err)

		got, err := app.GetPrivateKey("ECDSA", 0, address)
		require.NoError(t, err)

		child, _, err := derive.ECDSAChild(fixtureECDSARoot(t), 0)
		require.NoError(t, err)
		assert.Equal(t, strutil.ToHex(child.Serialize()), got)
	})

	t.Run("異常系_確認済みアドレスと不一致なら秘密鍵を返さない", func(t *testing.T) {
		app := restoreSession(t)

		got, err := app.GetPrivateKey(
			"ECDSA", 0, "0x0000000000000000000000000000000000000000",
		)
		assert.Error(t, err)
		assert.Empty(t, got)
	})

	t.Run("異常系_復元前は取り出せない", func(t *testing.T) {
		app := newTestApp(t)
		_, err := app.GetPrivateKey("ECDSA", 0, "0xdummy")
		assert.Error(t, err)
	})
}
