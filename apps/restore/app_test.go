package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/wailsapp/wails/v2/pkg/runtime"

	"github.com/nsuiteio/nsuite-mpc-key-export/internal/testfixture"
	"github.com/nsuiteio/nsuite-mpc-key-export/service/derive"
	"github.com/nsuiteio/nsuite-mpc-key-export/service/exportpubkey"
	"github.com/nsuiteio/nsuite-mpc-key-export/service/keypairfile"
	"github.com/nsuiteio/nsuite-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nsuite-mpc-key-export/utility/logutil"
	"github.com/nsuiteio/nsuite-mpc-key-export/utility/secutil"
	"github.com/nsuiteio/nsuite-mpc-key-export/utility/strutil"
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

// writeFixtureKeyPairFile はフィクスチャの取出用キーペアをファイルに書き出す。
func writeFixtureKeyPairFile(t *testing.T, dir string) string {
	t.Helper()
	prv, err := testfixture.RSAPrivateKey()
	require.NoError(t, err)
	path := filepath.Join(dir, "nsuite-mpc-extraction-keypair-ABCD1234.nstkey")
	require.NoError(
		t,
		os.WriteFile(path, keypairfile.Encode(prv), 0600),
	)
	return path
}

// writeFixtureZip はフィクスチャの暗号化ウォレット秘密鍵ファイル（zip）を
// ファイルに書き出す。
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

// fixtureEdDSARoot はフィクスチャの期待root鍵（EdDSA）を返す。
func fixtureEdDSARoot(t *testing.T) *edwards.PrivateKey {
	t.Helper()
	bs, err := strutil.FromHex(testfixture.SamplePrivateKeyEdDSAHex)
	require.NoError(t, err)
	prv, _, err := edwards.PrivKeyFromScalar(bs)
	require.NoError(t, err)
	return prv
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
		assert.Equal(t, path, got.FilePath)
	})

	// ファイル名の命名規則を変更する前（receiving-keypair.nstkey）に保存された
	// ファイルも開けること。読み込みはファイル名でなく Magic ヘッダーで判定し、
	// 保存フォーマット自体は変更していないため互換が保たれる。
	t.Run("正常系_旧命名のファイルもそのまま読み込める", func(t *testing.T) {
		app := newTestApp(t)
		prv, err := testfixture.RSAPrivateKey()
		require.NoError(t, err)
		path := filepath.Join(t.TempDir(), "receiving-keypair.nstkey")
		require.NoError(
			t,
			os.WriteFile(path, keypairfile.Encode(prv), 0600),
		)
		stubOpenDialog(app, path)

		got, err := app.ChooseKeyPairFile()
		require.NoError(t, err)
		require.NotNil(t, got)
		assert.Equal(
			t,
			exportpubkey.FormatFingerprint(
				exportpubkey.Fingerprint(
					prv.PublicKey().MarshalToBytes(),
				),
			),
			got.Fingerprint,
		)
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

func TestChooseKeySharesSessionInvalidation(t *testing.T) {
	t.Run("異常系_復元済み後に壊れたzipで失敗すると旧root鍵は使えない", func(t *testing.T) {
		app := restoreSession(t)

		// 復元済みであることを確認
		_, err := app.DeriveAddress("ECDSA", 0)
		require.NoError(t, err)

		// 壊れたzipを選択して復元に失敗する
		brokenPath := filepath.Join(t.TempDir(), "broken.zip")
		require.NoError(
			t,
			os.WriteFile(
				brokenPath, []byte("not a zip file"), 0600,
			),
		)
		stubOpenDialog(app, brokenPath)
		_, err = app.ChooseKeyShares()
		require.Error(t, err)

		// 失敗後は前回復元したroot鍵も利用できない
		_, err = app.DeriveAddress("ECDSA", 0)
		assert.Error(t, err)
	})

	t.Run("正常系_選択キャンセルなら復元済みセッションは維持される", func(t *testing.T) {
		app := restoreSession(t)

		stubOpenDialog(app, "")
		got, err := app.ChooseKeyShares()
		require.NoError(t, err)
		require.Equal(t, "", got)

		// キャンセルは「何もしなかった」なので旧セッションは有効なまま
		_, err = app.DeriveAddress("ECDSA", 0)
		assert.NoError(t, err)
	})

	t.Run("異常系_zip復元中にキーペアが選び直されたら結果を書き戻さない", func(t *testing.T) {
		app := newTestApp(t)
		dir := t.TempDir()

		stubOpenDialog(app, writeFixtureKeyPairFile(t, dir))
		_, err := app.ChooseKeyPairFile()
		require.NoError(t, err)

		// 別のキーペアファイルを用意する
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

		// zip選択ダイアログの最中にキーペアが選び直される状況を模擬する
		zipPath := writeFixtureZip(t, dir)
		app.openFileDialog = func(
			_ context.Context, _ runtime.OpenDialogOptions,
		) (string, error) {
			stubOpenDialog(app, otherPath)
			if _, err := app.ChooseKeyPairFile(); err != nil {
				return "", err
			}
			return zipPath, nil
		}

		// zipの復号自体は元のキーペアのスナップショットで成功するが、
		// セッションが変わっているため結果は書き戻されない
		_, err = app.ChooseKeyShares()
		assert.Error(t, err)

		_, err = app.DeriveAddress("ECDSA", 0)
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

func TestDeriveAddresses(t *testing.T) {
	t.Run("正常系_ECDSAの各要素は単発のDeriveAddressと一致する", func(t *testing.T) {
		app := restoreSession(t)

		got, err := app.DeriveAddresses("ECDSA", 0, 8)
		require.NoError(t, err)
		require.Len(t, got, 8)

		for i, entry := range got {
			assert.Equal(t, int32(i), entry.Index)
			want, err := app.DeriveAddress("ECDSA", int32(i))
			require.NoError(t, err)
			assert.Equal(t, want, entry.Address)
		}
	})

	t.Run("正常系_EdDSAの各要素は単発のDeriveAddressと一致する", func(t *testing.T) {
		app := restoreSession(t)

		got, err := app.DeriveAddresses("EdDSA", 0, 8)
		require.NoError(t, err)
		require.Len(t, got, 8)

		for i, entry := range got {
			assert.Equal(t, int32(i), entry.Index)
			want, err := app.DeriveAddress("EdDSA", int32(i))
			require.NoError(t, err)
			assert.Equal(t, want, entry.Address)
		}
	})

	t.Run("正常系_startIndexのオフセットが反映される", func(t *testing.T) {
		app := restoreSession(t)

		got, err := app.DeriveAddresses("ECDSA", 8, 8)
		require.NoError(t, err)
		require.Len(t, got, 8)
		assert.Equal(t, int32(8), got[0].Index)

		want, err := app.DeriveAddress("ECDSA", 8)
		require.NoError(t, err)
		assert.Equal(t, want, got[0].Address)
	})

	t.Run("異常系_復元前は導出できない", func(t *testing.T) {
		app := newTestApp(t)
		_, err := app.DeriveAddresses("ECDSA", 0, 8)
		assert.Error(t, err)
	})

	t.Run("異常系_負のstartIndexはエラー", func(t *testing.T) {
		app := restoreSession(t)
		_, err := app.DeriveAddresses("ECDSA", -1, 8)
		assert.Error(t, err)
	})

	t.Run("異常系_countが0以下はエラー", func(t *testing.T) {
		app := restoreSession(t)
		_, err := app.DeriveAddresses("ECDSA", 0, 0)
		assert.Error(t, err)
	})

	t.Run("異常系_countが上限を超えるとエラー", func(t *testing.T) {
		app := restoreSession(t)
		_, err := app.DeriveAddresses("ECDSA", 0, 101)
		assert.Error(t, err)
	})

	t.Run("正常系_終端がちょうどMaxInt32なら導出できる", func(t *testing.T) {
		app := restoreSession(t)

		got, err := app.DeriveAddresses("ECDSA", 2147483647-7, 8)
		require.NoError(t, err)
		require.Len(t, got, 8)
		assert.Equal(t, int32(2147483647), got[7].Index)

		want, err := app.DeriveAddress("ECDSA", 2147483647)
		require.NoError(t, err)
		assert.Equal(t, want, got[7].Address)
	})

	t.Run("異常系_終端がMaxInt32を超えるとエラー", func(t *testing.T) {
		app := restoreSession(t)
		_, err := app.DeriveAddresses("ECDSA", 2147483647-6, 8)
		assert.Error(t, err)
	})

	t.Run("異常系_startIndexとcountの合計がint32を超えるとエラー", func(t *testing.T) {
		app := restoreSession(t)
		_, err := app.DeriveAddresses("ECDSA", 2147483647, 8)
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

	t.Run("正常系_EdDSAも確認済みアドレスと一致すれば子秘密鍵を返す", func(t *testing.T) {
		app := restoreSession(t)

		address, err := app.DeriveAddress("EdDSA", 0)
		require.NoError(t, err)

		got, err := app.GetPrivateKey("EdDSA", 0, address)
		require.NoError(t, err)

		child, _, err := derive.EdDSAChild(fixtureEdDSARoot(t), 0)
		require.NoError(t, err)
		assert.Equal(t, strutil.ToHex(child.Serialize()), got)
	})

	t.Run("異常系_EdDSAも確認済みアドレスと不一致なら秘密鍵を返さない", func(t *testing.T) {
		app := restoreSession(t)

		got, err := app.GetPrivateKey(
			"EdDSA", 0, "So1anaWrongAddress1111111111111111111111111",
		)
		assert.Error(t, err)
		assert.Empty(t, got)
	})
}
