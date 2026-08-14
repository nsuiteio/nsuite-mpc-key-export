package main

import (
	"context"
	"strings"
	"testing"

	"github.com/nsuiteio/nst-mpc-key-export/service/exportpubkey"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
)

// mapStorage は cfgutil.Storage のインメモリ実装（テスト用）。
type mapStorage struct {
	data map[string][]byte
}

func newMapStorage() *mapStorage {
	return &mapStorage{data: map[string][]byte{}}
}

func (m *mapStorage) Save(
	_ context.Context, data []byte, path ...string,
) error {
	m.data[strings.Join(path, "/")] = data
	return nil
}

func (m *mapStorage) Load(
	_ context.Context, path ...string,
) ([]byte, bool, error) {
	bs, ok := m.data[strings.Join(path, "/")]
	return bs, ok, nil
}

// GetKeyPairFingerprint は保存済み公開鍵のフィンガープリント
// （4 文字区切り・大文字。モバイル側の表示と同一）を返すこと。
func TestGetKeyPairFingerprint(t *testing.T) {
	app := &App{
		config:  &cfgutil.WailsJson{Name: "test"},
		ctx:     context.Background(),
		storage: newMapStorage(),
	}
	const password = "correct horse battery staple"

	if _, err := app.GenerateKeyPair(password, false); err != nil {
		t.Fatal(err)
	}

	got, err := app.GetKeyPairFingerprint(password)
	if err != nil {
		t.Fatal(err)
	}

	// 保存された鍵ペアから期待値を独立に計算する。
	akey, err := secutil.NewAESPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	prv, ok, err := app.loadKeyPair(app.ctx, akey)
	if err != nil || !ok {
		t.Fatalf("keypair not stored: ok=%v err=%v", ok, err)
	}
	want := exportpubkey.FormatFingerprint(
		exportpubkey.Fingerprint(prv.PublicKey().MarshalToBytes()),
	)
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
	if len(got) != 64+15 { // 64 hex + 15 スペース
		t.Errorf("unexpected display length: %d (%q)", len(got), got)
	}
}

// GetPublicKeyHex は保存済み公開鍵の hex（QR ペイロードと同一形式）を返すこと。
// モバイル側の開発時用テキスト入力（カメラ非対応環境）への受け渡しに使う。
func TestGetPublicKeyHex(t *testing.T) {
	app := &App{
		config:  &cfgutil.WailsJson{Name: "test"},
		ctx:     context.Background(),
		storage: newMapStorage(),
	}
	const password = "correct horse battery staple"

	if _, err := app.GenerateKeyPair(password, false); err != nil {
		t.Fatal(err)
	}

	got, err := app.GetPublicKeyHex(password)
	if err != nil {
		t.Fatal(err)
	}

	// 保存された鍵ペアから期待値を独立に計算する。
	akey, err := secutil.NewAESPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	prv, ok, err := app.loadKeyPair(app.ctx, akey)
	if err != nil || !ok {
		t.Fatalf("keypair not stored: ok=%v err=%v", ok, err)
	}
	want := exportpubkey.Payload(prv.PublicKey().MarshalToBytes())
	if got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
