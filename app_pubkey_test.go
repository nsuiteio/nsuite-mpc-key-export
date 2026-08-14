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

// GenerateKeyPair は QR・フィンガープリント・公開鍵 hex を同一の鍵から
// 生成した単一スナップショットとして返すこと（別 API の読み直しによる
// 鍵不一致を構造的に防ぐ）。
func TestGenerateKeyPair_SingleSnapshot(t *testing.T) {
	app := &App{
		config:  &cfgutil.WailsJson{Name: "test"},
		ctx:     context.Background(),
		storage: newMapStorage(),
	}
	const password = "correct horse battery staple"

	res, err := app.GenerateKeyPair(password, false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(res.QRImage, "data:image/png;base64,") {
		t.Errorf("unexpected QR image format: %.40s", res.QRImage)
	}

	// 保存された鍵ペアから期待値を独立に計算し、全フィールドが
	// 同一の公開鍵に由来することを確認する。
	akey, err := secutil.NewAESPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	prv, ok, err := app.loadKeyPair(app.ctx, akey)
	if err != nil || !ok {
		t.Fatalf("keypair not stored: ok=%v err=%v", ok, err)
	}
	pubkeyBs := prv.PublicKey().MarshalToBytes()
	if want := exportpubkey.Payload(pubkeyBs); res.PublicKeyHex != want {
		t.Errorf("publicKeyHex: got %q want %q", res.PublicKeyHex, want)
	}
	wantFp := exportpubkey.FormatFingerprint(
		exportpubkey.Fingerprint(pubkeyBs),
	)
	if res.Fingerprint != wantFp {
		t.Errorf("fingerprint: got %q want %q", res.Fingerprint, wantFp)
	}
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

// GetKeyPairInfo はフィンガープリントと公開鍵 hex を単一の鍵読み込みから
// 返すこと（別 API の読み直しによる鍵不一致スナップショットを構造的に防ぐ）。
func TestGetKeyPairInfo(t *testing.T) {
	app := &App{
		config:  &cfgutil.WailsJson{Name: "test"},
		ctx:     context.Background(),
		storage: newMapStorage(),
	}
	const password = "correct horse battery staple"

	if _, err := app.GenerateKeyPair(password, false); err != nil {
		t.Fatal(err)
	}

	got, err := app.GetKeyPairInfo(password)
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
	pubkeyBs := prv.PublicKey().MarshalToBytes()
	if want := exportpubkey.Payload(pubkeyBs); got.PublicKeyHex != want {
		t.Errorf("publicKeyHex: got %q want %q", got.PublicKeyHex, want)
	}
	wantFp := exportpubkey.FormatFingerprint(
		exportpubkey.Fingerprint(pubkeyBs),
	)
	if got.Fingerprint != wantFp {
		t.Errorf("fingerprint: got %q want %q", got.Fingerprint, wantFp)
	}
}

// GetKeyPairInfo は鍵ペア未生成の場合エラーを返すこと。
func TestGetKeyPairInfo_NotFound(t *testing.T) {
	app := &App{
		config:  &cfgutil.WailsJson{Name: "test"},
		ctx:     context.Background(),
		storage: newMapStorage(),
	}
	if _, err := app.GetKeyPairInfo("pw"); err == nil {
		t.Error("expected error for missing key pair")
	}
}
