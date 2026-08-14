package main

import (
	"context"
	"testing"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"

	"github.com/nsuiteio/nst-mpc-key-export/service/derive"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/strutil"
)

// memStorage は cfgutil.Storage のインメモリ実装（テスト用）。
type memStorage struct {
	data map[string][]byte
}

func newMemStorage() *memStorage {
	return &memStorage{data: map[string][]byte{}}
}

func (m *memStorage) Save(
	_ context.Context, data []byte, path ...string,
) error {
	key := ""
	for _, p := range path {
		key += "/" + p
	}
	m.data[key] = data
	return nil
}

func (m *memStorage) Load(
	_ context.Context, path ...string,
) ([]byte, bool, error) {
	key := ""
	for _, p := range path {
		key += "/" + p
	}
	bs, ok := m.data[key]
	return bs, ok, nil
}

const testPassword = "correct horse battery staple"

func newTestApp(t *testing.T) (*App, secutil.EncryptionKey) {
	t.Helper()
	app := &App{
		config:  &cfgutil.WailsJson{Name: "test"},
		ctx:     context.Background(),
		storage: newMemStorage(),
	}
	akey, err := secutil.NewAESPassword(testPassword)
	if err != nil {
		t.Fatal(err)
	}
	return app, akey
}

// GetPrivateKey は保存された root ECDSA 鍵から index 導出した子秘密鍵の hex を返す。
func TestGetPrivateKey_ECDSA_DerivesByIndex(t *testing.T) {
	app, akey := newTestApp(t)
	rootBs := make([]byte, 32)
	rootBs[31] = 42
	root := secp256k1.PrivKeyFromBytes(rootBs)
	if err := app.saveECDSA(app.ctx, akey, root); err != nil {
		t.Fatal(err)
	}

	const index = int32(5)
	addr, err := app.DeriveAddress(testPassword, "ECDSA", index)
	if err != nil {
		t.Fatal(err)
	}
	got, err := app.GetPrivateKey(testPassword, "ECDSA", index, addr)
	if err != nil {
		t.Fatal(err)
	}

	childPrv, _, err := derive.ECDSAChild(root, uint32(index))
	if err != nil {
		t.Fatal(err)
	}
	if want := strutil.ToHex(childPrv.Serialize()); got != want {
		t.Errorf("got %s want %s", got, want)
	}
	// root 鍵そのものは返さない（TODO 未実装状態の回帰防止）。
	if got == strutil.ToHex(root.Serialize()) {
		t.Error("must not return the root key")
	}
}

// GetPrivateKey は保存された root EdDSA 鍵から index 導出した子秘密鍵の hex を返す。
func TestGetPrivateKey_EdDSA_DerivesByIndex(t *testing.T) {
	app, akey := newTestApp(t)
	root, err := edwards.GeneratePrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if err := app.saveEdDSA(app.ctx, akey, root); err != nil {
		t.Fatal(err)
	}

	const index = int32(3)
	addr, err := app.DeriveAddress(testPassword, "EdDSA", index)
	if err != nil {
		t.Fatal(err)
	}
	got, err := app.GetPrivateKey(testPassword, "EdDSA", index, addr)
	if err != nil {
		t.Fatal(err)
	}

	childPrv, _, err := derive.EdDSAChild(root, uint32(index))
	if err != nil {
		t.Fatal(err)
	}
	if want := strutil.ToHex(childPrv.Serialize()); got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

// DeriveAddress は index 導出した子アドレスを返す（ECDSA=EVM, EdDSA=Solana）。
func TestDeriveAddress(t *testing.T) {
	app, akey := newTestApp(t)
	rootBs := make([]byte, 32)
	rootBs[31] = 7
	ecdsaRoot := secp256k1.PrivKeyFromBytes(rootBs)
	if err := app.saveECDSA(app.ctx, akey, ecdsaRoot); err != nil {
		t.Fatal(err)
	}

	gotAddr, err := app.DeriveAddress(testPassword, "ECDSA", 2)
	if err != nil {
		t.Fatal(err)
	}
	_, wantAddr, err := derive.ECDSAChild(ecdsaRoot, 2)
	if err != nil {
		t.Fatal(err)
	}
	if gotAddr != wantAddr {
		t.Errorf("got %s want %s", gotAddr, wantAddr)
	}
}

// 負の index は拒否する。
func TestGetPrivateKey_NegativeIndex(t *testing.T) {
	app, akey := newTestApp(t)
	rootBs := make([]byte, 32)
	rootBs[31] = 1
	if err := app.saveECDSA(
		app.ctx, akey, secp256k1.PrivKeyFromBytes(rootBs),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := app.GetPrivateKey(
		testPassword, "ECDSA", -1, "",
	); err == nil {
		t.Error("expected error for negative index")
	}
}

// GetPrivateKey は expectedAddress と導出アドレスが一致しない場合に秘密鍵を
// 返さない（確認したアドレスと違う index/curve の指定や、確認後に root 鍵が
// 差し替わった場合の防御）。
func TestGetPrivateKey_ExpectedAddressMismatch(t *testing.T) {
	app, akey := newTestApp(t)
	rootBs := make([]byte, 32)
	rootBs[31] = 9
	root := secp256k1.PrivKeyFromBytes(rootBs)
	if err := app.saveECDSA(app.ctx, akey, root); err != nil {
		t.Fatal(err)
	}

	addr, err := app.DeriveAddress(testPassword, "ECDSA", 0)
	if err != nil {
		t.Fatal(err)
	}

	// 別 index のアドレスを期待値として渡す → 拒否
	if _, err := app.GetPrivateKey(
		testPassword, "ECDSA", 1, addr,
	); err == nil {
		t.Error("expected error for address mismatch")
	}

	// 確認後に root 鍵が差し替わった場合も拒否される
	otherBs := make([]byte, 32)
	otherBs[31] = 10
	if err := app.saveECDSA(
		app.ctx, akey, secp256k1.PrivKeyFromBytes(otherBs),
	); err != nil {
		t.Fatal(err)
	}
	if _, err := app.GetPrivateKey(
		testPassword, "ECDSA", 0, addr,
	); err == nil {
		t.Error("expected error after root key replacement")
	}
}
