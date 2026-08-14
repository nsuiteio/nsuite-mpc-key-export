package exportpubkey

import (
	"context"
	"encoding/hex"
	"regexp"
	"testing"

	"github.com/nsuiteio/nst-mpc-key-export/utility/secutil"
)

// QR ペイロードはモバイル側パーサー（nst-mobile-app lib/exportPubkey.ts
// parseExportPubkey）の受け入れ条件を満たすこと:
// hex 文字列（0x なし大文字。QR の英数字モードに乗り容量が最小になる）・
// デコード後 [keyType 0x00][DER SEQUENCE 0x30]・32〜4096 バイト。
func TestPayload_MeetsMobileParserContract(t *testing.T) {
	ctx := context.Background()
	prv, err := secutil.GenerateEncryptionKeyPair(
		ctx, secutil.EncryptionKeyPairTypeRSA,
	)
	if err != nil {
		t.Fatal(err)
	}
	pubkeyBs := prv.PublicKey().MarshalToBytes()

	payload := Payload(pubkeyBs)

	if !regexp.MustCompile(`^[0-9A-F]+$`).MatchString(payload) {
		t.Errorf("payload must be uppercase hex without 0x: %q", payload)
	}
	decoded, err := hex.DecodeString(payload)
	if err != nil {
		t.Fatalf("payload must be hex-decodable: %v", err)
	}
	if string(decoded) != string(pubkeyBs) {
		t.Error("decoded payload must equal original pubkey bytes")
	}
	if decoded[0] != 0x00 {
		t.Errorf("first byte must be 0x00 (RSA): got %#x", decoded[0])
	}
	if decoded[1] != 0x30 {
		t.Errorf("second byte must be 0x30 (DER SEQUENCE): got %#x", decoded[1])
	}
	if len(decoded) < 32 || len(decoded) > 4096 {
		t.Errorf("decoded length out of range: %d", len(decoded))
	}
}

// フィンガープリントは Core API（nst-core go/service/mpc/export.go）・モバイル側と
// 同一計算 hex(sha256(pubkeyBytes)) であること。期待値は Python hashlib で独立計算。
func TestFingerprint_KnownVector(t *testing.T) {
	input, err := hex.DecodeString(
		"00306e73742d6d70632d6b65792d6578706f7274" +
			"2066696e6765727072696e74207465737420766563746f72")
	if err != nil {
		t.Fatal(err)
	}
	const want = "f570c28f4ae12d3cc47a09041190afce" +
		"712bc5561826c0c60b50f1e83f147fbb"
	if got := Fingerprint(input); got != want {
		t.Errorf("got %s want %s", got, want)
	}
}

// 表示形式はモバイル側（formatFingerprint）と同じ 4 文字区切り・大文字であること。
func TestFormatFingerprint(t *testing.T) {
	const fp = "f570c28f4ae12d3cc47a09041190afce" +
		"712bc5561826c0c60b50f1e83f147fbb"
	const want = "F570 C28F 4AE1 2D3C C47A 0904 1190 AFCE " +
		"712B C556 1826 C0C6 0B50 F1E8 3F14 7FBB"
	if got := FormatFingerprint(fp); got != want {
		t.Errorf("got %q want %q", got, want)
	}
}
