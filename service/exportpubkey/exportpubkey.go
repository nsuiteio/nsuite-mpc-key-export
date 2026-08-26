// Package exportpubkey は、Export 用公開鍵の QR ペイロードと
// フィンガープリントの整形を提供する。
//
// フォーマットはモバイル側パーサー（nst-mobile-app lib/exportPubkey.ts）と
// Core API（nst-core go/service/mpc/export.go のフィンガープリント記録）の
// 実装に厳密に一致させている。
package exportpubkey

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

// Payload は公開鍵バイト列（[keyType 1バイト] + PKCS1 DER）を QR コードに
// 載せるための hex 文字列にする。0x なし・大文字（モバイル側は 0x 任意・
// 大文字小文字不問。大文字 hex は QR の英数字モード（5.5bit/文字）に乗る
// ため、バイトモード（8bit/文字）になる小文字より QR 容量が小さくなる）。
// 生バイナリを QR の文字列ペイロードにすると、スキャナ側の JS string 経由で
// 不正 UTF-8 が U+FFFD に置換され不可逆に破損するため、必ず hex を使う。
func Payload(pubkeyBytes []byte) string {
	return strings.ToUpper(hex.EncodeToString(pubkeyBytes))
}

// Fingerprint は公開鍵バイト列のフィンガープリント hex(sha256(pubkeyBytes))
// を返す（小文字）。Core API・モバイル側と同一計算。
func Fingerprint(pubkeyBytes []byte) string {
	sum := sha256.Sum256(pubkeyBytes)
	return hex.EncodeToString(sum[:])
}

// FormatFingerprint はフィンガープリントを目視照合しやすいよう
// 4 文字区切り・大文字で整形する（モバイル側の表示と同一形式）。
func FormatFingerprint(fingerprint string) string {
	upper := strings.ToUpper(fingerprint)
	var groups []string
	for i := 0; i < len(upper); i += 4 {
		end := i + 4
		if end > len(upper) {
			end = len(upper)
		}
		groups = append(groups, upper[i:end])
	}
	return strings.Join(groups, " ")
}

// ShortFingerprintLength はファイル名に使う短縮フィンガープリントの文字数。
// sha256 の先頭 32bit 相当で、ファイル名の視認性と取り違え防止を両立する
// （厳密な照合は表示用の全長フィンガープリントで行う前提）。
const ShortFingerprintLength = 8

// ShortFingerprint はフィンガープリントの先頭 8 文字を大文字で返す。
// ファイル名に埋め込む用途で、出力は hex（0-9A-F）のみ。
// 表示用の「ABCD EFGH」形式は FormatFingerprint と組み合わせて得る。
//
// 8 文字未満の入力はそのまま大文字化して返す（鍵生成後の唯一の失敗点を
// 作らないため、異常値でもパニックさせない）。
func ShortFingerprint(fingerprint string) string {
	upper := strings.ToUpper(fingerprint)
	if len(upper) <= ShortFingerprintLength {
		return upper
	}
	return upper[:ShortFingerprintLength]
}
