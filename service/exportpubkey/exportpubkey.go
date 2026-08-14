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
// 載せるための hex 文字列にする。0x なし・小文字（モバイル側は 0x 任意・
// 大文字小文字不問のため、QR 容量が最小になる形式を選ぶ）。
// 生バイナリを QR の文字列ペイロードにすると、スキャナ側の JS string 経由で
// 不正 UTF-8 が U+FFFD に置換され不可逆に破損するため、必ず hex を使う。
func Payload(pubkeyBytes []byte) string {
	return hex.EncodeToString(pubkeyBytes)
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
