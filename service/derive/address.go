package derive

import (
	"math/big"

	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/decred/dcrd/dcrec/secp256k1/v4"
	"golang.org/x/crypto/sha3"
)

// EVMAddress は secp256k1 公開鍵から EVM アドレス（EIP-55 チェックサム済み）を返す。
// アドレス = Keccak256(非圧縮公開鍵の X||Y 64 バイト) の下位 20 バイト。
func EVMAddress(pub *secp256k1.PublicKey) string {
	var xy [64]byte
	copy(xy[0:32], leftPad32(pub.X().Bytes()))
	copy(xy[32:64], leftPad32(pub.Y().Bytes()))
	hash := keccak256(xy[:])
	return toChecksumAddress(hash[12:])
}

// SolanaAddress は ed25519 公開鍵 32 バイトの base58 表現を返す。
func SolanaAddress(pub *edwards.PublicKey) string {
	return base58Encode(pub.Serialize())
}

func keccak256(data []byte) []byte {
	h := sha3.NewLegacyKeccak256()
	h.Write(data)
	return h.Sum(nil)
}

// toChecksumAddress は 20 バイトアドレスを EIP-55 チェックサム付き 0x 文字列にする。
func toChecksumAddress(addr []byte) string {
	const hexDigits = "0123456789abcdef"
	lower := make([]byte, 40)
	for i, b := range addr {
		lower[i*2] = hexDigits[b>>4]
		lower[i*2+1] = hexDigits[b&0x0f]
	}
	hash := keccak256(lower)
	out := []byte("0x")
	for i, c := range lower {
		if c >= 'a' && c <= 'f' {
			// hash の当該 nibble が 8 以上なら大文字化。
			nibble := hash[i/2]
			if i%2 == 0 {
				nibble >>= 4
			} else {
				nibble &= 0x0f
			}
			if nibble >= 8 {
				c -= 32 // to upper
			}
		}
		out = append(out, c)
	}
	return string(out)
}

const base58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

// base58Encode は Bitcoin/Solana 系 base58（先頭ゼロは "1" で保存）でエンコードする。
func base58Encode(input []byte) string {
	x := new(big.Int).SetBytes(input)
	radix := big.NewInt(58)
	zero := big.NewInt(0)
	mod := new(big.Int)

	var out []byte
	for x.Cmp(zero) > 0 {
		x.DivMod(x, radix, mod)
		out = append(out, base58Alphabet[mod.Int64()])
	}
	for _, b := range input {
		if b != 0 {
			break
		}
		out = append(out, base58Alphabet[0])
	}
	// out は逆順なので反転する。
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return string(out)
}

func leftPad32(bs []byte) []byte {
	if len(bs) >= 32 {
		return bs
	}
	out := make([]byte, 32)
	copy(out[32-len(bs):], bs)
	return out
}
