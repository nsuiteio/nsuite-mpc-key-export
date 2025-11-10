package keyutil

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"strconv"
	"strings"

	"github.com/nsuiteio/nst-mpc-key-export/utility/strutil"
)

type (
	ChainCode  [32]byte
	DerivePath []uint32

	KeyDerivationDelta big.Int

	DeriveKey struct {
		chainCode ChainCode
		path      DerivePath
	}
)

func (cc *ChainCode) Generate() (*ChainCode, error) {
	bs := make([]byte, 32)
	if _, err := rand.Read(bs); err != nil {
		return nil, err
	}
	cc.SetBytes(bs)
	return cc, nil
}

func (cc *ChainCode) SetBytes(bs []byte) ChainCode {
	copy(cc[:], bs)
	return *cc
}

func (cc *ChainCode) Bytes() []byte {
	return cc[:]
}

func (cc *ChainCode) String() string {
	return cc.Hex()
}

func (cc *ChainCode) Hex() string {
	return strutil.ToHex(cc.Bytes())
}

func (cc *ChainCode) ParseHex(s string) (*ChainCode, error) {
	bs, err := strutil.FromHex(s)
	if err != nil {
		return nil, err
	}
	if len(bs) != 32 {
		return nil, fmt.Errorf("invalid length: %v", len(bs))
	}
	cc.SetBytes(bs)
	return cc, nil
}

func (dp *DerivePath) String() string {
	var ps []string
	for _, p := range *dp {
		ps = append(ps, fmt.Sprintf("%v", p))
	}
	return fmt.Sprintf("m/%v", strings.Join(ps, "/"))
}

func (dp *DerivePath) Parse(givenStr string) (DerivePath, error) {
	const prefix = "m/"
	str := strings.TrimPrefix(givenStr, prefix)
	if str == givenStr {
		return nil, fmt.Errorf("invalid prefix: %v", givenStr)
	}
	var parts []string
	if len(str) > 0 {
		parts = strings.Split(str, "/")
	}
	var ndp DerivePath
	for _, p := range parts {
		n, err := strconv.ParseUint(p, 10, 32)
		if err != nil {
			return nil, err
		}
		ndp = append(ndp, uint32(n))
	}
	*dp = ndp
	return ndp, nil
}

func (kdd *KeyDerivationDelta) Bytes() []byte {
	return (*big.Int)(kdd).Bytes()
}

func (dk *DeriveKey) InitWithRandom(
	path ...uint32,
) error {
	cc, err := new(ChainCode).Generate()
	if err != nil {
		return err
	}
	dk.chainCode = *cc
	dk.path = path
	return nil
}

func (dk *DeriveKey) Init(
	chainCode []byte,
	path ...uint32,
) {
	dk.chainCode = new(ChainCode).SetBytes(chainCode)
	dk.path = path
}

func (dk *DeriveKey) ChainCode() []byte {
	return dk.chainCode.Bytes()
}

func (dk *DeriveKey) ChainCodeHex() string {
	return dk.chainCode.Hex()
}

func (dk *DeriveKey) Path() DerivePath {
	return dk.path[:]
}

func (dk *DeriveKey) HDPath() string {
	return dk.path.String()
}
