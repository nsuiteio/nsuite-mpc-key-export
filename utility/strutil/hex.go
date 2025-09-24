package strutil

import (
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/nsuiteio/trial-mpc-key-export/utility/errutil"
)

func ToHex(bs []byte) string {
	return "0x" + hex.EncodeToString(bs)
}

func FromHex(str string) ([]byte, error) {
	if !strings.HasPrefix(str, "0x") {
		err := fmt.Errorf("invalid hex string: %s", str)
		return nil, errutil.Wrap(err)
	}
	return hex.DecodeString(strings.TrimPrefix(str, "0x"))
}
