package keyutil

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestDerivePath_Parse_String(t *testing.T) {
	testCases := []struct {
		src     string
		exp     DerivePath
		isError bool
	}{
		{
			src:     "m/0/1/2",
			exp:     DerivePath{0, 1, 2},
			isError: false,
		},
		{
			src:     "m/0",
			exp:     DerivePath{0},
			isError: false,
		},
		{
			src:     "m/",
			exp:     DerivePath{},
			isError: false,
		},
		{
			src:     "",
			exp:     nil,
			isError: true,
		},
		{
			src:     "0/1/2",
			exp:     nil,
			isError: true,
		},
		{
			src:     "m/0/1/2/",
			exp:     nil,
			isError: true,
		},
		{
			src:     "m/0/1/a/3",
			exp:     nil,
			isError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.src, func(t *testing.T) {
				origin := new(DerivePath)
				dp, err := origin.Parse(tc.src)
				if tc.isError {
					assert.Error(t, err)
					return
				} else {
					assert.NoError(t, err)
				}
				assert.Equal(t, len(tc.exp), len(dp))
				for i, n := range dp {
					assert.Equal(t, tc.exp[i], n)
				}

				assert.Equal(t, tc.src, dp.String())
				assert.Equal(t, tc.src, origin.String())

				assert.Equal(t, len(tc.exp), len(*origin))
				for i, n := range *origin {
					assert.Equal(t, tc.exp[i], n)
				}
			},
		)
	}
}

func TestChainCode_Generate(t *testing.T) {
	// 10 times
	for i := 0; i < 10; i++ {
		cc := new(ChainCode)
		gg, err := cc.Generate()
		assert.NoError(t, err)
		assert.NotEmpty(t, cc.Bytes())
		assert.True(t, bytes.Equal(cc.Bytes(), gg.Bytes()))
		fmt.Println(cc.Hex())
	}
}

func TestChainCode_ParseHex(t *testing.T) {
	testCases := []struct {
		name    string
		src     string
		isError bool
	}{
		{
			name:    "正常 #1",
			src:     "0xee823f3ffd9506ba125760e4bcb9f6e5111a06bb447d7499fea0e6fdc11b37d2",
			isError: false,
		},
		{
			name:    "正常 #2",
			src:     "0x41892db38a1c264aa1ca7c89ccb39f06d8ae4817b6ae0d061e084ae36cff6545",
			isError: false,
		},
		{
			name:    "空バイト列",
			src:     "0x",
			isError: true,
		},
		{
			name:    "長すぎる（33バイト）",
			src:     "0x41892db38a1c264aa1ca7c89ccb39f06d8ae4817b6ae0d061e084ae36cff6545a",
			isError: true,
		},
		{
			name:    "短すぎる（31バイト）",
			src:     "0x41892db38a1c264aa1ca7c89ccb39f06d8ae4817b6ae0d061e084ae36cff654",
			isError: true,
		},
		{
			name:    "0x で始まらない",
			src:     "41892db38a1c264aa1ca7c89ccb39f06d8ae4817b6ae0d061e084ae36cff6545",
			isError: true,
		},
		{
			name:    "16進数でない",
			src:     "0xabcxyz",
			isError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(
			tc.name, func(t *testing.T) {
				cc := new(ChainCode)
				parsed, err := cc.ParseHex(tc.src)
				if tc.isError {
					assert.Error(t, err)
					return
				}
				assert.NoError(t, err)
				assert.Equal(t, tc.src, cc.Hex())
				assert.Equal(t, tc.src, parsed.Hex())
			},
		)
	}
}
