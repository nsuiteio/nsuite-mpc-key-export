package qrutil

import (
	"bytes"
	"io"

	"github.com/yeqown/go-qrcode/v2"
	"github.com/yeqown/go-qrcode/writer/standard"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
)

func GenerateQRCodePNG(src []byte) ([]byte, error) {
	qrc, err := qrcode.New(string(src))
	if err != nil {
		return nil, errutil.Wrap(err)
	}

	var buf bytes.Buffer
	wr := standard.NewWithWriter(
		struct {
			io.Writer
			io.Closer
		}{
			Writer: &buf,
			Closer: io.NopCloser(nil),
		},
	)
	if err := qrc.Save(wr); err != nil {
		return nil, errutil.Wrap(err)
	}
	if err := wr.Close(); err != nil {
		return nil, errutil.Wrap(err)
	}

	bs := buf.Bytes()
	return bs, nil
}
