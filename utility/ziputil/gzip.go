package ziputil

import (
	"bytes"
	"compress/gzip"
	"context"
	"log/slog"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
)

func GzipBytes(
	ctx context.Context,
	data []byte,
) ([]byte, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "GzipBytes"),
		slog.Int("original_size", len(data)),
	)
	buf := bytes.NewBuffer(nil)
	gw := gzip.NewWriter(buf)
	if _, err := gw.Write(data); err != nil {
		logger.Error(
			"failed to write to gzip",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	}
	if err := gw.Flush(); err != nil {
		logger.Error(
			"failed to flush gzip",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	}
	if err := gw.Close(); err != nil {
		logger.Error(
			"failed to close gzip",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	}
	result := buf.Bytes()
	logger.Info(
		"compressed",
		slog.Int("compressed_size", len(result)),
	)
	return result, nil
}

func GunzipBytes(
	ctx context.Context,
	data []byte,
) ([]byte, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "GunzipBytes"),
	)
	gr, err := gzip.NewReader(bytes.NewBuffer(data))
	if err != nil {
		logger.Error(
			"failed to create gzip reader",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	}
	defer func() {
		if err := gr.Close(); err != nil {
			logger.Error(
				"failed to close gzip reader",
				slog.String("error", err.Error()),
			)
		}
	}()

	buf := bytes.NewBuffer(nil)
	if _, err := buf.ReadFrom(gr); err != nil {
		logger.Error(
			"failed to read from gzip",
			slog.String("error", err.Error()),
		)
		return nil, errutil.Wrap(err)
	}
	return buf.Bytes(), nil
}
