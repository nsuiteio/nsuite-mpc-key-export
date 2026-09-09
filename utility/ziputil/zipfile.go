package ziputil

import (
	"archive/zip"
	"context"
	"io"
	"log/slog"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
)

func UnzipFile(ctx context.Context, filePath string) (
	map[string][]byte,
	error,
) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "UnzipFile"),
		slog.String("file", filePath),
	)
	zipData, err := zip.OpenReader(filePath)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	defer func(zipData *zip.ReadCloser) {
		err := zipData.Close()
		if err != nil {
			logger.Error(
				"failed to close zip file",
				slog.String("error", err.Error()),
			)
		}
	}(zipData)

	files := make(map[string][]byte)
	for _, f := range zipData.File {
		rc, err := f.Open()
		if err != nil {
			return nil, errutil.Wrap(err)
		}
		bs, err := io.ReadAll(rc)
		if err != nil {
			return nil, errutil.Wrap(err)
		}
		files[f.Name] = bs
	}
	return files, nil
}
