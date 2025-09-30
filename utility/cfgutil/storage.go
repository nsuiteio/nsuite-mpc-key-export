package cfgutil

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
)

type (
	Storage interface {
		Save(ctx context.Context, data []byte, path ...string) error
		Load(ctx context.Context, path ...string) ([]byte, error)
	}

	secStorageImpl struct {
		basePath string
	}
)

func NewSecStorage(ctx context.Context, appName string) (Storage, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "NewSecStorage"),
	)
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	appPath := filepath.Join(configDir, appName)
	if err := os.MkdirAll(appPath, 0700); err != nil {
		return nil, errutil.Wrap(err)
	}
	logger.Info(
		"created app config directory",
		slog.String("path", appPath),
	)
	ss := &secStorageImpl{
		basePath: appPath,
	}
	return ss, nil
}

func (ss *secStorageImpl) Save(
	ctx context.Context,
	data []byte,
	path ...string,
) error {
	logger := logutil.Get(ctx).With(
		slog.String("function", "Save"),
		slog.String("sub_path", filepath.Join(path...)),
		slog.Int("size", len(data)),
	)
	pathElms := append([]string{ss.basePath}, path...)
	fullPath := filepath.Join(pathElms...)
	logger = logger.With(
		slog.String("full_path", fullPath),
	)
	logger.Info("creating file")
	file, err := os.Create(fullPath)
	if err != nil {
		return errutil.Wrap(err)
	}
	wl, err := file.Write(data)
	if err != nil {
		return errutil.Wrap(err)
	}
	logger.Info(
		"wrote data",
		slog.Int("written_size", wl),
	)
	if err := file.Close(); err != nil {
		return errutil.Wrap(err)
	}
	return nil
}

func (ss *secStorageImpl) Load(
	ctx context.Context,
	path ...string,
) ([]byte, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "Load"),
		slog.String("sub_path", filepath.Join(path...)),
	)
	pathElms := append([]string{ss.basePath}, path...)
	fullPath := filepath.Join(pathElms...)
	logger = logger.With(
		slog.String("full_path", fullPath),
	)
	logger.Info("loading file")
	file, err := os.Open(fullPath)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	data, err := os.ReadFile(fullPath)
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	if err := file.Close(); err != nil {
		return nil, errutil.Wrap(err)
	}
	return data, nil
}
