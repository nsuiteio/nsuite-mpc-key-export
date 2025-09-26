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
	SecStorage struct {
		basePath string
	}
)

func GetSecStorage(ctx context.Context, appName string) (*SecStorage, error) {
	logger := logutil.Get(ctx).With(
		slog.String("function", "GetSecStorage"),
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
	ss := &SecStorage{
		basePath: appPath,
	}
	return ss, nil
}
