package cfgutil

import (
	"os"
	"path/filepath"

	"github.com/nsuiteio/nst-mpc-key-export/utility/errutil"
)

type (
	SecStorage struct {
		basePath string
	}
)

func GetSecStorage(appName string) (*SecStorage, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return nil, errutil.Wrap(err)
	}
	appPath := filepath.Join(configDir, appName)
	if err := os.MkdirAll(appPath, 0700); err != nil {
		return nil, errutil.Wrap(err)
	}
	ss := &SecStorage{
		basePath: appPath,
	}
	return ss, nil
}
