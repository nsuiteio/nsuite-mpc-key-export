package main

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/nsuiteio/nst-mpc-key-export/service/reconstruct"
	"github.com/nsuiteio/nst-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nst-mpc-key-export/utility/logutil"
)

// App struct
type App struct {
	config *cfgutil.WailsJson

	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp(config *cfgutil.WailsJson) *App {
	return &App{config: config}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = logutil.Setup(ctx, a.config.Name)
}

// Reconstruct returns sample private key
func (a *App) Reconstruct(curveName string) string {
	var bsHex string
	switch curveName {
	case "ECDSA":
		if hex, err := reconstruct.SampleECDSA(a.ctx); err != nil {
			return err.Error()
		} else {
			bsHex = hex
		}
	case "EdDSA":
		if hex, err := reconstruct.SampleEdDSA(a.ctx); err != nil {
			return err.Error()
		} else {
			bsHex = hex
		}
	}
	return fmt.Sprintf("Private Key: %s", bsHex)
}

func (a *App) GenerateKeyPair() string {
	return "Generate Key Pair"
}
