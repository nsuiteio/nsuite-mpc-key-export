package main

import (
	"context"
	_ "embed"
	"fmt"

	"github.com/nsuiteio/nst-mpc-key-export/service/reconstruct"
)

// App struct
type App struct {
	name string

	ctx context.Context
}

// NewApp creates a new App application struct
func NewApp(name string) *App {
	return &App{name: name}
}

// startup is called when the app starts. The context is saved
// so we can call the runtime methods
func (a *App) startup(ctx context.Context) {
	a.ctx = ctx
}

// Greet returns a greeting for the given name
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
