package main

import (
	"embed"
	"encoding/json"
	"log"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"

	"github.com/nsuiteio/nsuite-mpc-key-export/utility/cfgutil"
	"github.com/nsuiteio/nsuite-mpc-key-export/utility/errutil"
)

//go:embed all:frontend/dist
var assets embed.FS

func main() {
	// Load app name from wails.json
	wj, err := loadWailsJson()
	if err != nil {
		log.Fatalf("Error loading wails.json: %s", err.Error())
	}

	// Create an instance of the app structure
	app := NewApp(wj)

	// Create application with options
	if err := wails.Run(
		&options.App{
			Title:  wj.Name,
			Width:  1024,
			Height: 768,
			AssetServer: &assetserver.Options{
				Assets: assets,
			},
			BackgroundColour: &options.RGBA{R: 27, G: 38, B: 54, A: 1},
			OnStartup:        app.startup,
			Bind: []any{
				app,
			},
		},
	); err != nil {
		println("Error:", err.Error())
	}
}

//go:embed wails.json
var wailsJson string

func loadWailsJson() (*cfgutil.WailsJson, error) {
	var wj cfgutil.WailsJson
	if err := json.Unmarshal([]byte(wailsJson), &wj); err != nil {
		return nil, errutil.Wrap(err)
	}
	return &wj, nil
}
