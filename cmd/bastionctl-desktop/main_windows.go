//go:build windows

package main

import (
	"context"
	"log"
	"sync"

	"bastionctl/internal/desktop"
	"bastionctl/internal/desktopui"

	"github.com/wailsapp/wails/v2"
	"github.com/wailsapp/wails/v2/pkg/options"
	"github.com/wailsapp/wails/v2/pkg/options/assetserver"
	"github.com/wailsapp/wails/v2/pkg/options/windows"
	"github.com/wailsapp/wails/v2/pkg/runtime"
)

var version = "dev"

type eventBridge struct {
	mu  sync.RWMutex
	ctx context.Context
}

func (b *eventBridge) set(ctx context.Context) {
	b.mu.Lock()
	b.ctx = ctx
	b.mu.Unlock()
}

func (b *eventBridge) emit(name string, payload any) {
	b.mu.RLock()
	ctx := b.ctx
	b.mu.RUnlock()
	if ctx != nil {
		runtime.EventsEmit(ctx, name, payload)
	}
}

func main() {
	bridge := &eventBridge{}
	app, err := desktop.New(version, "", bridge.emit)
	if err != nil {
		log.Fatal(err)
	}
	err = wails.Run(&options.App{
		Title:             "bastionctl",
		Width:             1280,
		Height:            820,
		MinWidth:          880,
		MinHeight:         560,
		DisableResize:     false,
		Frameless:         false,
		StartHidden:       false,
		HideWindowOnClose: false,
		BackgroundColour:  &options.RGBA{R: 48, G: 48, B: 48, A: 255},
		AssetServer:       &assetserver.Options{Assets: desktopui.Assets},
		OnStartup: func(ctx context.Context) {
			bridge.set(ctx)
		},
		OnShutdown: func(context.Context) { app.Close() },
		Bind:       []any{app},
		Windows: &windows.Options{
			WebviewIsTransparent:              false,
			WindowIsTranslucent:               false,
			DisableWindowIcon:                 true,
			DisableFramelessWindowDecorations: false,
			WebviewUserDataPath:               "",
			ZoomFactor:                        1,
		},
	})
	if err != nil {
		log.Fatal(err)
	}
}
