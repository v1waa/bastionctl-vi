package desktopui

import "embed"

// Assets contains the production Windows frontend.
//
//go:embed all:dist
var Assets embed.FS
