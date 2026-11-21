package gui

import (
	_ "embed"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"
)

// The icon is compiled into the binary so a standalone copy of EyeOFmX still
// has its own window icon even when no desktop icon theme entry is installed.
//
//go:embed eyeofmx.png
var embeddedIcon []byte

// setWindowIcon applies the bundled icon to the main window.
func setWindowIcon(win *gtk.Window) {
	pixbuf, err := gdk.PixbufNewFromDataOnly(embeddedIcon)
	if err != nil {
		return
	}
	win.SetIcon(pixbuf)
}

// iconPixbuf returns a fresh pixbuf for dialogs that need a logo.
func iconPixbuf() *gdk.Pixbuf {
	pixbuf, err := gdk.PixbufNewFromDataOnly(embeddedIcon)
	if err != nil {
		return nil
	}
	return pixbuf
}
