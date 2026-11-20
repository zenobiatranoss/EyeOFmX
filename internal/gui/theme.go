package gui

import (
	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"
)

// themeCSS implements the EyeOFmX retro technical look with one explicit,
// self-contained palette. Every light surface is paired with near-black ink and
// every terminal surface with near-white ink, so legibility does not depend on
// the user's GTK theme (a dark XFCE theme would otherwise produce black-on-dark
// text in dialogs, menus and tables).
const themeCSS = `
@define-color eye-bg       #f2efe8;
@define-color eye-surface  #fdfcf8;
@define-color eye-alt      #e6e2d8;
@define-color eye-ink      #080808;
@define-color eye-ink-soft #26241f;
@define-color eye-line     #78746b;
@define-color eye-term-bg  #0d1012;
@define-color eye-term-ink #f5f7f3;

/* ---------- universal typography ---------- */
window, dialog, messagedialog, filechooser, aboutdialog, box, grid, frame,
notebook, notebook header, notebook header tab, menubar, menu, menuitem,
toolbar, scrolledwindow, viewport, entry, button, checkbutton, combobox,
spinbutton, label, separator, statusbar, treeview, progressbar, scale, tooltip {
    font-family: "DejaVu Sans Mono", "Liberation Mono", "Courier New", monospace;
    font-size: 13px;
    background-color: @eye-bg;
    color: @eye-ink;
}

/* ---------- all light surfaces: dark ink, guaranteed ---------- */
window, dialog, messagedialog, filechooser, aboutdialog,
box, grid, frame, toolbar, scrolledwindow, viewport, statusbar,
menubar, menu, menuitem, button, checkbutton, combobox, spinbutton,
label, separator, progressbar, scale, tooltip {
    background-color: @eye-bg;
    background-image: none;
    color: @eye-ink;
}

/* Menu items use the same light ink as every other light surface. The only
   accent is the blue edge bar used by buttons, tabs and selected rows. */
menuitem, .eye-menu-item { background-color: @eye-bg; color: @eye-ink; background-image: none; }
menuitem label, .eye-menu-item label { color: @eye-ink; }
menuitem:hover, .eye-menu-item:hover {
    background-color: #d9e6f0;
    color: #000000;
    box-shadow: inset 4px 0 0 #1f5985;
}
menuitem:active, .eye-menu-item:active {
    background-color: #b6d2e8;
    color: #000000;
    box-shadow: inset 4px 0 0 #1f5985;
}
tooltip { background-color: @eye-surface; color: @eye-ink; border: 1px solid @eye-line; }

/* ---------- title / notebook tabs ---------- */
#eye-app { background-color: @eye-bg; }

menubar {
    background-color: @eye-alt;
    border-bottom: 1px solid @eye-line;
    color: @eye-ink;
}

notebook header {
    background-color: #dedad0;
    border-bottom: 1px solid @eye-line;
    padding: 2px 4px;
    color: @eye-ink;
}

notebook header tab {
    border: 1px solid #8d897f;
    border-radius: 0;
    padding: 4px 10px;
    background-color: @eye-alt;
    color: @eye-ink;
}

notebook header tab:hover { background-color: #d3cec0; color: #000000; }

notebook header tab:checked {
    background-color: @eye-bg;
    border-bottom-color: @eye-bg;
    color: #000000;
    box-shadow: inset 0 -3px 0 #1f5985;
}

/* ---------- tables: dark text on near-white cells ---------- */
treeview, #eye-table.view {
    background-color: @eye-surface;
    color: #000000;
    border: 1px solid @eye-line;
}

/* ID-qualified rules are required here: #eye-table.view otherwise wins on
   specificity and hides the ordinary :selected style. */
treeview.view:hover { background-color: #eaf2f8; }

treeview.view:selected,
#eye-table.view:selected {
    background-color: #b6d2e8;
    color: #000000;
    box-shadow: inset 4px 0 0 #1f5985, inset 0 -1px 0 #1f5985;
}

#eye-table.view:hover { background-color: #eaf2f8; }

treeview header {
    background-color: @eye-alt;
    color: #000000;
    font-weight: bold;
    border-bottom: 1px solid @eye-line;
}

/* ---------- metadata inspector (light panel) ---------- */
#eye-inspector.view, #eye-inspector {
    background-color: @eye-surface;
    color: #000000;
    border: 1px solid @eye-line;
    padding: 4px;
}

#eye-inspector text { background-color: transparent; color: #000000; }

/* ---------- terminal panels (dark panel, light text) ---------- */
#eye-terminal.view, #eye-file-view.view, #eye-terminal, #eye-file-view {
    background-color: @eye-term-bg;
    color: @eye-term-ink;
    border: 1px solid #454b50;
}

#eye-terminal text, #eye-file-view text {
    background-color: transparent;
    color: @eye-term-ink;
}

#eye-terminal text:selected, #eye-file-view text:selected,
#eye-inspector text:selected {
    background-color: #34536b;
    color: #ffffff;
}

/* ---------- surrounding surfaces ---------- */
#eye-scrolled { background-color: #f7f5ef; border: 1px solid @eye-line; }

#eye-status {
    background-color: @eye-alt;
    color: #141312;
    border-top: 1px solid @eye-line;
    padding: 3px 6px;
}

.eye-strong { font-weight: bold; color: #000000; }
.eye-muted  { color: @eye-ink-soft; }

/* Buttons: one light palette plus the same blue edge accent everywhere.
   background-image/box-shadow are reset so no dark system-theme gradient can
   leak through as white text on dark grey edges. */
button, button.eye-button {
    border: 1px solid #6f6b62;
    border-radius: 0;
    background-color: #e8e4da;
    background-image: none;
    color: @eye-ink;
    padding: 3px 9px;
    box-shadow: none;
}
button label, button.eye-button label { color: @eye-ink; background-color: transparent; }

button:hover, button.eye-button:hover {
    background-color: #d3cec0;
    color: #000000;
    box-shadow: inset 0 -3px 0 #1f5985;
}
button:hover label, button.eye-button:hover label { color: #000000; }

button:active, button.eye-button:active,
button:checked, button.eye-button:checked {
    background-color: #b6d2e8;
    color: #000000;
    box-shadow: inset 0 -3px 0 #1f5985;
}
button:active label, button.eye-button:active label { color: #000000; }

button:focus, button.eye-button:focus { border-color: #1f5985; }

entry {
    border: 1px solid #6f6b62;
    border-radius: 0;
    background-color: @eye-surface;
    background-image: none;
    color: #000000;
    padding: 2px 5px;
}

entry:focus {
    border-color: #1f5985;
    box-shadow: inset 0 0 0 1px #1f5985;
}

checkbutton, combobox {
    background-color: @eye-bg;
    background-image: none;
    color: @eye-ink;
}

checkbutton:hover, combobox:hover { background-color: #ded9cc; }
checkbutton:active, combobox:active { background-color: #c9c2b2; }
combobox window, combobox menu, combobox menuitem { background-color: @eye-bg; color: @eye-ink; }

separator { background-color: @eye-line; }
`

func applyTheme(screen *gdk.Screen) {
	provider, err := gtk.CssProviderNew()
	if err != nil {
		return
	}
	if err := provider.LoadFromData(themeCSS); err != nil {
		return
	}
	if screen != nil {
		gtk.AddProviderForScreen(screen, provider, uint(gtk.STYLE_PROVIDER_PRIORITY_APPLICATION))
	}
}
