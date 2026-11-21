// Package gui implements the native GTK 3 desktop interface of EyeOFmX.
// There is no web server, browser view or HTML content anywhere in this
// application: every widget is a native GTK widget.
package gui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/gtk"

	"eyeofmx/internal/scan"
	"eyeofmx/internal/sysutil"
	"eyeofmx/internal/watcher"
)

// App owns the main window, tab notebook and all page controllers.
type App struct {
	window      *gtk.Window
	notebook    *gtk.Notebook
	status      *gtk.Label
	watcher     *watcher.Watcher
	conn        *ConnectionsPage
	files       *FilesPage
	live        *LivePage
	history     *HistoryPage
	logs        *LogsPage
	scan        *ScanPage
	fullOnStart bool
}

// Run initialises GTK, builds the UI and enters the native event loop.
func Run() error { return run(false) }

// RunWithFullScan starts the GUI and immediately runs the full comprehensive
// scan. It is used when the application is relaunched as root after installing
// the optional scanning engines.
func RunWithFullScan() error { return run(true) }

func run(fullOnStart bool) error {
	gtk.Init(nil)
	if screen, err := gdk.ScreenGetDefault(); err == nil {
		applyTheme(screen)
	}

	app := &App{watcher: watcher.New(), fullOnStart: fullOnStart}
	if err := app.build(); err != nil {
		return err
	}
	app.watcher.Start()
	app.window.ShowAll()
	app.setStatus(buildStatusLine())
	if !fullOnStart {
		idle(app.offerScanToolInstall)
	}
	gtk.Main()
	app.watcher.Stop()
	return nil
}

func (a *App) build() error {
	win, err := gtk.WindowNew(gtk.WINDOW_TOPLEVEL)
	if err != nil {
		return err
	}
	a.window = win
	win.SetTitle("EyeOFmX — Linux Monitoring & Security Inspector")
	setWindowIcon(win)
	win.SetDefaultSize(1440, 900)
	win.SetPosition(gtk.WIN_POS_CENTER)
	win.Connect("destroy", func() { gtk.MainQuit() })
	win.SetName("eye-app")

	outer := mustBox(gtk.ORIENTATION_VERTICAL, 0)
	win.Add(outer)

	outer.PackStart(a.buildMenu(), false, false, 0)

	a.notebook = mustNotebook()
	a.notebook.Connect("switch-page", func() { a.refreshActiveStatus() })

	a.conn = newConnectionsPage(a)
	a.files = newFilesPage(a)
	a.live = newLivePage(a, a.watcher)
	a.history = newHistoryPage(a)
	a.logs = newLogsPage(a)
	a.scan = newScanPage(a)

	for _, page := range []interface {
		Widget() gtk.IWidget
		Title() string
	}{a.conn, a.files, a.live, a.history, a.logs, a.scan} {
		a.notebook.AppendPage(page.Widget(), mustLabel(page.Title()))
	}
	outer.PackStart(a.notebook, true, true, 0)

	statusBar := mustBox(gtk.ORIENTATION_HORIZONTAL, 8)
	statusBar.SetName("eye-status")
	a.status = mustLabel(buildStatusLine())
	statusBar.PackStart(a.status, true, false, 0)
	hint := mustLabel("F5 refresh active tab   |   Ctrl+Q quit")
	ctx, _ := hint.GetStyleContext()
	ctx.AddClass("eye-muted")
	statusBar.PackStart(hint, false, false, 0)
	outer.PackStart(statusBar, false, false, 0)

	accels, err := gtk.AccelGroupNew()
	if err == nil {
		win.AddAccelGroup(accels)
		key, mods := gtk.AcceleratorParse("<Control>q")
		accels.Connect(key, mods, gtk.ACCEL_VISIBLE, func() { gtk.MainQuit() })
		key, mods = gtk.AcceleratorParse("F5")
		accels.Connect(key, mods, gtk.ACCEL_VISIBLE, func() { a.RefreshActive() })
	}
	return nil
}

func (a *App) buildMenu() *gtk.MenuBar {
	bar, _ := gtk.MenuBarNew()

	fileItem, _ := gtk.MenuItemNewWithLabel("File")
	styleMenuItem(fileItem)
	fileMenu, _ := gtk.MenuNew()
	fileItem.SetSubmenu(fileMenu)
	bar.Append(fileItem)

	addMenuItem(fileMenu, "Refresh active tab   F5", a.RefreshActive)
	addMenuItem(fileMenu, "Refresh all tabs", a.RefreshAll)
	addMenuItem(fileMenu, "Copy status summary", func() { copyToClipboard(buildStatusLine()) })
	addMenuItem(fileMenu, "Quit   Ctrl+Q", func() { gtk.MainQuit() })

	toolsItem, _ := gtk.MenuItemNewWithLabel("Tools")
	styleMenuItem(toolsItem)
	toolsMenu, _ := gtk.MenuNew()
	toolsItem.SetSubmenu(toolsMenu)
	bar.Append(toolsItem)
	addMenuItem(toolsMenu, "Open /etc file read-only", func() { a.files.openPathDialog() })
	addMenuItem(toolsMenu, "Install scanning tools (root)", func() { a.installScanTools() })
	addMenuItem(toolsMenu, "Run full comprehensive scan", func() {
		a.notebook.SetCurrentPage(5)
		a.scan.run(scan.Full(), "Full comprehensive")
	})
	addMenuItem(toolsMenu, "Privileges and tool availability", a.showCapabilityDialog)
	addMenuItem(toolsMenu, "Retro theme information", func() {
		showInfo(a.window, "Theme", "EyeOFmX uses a native GTK 3 theme: off-white workspace, monospace type, sharp borders and dark terminal panels for logs.")
	})

	helpItem, _ := gtk.MenuItemNewWithLabel("Help")
	styleMenuItem(helpItem)
	helpMenu, _ := gtk.MenuNew()
	helpItem.SetSubmenu(helpMenu)
	bar.Append(helpItem)
	addMenuItem(helpMenu, "About EyeOFmX", a.showAbout)

	return bar
}

func styleMenuItem(item *gtk.MenuItem) {
	if item == nil {
		return
	}
	if ctx, err := item.GetStyleContext(); err == nil {
		ctx.AddClass("eye-menu-item")
	}
}

func addMenuItem(menu *gtk.Menu, label string, fn func()) {
	item, err := gtk.MenuItemNewWithLabel(label)
	if err != nil {
		return
	}
	styleMenuItem(item)
	item.Connect("activate", func() { fn() })
	menu.Append(item)
}

func buildStatusLine() string {
	priv := "unprivileged (run as root for full access)"
	if sysutil.IsRoot() {
		priv = "root — full access"
	}
	init := "sysinit"
	if sysutil.IsSystemd() {
		init = "systemd"
	}
	tools := []string{}
	for _, t := range sysutil.ToolList() {
		if t.Available {
			tools = append(tools, t.Binary)
		}
	}
	if len(tools) == 0 {
		tools = []string{"no optional tools"}
	}
	host, _ := os.Hostname()
	return fmt.Sprintf("EyeOFmX  |  %s  |  %s  |  %s/%s  |  tools: %s",
		host, priv, init, sysutil.Libc(), strings.Join(tools, ","))
}

func (a *App) setStatus(text string) {
	// The notebook emits "switch-page" while tabs are being appended, before
	// the status label is constructed. Ignore those early callbacks.
	if a.status != nil {
		a.status.SetText(text)
	}
}

func (a *App) refreshActiveStatus() {
	a.setStatus(fmt.Sprintf("%s  |  %s", buildStatusLine(), timeNow()))
}

func timeNow() string {
	return time.Now().Format("15:04:05")
}

// RefreshActive refreshes the currently visible tab.
func (a *App) RefreshActive() {
	switch a.notebook.GetCurrentPage() {
	case 0:
		a.conn.Refresh()
	case 1:
		a.files.QuickCheck()
	case 2:
		a.live.watcher.Clear()
	case 3:
		a.history.Refresh()
	case 4:
		a.logs.Refresh()
	case 5:
		a.scan.RefreshQuick()
	}
}

// RefreshAll re-runs every collector that has an explicit refresh action.
func (a *App) RefreshAll() {
	a.conn.Refresh()
	a.files.Refresh()
	a.history.Refresh()
	a.logs.Refresh()
	a.scan.RefreshAll()
	a.setStatus("Refreshing all tabs…")
}

func (a *App) showCapabilityDialog() {
	var b strings.Builder
	init := "sysinit/OpenRC/runit"
	if sysutil.IsSystemd() {
		init = "systemd"
	}
	fmt.Fprintf(&b, "init: %s\nlibc: %s\nkernel: %s\n\n", init, sysutil.Libc(), sysutil.KernelRelease())
	if sysutil.IsRoot() {
		b.WriteString("Running as root.\nAll /proc entries, protected logs and restricted /etc files are readable.\n")
	} else {
		b.WriteString("Running unprivileged.\nThe following data will be incomplete:\n")
		b.WriteString("  - process owners and command lines of other users\n")
		b.WriteString("  - /etc/shadow, /etc/gshadow and restricted sudo policy files\n")
		b.WriteString("  - journal entries restricted to root\n")
		b.WriteString("Restart EyeOFmX as root (sudo, doas or su) for full access.\n")
	}
	b.WriteString("\nDetected capabilities:\n")
	for _, tool := range sysutil.ToolList() {
		binary := tool.Binary
		if binary == "" {
			binary = "not installed"
		}
		fmt.Fprintf(&b, "  %-16s %s\n", tool.Capability+":", binary)
	}
	showInfo(a.window, "Privileges and tools", b.String())
}

func (a *App) showAbout() {
	d, err := gtk.AboutDialogNew()
	if err != nil {
		return
	}
	d.SetTransientFor(a.window)
	d.SetProgramName("EyeOFmX")
	if logo := iconPixbuf(); logo != nil {
		d.SetLogo(logo)
	}
	d.SetVersion("1.0.1")
	d.SetComments("Created by Zenobia\nFor NT Protection\n\n" +
		"Native GTK 3 monitoring and security inspection for Linux desktops.\n" +
		"Includes a comprehensive posture scan aggregating rkhunter, chkrootkit, lynis, " +
		"aide, ClamAV, osquery and native checks into one brief report.\n" +
		"Collectors are read-only. Installing optional engines is a separate, " +
		"explicit action with system authentication.")
	d.SetCopyright("Copyright (c) 2026 Zenobia")
	d.SetLicense("MIT")
	d.SetAuthors([]string{"Zenobia"})
	d.SetWrapLicense(true)
	d.Connect("response", func() { d.Destroy() })
	d.ShowAll()
}
