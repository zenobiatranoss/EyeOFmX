package gui

import (
	"fmt"
	"strings"

	"github.com/gotk3/gotk3/gtk"

	"eyeofmx/internal/cmdhistory"
	"eyeofmx/internal/model"
)

// HistoryPage displays shell history files and live-observed commands in a
// dark terminal-style view with search and filtering.
type HistoryPage struct {
	app     *App
	root    *gtk.Box
	table   *table
	term    *gtk.TextView
	filter  *gtk.Entry
	shell   *gtk.ComboBoxText
	live    *gtk.CheckButton
	status  *gtk.Label
	entries []model.HistoryEntry
	visible []model.HistoryEntry
}

func newHistoryPage(app *App) *HistoryPage {
	p := &HistoryPage{app: app}
	root := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	root.SetBorderWidth(10)

	bar := mustBox(gtk.ORIENTATION_HORIZONTAL, 6)
	bar.PackStart(toolbarButton("Refresh", p.Refresh), false, false, 0)
	bar.PackStart(mustLabel("Search:"), false, false, 0)
	p.filter = mustEntry()
	p.filter.SetPlaceholderText("command text, user, source")
	p.filter.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.filter, true, true, 0)
	p.shell = mustCombo("All shells", "bash", "zsh", "fish", "live")
	p.shell.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.shell, false, false, 0)
	p.live = mustCheck("Include live process commands", true)
	p.live.Connect("toggled", func() { p.Refresh() })
	bar.PackStart(p.live, false, false, 0)
	bar.PackStart(toolbarButton("Copy all", p.copyAll), false, false, 0)
	root.PackStart(bar, false, false, 0)

	p.status = mustLabel("No history loaded.")
	root.PackStart(p.status, false, false, 0)
	root.PackStart(mustSeparator(gtk.ORIENTATION_HORIZONTAL), false, false, 0)

	paned := mustPaned(gtk.ORIENTATION_VERTICAL)
	p.table = newTable([]tableSpec{
		{"TIME", 165}, {"USER", 100}, {"SHELL", 75}, {"COMMAND", 600}, {"SOURCE", 260},
	}, false)
	p.table.OnSelectionChanged(p.showTerminal)
	paned.Pack1(newScrolled(p.table.view), true, false)

	p.term = newTerminal("eye-terminal")
	paned.Pack2(newScrolled(p.term), true, false)
	paned.SetPosition(360)
	root.PackStart(paned, true, true, 0)

	p.root = root
	p.Refresh()
	return p
}

func (p *HistoryPage) Widget() gtk.IWidget { return p.root }
func (p *HistoryPage) Title() string       { return "4  Command History" }

// Refresh reads history files (and optionally live observations) off the GUI
// thread so a large ~/.bash_history cannot freeze the window.
func (p *HistoryPage) Refresh() {
	includeLive := p.live.GetActive() // read GTK state on the main thread
	go func() {
		entries := cmdhistory.Collect(includeLive, p.app.watcher.Events())
		idle(func() {
			p.entries = entries
			p.applyFilter()
		})
	}()
}

func (p *HistoryPage) applyFilter() {
	p.table.beginUpdate()
	defer p.table.endUpdate()
	text, _ := p.filter.GetText()
	text = strings.ToLower(strings.TrimSpace(text))
	shell := p.shell.GetActiveText()
	p.table.clear()
	p.visible = nil
	for _, e := range p.entries {
		if shell != "All shells" && !strings.EqualFold(e.Shell, shell) {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(e.Text), text) &&
			!strings.Contains(strings.ToLower(e.User), text) &&
			!strings.Contains(strings.ToLower(e.Source), text) {
			continue
		}
		p.visible = append(p.visible, e)
		p.table.add(formatTime(e.Time), e.User, e.Shell, e.Text, e.Source)
	}
	p.status.SetText(fmt.Sprintf("%d of %d commands shown — newest first", len(p.visible), len(p.entries)))
	p.showTerminal()
}

func (p *HistoryPage) showTerminal() {
	var b strings.Builder
	b.WriteString("# EyeOFmX command history — read-only reconstruction\n")
	b.WriteString("# Format: timestamp  user@shell  $ command\n\n")
	for _, e := range p.visible {
		user := e.User
		if user == "" {
			user = "unknown"
		}
		fmt.Fprintf(&b, "%s  %s@%s  $ %s\n", formatTime(e.Time), user, e.Shell, e.Text)
	}
	setText(p.term, b.String())
}

func (p *HistoryPage) copyAll() {
	copyToClipboard(textViewString(p.term))
}
