package gui

import (
	"fmt"
	"strings"

	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"

	"eyeofmx/internal/model"
	"eyeofmx/internal/watcher"
)

// LivePage renders the real-time system and user activity feed.
type LivePage struct {
	app      *App
	root     *gtk.Box
	terminal *gtk.TextView
	filter   *gtk.Entry
	category *gtk.ComboBoxText
	follow   *gtk.CheckButton
	status   *gtk.Label
	watcher  *watcher.Watcher
	shown    int
	lastKey  string
	running  bool
}

func newLivePage(app *App, w *watcher.Watcher) *LivePage {
	p := &LivePage{app: app, watcher: w}
	root := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	root.SetBorderWidth(10)

	bar := mustBox(gtk.ORIENTATION_HORIZONTAL, 6)
	var startStop *gtk.Button
	startStop = toolbarButton("Pause feed", func() {
		if p.running {
			w.Stop()
			p.running = false
			startStop.SetLabel("Resume feed")
		} else {
			w.Start()
			p.running = true
			startStop.SetLabel("Pause feed")
		}
	})
	p.running = true
	bar.PackStart(startStop, false, false, 0)
	bar.PackStart(toolbarButton("Clear feed", func() {
		w.Clear()
		p.shown = 0
		setText(p.terminal, "")
	}), false, false, 0)
	bar.PackStart(mustLabel("Filter:"), false, false, 0)
	p.filter = mustEntry()
	p.filter.SetPlaceholderText("process name, port, path, keyword")
	p.filter.Connect("changed", func() { p.render(true) })
	bar.PackStart(p.filter, true, true, 0)
	p.category = mustCombo("All categories", "BOOT", "PROCESS", "NETWORK", "FILE", "AUTH", "SYSTEM")
	p.category.Connect("changed", func() { p.render(true) })
	bar.PackStart(p.category, false, false, 0)
	p.follow = mustCheck("Auto-scroll", true)
	bar.PackStart(p.follow, false, false, 0)
	root.PackStart(bar, false, false, 0)

	p.status = mustLabel("Sampling processes, sockets, critical files and auth logs every 2 seconds.")
	root.PackStart(p.status, false, false, 0)
	root.PackStart(mustSeparator(gtk.ORIENTATION_HORIZONTAL), false, false, 0)

	p.terminal = newTerminal("eye-terminal")
	root.PackStart(newScrolled(p.terminal), true, true, 0)
	p.root = root

	glib.TimeoutAdd(1000, func() bool {
		p.render(false)
		return true
	})
	p.render(true)
	return p
}

func (p *LivePage) Widget() gtk.IWidget { return p.root }
func (p *LivePage) Title() string       { return "3  Live Activity" }

func (p *LivePage) render(force bool) {
	events := p.watcher.Events()
	text, _ := p.filter.GetText()
	key := liveFilterKey(text, p.category.GetActiveText())
	if key != p.lastKey || force || len(events) < p.shown {
		setText(p.terminal, "")
		p.shown = 0
		p.lastKey = key
	}
	if p.shown >= len(events) {
		p.updateStatus(events)
		return
	}
	for _, e := range events[p.shown:] {
		if !liveMatches(e, key) {
			continue
		}
		appendText(p.terminal, formatEvent(e), severityTag(e.Severity), p.follow.GetActive())
	}
	p.shown = len(events)
	p.updateStatus(events)
}

func (p *LivePage) updateStatus(events []model.ActivityEvent) {
	counts := map[string]int{}
	for _, e := range events {
		counts[e.Category]++
	}
	p.status.SetText(fmt.Sprintf(
		"Events: %d  |  process %d  network %d  auth %d  file %d  |  sampling every 2s",
		len(events), counts["PROCESS"], counts["NETWORK"], counts["AUTH"], counts["FILE"]))
}

// liveFilterKey stores category first, search text second. Keeping the two
// fields in one string lets render() detect filter changes cheaply.
func liveFilterKey(text, category string) string {
	return category + "|" + strings.ToLower(strings.TrimSpace(text))
}

func liveMatches(e model.ActivityEvent, key string) bool {
	parts := strings.SplitN(key, "|", 2)
	category, text := "", ""
	if len(parts) > 0 {
		category = parts[0]
	}
	if len(parts) > 1 {
		text = parts[1]
	}
	if category != "" && !strings.EqualFold(category, "all categories") &&
		!strings.EqualFold(e.Category, category) {
		return false
	}
	if text == "" {
		return true
	}
	return strings.Contains(strings.ToLower(e.Message), text) ||
		strings.Contains(strings.ToLower(e.Detail), text) ||
		strings.Contains(strings.ToLower(e.Category), text)
}

func formatEvent(e model.ActivityEvent) string {
	stamp := e.Time.Format("2006-01-02 15:04:05")
	out := fmt.Sprintf("%s  [%-7s/%-6s] %s\n", stamp, e.Category, e.Severity, e.Message)
	if e.Detail != "" {
		out += "    " + e.Detail + "\n"
	}
	return out
}

func severityTag(severity string) string {
	switch strings.ToUpper(severity) {
	case "ALERT":
		return "risk-critical"
	case "WARN":
		return "risk-medium"
	case "NOTICE":
		return "risk-low"
	default:
		return ""
	}
}
