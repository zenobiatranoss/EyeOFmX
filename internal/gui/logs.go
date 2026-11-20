package gui

import (
	"fmt"
	"strings"

	"github.com/gotk3/gotk3/gtk"

	"eyeofmx/internal/extlogs"
	"eyeofmx/internal/model"
)

// LogsPage aggregates journalctl, syslog/auth.log, ufw, osquery, lynis and
// aide output into one filterable dark terminal viewer.
type LogsPage struct {
	app      *App
	root     *gtk.Box
	table    *table
	terminal *gtk.TextView
	filter   *gtk.Entry
	severity *gtk.ComboBoxText
	source   *gtk.ComboBoxText
	optOSQ   *gtk.CheckButton
	optLynis *gtk.CheckButton
	optAIDE  *gtk.CheckButton
	status   *gtk.Label
	entries  []model.LogEntry
	visible  []model.LogEntry
	sources  []string
}

func newLogsPage(app *App) *LogsPage {
	p := &LogsPage{app: app}
	root := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	root.SetBorderWidth(10)

	bar := mustBox(gtk.ORIENTATION_HORIZONTAL, 6)
	bar.PackStart(toolbarButton("Refresh", p.Refresh), false, false, 0)
	p.optOSQ = mustCheck("osquery", true)
	p.optLynis = mustCheck("lynis", false)
	p.optAIDE = mustCheck("aide", false)
	bar.PackStart(p.optOSQ, false, false, 0)
	bar.PackStart(p.optLynis, false, false, 0)
	bar.PackStart(p.optAIDE, false, false, 0)
	bar.PackStart(mustSeparator(gtk.ORIENTATION_VERTICAL), false, false, 0)
	bar.PackStart(mustLabel("Search:"), false, false, 0)
	p.filter = mustEntry()
	p.filter.SetPlaceholderText("keyword, host, pid, unit")
	p.filter.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.filter, true, true, 0)
	p.severity = mustCombo("All severities", "ALERT", "WARN", "NOTICE", "INFO", "ERROR")
	p.severity.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.severity, false, false, 0)
	p.source = mustCombo("All sources")
	p.source.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.source, false, false, 0)
	root.PackStart(bar, false, false, 0)

	bar2 := mustBox(gtk.ORIENTATION_HORIZONTAL, 6)
	bar2.PackStart(toolbarButton("Show selected raw", p.showSelected), false, false, 0)
	bar2.PackStart(toolbarButton("Show all filtered raw", p.showAllRaw), false, false, 0)
	bar2.PackStart(toolbarButton("Copy viewer", func() { copyToClipboard(textViewString(p.terminal)) }), false, false, 0)
	root.PackStart(bar2, false, false, 0)

	p.status = mustLabel("No log data collected yet.")
	root.PackStart(p.status, false, false, 0)
	root.PackStart(mustSeparator(gtk.ORIENTATION_HORIZONTAL), false, false, 0)

	paned := mustPaned(gtk.ORIENTATION_VERTICAL)
	p.table = newTable([]tableSpec{
		{"TIME", 165}, {"SOURCE", 150}, {"SEVERITY", 85}, {"TAG", 95}, {"MESSAGE", 700},
	}, true)
	p.table.OnSelectionChanged(p.showSelected)
	paned.Pack1(newScrolled(p.table.view), true, false)
	p.terminal = newTerminal("eye-terminal")
	paned.Pack2(newScrolled(p.terminal), true, false)
	paned.SetPosition(320)
	root.PackStart(paned, true, true, 0)

	p.root = root
	p.Refresh()
	return p
}

func (p *LogsPage) Widget() gtk.IWidget { return p.root }
func (p *LogsPage) Title() string       { return "5  Security Logs" }

// Refresh queries every enabled external tool. Heavy optional tools (lynis,
// aide) are only run when their checkbox is selected.
func (p *LogsPage) Refresh() {
	opts := extlogs.DefaultOptions()
	opts.OSQuery = p.optOSQ.GetActive()
	opts.Lynis = p.optLynis.GetActive()
	opts.AIDE = p.optAIDE.GetActive()
	go func() {
		idle(func() { p.status.SetText("Reading journalctl, logs and firewall state…") })
		entries := extlogs.Collect(opts)
		idle(func() {
			p.entries = entries
			p.rebuildSources()
			p.applyFilter()
			p.app.setStatus(fmt.Sprintf("Security log entries: %d", len(entries)))
		})
	}()
}

func (p *LogsPage) rebuildSources() {
	active := p.source.GetActiveText()
	seen := map[string]bool{}
	p.sources = nil
	for _, e := range p.entries {
		if !seen[e.Source] {
			seen[e.Source] = true
			p.sources = append(p.sources, e.Source)
		}
	}
	p.source.RemoveAll()
	p.source.AppendText("All sources")
	for _, s := range p.sources {
		p.source.AppendText(s)
	}
	if active == "" {
		active = "All sources"
	}
	p.source.SetActive(0)
	for i := 0; i < len(p.sources)+1; i++ {
		p.source.SetActive(i)
		if p.source.GetActiveText() == active {
			break
		}
	}
}

func (p *LogsPage) applyFilter() {
	p.table.beginUpdate()
	defer p.table.endUpdate()
	text, _ := p.filter.GetText()
	text = strings.ToLower(strings.TrimSpace(text))
	sev := p.severity.GetActiveText()
	src := p.source.GetActiveText()
	p.table.clear()
	p.visible = nil
	for _, e := range p.entries {
		if sev != "All severities" && !strings.EqualFold(e.Severity, sev) {
			continue
		}
		if src != "All sources" && e.Source != src {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(e.Message), text) &&
			!strings.Contains(strings.ToLower(e.Raw), text) &&
			!strings.Contains(strings.ToLower(e.Tag), text) {
			continue
		}
		p.visible = append(p.visible, e)
		p.table.add(formatTime(e.Time), e.Source, e.Severity, e.Tag, e.Message, severityColor(e.Severity))
	}
	alerts := 0
	for _, e := range p.visible {
		if e.Severity == "ALERT" || e.Severity == "ERROR" {
			alerts++
		}
	}
	p.status.SetText(fmt.Sprintf("%d of %d entries — %d alerts/errors",
		len(p.visible), len(p.entries), alerts))
	if len(p.visible) == 0 {
		setText(p.terminal, "# No log entries match the current filter.")
	}
}

func (p *LogsPage) selected() (model.LogEntry, bool) {
	iter, ok := selectedIter(p.table)
	if !ok {
		return model.LogEntry{}, false
	}
	stamp, source, severity, message := p.table.cell(iter, 0), p.table.cell(iter, 1),
		p.table.cell(iter, 2), p.table.cell(iter, 4)
	for _, e := range p.visible {
		if e.Message == message && e.Source == source && e.Severity == severity &&
			formatTime(e.Time) == stamp {
			return e, true
		}
	}
	return model.LogEntry{}, false
}

func (p *LogsPage) showSelected() {
	e, ok := p.selected()
	if !ok {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "SOURCE   : %s\nSEVERITY : %s\nTAG      : %s\nTIME     : %s\n\nFULL ENTRY:\n%s\n",
		e.Source, e.Severity, e.Tag, formatTime(e.Time), e.Raw)
	setTextWithTags(&b, p.terminal, e.Severity)
}

func (p *LogsPage) showAllRaw() {
	var b strings.Builder
	for _, e := range p.visible {
		fmt.Fprintf(&b, "%s [%s/%s] %s\n", formatTime(e.Time), e.Source, e.Severity, e.Raw)
	}
	setText(p.terminal, b.String())
}

// setTextWithTags colours the first header lines according to severity.
func setTextWithTags(b *strings.Builder, tv *gtk.TextView, severity string) {
	setText(tv, b.String())
	buf, err := tv.GetBuffer()
	if err != nil {
		return
	}
	tag := ""
	switch severity {
	case "ALERT", "ERROR":
		tag = "risk-critical"
	case "WARN":
		tag = "risk-medium"
	case "NOTICE":
		tag = "risk-low"
	}
	if tag == "" {
		return
	}
	start := buf.GetStartIter()
	end := buf.GetIterAtLineOffset(1, 0)
	buf.ApplyTagByName(tag, start, end)
}
