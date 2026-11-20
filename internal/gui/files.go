package gui

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gotk3/gotk3/gtk"

	"eyeofmx/internal/etcaudit"
	"eyeofmx/internal/model"
)

// FilesPage is the read-only /etc and high-risk filesystem audit browser.
type FilesPage struct {
	app      *App
	root     *gtk.Box
	table    *table
	meta     *gtk.TextView
	viewer   *gtk.TextView
	filter   *gtk.Entry
	risk     *gtk.ComboBoxText
	mask     *gtk.CheckButton
	status   *gtk.Label
	records  []model.FileRecord
	visible  []model.FileRecord
	current  model.FileRecord
	viewPath string
}

func newFilesPage(app *App) *FilesPage {
	p := &FilesPage{app: app}
	root := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	root.SetBorderWidth(10)

	bar := mustBox(gtk.ORIENTATION_HORIZONTAL, 6)
	bar.PackStart(toolbarButton("Quick check", p.QuickCheck), false, false, 0)
	bar.PackStart(toolbarButton("Full audit", p.Refresh), false, false, 0)
	bar.PackStart(mustLabel("Filter:"), false, false, 0)
	p.filter = mustEntry()
	p.filter.SetPlaceholderText("path, owner, finding")
	p.filter.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.filter, true, true, 0)
	p.risk = mustCombo("All risk levels", "Medium and above", "High and above", "Critical only")
	p.risk.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.risk, false, false, 0)
	p.mask = mustCheck("Mask secrets", true)
	bar.PackStart(p.mask, false, false, 0)
	bar.PackStart(toolbarButton("Reload view", p.loadCurrent), false, false, 0)
	root.PackStart(bar, false, false, 0)

	p.status = mustLabel("No audit run yet. Use Quick check for curated files or Full audit for filesystem scans.")
	root.PackStart(p.status, false, false, 0)
	root.PackStart(mustSeparator(gtk.ORIENTATION_HORIZONTAL), false, false, 0)

	paned := mustPaned(gtk.ORIENTATION_HORIZONTAL)
	p.table = newTable([]tableSpec{
		{"RISK", 80}, {"PATH", 300}, {"MODE", 90}, {"OWNER", 90},
		{"SIZE", 80}, {"MODIFIED", 160}, {"FINDINGS", 320},
	}, true)
	p.table.OnSelectionChanged(p.onSelect)
	paned.Pack1(newScrolled(p.table.view), true, false)

	right := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	right.PackStart(labelBold("FILE METADATA (stat / lstat)"), false, false, 0)
	p.meta = newTerminal("eye-inspector")
	p.meta.SetEditable(false)
	right.PackStart(p.meta, false, false, 0)
	right.PackStart(labelBold("READ-ONLY VIEWER — risky lines highlighted"), false, false, 0)
	p.viewer = newTerminal("eye-file-view")
	right.PackStart(newScrolled(p.viewer), true, true, 0)
	actions := mustBox(gtk.ORIENTATION_HORIZONTAL, 5)
	actions.PackStart(toolbarButton("Copy metadata", p.copyMeta), false, false, 0)
	actions.PackStart(toolbarButton("Copy file text", p.copyViewer), false, false, 0)
	actions.PackStart(toolbarButton("Open another path", p.openPathDialog), false, false, 0)
	right.PackStart(actions, false, false, 0)
	paned.Pack2(right, true, false)
	paned.SetPosition(720)
	root.PackStart(paned, true, true, 0)

	p.root = root
	p.QuickCheck()
	return p
}

func (p *FilesPage) Widget() gtk.IWidget { return p.root }
func (p *FilesPage) Title() string       { return "2  /etc & Risk Files" }

// QuickCheck inspects only the curated checklist.
func (p *FilesPage) QuickCheck() {
	go func() {
		idle(func() { p.status.SetText("Running curated file checks…") })
		records := etcaudit.CuratedAudit()
		idle(func() { p.setRecords(records, "curated checklist") })
	}()
}

// Refresh performs the full audit including SUID/SGID and temp-directory scans.
func (p *FilesPage) Refresh() {
	go func() {
		idle(func() { p.status.SetText("Running full audit — filesystem scans may take up to a minute…") })
		records := etcaudit.Audit()
		idle(func() { p.setRecords(records, "full audit") })
	}()
}

func (p *FilesPage) setRecords(records []model.FileRecord, label string) {
	p.records = records
	p.applyFilter()
	high := 0
	for _, r := range records {
		if r.Risk == "CRITICAL" || r.Risk == "HIGH" {
			high++
		}
	}
	p.status.SetText(fmt.Sprintf("%d entries (%d high/critical) — %s — %s",
		len(records), high, label, time.Now().Format("15:04:05")))
}

func (p *FilesPage) applyFilter() {
	p.table.beginUpdate()
	defer p.table.endUpdate()
	text, _ := p.filter.GetText()
	text = strings.ToLower(strings.TrimSpace(text))
	level := p.risk.GetActiveText()
	min := 0
	switch level {
	case "Medium and above":
		min = 2
	case "High and above":
		min = 3
	case "Critical only":
		min = 4
	}
	p.table.clear()
	p.visible = nil
	for _, r := range p.records {
		if riskRank(r.Risk) < min {
			continue
		}
		if text != "" && !matchFile(r, text) {
			continue
		}
		p.visible = append(p.visible, r)
		p.table.add(r.Risk, r.Path, r.Mode, r.Owner,
			formatSize(r.Size), formatTime(r.Modified), strings.Join(r.Findings, "; "), riskColor(r.Risk))
	}
}

func riskRank(risk string) int {
	switch strings.ToUpper(risk) {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

func matchFile(r model.FileRecord, text string) bool {
	fields := []string{r.Path, r.Owner, r.Group, r.Mode, r.Risk, r.Description,
		strings.Join(r.Findings, " "), r.ReadError}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), text) {
			return true
		}
	}
	return false
}

func (p *FilesPage) selected() (model.FileRecord, bool) {
	iter, ok := selectedIter(p.table)
	if !ok {
		return model.FileRecord{}, false
	}
	path := p.table.cell(iter, 1)
	for _, r := range p.visible {
		if r.Path == path {
			return r, true
		}
	}
	return model.FileRecord{}, false
}

func (p *FilesPage) onSelect() {
	r, ok := p.selected()
	if !ok {
		return
	}
	p.current = r
	setText(p.meta, formatFileMeta(r))
	p.loadCurrent()
}

func formatFileMeta(r model.FileRecord) string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-14s %s\n", k+":", v) }
	line("PATH", r.Path)
	line("EXISTS", yesNo(r.Exists))
	line("TYPE", firstNonEmpty(r.GroupLabel, "file"))
	line("DESCRIPTOR", r.Mode+" ("+r.ModeOctal+")")
	line("OWNER", fmt.Sprintf("%s (%d)", r.Owner, r.UID))
	line("GROUP", fmt.Sprintf("%s (%d)", r.Group, r.GID))
	line("SIZE", formatSize(r.Size))
	line("INODE", strconv.FormatUint(r.Inode, 10))
	line("MODIFIED", formatTime(r.Modified))
	line("CHANGED", formatTime(r.Changed))
	line("ACCESSED", formatTime(r.Accessed))
	line("RISK", r.Risk)
	if r.ReadError != "" {
		line("READ ERROR", r.ReadError)
	}
	if len(r.Findings) > 0 {
		b.WriteString("\nFINDINGS:\n")
		for _, f := range r.Findings {
			b.WriteString("  - " + f + "\n")
		}
	}
	if r.Description != "" {
		b.WriteString("\nPURPOSE:\n  " + r.Description + "\n")
	}
	return b.String()
}

func (p *FilesPage) loadCurrent() {
	r := p.current
	if r.Path == "" {
		return
	}
	p.viewPath = r.Path
	st, err := os.Stat(r.Path)
	if err == nil && st.IsDir() {
		entries, err := os.ReadDir(r.Path)
		if err != nil {
			setText(p.viewer, "Cannot list directory: "+err.Error()+
				"\n(run EyeOFmX as root — sudo, doas or su — to inspect protected directories)")
			return
		}
		var b strings.Builder
		fmt.Fprintf(&b, "DIRECTORY LISTING (read-only): %s — %d entries\n\n", r.Path, len(entries))
		for _, e := range entries {
			info, err := e.Info()
			if err != nil {
				fmt.Fprintf(&b, "%s  %s\n", "?", e.Name())
				continue
			}
			fmt.Fprintf(&b, "%s  %-7s %-12s %8d  %s\n", info.Mode().String(),
				info.ModTime().Format("01-02 15:04"), ownerShort(info), info.Size(), e.Name())
		}
		setText(p.viewer, b.String())
		return
	}
	text, err := etcaudit.ReadFile(r.Path)
	if err != nil {
		setText(p.viewer, "READ FAILED: "+err.Error()+
			"\n\nRun EyeOFmX as root (sudo, doas or su) to read protected files.")
		return
	}
	if p.mask.GetActive() && strings.Contains(filepath.Base(r.Path), "shadow") {
		text = maskHashes(text)
	}
	setText(p.viewer, text)
	highlightRiskyLines(p.viewer, etcaudit.HighlightPatterns(r.Path))
}

func ownerShort(info os.FileInfo) string {
	if st, ok := info.Sys().(*syscall.Stat_t); ok {
		return fmt.Sprintf("uid=%d", st.Uid)
	}
	return "-"
}

func maskHashes(text string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.HasPrefix(line, "#") || !strings.Contains(line, ":") {
			continue
		}
		f := strings.SplitN(line, ":", 7)
		if len(f) == 7 && strings.TrimSpace(f[1]) != "" {
			f[1] = "<hash masked>"
			lines[i] = strings.Join(f, ":")
		}
	}
	return strings.Join(lines, "\n")
}

func (p *FilesPage) copyMeta() {
	buf, _ := p.meta.GetBuffer()
	start, end := buf.GetStartIter(), buf.GetEndIter()
	text, _ := buf.GetText(start, end, true)
	copyToClipboard(text)
}

func (p *FilesPage) copyViewer() {
	buf, _ := p.viewer.GetBuffer()
	start, end := buf.GetStartIter(), buf.GetEndIter()
	text, _ := buf.GetText(start, end, true)
	copyToClipboard(text)
}

func (p *FilesPage) openPathDialog() {
	d, err := gtk.FileChooserDialogNewWith1Button(
		"Open a file read-only", p.app.window, gtk.FILE_CHOOSER_ACTION_OPEN,
		"Open", gtk.RESPONSE_ACCEPT)
	if err != nil {
		return
	}
	d.Connect("response", func(_ *gtk.FileChooserDialog, response gtk.ResponseType) {
		if response != gtk.RESPONSE_ACCEPT {
			d.Destroy()
			return
		}
		path := d.GetFilename()
		d.Destroy()
		p.current = etcaudit.Refresh(path, "Manually opened path", "manual")
		setText(p.meta, formatFileMeta(p.current))
		p.loadCurrent()
	})
	d.ShowAll()
}

func formatSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	val := float64(n)
	for _, u := range []string{"KiB", "MiB", "GiB", "TiB"} {
		val /= unit
		if val < unit {
			return fmt.Sprintf("%.1f %s", val, u)
		}
	}
	return fmt.Sprintf("%.1f PiB", val/unit)
}

func highlightRiskyLines(tv *gtk.TextView, patterns []string) {
	buf, err := tv.GetBuffer()
	if err != nil || len(patterns) == 0 {
		return
	}
	start, end := buf.GetStartIter(), buf.GetEndIter()
	text, err := buf.GetText(start, end, true)
	if err != nil {
		return
	}
	for lineNo, line := range strings.Split(text, "\n") {
		for _, pattern := range patterns {
			col := strings.Index(line, pattern)
			if col < 0 {
				continue
			}
			from := buf.GetIterAtLineOffset(lineNo, col)
			to := buf.GetIterAtLineOffset(lineNo, col+len(pattern))
			buf.ApplyTagByName("risk-high", from, to)
		}
	}
}
