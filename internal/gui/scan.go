package gui

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/gotk3/gotk3/gtk"

	"eyeofmx/internal/model"
	"eyeofmx/internal/scan"
)

// ScanPage is the comprehensive posture report tab. It aggregates external
// scanners and native checks into a short report, a ranked finding table and
// the raw output of every engine that ran.
type ScanPage struct {
	app      *App
	root     *gtk.Box
	summary  *gtk.TextView
	table    *table
	raw      *gtk.TextView
	filter   *gtk.Entry
	severity *gtk.ComboBoxText
	category *gtk.ComboBoxText
	status   *gtk.Label
	quickBtn *gtk.Button
	fullBtn  *gtk.Button
	optRoot  *gtk.CheckButton
	optMal   *gtk.CheckButton
	optInteg *gtk.CheckButton
	optHard  *gtk.CheckButton
	optOSQ   *gtk.CheckButton
	optNat   *gtk.CheckButton

	report  model.ScanReport
	visible []model.ScanFinding
	running bool
}

func newScanPage(app *App) *ScanPage {
	p := &ScanPage{app: app}
	root := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	root.SetBorderWidth(10)

	bar := mustBox(gtk.ORIENTATION_HORIZONTAL, 6)
	p.quickBtn = toolbarButton("Quick posture", func() { p.run(quickOptions(), "Quick posture") })
	p.fullBtn = toolbarButton("Full comprehensive", func() { p.run(fullOptions(), "Full comprehensive") })
	bar.PackStart(p.quickBtn, false, false, 0)
	bar.PackStart(p.fullBtn, false, false, 0)
	bar.PackStart(mustSeparator(gtk.ORIENTATION_VERTICAL), false, false, 0)
	p.optNat = mustCheck("native", true)
	p.optOSQ = mustCheck("osquery", true)
	p.optRoot = mustCheck("rootkit", false)
	p.optMal = mustCheck("malware", false)
	p.optInteg = mustCheck("integrity", false)
	p.optHard = mustCheck("hardening", false)
	for _, c := range []*gtk.CheckButton{p.optNat, p.optOSQ, p.optRoot, p.optMal, p.optInteg, p.optHard} {
		bar.PackStart(c, false, false, 0)
	}
	bar.PackStart(toolbarButton("Install tools", p.app.installScanTools), false, false, 0)
	bar.PackStart(toolbarButton("Copy report", p.copyReport), false, false, 0)
	bar.PackStart(toolbarButton("Save report", p.saveReport), false, false, 0)
	root.PackStart(bar, false, false, 0)

	filterBar := mustBox(gtk.ORIENTATION_HORIZONTAL, 6)
	filterBar.PackStart(mustLabel("Filter:"), false, false, 0)
	p.filter = mustEntry()
	p.filter.SetPlaceholderText("finding, source, evidence")
	p.filter.Connect("changed", func() { p.applyFilter() })
	filterBar.PackStart(p.filter, true, true, 0)
	p.severity = mustCombo("All severities", "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
	p.severity.Connect("changed", func() { p.applyFilter() })
	filterBar.PackStart(p.severity, false, false, 0)
	p.category = mustCombo("All categories", "ROOTKIT", "MALWARE", "INTEGRITY", "SUSPICIOUS_FILE",
		"PERSISTENCE", "PRIVILEGE", "NETWORK", "HARDENING", "AUTH", "TOOL")
	p.category.Connect("changed", func() { p.applyFilter() })
	filterBar.PackStart(p.category, false, false, 0)
	filterBar.PackStart(toolbarButton("Selected evidence", p.showSelected), false, false, 0)
	filterBar.PackStart(toolbarButton("All raw output", p.showAllRaw), false, false, 0)
	filterBar.PackStart(toolbarButton("Copy raw", func() { copyToClipboard(textViewString(p.raw)) }), false, false, 0)
	root.PackStart(filterBar, false, false, 0)

	p.status = mustLabel("No scan has run yet.")
	root.PackStart(p.status, false, false, 0)
	root.PackStart(mustSeparator(gtk.ORIENTATION_HORIZONTAL), false, false, 0)

	p.summary = newTerminal("eye-terminal")
	p.summary.SetSizeRequest(-1, 170)
	root.PackStart(newScrolled(p.summary), false, false, 0)

	paned := mustPaned(gtk.ORIENTATION_VERTICAL)
	p.table = newTable([]tableSpec{
		{"SEVERITY", 85}, {"CATEGORY", 130}, {"SOURCE", 100},
		{"FINDING", 280}, {"DETAIL", 650},
	}, true)
	p.table.OnSelectionChanged(p.showSelected)
	paned.Pack1(newScrolled(p.table.view), true, false)

	rawBox := mustBox(gtk.ORIENTATION_VERTICAL, 4)
	rawBox.PackStart(labelBold("RAW OUTPUT — aggregated from every enabled engine"), false, false, 0)
	p.raw = newTerminal("eye-terminal")
	rawBox.PackStart(newScrolled(p.raw), true, true, 0)
	paned.Pack2(rawBox, true, false)
	paned.SetPosition(380)
	root.PackStart(paned, true, true, 0)

	p.root = root
	if p.app.fullOnStart {
		p.run(scan.Full(), "Full comprehensive")
	} else {
		p.RefreshQuick()
	}
	return p
}

func (p *ScanPage) Widget() gtk.IWidget { return p.root }
func (p *ScanPage) Title() string       { return "6  Comprehensive Scan" }

func quickOptions() scan.Options {
	return scan.Quick()
}

func fullOptions() scan.Options {
	return scan.Full()
}

// RefreshQuick is used by the global refresh action: it runs the cheap checks
// without turning on multi-minute external scanners.
func (p *ScanPage) RefreshQuick() { p.run(quickOptions(), "Quick posture") }

// RefreshAll runs the engines selected by the checkboxes. The full button is
// not forced here so a global refresh never starts a surprise long scan.
func (p *ScanPage) RefreshAll() { p.run(p.optionsFromUI(), "Selected engines") }

func (p *ScanPage) optionsFromUI() scan.Options {
	return scan.Options{
		NativeChecks: p.optNat.GetActive(),
		OSQuery:      p.optOSQ.GetActive(),
		RootkitTools: p.optRoot.GetActive(),
		AntiMalware:  p.optMal.GetActive(),
		Integrity:    p.optInteg.GetActive(),
		Hardening:    p.optHard.GetActive(),
	}
}

func (p *ScanPage) run(o scan.Options, label string) {
	if p.running {
		return
	}
	p.running = true
	p.quickBtn.SetSensitive(false)
	p.fullBtn.SetSensitive(false)
	message := "Running " + label + " — collecting read-only system posture…"
	if o.RootkitTools || o.AntiMalware || o.Integrity || o.Hardening {
		message = "Running " + label + " — rootkit, malware and integrity engines may take several minutes…"
	}
	p.status.SetText(message)
	go func() {
		report := scan.Scan(o)
		idle(func() {
			p.running = false
			p.quickBtn.SetSensitive(true)
			p.fullBtn.SetSensitive(true)
			p.setReport(report)
		})
	}()
}

func (p *ScanPage) setReport(report model.ScanReport) {
	p.report = report
	p.renderSummary()
	p.rebuildCategories()
	p.applyFilter()
	p.showAllRaw()
	p.status.SetText(fmt.Sprintf("%s — %d finding(s) in %s — %s",
		report.Mode, len(report.Findings), report.Duration.Round(time.Second), report.SummaryLine()))
	p.app.setStatus("Comprehensive scan: " + report.Posture)
}

func (p *ScanPage) renderSummary() {
	setText(p.summary, scan.FormatBrief(p.report))
}

func (p *ScanPage) rebuildCategories() {
	active := p.category.GetActiveText()
	seen := map[string]bool{}
	for _, f := range p.report.Findings {
		seen[f.Category] = true
	}
	categories := make([]string, 0, len(seen))
	for k := range seen {
		categories = append(categories, k)
	}
	sortStrings(categories)
	p.category.RemoveAll()
	p.category.AppendText("All categories")
	for _, c := range categories {
		p.category.AppendText(c)
	}
	p.category.SetActive(0)
	for i := 0; i <= len(categories); i++ {
		p.category.SetActive(i)
		if p.category.GetActiveText() == active {
			return
		}
	}
}

func sortStrings(a []string) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

func (p *ScanPage) applyFilter() {
	p.table.beginUpdate()
	defer p.table.endUpdate()
	text, _ := p.filter.GetText()
	text = strings.ToLower(strings.TrimSpace(text))
	sev := p.severity.GetActiveText()
	cat := p.category.GetActiveText()
	p.table.clear()
	p.visible = nil
	for _, f := range p.report.Findings {
		if sev != "All severities" && !strings.EqualFold(f.Severity, sev) {
			continue
		}
		if cat != "All categories" && f.Category != cat {
			continue
		}
		if text != "" && !strings.Contains(strings.ToLower(f.Title), text) &&
			!strings.Contains(strings.ToLower(f.Detail), text) &&
			!strings.Contains(strings.ToLower(f.Evidence), text) &&
			!strings.Contains(strings.ToLower(f.Source), text) {
			continue
		}
		p.visible = append(p.visible, f)
		p.table.add(f.Severity, f.Category, f.Source, f.Title, f.Detail, severityColor(f.Severity))
	}
	if len(p.visible) == 0 {
		setText(p.raw, "# No findings match the current filter. Use 'All raw output' to see engine output.")
	}
}

func (p *ScanPage) selected() (model.ScanFinding, bool) {
	iter, ok := selectedIter(p.table)
	if !ok {
		return model.ScanFinding{}, false
	}
	sev, src, title := p.table.cell(iter, 0), p.table.cell(iter, 2), p.table.cell(iter, 3)
	for _, f := range p.visible {
		if f.Severity == sev && f.Source == src && f.Title == title {
			return f, true
		}
	}
	return model.ScanFinding{}, false
}

func (p *ScanPage) showSelected() {
	f, ok := p.selected()
	if !ok {
		return
	}
	var b strings.Builder
	fmt.Fprintf(&b, "ID           : %s\nSEVERITY     : %s\nCATEGORY     : %s\nSOURCE       : %s\nTIME         : %s\n\nTITLE\n%s\n\nDETAIL\n%s\n\nEVIDENCE\n%s\n\nRECOMMENDED ACTION\n%s\n",
		f.ID, f.Severity, f.Category, f.Source, p.report.Time.Format(time.RFC3339),
		f.Title, f.Detail, f.Evidence, f.Recommendation)
	setTextWithTags(&b, p.raw, f.Severity)
}

func (p *ScanPage) showAllRaw() {
	var b strings.Builder
	for _, tool := range p.report.Tools {
		fmt.Fprintf(&b, "--- %s | %s | %s ---\n", tool.Tool, tool.Status, tool.Command)
		if tool.Raw == "" {
			b.WriteString("(no output)\n")
		} else {
			b.WriteString(tool.Raw)
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	if b.Len() == 0 {
		b.WriteString("# No scan has run yet.\n")
	}
	setText(p.raw, b.String())
}

func (p *ScanPage) copyReport() {
	if p.report.Findings == nil && len(p.report.Tools) == 0 {
		return
	}
	copyToClipboard(scan.FormatReport(p.report))
	p.status.SetText("Full posture report copied to clipboard.")
}

func (p *ScanPage) saveReport() {
	if len(p.report.Tools) == 0 {
		showInfo(p.app.window, "Save report", "Run a scan before saving a report.")
		return
	}
	d, err := gtk.FileChooserDialogNewWith2Buttons("Save posture report", p.app.window,
		gtk.FILE_CHOOSER_ACTION_SAVE, "Cancel", gtk.RESPONSE_CANCEL, "Save", gtk.RESPONSE_ACCEPT)
	if err != nil {
		return
	}
	d.SetCurrentName("eyeofmx-posture-report.txt")
	response := d.Run()
	if response == gtk.RESPONSE_ACCEPT {
		path := d.GetFilename()
		if path != "" {
			if err := os.WriteFile(path, []byte(scan.FormatReport(p.report)), 0644); err != nil {
				showError(p.app.window, "Save report", "Could not write the report: "+err.Error())
			} else {
				p.status.SetText("Posture report saved to " + path)
			}
		}
	}
	d.Destroy()
}
