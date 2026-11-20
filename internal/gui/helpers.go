package gui

import (
	"fmt"
	"strings"

	"github.com/gotk3/gotk3/gdk"
	"github.com/gotk3/gotk3/glib"
	"github.com/gotk3/gotk3/gtk"
)

// mustI unwraps a GTK constructor error. GTK object creation failures are
// programming/environment errors, so failing fast with a clear message is
// preferable to silently building a broken window.
func mustI(w gtk.IWidget, err error) gtk.IWidget {
	if err != nil {
		panic(fmt.Sprintf("EyeOFmX: GTK widget creation failed: %v", err))
	}
	return w
}

func mustBox(orientation gtk.Orientation, spacing int) *gtk.Box {
	b, err := gtk.BoxNew(orientation, spacing)
	if err != nil {
		panic(err)
	}
	return b
}

func mustLabel(text string) *gtk.Label {
	l, err := gtk.LabelNew(text)
	if err != nil {
		panic(err)
	}
	l.SetLineWrap(false)
	l.SetXAlign(0)
	return l
}

func mustButton(label string) *gtk.Button {
	b, err := gtk.ButtonNewWithLabel(label)
	if err != nil {
		panic(err)
	}
	return b
}

func mustEntry() *gtk.Entry {
	e, err := gtk.EntryNew()
	if err != nil {
		panic(err)
	}
	return e
}

func mustCombo(items ...string) *gtk.ComboBoxText {
	c, err := gtk.ComboBoxTextNew()
	if err != nil {
		panic(err)
	}
	for _, item := range items {
		c.AppendText(item)
	}
	if len(items) > 0 {
		c.SetActive(0)
	}
	return c
}

func mustCheck(label string, active bool) *gtk.CheckButton {
	c, err := gtk.CheckButtonNewWithLabel(label)
	if err != nil {
		panic(err)
	}
	c.SetActive(active)
	return c
}

func mustPaned(orientation gtk.Orientation) *gtk.Paned {
	p, err := gtk.PanedNew(orientation)
	if err != nil {
		panic(err)
	}
	return p
}

func mustNotebook() *gtk.Notebook {
	n, err := gtk.NotebookNew()
	if err != nil {
		panic(err)
	}
	return n
}

func mustSeparator(orientation gtk.Orientation) *gtk.Separator {
	s, err := gtk.SeparatorNew(orientation)
	if err != nil {
		panic(err)
	}
	return s
}

// newTerminal returns a read-only monospace text view styled as a terminal.
func newTerminal(name string) *gtk.TextView {
	tv, err := gtk.TextViewNew()
	if err != nil {
		panic(err)
	}
	tv.SetName(name)
	tv.SetEditable(false)
	tv.SetCursorVisible(true)
	tv.SetWrapMode(gtk.WRAP_NONE)
	buf, err := tv.GetBuffer()
	if err != nil {
		panic(err)
	}
	createTags(buf)
	return tv
}

func createTags(buf *gtk.TextBuffer) {
	// Tags are applied only inside the dark terminal panels, so every ink
	// colour here is light and high-contrast against #0d1012.
	specs := []struct {
		name, color string
		weight      int
	}{
		{"risk-critical", "#ff7b70", 700},
		{"risk-high", "#ffab7c", 700},
		{"risk-medium", "#ffd97a", 700},
		{"risk-low", "#a9d8f5", 400},
		{"risk-info", "#e2e9ec", 400},
		{"term-time", "#9ed0f5", 400},
		{"term-ok", "#bbf08d", 400},
	}
	for _, s := range specs {
		props := map[string]interface{}{"foreground": s.color, "weight": s.weight}
		if buf.CreateTag(s.name, props) == nil {
			// Tag already present in this buffer; nothing to do.
		}
	}
}

func setText(tv *gtk.TextView, text string) {
	buf, err := tv.GetBuffer()
	if err != nil {
		return
	}
	buf.SetText(sanitize(text))
}

// textViewString returns the complete text of a text view.
func textViewString(tv *gtk.TextView) string {
	buf, err := tv.GetBuffer()
	if err != nil {
		return ""
	}
	s, _ := buf.GetText(buf.GetStartIter(), buf.GetEndIter(), true)
	return s
}

func appendText(tv *gtk.TextView, text string, tag string, follow bool) {
	buf, err := tv.GetBuffer()
	if err != nil {
		return
	}
	end := buf.GetEndIter()
	if tag != "" {
		buf.InsertWithTagByName(end, sanitize(text), tag)
	} else {
		buf.Insert(end, sanitize(text))
	}
	if follow {
		end = buf.GetEndIter()
		tv.ScrollToIter(end, 0.02, false, 0, 1)
	}
}

// sanitize keeps control characters (except tab/newline) out of GTK text
// buffers and normalises CRLF from log files.
func sanitize(s string) string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || r >= 32 {
			b.WriteRune(r)
		}
	}
	return b.String()
}

func newScrolled(w gtk.IWidget) *gtk.ScrolledWindow {
	sw, err := gtk.ScrolledWindowNew(nil, nil)
	if err != nil {
		panic(err)
	}
	sw.SetPolicy(gtk.POLICY_AUTOMATIC, gtk.POLICY_AUTOMATIC)
	sw.Add(w)
	sw.SetName("eye-scrolled")
	return sw
}

// tableSpec describes one visible table column. The colour column is appended
// automatically and used for foreground markup.
type tableSpec struct {
	title string
	width int
}

type table struct {
	view  *gtk.TreeView
	store *gtk.ListStore
	cols  int

	// Selection callbacks must never run while the store is being cleared and
	// refilled: GTK emits "changed" synchronously from ListStore.Clear/Append,
	// and a nested callback that rewrites a TextView produced a fatal GTK
	// critical in long-running sessions. The signal handler is blocked for the
	// whole refill and a single debounced idle callback runs once it settles.
	sel               *gtk.TreeSelection
	selHandler        glib.SignalHandle
	selConnected      bool
	onSelectionChange func()
	updating          int
	syncQueued        bool
}

// OnSelectionChanged registers a page callback that runs on the GTK main loop
// after any in-flight table update has finished.
func (t *table) OnSelectionChanged(fn func()) {
	t.onSelectionChange = fn
	sel, err := t.view.GetSelection()
	if err != nil || sel == nil {
		return
	}
	t.sel = sel
	t.selHandler = sel.Connect("changed", func() { t.queueSelectionSync() })
	t.selConnected = true
}

func (t *table) beginUpdate() {
	t.updating++
	if t.updating == 1 && t.selConnected {
		t.sel.HandlerBlock(t.selHandler)
	}
}

func (t *table) endUpdate() {
	if t.updating == 0 {
		return
	}
	t.updating--
	if t.updating == 0 {
		if t.selConnected {
			t.sel.HandlerUnblock(t.selHandler)
		}
		t.queueSelectionSync()
	}
}

func (t *table) queueSelectionSync() {
	if t.syncQueued {
		return
	}
	t.syncQueued = true
	idle(func() {
		t.syncQueued = false
		if t.updating > 0 || t.onSelectionChange == nil {
			return
		}
		t.onSelectionChange()
	})
}

func newTable(specs []tableSpec, colorColumn bool) *table {
	types := make([]glib.Type, 0, len(specs)+1)
	for range specs {
		types = append(types, glib.TYPE_STRING)
	}
	colorIdx := len(specs)
	if colorColumn {
		types = append(types, glib.TYPE_STRING)
	}
	store, err := gtk.ListStoreNew(types...)
	if err != nil {
		panic(err)
	}
	view, err := gtk.TreeViewNew()
	if err != nil {
		panic(err)
	}
	view.SetModel(store)
	view.SetHeadersVisible(true)
	view.SetName("eye-table")
	view.SetSearchColumn(0)

	for i, spec := range specs {
		renderer, err := gtk.CellRendererTextNew()
		if err != nil {
			panic(err)
		}
		col, err := gtk.TreeViewColumnNewWithAttribute(spec.title, renderer, "text", i)
		if err != nil {
			panic(err)
		}
		if colorColumn {
			col.AddAttribute(renderer, "foreground", colorIdx)
		}
		if spec.width > 0 {
			col.SetMinWidth(spec.width)
		}
		col.SetResizable(true)
		view.AppendColumn(col)
	}
	return &table{view: view, store: store, cols: len(specs)}
}

func (t *table) clear() { t.store.Clear() }

func (t *table) add(values ...string) *gtk.TreeIter {
	iter := t.store.Append()
	cols := make([]int, len(values))
	vals := make([]interface{}, len(values))
	for i, v := range values {
		cols[i] = i
		vals[i] = v
	}
	_ = t.store.Set(iter, cols, vals)
	return iter
}

// cell returns the string value of one column of the selected row.
func (t *table) cell(iter *gtk.TreeIter, column int) string {
	v, err := t.store.GetValue(iter, column)
	if err != nil {
		return ""
	}
	s, err := v.GetString()
	if err != nil {
		return ""
	}
	return s
}

func selectedIter(t *table) (*gtk.TreeIter, bool) {
	sel, err := t.view.GetSelection()
	if err != nil {
		return nil, false
	}
	_, iter, ok := sel.GetSelected()
	return iter, ok
}

// riskColor is used for table cell foregrounds on the near-white workspace,
// so these are deliberately dark, saturated inks (never pale colours).
func riskColor(risk string) string {
	switch strings.ToUpper(risk) {
	case "CRITICAL", "ERROR", "ALERT":
		return "#a30f08"
	case "HIGH":
		return "#9c3d08"
	case "MEDIUM", "WARN":
		return "#7d5600"
	case "LOW", "NOTICE":
		return "#175779"
	default:
		return "#141414"
	}
}

func severityColor(sev string) string { return riskColor(sev) }

func copyToClipboard(text string) {
	if c, err := gtk.ClipboardGet(gdk.SELECTION_CLIPBOARD); err == nil {
		c.SetText(text)
		c.Store()
	}
}

func showDialog(parent gtk.IWindow, title, message string, mtype gtk.MessageType) {
	d := gtk.MessageDialogNew(parent, gtk.DIALOG_MODAL, mtype, gtk.BUTTONS_OK, "%s", message)
	d.SetTitle(title)
	d.Connect("response", func() { d.Destroy() })
	d.ShowAll()
}

func showInfo(parent gtk.IWindow, title, message string) {
	showDialog(parent, title, message, gtk.MESSAGE_INFO)
}

func showError(parent gtk.IWindow, title, message string) {
	showDialog(parent, title, message, gtk.MESSAGE_ERROR)
}

// toolbarButton creates a compact button with a fixed label. The explicit CSS
// class gives our theme rule priority over any dark system-theme button style.
func toolbarButton(label string, onClick func()) *gtk.Button {
	b := mustButton(label)
	if ctx, err := b.GetStyleContext(); err == nil {
		ctx.AddClass("eye-button")
	}
	b.Connect("clicked", func() { onClick() })
	return b
}

func labelBold(text string) *gtk.Label {
	l := mustLabel(text)
	ctx, err := l.GetStyleContext()
	if err == nil {
		ctx.AddClass("eye-strong")
	}
	return l
}

// idle runs a GUI-mutating function on the GTK main loop, from any goroutine.
func idle(fn func()) { glib.IdleAdd(func() bool { fn(); return false }) }
