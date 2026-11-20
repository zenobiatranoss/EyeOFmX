package gui

import (
	"fmt"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/gotk3/gotk3/gtk"

	"eyeofmx/internal/model"
	"eyeofmx/internal/netinfo"
	"eyeofmx/internal/procinfo"
	"eyeofmx/internal/sysutil"
)

// ConnectionsPage is the active connections / listening ports inspector.
type ConnectionsPage struct {
	app       *App
	root      *gtk.Box
	table     *table
	detail    *gtk.TextView
	filter    *gtk.Entry
	scope     *gtk.ComboBoxText
	status    *gtk.Label
	conns     []model.Connection
	visible   []model.Connection
	lastFetch time.Time
}

func newConnectionsPage(app *App) *ConnectionsPage {
	p := &ConnectionsPage{app: app}
	root := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	root.SetBorderWidth(10)

	bar := mustBox(gtk.ORIENTATION_HORIZONTAL, 6)
	refresh := toolbarButton("Refresh", p.Refresh)
	bar.PackStart(refresh, false, false, 0)
	bar.PackStart(mustLabel("Filter:"), false, false, 0)
	p.filter = mustEntry()
	p.filter.SetPlaceholderText("host, port, pid, process, state")
	p.filter.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.filter, true, true, 0)
	p.scope = mustCombo("All sockets", "Listening only", "Established only", "UDP only", "Root-owned processes")
	p.scope.Connect("changed", func() { p.applyFilter() })
	bar.PackStart(p.scope, false, false, 0)
	bar.PackStart(toolbarButton("Copy row", p.copySelected), false, false, 0)
	root.PackStart(bar, false, false, 0)

	p.status = mustLabel("No data collected yet.")
	root.PackStart(p.status, false, false, 0)
	root.PackStart(mustSeparator(gtk.ORIENTATION_HORIZONTAL), false, false, 0)

	paned := mustPaned(gtk.ORIENTATION_HORIZONTAL)
	p.table = newTable([]tableSpec{
		{"PROTO", 60}, {"STATE", 105}, {"LOCAL ADDRESS", 190},
		{"REMOTE ADDRESS", 190}, {"PID", 60}, {"PROCESS", 170},
	}, true)
	p.table.OnSelectionChanged(p.onSelect)
	paned.Pack1(newScrolled(p.table.view), true, false)

	right := mustBox(gtk.ORIENTATION_VERTICAL, 6)
	right.PackStart(labelBold("INSPECTION — select a connection"), false, false, 0)
	p.detail = newTerminal("eye-terminal")
	right.PackStart(newScrolled(p.detail), true, true, 0)
	actions := mustBox(gtk.ORIENTATION_HORIZONTAL, 5)
	actions.PackStart(toolbarButton("Inspect binary path", p.inspectBinary), false, false, 0)
	actions.PackStart(toolbarButton("Check related files", p.relatedFiles), false, false, 0)
	actions.PackStart(toolbarButton("Copy details", p.copyDetails), false, false, 0)
	actions.PackStart(toolbarButton("Lookup IP info", p.lookupIP), false, false, 0)
	right.PackStart(actions, false, false, 0)
	paned.Pack2(right, true, false)
	paned.SetPosition(780)
	root.PackStart(paned, true, true, 0)

	p.root = root
	p.Refresh()
	return p
}

func (p *ConnectionsPage) Widget() gtk.IWidget { return p.root }
func (p *ConnectionsPage) Title() string       { return "1  Connections / Processes" }

// Refresh recollects sockets from ss, /proc and lsof.
func (p *ConnectionsPage) Refresh() {
	go func() {
		conns := netinfo.Collect()
		idle(func() {
			p.conns = conns
			p.lastFetch = time.Now()
			p.applyFilter()
			p.app.setStatus(fmt.Sprintf("Sockets: %d   last refresh %s", len(conns),
				p.lastFetch.Format("15:04:05")))
		})
	}()
}

func (p *ConnectionsPage) applyFilter() {
	p.table.beginUpdate()
	defer p.table.endUpdate()
	text, _ := p.filter.GetText()
	text = strings.ToLower(strings.TrimSpace(text))
	scope := p.scope.GetActiveText()
	p.table.clear()
	p.visible = nil
	for _, c := range p.conns {
		if !matchScope(c, scope) {
			continue
		}
		if text != "" && !matchConnection(c, text) {
			continue
		}
		p.visible = append(p.visible, c)
		// Dark inks for the light table background.
		color := "#141414"
		switch {
		case strings.EqualFold(c.State, "LISTEN"):
			color = "#175779"
		case strings.EqualFold(c.State, "ESTAB"):
			color = "#1d6b31"
		case strings.Contains(c.State, "SYN"):
			color = "#7d5600"
		}
		p.table.add(c.Protocol, c.State,
			fmt.Sprintf("%s:%d", c.LocalAddr, c.LocalPort),
			fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort),
			strconv.Itoa(c.PID), c.Process, color)
	}
	p.status.SetText(fmt.Sprintf("%d of %d sockets shown   |   collected %s",
		len(p.visible), len(p.conns), p.lastFetch.Format("15:04:05")))
	setText(p.detail, "Select a row to inspect full socket, process and file metadata.")
}

func matchScope(c model.Connection, scope string) bool {
	switch scope {
	case "Listening only":
		return strings.EqualFold(c.State, "LISTEN") || strings.EqualFold(c.State, "UNCONN")
	case "Established only":
		return strings.EqualFold(c.State, "ESTAB") || strings.EqualFold(c.State, "ESTABLISHED")
	case "UDP only":
		return strings.HasPrefix(c.Protocol, "udp")
	case "Root-owned processes":
		return c.PID > 0 && procinfo.UIDForPID(c.PID) == 0
	}
	return true
}

func matchConnection(c model.Connection, text string) bool {
	fields := []string{c.Protocol, c.State, c.LocalAddr, c.RemoteAddr, c.Process,
		strconv.Itoa(c.LocalPort), strconv.Itoa(c.RemotePort), strconv.Itoa(c.PID)}
	for _, f := range fields {
		if strings.Contains(strings.ToLower(f), text) {
			return true
		}
	}
	return false
}

func (p *ConnectionsPage) selected() (model.Connection, bool) {
	iter, ok := selectedIter(p.table)
	if !ok {
		return model.Connection{}, false
	}
	for _, c := range p.visible {
		if p.table.cell(iter, 0) == c.Protocol &&
			p.table.cell(iter, 1) == c.State &&
			p.table.cell(iter, 2) == fmt.Sprintf("%s:%d", c.LocalAddr, c.LocalPort) &&
			p.table.cell(iter, 3) == fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort) &&
			p.table.cell(iter, 4) == strconv.Itoa(c.PID) {
			return c, true
		}
	}
	return model.Connection{}, false
}

func (p *ConnectionsPage) onSelect() {
	c, ok := p.selected()
	if !ok {
		return
	}
	go func() {
		proc := procinfo.ReadProcess(c.PID)
		idle(func() {
			setText(p.detail, formatConnectionDetail(c, proc))
			if proc.Error != "" {
				appendText(p.detail, "\nNOTE: "+proc.Error+"\n", "risk-medium", false)
			}
		})
	}()
}

func formatConnectionDetail(c model.Connection, proc model.Process) string {
	var b strings.Builder
	line := func(k, v string) { fmt.Fprintf(&b, "%-14s %s\n", k+":", v) }
	line("LOCAL", fmt.Sprintf("%s:%d", c.LocalAddr, c.LocalPort))
	line("REMOTE", fmt.Sprintf("%s:%d", c.RemoteAddr, c.RemotePort))
	line("PROTOCOL", c.Protocol)
	line("STATE", c.State)
	line("PID / PPID", fmt.Sprintf("%d / %d", proc.PID, proc.PPID))
	line("PROCESS", firstNonEmpty(proc.Name, c.Process, "<unknown>"))
	line("EXECUTABLE", proc.Executable)
	line("COMMAND", firstNonEmpty(proc.Cmdline, "<unavailable>"))
	line("USER / UID", fmt.Sprintf("%s (%d)", firstNonEmpty(proc.User, "unknown"), proc.UID))
	line("START TIME", formatTime(proc.StartTime))
	line("UPTIME", firstNonEmpty(proc.Uptime, "<unknown>"))
	line("THREADS", strconv.Itoa(proc.Threads))
	line("CWD", firstNonEmpty(proc.CWD, "<unavailable>"))
	line("ROOT", firstNonEmpty(proc.Root, "<unavailable>"))
	line("SOCKET INODE", firstNonEmpty(c.Inode, "<not available>"))
	line("SOCKET FD", firstNonEmpty(c.FD, "<not available>"))
	line("SOURCE", c.Source)
	line("DELETED IMAGE", yesNo(proc.DeletedImage))
	if len(proc.FDs) > 0 {
		b.WriteString("\nOPEN FILE DESCRIPTORS:\n")
		for _, fd := range proc.FDs {
			b.WriteString("  " + fd + "\n")
		}
	}
	b.WriteString("\nRAW SOCKET ROW:\n")
	b.WriteString(c.Raw + "\n")
	return b.String()
}

func (p *ConnectionsPage) copySelected() {
	c, ok := p.selected()
	if !ok {
		return
	}
	copyToClipboard(fmt.Sprintf("%s %s %s:%d -> %s:%d pid=%d process=%s",
		c.Protocol, c.State, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort, c.PID, c.Process))
}

func (p *ConnectionsPage) copyDetails() {
	buf, _ := p.detail.GetBuffer()
	start, end := buf.GetStartIter(), buf.GetEndIter()
	text, _ := buf.GetText(start, end, true)
	if strings.TrimSpace(text) != "" {
		copyToClipboard(text)
	}
}

func (p *ConnectionsPage) inspectBinary() {
	c, ok := p.selected()
	if !ok {
		return
	}
	exe := procinfo.Executable(c.PID)
	showInfo(p.app.window, "Binary path inspection", inspectPath(exe))
}

// inspectPath reads file metadata directly from the kernel. GNU stat -c is a
// Debian-ism; busybox/toybox stat use different format specifiers and may even
// lack -c entirely.
func inspectPath(path string) string {
	var b strings.Builder
	st, err := os.Lstat(path)
	if err != nil {
		return fmt.Sprintf("Executable: %s\nMetadata unavailable: %v\n"+
			"Run EyeOFmX as root (sudo, doas or su) if this path is protected.\n", path, err)
	}
	fmt.Fprintf(&b, "Path: %s\nSize: %d bytes\nMode: %s (%04o)\n",
		path, st.Size(), st.Mode().String(), st.Mode().Perm())
	if raw, ok := st.Sys().(*syscall.Stat_t); ok {
		uid, gid := int(raw.Uid), int(raw.Gid)
		owner, group := strconv.Itoa(uid), strconv.Itoa(gid)
		if u, err := user.LookupId(strconv.Itoa(uid)); err == nil {
			owner = u.Username
		}
		if g, err := user.LookupGroupId(strconv.Itoa(gid)); err == nil {
			group = g.Name
		}
		fmt.Fprintf(&b, "Owner: %s (%d)\nGroup: %s (%d)\nInode: %d\n",
			owner, uid, group, gid, raw.Ino)
	}
	fmt.Fprintf(&b, "Modified: %s\n", st.ModTime().Format(time.RFC3339))
	if st.Mode()&os.ModeSymlink != 0 {
		if target, err := os.Readlink(path); err == nil {
			fmt.Fprintf(&b, "Symlink target: %s\n", target)
		}
	}
	if st.Mode()&0111 == 0 {
		b.WriteString("Note: path is not marked executable.\n")
	}
	return b.String()
}

func (p *ConnectionsPage) relatedFiles() {
	c, ok := p.selected()
	if !ok {
		return
	}
	proc := procinfo.ReadProcess(c.PID)
	var b strings.Builder
	fmt.Fprintf(&b, "PID %d — %s\nExecutable: %s\nWorking directory: %s\nRoot: %s\n\nFILE DESCRIPTORS (%d):\n",
		proc.PID, proc.Name, proc.Executable, proc.CWD, proc.Root, proc.FDCount)
	if len(proc.FDs) == 0 {
		b.WriteString("  <no readable file descriptors; running EyeOFmX as root may be required>\n")
	}
	for _, fd := range proc.FDs {
		b.WriteString("  " + fd + "\n")
	}
	showInfo(p.app.window, "Related files and descriptors", b.String())
}

func (p *ConnectionsPage) lookupIP() {
	c, ok := p.selected()
	if !ok {
		return
	}
	ip := c.RemoteAddr
	if ip == "*" || ip == "0.0.0.0" || ip == "::" || ip == "" {
		ip = c.LocalAddr
	}
	appendText(p.detail, "\n\nIP LOOKUP — "+ip+"\n", "risk-info", true)
	go func() {
		var out string
		if sysutil.Available("whois") {
			raw, err := sysutil.RunStdout(12*time.Second, "whois", ip)
			if err == nil && strings.TrimSpace(raw) != "" {
				lines := strings.Split(raw, "\n")
				if len(lines) > 60 {
					lines = lines[:60]
				}
				out = strings.Join(lines, "\n")
			}
		}
		if out == "" {
			if parsed := net.ParseIP(ip); parsed != nil {
				out = "IP version: "
				if parsed.To4() != nil {
					out += "IPv4"
				} else {
					out += "IPv6"
				}
				out += "\nPrivate address: " + yesNo(parsed.IsPrivate()) +
					"\nLoopback: " + yesNo(parsed.IsLoopback())
			}
			var reverse []string
			if sysutil.Available("getent") {
				if raw, err := sysutil.RunStdout(5*time.Second, "getent", "hosts", ip); err == nil {
					if s := strings.TrimSpace(raw); s != "" {
						reverse = strings.Fields(s)
					}
				}
			}
			if len(reverse) == 0 {
				// glibc, musl and BSD libc all expose the resolver through Go's
				// net package, so this works even without the getent binary.
				if names, err := net.LookupAddr(ip); err == nil {
					reverse = names
				}
			}
			if len(reverse) > 0 {
				out += "\nReverse lookup: " + strings.Join(reverse, ", ")
			}
			if strings.TrimSpace(out) == "" {
				out = "No reverse DNS record found."
			}
		}
		idle(func() { appendText(p.detail, sanitize(out)+"\n", "", false) })
	}()
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "<unavailable>"
	}
	return t.Format("2006-01-02 15:04:05")
}

func yesNo(v bool) string {
	if v {
		return "yes"
	}
	return "no"
}
