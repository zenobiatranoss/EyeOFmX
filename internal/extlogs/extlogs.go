// Package extlogs aggregates and normalises output from the security and
// diagnostic tools already present on any Linux distribution: journalctl,
// syslog/auth.log/secure/messages, ufw/firewalld/nftables/iptables, osqueryi,
// lynis and aide. It never reimplements their logic — it parses their output
// into structured, filterable findings.
package extlogs

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"eyeofmx/internal/model"
	"eyeofmx/internal/sysutil"
)

// Options controls which external sources are queried and how deeply.
type Options struct {
	JournalLines int
	LogLines     int
	OSQuery      bool
	Lynis        bool
	AIDE         bool
}

// DefaultOptions is the balanced setting used by the GUI.
func DefaultOptions() Options {
	return Options{JournalLines: 400, LogLines: 300, OSQuery: true, Lynis: false, AIDE: false}
}

// Collect gathers all requested sources. Individual source failures are added
// as ERROR entries so the operator can see exactly what could not be read.
func Collect(o Options) []model.LogEntry {
	var out []model.LogEntry
	out = append(out, journal(o.JournalLines)...)
	out = append(out, syslogFiles(o.LogLines)...)
	out = append(out, firewall(o.LogLines)...)
	out = append(out, fail2ban(o.LogLines)...)
	if o.OSQuery {
		out = append(out, osquery()...)
	}
	if o.Lynis {
		out = append(out, lynis()...)
	}
	if o.AIDE {
		out = append(out, aide()...)
	}
	return out
}

func journal(n int) []model.LogEntry {
	if n <= 0 {
		return nil
	}
	if !sysutil.IsSystemd() {
		return []model.LogEntry{{
			Time: time.Now(), Source: "journalctl", Severity: "INFO", Tag: "TOOL",
			Message: "systemd journal is not in use — syslog files are the primary source on this system.",
			Raw:     "non-systemd init detected",
		}}
	}
	if !sysutil.Available("journalctl") {
		return []model.LogEntry{{
			Time: time.Now(), Source: "journalctl", Severity: "INFO", Tag: "TOOL",
			Message: "journalctl is not installed — syslog files are used instead.",
			Raw:     "journalctl not installed",
		}}
	}
	text, err := sysutil.RunStdout(25*time.Second, "journalctl", "-n", fmt.Sprint(n), "--no-pager", "-o", "short-iso")
	if err != nil && strings.TrimSpace(text) == "" {
		return []model.LogEntry{{
			Time: time.Now(), Source: "journalctl", Severity: "ERROR", Tag: "TOOL",
			Message: "journalctl could not be read: " + err.Error(), Raw: err.Error(),
		}}
	}
	trimmed := strings.TrimSpace(text)
	if strings.Contains(trimmed, "No journal files were found") || strings.Contains(trimmed, "-- No entries --") {
		return []model.LogEntry{{
			Time: time.Now(), Source: "journalctl", Severity: "WARN", Tag: "TOOL",
			Message: "No journal entries are visible to this user — run EyeOFmX as root to read the systemd journal.",
			Raw:     trimmed,
		}}
	}
	var out []model.LogEntry
	for _, line := range strings.Split(text, "\n") {
		if strings.TrimSpace(line) == "" {
			continue
		}
		t, msg := parseJournalLine(line)
		e := classify(msg, "journalctl")
		e.Time, e.Raw = t, line
		out = append(out, e)
	}
	return out
}

// parseJournalLine handles "2026-11-20T12:34:56+00:00 host unit[pid]: message".
func parseJournalLine(line string) (time.Time, string) {
	fields := strings.Fields(line)
	if len(fields) < 3 {
		return time.Time{}, line
	}
	var t time.Time
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02T15:04:05.000000+0000"} {
		if parsed, err := time.Parse(layout, fields[0]); err == nil {
			t = parsed
			break
		}
	}
	return t, strings.Join(fields[2:], " ")
}

func syslogFiles(n int) []model.LogEntry {
	var out []model.LogEntry
	for _, p := range sysutil.SyslogPaths() {
		lines, err := sysutil.ReadTail(p, n)
		if err != nil {
			continue
		}
		source := "syslog"
		if strings.Contains(p, "auth") || strings.Contains(p, "secure") {
			source = "auth.log"
		}
		if strings.Contains(p, "kern") {
			source = "kern.log"
		}
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			t, msg := parseSyslogLine(line)
			e := classify(msg, source)
			e.Time, e.Raw = t, line
			out = append(out, e)
		}
	}
	return out
}

// parseSyslogLine handles classic RFC3164 lines:
// "Nov 20 12:34:56 host sshd[123]: Failed password for ..."
func parseSyslogLine(line string) (time.Time, string) {
	// Modern rsyslog/syslog-ng installations often use RFC3339 in the same
	// files. Reuse the journal parser when the first field is an ISO stamp.
	if t, msg := parseJournalLine(line); !t.IsZero() {
		return t, msg
	}
	f := strings.Fields(line)
	if len(f) < 4 {
		return time.Time{}, line
	}
	stamp := strings.Join(f[:3], " ")
	var t time.Time
	for _, layout := range []string{"Jan _2 15:04:05", "Jan  2 15:04:05"} {
		if parsed, err := time.ParseInLocation(layout, stamp, time.Local); err == nil {
			now := time.Now()
			year := now.Year()
			// A December line read in January belongs to the previous year.
			if parsed.Month() > now.Month()+1 {
				year--
			}
			t = parsed.AddDate(year, 0, 0)
			break
		}
	}
	msg := strings.Join(f[4:], " ")
	if len(f) > 3 && strings.HasSuffix(f[3], ":") {
		msg = strings.Join(f[4:], " ")
	} else {
		msg = strings.Join(f[3:], " ")
	}
	return t, msg
}

func firewall(n int) []model.LogEntry {
	var out []model.LogEntry
	// Every major distro family uses a different firewall front end. Probe
	// them in order and show whichever one answers; no source is assumed.
	probes := []struct {
		binary string
		args   []string
		source string
	}{
		{"ufw", []string{"status", "verbose"}, "ufw status"},
		{"firewall-cmd", []string{"--state"}, "firewalld"},
		{"firewall-cmd", []string{"--list-all"}, "firewalld"},
		{"nft", []string{"list", "ruleset"}, "nftables"},
		{"iptables", []string{"-L", "-n", "-v"}, "iptables"},
	}
	answered := false
	for _, probe := range probes {
		if !sysutil.Available(probe.binary) {
			continue
		}
		text, err := sysutil.RunStdout(12*time.Second, probe.binary, probe.args...)
		if err != nil || strings.TrimSpace(text) == "" {
			continue
		}
		answered = true
		lines := strings.Split(text, "\n")
		if len(lines) > 120 {
			lines = lines[:120]
		}
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			e := classify(line, probe.source)
			e.Tag, e.Time, e.Raw = "FIREWALL", time.Now(), line
			out = append(out, e)
		}
	}
	if !answered {
		out = append(out, model.LogEntry{Time: time.Now(), Source: "firewall", Severity: "INFO",
			Tag: "FIREWALL", Message: "No supported firewall front end answered (ufw/firewalld/nftables/iptables).",
			Raw: "firewall status unavailable"})
	}
	for _, p := range sysutil.FirewallLogPaths() {
		lines, _ := sysutil.ReadTail(p, n)
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			t, msg := parseSyslogLine(line)
			e := classify(msg, filepathBase(p))
			e.Tag, e.Time, e.Raw = "FIREWALL", t, line
			out = append(out, e)
		}
	}
	return out
}

// filepathBase avoids importing path/filepath just for one filename.
func filepathBase(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func fail2ban(n int) []model.LogEntry {
	var out []model.LogEntry
	for _, path := range sysutil.Fail2banLogPaths() {
		lines, err := sysutil.ReadTail(path, n)
		if err != nil {
			continue
		}
		for _, line := range lines {
			if strings.TrimSpace(line) == "" {
				continue
			}
			f := strings.Fields(line)
			var t time.Time
			if len(f) >= 2 {
				if parsed, err := time.Parse("2006-01-02 15:04:05,000", f[0]+" "+f[1]); err == nil {
					t = parsed
				}
			}
			e := classify(line, "fail2ban")
			e.Tag, e.Time, e.Raw = "FIREWALL", t, line
			out = append(out, e)
		}
	}
	return out
}

func osquery() []model.LogEntry {
	if !sysutil.Available("osqueryi") {
		return nil
	}
	queries := []struct {
		name, sql string
	}{
		{"osquery/processes", "SELECT pid, parent, uid, name, path, cmdline FROM processes LIMIT 250;"},
		{"osquery/listening_ports", "SELECT port, protocol, address, pid, name FROM listening_ports WHERE address IS NOT NULL LIMIT 250;"},
		{"osquery/users", "SELECT uid, gid, username, description, home_directory, shell FROM users;"},
	}
	var out []model.LogEntry
	for _, q := range queries {
		text, err := sysutil.RunStdout(20*time.Second, "osqueryi", "--json", q.sql)
		if err != nil || strings.TrimSpace(text) == "" {
			continue
		}
		var rows []map[string]interface{}
		if err := json.Unmarshal([]byte(text), &rows); err != nil {
			continue
		}
		for _, row := range rows {
			parts := make([]string, 0, len(row))
			for _, k := range sortedKeys(row) {
				parts = append(parts, fmt.Sprintf("%s=%v", k, row[k]))
			}
			msg := strings.Join(parts, " ")
			e := classify(msg, q.name)
			e.Tag, e.Time, e.Raw = "OSQUERY", time.Now(), msg
			out = append(out, e)
		}
	}
	return out
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	for i := 1; i < len(keys); i++ {
		for j := i; j > 0 && keys[j] < keys[j-1]; j-- {
			keys[j], keys[j-1] = keys[j-1], keys[j]
		}
	}
	return keys
}

func lynis() []model.LogEntry {
	if !sysutil.Available("lynis") {
		return []model.LogEntry{{
			Time: time.Now(), Source: "lynis", Severity: "INFO", Tag: "TOOL",
			Message: "lynis is not installed — install it with your distribution's package manager to enable this source.",
			Raw:     "lynis not installed",
		}}
	}
	text, err := sysutil.RunStdout(180*time.Second, "lynis", "audit", "system", "--quick", "--no-colors")
	if err != nil && strings.TrimSpace(text) == "" {
		return []model.LogEntry{{Time: time.Now(), Source: "lynis", Severity: "ERROR", Tag: "TOOL",
			Message: "lynis audit failed: " + err.Error(), Raw: err.Error()}}
	}
	var out []model.LogEntry
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(trimmed, "[") {
			continue
		}
		upper := strings.ToUpper(trimmed)
		if !strings.Contains(upper, "WARNING") && !strings.Contains(upper, "SUGGESTION") &&
			!strings.Contains(upper, "FOUND") {
			continue
		}
		e := classify(trimmed, "lynis")
		e.Tag, e.Time, e.Raw = "LYNIS", time.Now(), line
		out = append(out, e)
	}
	return out
}

func aide() []model.LogEntry {
	if !sysutil.Available("aide") {
		return []model.LogEntry{{
			Time: time.Now(), Source: "aide", Severity: "INFO", Tag: "TOOL",
			Message: "aide is not installed — install and initialise its database to enable integrity checks.",
			Raw:     "aide not installed",
		}}
	}
	text, err := sysutil.RunStdout(240*time.Second, "aide", "--check")
	if err != nil && strings.TrimSpace(text) == "" {
		return []model.LogEntry{{Time: time.Now(), Source: "aide", Severity: "ERROR", Tag: "TOOL",
			Message: "aide --check failed: " + err.Error(), Raw: err.Error()}}
	}
	var out []model.LogEntry
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "Start check") || strings.HasPrefix(trimmed, "End check") {
			continue
		}
		e := classify(trimmed, "aide")
		e.Tag, e.Time, e.Raw = "INTEGRITY", time.Now(), line
		out = append(out, e)
	}
	return out
}

// classify assigns a severity and tag from well-known security log wording.
func classify(message, source string) model.LogEntry {
	lower := strings.ToLower(message)
	severity := "INFO"
	tag := "SYSTEM"

	alert := []string{
		"failed password", "invalid user", "authentication failure", "break-in",
		"illegal user", "unauthorized", "ufw block", "ufw deny", " denied ",
		"critical", "segfault", "root login", "exploit", "malware", "intrusion",
		"add user to shadow", "password changed", "new user",
		"avc: denied", "selinux", "audit:", "nftables", "firewalld", "reject",
	}
	warn := []string{
		"warning", "warn", "failed", "refused", "error", "sudo:", "authentication",
		"session closed", "disconnect", "timeout", "changed", "added", "removed",
		"not allowed", "no such", "denied",
	}
	notice := []string{
		"accepted password", "accepted publickey", "session opened", "started",
		"stopped", "listening", "connection", "login", "opened", "success",
	}

	for _, k := range alert {
		if strings.Contains(lower, k) {
			severity = "ALERT"
			break
		}
	}
	if severity == "INFO" {
		for _, k := range warn {
			if strings.Contains(lower, k) {
				severity = "WARN"
				break
			}
		}
	}
	if severity == "INFO" {
		for _, k := range notice {
			if strings.Contains(lower, k) {
				severity = "NOTICE"
				break
			}
		}
	}

	switch {
	case strings.Contains(lower, "ssh") || strings.Contains(lower, "sshd"):
		tag = "SSH"
	case strings.Contains(lower, "sudo") || strings.Contains(lower, "su:"):
		tag = "SUDO"
	case strings.Contains(lower, "ufw") || strings.Contains(lower, "firewall") || strings.Contains(lower, "fail2ban"):
		tag = "FIREWALL"
	case strings.Contains(lower, "kernel") || strings.Contains(lower, "kern") || strings.Contains(lower, "segfault"):
		tag = "KERNEL"
	case strings.Contains(lower, "systemd") || strings.Contains(lower, "service"):
		tag = "SERVICE"
	case strings.Contains(lower, "cron"):
		tag = "CRON"
	case strings.Contains(lower, "auth") || strings.Contains(lower, "login") || strings.Contains(lower, "session"):
		tag = "AUTH"
	}
	if strings.Contains(strings.ToLower(source), "osquery") {
		tag = "OSQUERY"
	}
	if strings.Contains(strings.ToLower(source), "lynis") {
		tag = "LYNIS"
	}
	if strings.Contains(strings.ToLower(source), "aide") {
		tag = "INTEGRITY"
	}

	m := message
	if len(m) > 400 {
		m = m[:400] + "…"
	}
	return model.LogEntry{Source: source, Severity: severity, Tag: tag, Message: m, Raw: message}
}
