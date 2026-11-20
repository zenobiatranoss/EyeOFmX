// Package scan implements the comprehensive posture scan shown in the sixth
// EyeOFmX tab. It aggregates the output of the strongest free, ready-to-use
// Linux security tools (rkhunter, chkrootkit, lynis, aide, ClamAV and osquery)
// with read-only native checks of /proc, /etc and temporary directories.
//
// Every check is best-effort, bounded by a timeout and never modifies the
// system. Missing tools are reported as reduced coverage, never as failures of
// EyeOFmX itself.
package scan

import (
	"encoding/json"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"eyeofmx/internal/etcaudit"
	"eyeofmx/internal/model"
	"eyeofmx/internal/procinfo"
	"eyeofmx/internal/sysutil"
)

const (
	maxRawChars        = 16000
	maxFindingsPerTool = 40
	maxTotalFindings   = 250
)

// Options enables the individual engines of the comprehensive scan. Quick is
// the cheap default; Full turns on every installed engine.
type Options struct {
	NativeChecks bool
	OSQuery      bool
	RootkitTools bool
	AntiMalware  bool
	Integrity    bool
	Hardening    bool
}

// Quick is the default posture check: native checks plus osquery when present.
// External scanners can take minutes and are opt-in.
func Quick() Options {
	return Options{NativeChecks: true, OSQuery: true}
}

// Full enables every engine. Tools that are not installed are skipped and
// listed as unavailable coverage in the report.
func Full() Options {
	return Options{NativeChecks: true, OSQuery: true, RootkitTools: true,
		AntiMalware: true, Integrity: true, Hardening: true}
}

// collector accumulates findings and per-tool results during one scan.
type collector struct {
	findings []model.ScanFinding
	tools    []*model.ScanToolResult
	seq      int
}

func (c *collector) add(category, severity, source, title, detail, evidence, recommendation string) {
	if len(c.findings) >= maxTotalFindings {
		return
	}
	c.seq++
	c.findings = append(c.findings, model.ScanFinding{
		ID:             fmt.Sprintf("S%03d", c.seq),
		Category:       category,
		Title:          title,
		Severity:       severity,
		Source:         source,
		Detail:         oneLine(detail, 500),
		Evidence:       trimEvidence(evidence, 900),
		Recommendation: recommendation,
	})
}

func (c *collector) finish(t *model.ScanToolResult, before int) {
	t.Findings = len(c.findings) - before
	if t.Findings > 0 && t.Status == "OK" {
		t.Status = "FINDINGS"
	}
}

// runTool executes one external engine and registers its result. The second
// return value is false when the binary is missing.
func (c *collector) runTool(name, command, binary string, timeout time.Duration, args ...string) (*model.ScanToolResult, string, bool) {
	if !sysutil.Available(binary) {
		t := &model.ScanToolResult{
			Tool: name, Command: command, Status: "NOT INSTALLED",
			Raw: binary + " is not installed — install it with your distribution package manager to enable this coverage area.",
		}
		c.tools = append(c.tools, t)
		return t, "", false
	}
	start := time.Now()
	out, err := sysutil.RunStdout(timeout, binary, args...)
	status, ran := "OK", true
	if err != nil {
		ran = false
		if strings.Contains(strings.ToLower(err.Error()), "timed out") {
			status = "TIMEOUT"
		} else {
			status = "FAILED"
		}
	}
	raw := trimEvidence(out, maxRawChars)
	if strings.TrimSpace(raw) == "" && err != nil {
		raw = err.Error()
	}
	t := &model.ScanToolResult{
		Tool: name, Command: command, Available: true, Ran: ran,
		Duration: time.Since(start).Round(time.Millisecond).String(),
		Status:   status, Raw: raw,
	}
	c.tools = append(c.tools, t)
	return t, out, true
}

// Scan runs the selected engines and returns one aggregated, severity-ranked
// posture report.
func Scan(o Options) model.ScanReport {
	start := time.Now()
	c := &collector{}

	if o.NativeChecks {
		c.nativeChecks()
	}
	if o.OSQuery {
		c.osquery()
	}
	if o.RootkitTools {
		c.rkhunter()
		c.chkrootkit()
	}
	if o.AntiMalware {
		c.antimalware()
	}
	if o.Integrity {
		c.aide()
	}
	if o.Hardening {
		c.lynis()
		c.kernelSecurity()
	}
	c.firewall()

	sort.SliceStable(c.findings, func(i, j int) bool {
		ri, rj := model.SeverityRank(c.findings[i].Severity), model.SeverityRank(c.findings[j].Severity)
		if ri != rj {
			return ri > rj
		}
		if c.findings[i].Source != c.findings[j].Source {
			return c.findings[i].Source < c.findings[j].Source
		}
		return c.findings[i].Title < c.findings[j].Title
	})

	counts := map[string]int{"INFO": 0, "LOW": 0, "MEDIUM": 0, "HIGH": 0, "CRITICAL": 0}
	for _, f := range c.findings {
		counts[strings.ToUpper(f.Severity)]++
	}
	posture := "HARDENED"
	switch {
	case counts["CRITICAL"] > 0:
		posture = "CRITICAL"
	case counts["HIGH"] > 0:
		posture = "AT RISK"
	case counts["MEDIUM"] > 0:
		posture = "ATTENTION"
	}

	host, _ := os.Hostname()
	priv := "unprivileged — some checks are incomplete"
	if sysutil.IsRoot() {
		priv = "root — full access"
	}
	init := "sysinit/OpenRC/runit"
	if sysutil.IsSystemd() {
		init = "systemd"
	}
	mode := "Quick posture"
	if o.RootkitTools || o.AntiMalware || o.Integrity || o.Hardening {
		mode = "Full comprehensive"
	}

	tools := make([]model.ScanToolResult, 0, len(c.tools))
	for _, t := range c.tools {
		tools = append(tools, *t)
	}
	return model.ScanReport{
		Time: time.Now(), Duration: time.Since(start), Host: host,
		Privilege: priv, Kernel: sysutil.KernelRelease(), Init: init,
		Libc: sysutil.Libc(), Mode: mode, Posture: posture,
		Counts: counts, Findings: c.findings, Tools: tools,
	}
}

// ---------------------------------------------------------------- native ---

func (c *collector) nativeChecks() {
	t := &model.ScanToolResult{
		Tool: "native", Command: "read-only Go checks (/proc, /etc, /tmp)",
		Available: true, Ran: true, Status: "OK",
	}
	c.tools = append(c.tools, t)
	before := len(c.findings)

	c.checkUID0()
	c.checkPreload()
	c.checkWorldWritableEtc()
	c.checkTempExecutables()
	c.checkPersistence()
	c.checkDeletedImages()
	c.checkHiddenProcesses()
	c.checkASLR()
	c.checkCurated()

	c.finish(t, before)
}

func (c *collector) checkUID0() {
	data, err := os.ReadFile("/etc/passwd")
	if err != nil {
		return
	}
	n := 0
	for _, line := range strings.Split(string(data), "\n") {
		f := strings.Split(line, ":")
		if len(f) >= 3 && f[2] == "0" && f[0] != "root" {
			n++
			if n <= 10 {
				c.add("PRIVILEGE", "CRITICAL", "native", "Unexpected UID 0 account",
					"Account '"+f[0]+"' has uid 0 in /etc/passwd.", line,
					"Confirm the account is authorised; remove it or change its UID if it is not.")
			}
		}
	}
	if n > 10 {
		c.add("PRIVILEGE", "CRITICAL", "native", "Multiple UID 0 accounts",
			fmt.Sprintf("%d unexpected UID 0 accounts found", n), "/etc/passwd",
			"Audit the account database immediately.")
	}
}

func (c *collector) checkPreload() {
	data, err := os.ReadFile("/etc/ld.so.preload")
	if err != nil || strings.TrimSpace(string(data)) == "" {
		return
	}
	c.add("SUSPICIOUS_FILE", "HIGH", "native", "Dynamic linker preload is active",
		"/etc/ld.so.preload injects libraries into every dynamically linked process.",
		string(data), "Verify every listed library against your package manager; rootkits commonly use this file.")
}

func (c *collector) checkWorldWritableEtc() {
	var examples []string
	n := 0
	_ = filepath.WalkDir("/etc", func(path string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		// Symlinks report mode 0777 on most filesystems and are not writable
		// configuration files; counting them produced hundreds of false hits.
		if d.Type()&os.ModeSymlink != 0 || !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil || info.Mode().Perm()&0002 == 0 {
			return nil
		}
		n++
		if len(examples) < 8 {
			examples = append(examples, path)
		}
		if n > 500 {
			return filepath.SkipAll
		}
		return nil
	})
	if n == 0 {
		return
	}
	if n > len(examples) {
		examples = append(examples, fmt.Sprintf("... and %d more", n-len(examples)))
	}
	c.add("SUSPICIOUS_FILE", "HIGH", "native", "World-writable files under /etc",
		fmt.Sprintf("%d regular configuration files are writable by any local user", n),
		strings.Join(examples, "\n"),
		"Remove the 'other write' bit and verify the files have not been modified.")
}

func (c *collector) checkTempExecutables() {
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		var recent, hidden []string
		recentCount, hiddenCount := 0, 0
		_ = filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !d.Type().IsRegular() {
				return nil
			}
			info, err := d.Info()
			if err != nil || info.Mode().Perm()&0111 == 0 {
				return nil
			}
			if strings.HasPrefix(d.Name(), ".") {
				hiddenCount++
				if len(hidden) < 8 {
					hidden = append(hidden, path)
				}
			}
			if time.Since(info.ModTime()) < 72*time.Hour {
				recentCount++
				if len(recent) < 8 {
					recent = append(recent, path)
				}
			}
			return nil
		})
		// One aggregated finding per category keeps the report brief while a
		// bounded list of example paths remains available as evidence.
		if recentCount > 0 {
			evidence := strings.Join(recent, "\n")
			if recentCount > len(recent) {
				evidence += fmt.Sprintf("\n... and %d more", recentCount-len(recent))
			}
			severity, detail := "HIGH", fmt.Sprintf("%d executable file(s) in %s were modified within the last 3 days", recentCount, dir)
			if recentCount >= 20 {
				// Large batches usually belong to a build or package cache; keep
				// the signal but do not label a busy development host as critical.
				severity = "MEDIUM"
				detail += " — this volume is more typical of a build/cache directory"
			}
			c.add("SUSPICIOUS_FILE", severity, "native", "Recently modified executable in "+dir,
				detail, evidence,
				"Inspect each file and its owning process; dropped payloads commonly hide in temporary directories.")
		}
		if hiddenCount > 0 {
			evidence := strings.Join(hidden, "\n")
			if hiddenCount > len(hidden) {
				evidence += fmt.Sprintf("\n... and %d more", hiddenCount-len(hidden))
			}
			c.add("SUSPICIOUS_FILE", "MEDIUM", "native", "Hidden executable in "+dir,
				fmt.Sprintf("%d executable file(s) in %s have hidden names", hiddenCount, dir),
				evidence,
				"Verify these files are legitimate; hidden executables are a common rootkit indicator.")
		}
	}
}

func (c *collector) checkPersistence() {
	paths := []string{"/etc/crontab"}
	if matches, err := filepath.Glob("/etc/cron.d/*"); err == nil {
		paths = append(paths, matches...)
	}
	paths = append(paths, "/etc/profile", "/etc/bash.bashrc", "/etc/bashrc")
	patterns := []string{"/tmp/", "/dev/shm/", "/var/tmp/", "curl ", "wget ", "nc -", "bash -i", "python -c"}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil || len(data) > 512*1024 {
			continue
		}
		for _, line := range strings.Split(string(data), "\n") {
			trimmed := strings.TrimSpace(line)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			lower := strings.ToLower(trimmed)
			for _, pattern := range patterns {
				if !strings.Contains(lower, pattern) {
					continue
				}
				c.add("PERSISTENCE", "HIGH", "native", "Suspicious persistence entry",
					"A cron or shell startup entry references a temporary location or a download/execute pattern.",
					path+": "+trimmed,
					"Verify the entry is intentional; attackers use cron and shell profiles to regain access after reboot.")
				break
			}
			if len(c.findings) >= maxTotalFindings {
				return
			}
		}
	}
}

func (c *collector) checkDeletedImages() {
	deleted := procinfo.DeletedExecutables()
	if len(deleted) == 0 {
		return
	}
	var examples []string
	for i, p := range deleted {
		if i >= 8 {
			break
		}
		examples = append(examples, fmt.Sprintf("PID %d %s — %s", p.PID, p.Name, p.Executable))
	}
	c.add("SUSPICIOUS_FILE", "HIGH", "native", "Running process uses a deleted image",
		fmt.Sprintf("%d running process(es) execute a file that was removed from disk", len(deleted)),
		strings.Join(examples, "\n"),
		"Investigate the processes; replacing an executable while it runs is a common rootkit technique.")
}

func (c *collector) checkHiddenProcesses() {
	procCount := len(procinfo.AllPIDs())
	if !sysutil.Available("ps") || procCount == 0 {
		return
	}
	out, err := sysutil.RunStdout(10*time.Second, "ps", "-e", "-o", "pid=")
	if err != nil {
		return
	}
	psCount := 0
	for _, line := range strings.Split(out, "\n") {
		if strings.TrimSpace(line) != "" {
			psCount++
		}
	}
	if psCount == 0 || procCount <= psCount {
		return
	}
	diff := procCount - psCount
	if diff > 2 && diff*100 > procCount*10 {
		c.add("ROOTKIT", "MEDIUM", "native", "Process count discrepancy",
			fmt.Sprintf("/proc lists %d processes but ps lists %d (difference %d). This is a heuristic, not proof of infection.", procCount, psCount, diff),
			fmt.Sprintf("/proc=%d ps=%d", procCount, psCount),
			"Compare with a trusted live distribution boot before concluding the host is compromised.")
	}
}

func (c *collector) checkASLR() {
	data, err := os.ReadFile("/proc/sys/kernel/randomize_va_space")
	if err == nil && strings.TrimSpace(string(data)) == "0" {
		c.add("HARDENING", "MEDIUM", "native", "Address space randomisation is disabled",
			"kernel.randomize_va_space is 0, which makes memory corruption exploits easier.",
			strings.TrimSpace(string(data)), "Set kernel.randomize_va_space to 2 unless a specific application requires it off.")
	}
}

func (c *collector) checkCurated() {
	n := 0
	for _, rec := range etcaudit.CuratedAudit() {
		// A missing distribution-specific path is not a security finding.
		if !rec.Exists || (rec.Risk != "CRITICAL" && rec.Risk != "HIGH") {
			continue
		}
		if n >= 20 {
			break
		}
		n++
		category := "SUSPICIOUS_FILE"
		switch rec.GroupLabel {
		case "identity", "privilege":
			category = "PRIVILEGE"
		case "persistence":
			category = "PERSISTENCE"
		case "network":
			category = "NETWORK"
		case "runtime":
			category = "SUSPICIOUS_FILE"
		}
		detail := rec.Path
		if len(rec.Findings) > 0 {
			detail = strings.Join(rec.Findings, "; ")
		}
		c.add(category, rec.Risk, "native", rec.Description, detail, rec.Path+" — "+rec.Mode+" uid="+itoa(rec.UID),
			"Review the file with the Files tab and confirm the configuration is intentional.")
	}
}

// ------------------------------------------------------------- external ----

func (c *collector) rkhunter() {
	t, out, ok := c.runTool("rkhunter", "rkhunter --check --sk --nocolors",
		"rkhunter", 240*time.Second, "--check", "--sk", "--nocolors")
	if !ok {
		return
	}
	before := len(c.findings)
	n := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if !strings.HasPrefix(lower, "warning") && !strings.Contains(lower, "possible rootkit") &&
			!strings.Contains(lower, "suspicious") {
			continue
		}
		severity := "HIGH"
		if strings.Contains(lower, "rootkit") || strings.Contains(lower, "malware") {
			severity = "CRITICAL"
		}
		c.add("ROOTKIT", severity, "rkhunter", "rkhunter rootkit warning", trimmed, trimmed,
			"Verify the named item against your package database or a trusted live boot before trusting the host.")
		n++
		if n >= maxFindingsPerTool {
			break
		}
	}
	c.finish(t, before)
}

func (c *collector) chkrootkit() {
	t, out, ok := c.runTool("chkrootkit", "chkrootkit -q", "chkrootkit", 180*time.Second, "-q")
	if !ok {
		return
	}
	before := len(c.findings)
	n := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(strings.ToLower(trimmed), "checking") {
			continue
		}
		c.add("ROOTKIT", "HIGH", "chkrootkit", "chkrootkit infection indicator", trimmed, trimmed,
			"chkrootkit -q prints only suspicious results; investigate the named item with a trusted live boot.")
		n++
		if n >= maxFindingsPerTool {
			break
		}
	}
	c.finish(t, before)
}

func (c *collector) lynis() {
	t, out, ok := c.runTool("lynis", "lynis audit system --quick --no-colors",
		"lynis", 180*time.Second, "audit", "system", "--quick", "--no-colors")
	if !ok {
		return
	}
	before := len(c.findings)
	n := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		isWarning := strings.Contains(lower, "warning")
		isSuggestion := strings.Contains(lower, "suggestion")
		if !isWarning && !isSuggestion {
			continue
		}
		severity := "LOW"
		title := "lynis hardening suggestion"
		if isWarning {
			severity, title = "HIGH", "lynis hardening warning"
		}
		c.add("HARDENING", severity, "lynis", title, trimmed, trimmed,
			"Apply the relevant lynis recommendation and re-run the quick audit to confirm.")
		n++
		if n >= maxFindingsPerTool {
			break
		}
	}
	c.finish(t, before)
}

func (c *collector) aide() {
	t, out, ok := c.runTool("aide", "aide --check", "aide", 240*time.Second, "--check")
	if !ok {
		return
	}
	before := len(c.findings)
	n := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		lower := strings.ToLower(trimmed)
		if !strings.Contains(lower, "added:") && !strings.Contains(lower, "removed:") &&
			!strings.Contains(lower, "changed:") {
			continue
		}
		severity := "MEDIUM"
		if strings.Contains(lower, "changed:") {
			severity = "HIGH"
		}
		c.add("INTEGRITY", severity, "aide", "File integrity change", trimmed, trimmed,
			"Compare the change with your update history; unexpected changes can indicate tampering.")
		n++
		if n >= maxFindingsPerTool {
			break
		}
	}
	c.finish(t, before)
}

func (c *collector) antimalware() {
	binary := sysutil.FirstAvailable("clamscan", "clamdscan")
	command := binary + " -r --infected --no-summary /tmp /var/tmp /dev/shm"
	args := []string{"-r", "--infected", "--no-summary", "/tmp", "/var/tmp", "/dev/shm"}
	if binary == "clamdscan" {
		command = "clamdscan --no-summary /tmp /var/tmp /dev/shm"
		args = []string{"--no-summary", "/tmp", "/var/tmp", "/dev/shm"}
	}
	if binary == "" {
		c.tools = append(c.tools, &model.ScanToolResult{
			Tool: "ClamAV", Command: "clamscan / clamdscan", Status: "NOT INSTALLED",
			Raw: "Neither clamscan nor clamdscan is installed — malware signature scanning is unavailable.",
		})
		return
	}
	t, out, ok := c.runTool("ClamAV", command, binary, 180*time.Second, args...)
	if !ok {
		return
	}
	before := len(c.findings)
	n := 0
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.Contains(strings.ToUpper(trimmed), "FOUND") {
			continue
		}
		c.add("MALWARE", "CRITICAL", binary, "Malware signature found", trimmed, trimmed,
			"Quarantine the file and investigate how it arrived before removing it.")
		n++
		if n >= maxFindingsPerTool {
			break
		}
	}
	c.finish(t, before)
}

func (c *collector) osquery() {
	if !sysutil.Available("osqueryi") {
		c.tools = append(c.tools, &model.ScanToolResult{
			Tool: "osquery", Command: "osqueryi endpoint queries", Status: "NOT INSTALLED",
			Raw: "osqueryi is not installed — live endpoint queries are unavailable.",
		})
		return
	}
	t := &model.ScanToolResult{
		Tool: "osquery", Command: "osqueryi endpoint queries", Available: true, Ran: true, Status: "OK",
	}
	c.tools = append(c.tools, t)
	before := len(c.findings)

	queries := []struct {
		name, sql, category, severity, title, recommendation string
	}{
		{"processes", "SELECT pid,name,path,cmdline FROM processes WHERE path LIKE '/tmp/%' OR path LIKE '/var/tmp/%' OR path LIKE '/dev/shm/%';",
			"SUSPICIOUS_FILE", "HIGH", "Process running from a temporary path",
			"Inspect the process tree and executable; legitimate software rarely runs from temporary directories."},
		{"users", "SELECT uid,username FROM users WHERE uid = 0;",
			"PRIVILEGE", "CRITICAL", "Multiple UID 0 accounts reported by osquery",
			"Keep exactly one UID 0 account and investigate any additional superuser."},
		{"crontab", "SELECT name,command,path FROM crontab WHERE command LIKE '%/tmp/%' OR command LIKE '%/dev/shm/%' OR command LIKE '%curl%' OR command LIKE '%wget%';",
			"PERSISTENCE", "HIGH", "Suspicious scheduled task reported by osquery",
			"Verify the scheduled command and remove it if it is not authorised."},
		{"listening_ports", "SELECT port,address,pid FROM listening_ports WHERE address = '0.0.0.0';",
			"NETWORK", "INFO", "Services listening on all interfaces",
			"Confirm each exposed service is required and protected by a firewall."},
	}
	var raw strings.Builder
	for _, q := range queries {
		out, err := sysutil.RunStdout(20*time.Second, "osqueryi", "--json", q.sql)
		fmt.Fprintf(&raw, "--- %s ---\n%s\n", q.name, trimEvidence(out, 3000))
		if err != nil || strings.TrimSpace(out) == "" {
			continue
		}
		var rows []map[string]interface{}
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			continue
		}
		if q.name == "users" && len(rows) <= 1 {
			continue
		}
		if q.name == "listening_ports" {
			if len(rows) > 0 {
				c.add(q.category, q.severity, "osquery", q.title,
					fmt.Sprintf("%d sockets listen on 0.0.0.0", len(rows)), trimEvidence(out, 600), q.recommendation)
			}
			continue
		}
		n := 0
		for _, row := range rows {
			parts := make([]string, 0, len(row))
			for _, k := range sortedKeys(row) {
				parts = append(parts, k+"="+fmt.Sprint(row[k]))
			}
			evidence := strings.Join(parts, " ")
			c.add(q.category, q.severity, "osquery", q.title, evidence, evidence, q.recommendation)
			n++
			if n >= maxFindingsPerTool {
				break
			}
		}
	}
	t.Raw = trimEvidence(raw.String(), maxRawChars)
	c.finish(t, before)
}

func (c *collector) kernelSecurity() {
	t := &model.ScanToolResult{
		Tool: "kernel-security", Command: "auditctl -s; sestatus / getenforce",
		Available: true, Ran: true, Status: "OK",
	}
	c.tools = append(c.tools, t)
	before := len(c.findings)
	var raw strings.Builder

	if sysutil.Available("auditctl") {
		out, err := sysutil.RunStdout(10*time.Second, "auditctl", "-s")
		fmt.Fprintf(&raw, "--- auditctl -s ---\n%s\n", out)
		if err == nil && strings.Contains(strings.ToLower(out), "enabled 0") {
			c.add("HARDENING", "MEDIUM", "auditctl", "Linux audit framework is disabled",
				"auditctl reports enabled 0 — process and file access auditing is inactive.",
				trimEvidence(out, 600), "Enable auditd if your security policy requires access auditing.")
		}
	} else {
		raw.WriteString("--- auditctl -s ---\nauditctl is not installed.\n")
	}

	if binary := sysutil.FirstAvailable("sestatus", "getenforce"); binary != "" {
		out, err := sysutil.RunStdout(10*time.Second, binary)
		fmt.Fprintf(&raw, "--- %s ---\n%s\n", binary, out)
		if err == nil {
			lower := strings.ToLower(out)
			if strings.Contains(lower, "disabled") || strings.Contains(lower, "permissive") {
				c.add("HARDENING", "MEDIUM", binary, "SELinux is not enforcing",
					"Mandatory access control is disabled or permissive on this host.",
					trimEvidence(out, 600), "Enable enforcing mode if SELinux is part of your security policy.")
			}
		}
	} else {
		raw.WriteString("--- sestatus/getenforce ---\nNot installed (AppArmor systems are unaffected).\n")
	}

	t.Raw = trimEvidence(raw.String(), maxRawChars)
	c.finish(t, before)
}

func (c *collector) firewall() {
	probes := []struct {
		binary, command string
		args            []string
	}{
		{"ufw", "ufw status", []string{"status"}},
		{"firewall-cmd", "firewall-cmd --state", []string{"--state"}},
		{"nft", "nft list ruleset", []string{"list", "ruleset"}},
		{"iptables", "iptables -S", []string{"-S"}},
	}
	binary := ""
	command := ""
	var args []string
	for _, p := range probes {
		if sysutil.Available(p.binary) {
			binary, command, args = p.binary, p.command, p.args
			break
		}
	}
	if binary == "" {
		c.tools = append(c.tools, &model.ScanToolResult{
			Tool: "firewall", Command: "ufw / firewalld / nftables / iptables", Status: "NOT INSTALLED",
			Raw: "No supported firewall front end is installed or visible to this user.",
		})
		c.add("NETWORK", "MEDIUM", "native", "No firewall front end detected",
			"None of ufw, firewalld, nftables or iptables answered the status query.",
			"no firewall binary available", "Enable a host firewall appropriate for your distribution.")
		return
	}
	t, out, ok := c.runTool("firewall", command, binary, 15*time.Second, args...)
	if !ok {
		return
	}
	before := len(c.findings)
	// RunStdout returns stdout only; permission errors arrive on stderr and are
	// stored in Raw by runTool, so classification must use the same text.
	lower := strings.ToLower(t.Raw)
	restricted := strings.Contains(lower, "permission denied") || strings.Contains(lower, "are you root") ||
		strings.Contains(lower, "must be root") || strings.Contains(lower, "requires root") ||
		strings.Contains(lower, "need to be root")
	if restricted {
		t.Status = "RESTRICTED"
		c.add("NETWORK", "INFO", binary, "Firewall status requires elevated privileges",
			"This user cannot query the firewall state; no conclusion is drawn about whether it is active.",
			trimEvidence(out, 600), "Re-run EyeOFmX as root (sudo, doas or su) to include firewall posture.")
		c.finish(t, before)
		return
	}
	inactive := strings.Contains(lower, "inactive") || strings.Contains(lower, "not running") ||
		strings.Contains(lower, "disabled") || (strings.TrimSpace(t.Raw) == "" && t.Status == "OK")
	if inactive {
		c.add("NETWORK", "MEDIUM", binary, "Firewall appears inactive",
			"The detected firewall front end did not report an active ruleset.",
			trimEvidence(out, 600), "Enable and configure the host firewall to restrict exposed services.")
	} else {
		c.add("NETWORK", "INFO", binary, "Firewall is active",
			"A firewall front end answered its status query.", trimEvidence(out, 400),
			"Review the ruleset periodically and keep only required services open.")
	}
	c.finish(t, before)
}

// --------------------------------------------------------------- helpers ---

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func trimEvidence(s string, max int) string {
	s = strings.TrimSpace(strings.ReplaceAll(s, "\r\n", "\n"))
	if len(s) > max {
		return s[:max] + "\n... [output truncated] ..."
	}
	return s
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}

// FormatBrief renders the short posture summary used by -scan and by the top
// panel of the GUI tab. Full evidence is available with FormatReport.
func FormatBrief(r model.ScanReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "EYEOFMX — COMPREHENSIVE POSTURE REPORT\n")
	fmt.Fprintf(&b, "Time      : %s\n", r.Time.Format(time.RFC3339))
	fmt.Fprintf(&b, "Host      : %s\n", r.Host)
	fmt.Fprintf(&b, "Privilege : %s\n", r.Privilege)
	fmt.Fprintf(&b, "System    : kernel %s / %s / %s\n", r.Kernel, r.Init, r.Libc)
	fmt.Fprintf(&b, "Mode      : %s\n", r.Mode)
	fmt.Fprintf(&b, "POSTURE   : %s\n", r.Posture)
	fmt.Fprintf(&b, "Summary   : %s\n\n", r.SummaryLine())

	b.WriteString("FINDINGS (highest severity first)\n")
	top := r.TopFindings(15)
	if len(top) == 0 {
		b.WriteString("  none — no indicators were produced by the enabled checks\n")
	}
	for _, f := range top {
		fmt.Fprintf(&b, "  [%s] %s — %s (%s)\n    %s\n", f.Severity, f.Category, f.Title, f.Source, f.Detail)
	}
	b.WriteString("\nCOVERAGE\n")
	for _, tool := range r.Tools {
		fmt.Fprintf(&b, "  %-16s %-13s %3d finding(s)  %s\n",
			tool.Tool, tool.Status, tool.Findings, tool.Command)
	}
	return sanitizeReport(b.String())
}

// FormatReport renders the aggregated report as plain English text for the
// Copy and Save actions in the GUI.
func FormatReport(r model.ScanReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "EYEOFMX — COMPREHENSIVE POSTURE REPORT\n")
	fmt.Fprintf(&b, "Time      : %s\n", r.Time.Format(time.RFC3339))
	fmt.Fprintf(&b, "Host      : %s\n", r.Host)
	fmt.Fprintf(&b, "Mode      : %s\n", r.Mode)
	fmt.Fprintf(&b, "Privilege : %s\n", r.Privilege)
	fmt.Fprintf(&b, "System    : kernel %s / %s / %s\n", r.Kernel, r.Init, r.Libc)
	fmt.Fprintf(&b, "Posture   : %s\n", r.Posture)
	fmt.Fprintf(&b, "Summary   : %s\n\n", r.SummaryLine())

	b.WriteString("COVERAGE\n")
	for _, tool := range r.Tools {
		fmt.Fprintf(&b, "  %-16s %-13s %4d finding(s)  %s\n", tool.Tool, tool.Status, tool.Findings, tool.Command)
	}
	b.WriteString("\nFINDINGS\n")
	if len(r.Findings) == 0 {
		b.WriteString("  No findings were produced by the enabled checks.\n")
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "\n[%s] %s — %s (%s)\n", f.Severity, f.Category, f.Title, f.Source)
		fmt.Fprintf(&b, "  Detail   : %s\n", f.Detail)
		if f.Evidence != "" {
			fmt.Fprintf(&b, "  Evidence : %s\n", f.Evidence)
		}
		if f.Recommendation != "" {
			fmt.Fprintf(&b, "  Action   : %s\n", f.Recommendation)
		}
	}
	b.WriteString("\nRAW TOOL OUTPUT\n")
	for _, tool := range r.Tools {
		fmt.Fprintf(&b, "\n--- %s (%s) ---\n%s\n", tool.Tool, tool.Status, tool.Raw)
	}
	return sanitizeReport(b.String())
}

func sanitizeReport(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || r >= 32 {
			b.WriteRune(r)
		}
	}
	return b.String()
}
