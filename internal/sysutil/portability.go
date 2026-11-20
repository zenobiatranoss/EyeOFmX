package sysutil

import (
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// This file contains the single source of truth for distribution-dependent
// choices: which tool provides a capability, which log files exist, which
// init system and libc are in use, and which critical files to watch. Keeping
// these decisions in one package prevents Debian-only assumptions from leaking
// into the collectors.

// Tool describes one detected capability for the diagnostics screen.
type Tool struct {
	Capability string
	Binary     string
	Available  bool
}

type toolCandidate struct {
	capability string
	candidates []string
}

var toolRegistry = []toolCandidate{
	{"socket stats", []string{"ss", "ip"}},
	{"socket owner", []string{"lsof"}},
	{"journal", []string{"journalctl"}},
	{"firewall", []string{"ufw", "firewall-cmd", "nft", "iptables"}},
	{"osquery", []string{"osqueryi"}},
	{"system audit", []string{"lynis"}},
	{"file integrity", []string{"aide"}},
	{"rootkit scan", []string{"rkhunter", "chkrootkit"}},
	{"anti-malware", []string{"clamscan", "clamdscan"}},
	{"audit rules", []string{"auditctl"}},
	{"SELinux", []string{"sestatus", "getenforce"}},
	{"process list", []string{"ps"}},
	{"IP lookup", []string{"whois", "getent"}},
}

// FirstAvailable returns the first executable present in PATH, or "".
func FirstAvailable(names ...string) string {
	for _, name := range names {
		if Available(name) {
			return name
		}
	}
	return ""
}

// DetectTools maps each logical capability to the binary that provides it.
// An empty string means no provider is installed, which is never fatal.
func DetectTools() map[string]string {
	out := make(map[string]string, len(toolRegistry))
	for _, t := range toolRegistry {
		out[t.capability] = FirstAvailable(t.candidates...)
	}
	return out
}

// ToolList is the ordered capability list used by -check and the GUI.
func ToolList() []Tool {
	out := make([]Tool, 0, len(toolRegistry))
	for _, t := range toolRegistry {
		binary := FirstAvailable(t.candidates...)
		out = append(out, Tool{Capability: t.capability, Binary: binary, Available: binary != ""})
	}
	return out
}

// IsSystemd reports whether systemd is the active init system. Journal-only
// installations without /run/systemd/system are deliberately treated as
// non-systemd so the syslog collectors become primary.
func IsSystemd() bool {
	st, err := os.Stat("/run/systemd/system")
	return err == nil && st.IsDir()
}

// Libc reports "musl" on Alpine and other musl systems, otherwise "glibc".
// We never fail because detecting libc is informational only.
func Libc() string {
	matches, _ := filepath.Glob("/etc/ld-musl-*.path")
	if len(matches) > 0 {
		return "musl"
	}
	matches, _ = filepath.Glob("/lib/ld-musl-*.so.1")
	if len(matches) > 0 {
		return "musl"
	}
	return "glibc"
}

// KernelRelease returns uname -r without spawning a subprocess.
func KernelRelease() string {
	var uts syscall.Utsname
	if err := syscall.Uname(&uts); err != nil {
		return "unknown"
	}
	var b strings.Builder
	for _, c := range uts.Release {
		if c == 0 {
			break
		}
		b.WriteByte(byte(c))
	}
	if b.Len() == 0 {
		return "unknown"
	}
	return b.String()
}

// SyslogPaths covers the classic and modern syslog destinations used by
// rsyslog, syslog-ng, busybox syslog and systemd's syslog bridge.
func SyslogPaths() []string {
	return existingPaths(
		"/var/log/auth.log", // Debian, Ubuntu, Alpine, Arch
		"/var/log/secure",   // RHEL, Fedora, CentOS, Rocky, Alma
		"/var/log/messages", // RHEL/Fedora and many syslog-ng setups
		"/var/log/syslog",   // Debian family
		"/var/log/kern.log",
	)
}

// AuthLogPaths is the subset relevant to live authentication events.
func AuthLogPaths() []string {
	return existingPaths(
		"/var/log/auth.log",
		"/var/log/secure",
		"/var/log/messages",
		"/var/log/syslog",
	)
}

// FirewallLogPaths covers ufw, firewalld and nftables/iptables kernel logs.
func FirewallLogPaths() []string {
	return existingPaths(
		"/var/log/ufw.log",
		"/var/log/firewalld",
		"/var/log/firewall",
	)
}

// Fail2banLogPaths covers both common log locations.
func Fail2banLogPaths() []string {
	return existingPaths(
		"/var/log/fail2ban.log",
		"/var/log/fail2ban/fail2ban.log",
	)
}

// CriticalFiles returns the file/directory set watched by the live activity
// feed. It adapts to systemd vs OpenRC/runit/s6 and glibc vs musl so a
// legitimate file on one distro is never reported as a suspicious absence.
func CriticalFiles() []string {
	paths := []string{
		"/etc/passwd", "/etc/group", "/etc/shadow", "/etc/gshadow",
		"/etc/sudoers", "/etc/ssh/sshd_config", "/etc/hosts",
		"/etc/resolv.conf", "/etc/ld.so.preload", "/etc/crontab", "/etc/profile",
	}
	if IsSystemd() {
		paths = append(paths, "/etc/systemd/system")
	} else {
		paths = append(paths, "/etc/init.d", "/etc/conf.d", "/etc/sv", "/etc/rc.d")
	}
	if Libc() == "musl" {
		matches, _ := filepath.Glob("/etc/ld-musl-*.path")
		paths = append(paths, matches...)
	} else {
		paths = append(paths, "/etc/ld.so.conf", "/etc/ld.so.conf.d")
	}
	return unique(paths)
}

// existingPaths filters out absent files but always keeps at least the first
// candidate, so a caller still knows which location was attempted.
func existingPaths(candidates ...string) []string {
	var out []string
	for _, p := range candidates {
		if _, err := os.Stat(p); err == nil {
			out = append(out, p)
		}
	}
	if len(out) == 0 && len(candidates) > 0 {
		out = append(out, candidates[0])
	}
	return unique(out)
}

func unique(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, p := range in {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}
