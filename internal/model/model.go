// Package model contains the shared data structures used by every EyeOFmX
// collector and by the GTK user interface.
package model

import (
	"fmt"
	"strings"
	"time"
)

// Connection describes one observed socket (TCP/UDP/UNIX) and the process that
// owns it, when that information is available to the current user.
type Connection struct {
	Protocol   string // tcp, tcp6, udp, udp6, unix
	State      string // LISTEN, ESTAB, SYN-SENT, UNCONN, ...
	LocalAddr  string
	LocalPort  int
	RemoteAddr string
	RemotePort int
	PID        int // 0 when the owner could not be determined
	PPID       int
	Process    string
	FD         string
	Inode      string
	Source     string // "ss", "/proc/net", "lsof"
	Raw        string
}

// Key returns a stable identity for a connection, used by the live watcher to
// detect newly appearing sockets.
func (c Connection) Key() string {
	return c.Protocol + "|" + c.LocalAddr + ":" + itoa(c.LocalPort) + "|" +
		c.RemoteAddr + ":" + itoa(c.RemotePort) + "|" + c.State + "|" + itoa(c.PID)
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

// Process is the full metadata snapshot shown in the inspection pane.
type Process struct {
	PID          int
	PPID         int
	Name         string
	Executable   string // result of readlink -f /proc/<pid>/exe
	Cmdline      string // human readable
	CmdlineRaw   string // NUL separated, as found in /proc/<pid>/cmdline
	User         string
	UID          int
	GID          int
	State        string
	Threads      int
	StartTime    time.Time
	Uptime       string
	CWD          string
	Root         string
	FDCount      int
	FDs          []string
	DeletedImage bool // executable or a mapped file is marked (deleted)
	Error        string
}

// FileRecord is one entry in the /etc and high-risk filesystem audit.
type FileRecord struct {
	Path        string
	Description string
	Risk        string // INFO, LOW, MEDIUM, HIGH, CRITICAL
	Exists      bool
	IsDir       bool
	Mode        string // e.g. -rw-r----- / drwxr-xr-x
	ModeOctal   string // e.g. 0640
	UID         int
	GID         int
	Owner       string
	Group       string
	Size        int64
	Inode       uint64
	Modified    time.Time
	Changed     time.Time
	Accessed    time.Time
	Findings    []string
	ReadError   string
	GroupLabel  string // "critical files", "persistence", "runtime", "scan"
}

// ActivityEvent is one line of the live activity feed.
type ActivityEvent struct {
	Time     time.Time
	Category string // BOOT, PROCESS, NETWORK, FILE, AUTH, SERVICE, SYSTEM
	Severity string // INFO, NOTICE, WARN, ALERT
	Message  string
	Detail   string
}

// HistoryEntry is one command reconstructed from a shell history file or from
// live process observation.
type HistoryEntry struct {
	Time   time.Time
	User   string
	Shell  string // bash, zsh, live
	Source string // file path or "live"
	Line   int
	Text   string
}

// LogEntry is one normalised line from an external security/tool log source.
type LogEntry struct {
	Time     time.Time
	Source   string // journalctl, auth.log, ufw, osquery, ...
	Severity string // INFO, NOTICE, WARN, ALERT, ERROR
	Tag      string // AUTH, FIREWALL, KERNEL, SUDO, ...
	Message  string
	Raw      string
}

// HasRisk reports whether the record contains a finding at or above level.
func (f FileRecord) HasRisk(level string) bool {
	order := map[string]int{"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	return order[f.Risk] >= order[level] && len(f.Findings) > 0
}

// ScanFinding is one aggregated item from the comprehensive posture scan.
// Evidence is kept short here; full tool output lives in ScanToolResult.Raw.
type ScanFinding struct {
	ID             string
	Category       string // ROOTKIT, MALWARE, INTEGRITY, SUSPICIOUS_FILE, PERSISTENCE, PRIVILEGE, NETWORK, HARDENING, AUTH, TOOL
	Title          string
	Severity       string // INFO, LOW, MEDIUM, HIGH, CRITICAL
	Source         string // rkhunter, chkrootkit, lynis, aide, clamscan, osquery, native, ...
	Detail         string
	Evidence       string
	Recommendation string
}

// ScanToolResult records what one scanning engine produced. Tools that are not
// installed are still listed with Status "NOT INSTALLED" so the report shows
// exactly which coverage areas were unavailable.
type ScanToolResult struct {
	Tool      string
	Command   string
	Available bool
	Ran       bool
	Duration  string
	Findings  int
	Status    string // OK, FINDINGS, NOT INSTALLED, FAILED, TIMEOUT
	Raw       string
}

// ScanReport is the brief aggregated posture report shown by the sixth tab.
type ScanReport struct {
	Time      time.Time
	Duration  time.Duration
	Host      string
	Privilege string
	Kernel    string
	Init      string
	Libc      string
	Mode      string // "Quick posture" or "Full comprehensive"
	Posture   string // HARDENED, ATTENTION, AT RISK, CRITICAL
	Counts    map[string]int
	Findings  []ScanFinding
	Tools     []ScanToolResult
}

// SeverityRank orders scan severities from least to most serious.
func SeverityRank(level string) int {
	switch strings.ToUpper(level) {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	}
	return 0
}

// TopFindings returns at most n highest-severity findings in stable order.
func (r ScanReport) TopFindings(n int) []ScanFinding {
	sorted := append([]ScanFinding(nil), r.Findings...)
	for i := 1; i < len(sorted); i++ {
		for j := i; j > 0 && SeverityRank(sorted[j].Severity) > SeverityRank(sorted[j-1].Severity); j-- {
			sorted[j], sorted[j-1] = sorted[j-1], sorted[j]
		}
	}
	if n > 0 && len(sorted) > n {
		sorted = sorted[:n]
	}
	return sorted
}

// SummaryLine is a one-line posture sentence used in the GUI status bar and
// in the exported plain-text report.
func (r ScanReport) SummaryLine() string {
	return fmt.Sprintf("%s — %d findings (%d critical, %d high, %d medium, %d low) in %s",
		r.Posture, len(r.Findings), r.Counts["CRITICAL"], r.Counts["HIGH"],
		r.Counts["MEDIUM"], r.Counts["LOW"], r.Duration.Round(time.Second))
}
