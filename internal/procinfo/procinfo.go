// Package procinfo reads process metadata directly from /proc and, where a
// wrapper is useful, from the standard coreutils readlink(1) implementation.
package procinfo

import (
	"bufio"
	"bytes"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"eyeofmx/internal/model"
	"eyeofmx/internal/sysutil"
)

var (
	bootOnce sync.Once
	bootTime time.Time
)

// BootTime returns the kernel boot time derived from /proc/stat "btime".
func BootTime() time.Time {
	bootOnce.Do(func() {
		bootTime = time.Now()
		f, err := os.Open("/proc/stat")
		if err != nil {
			return
		}
		defer f.Close()
		s := bufio.NewScanner(f)
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) >= 2 && fields[0] == "btime" {
				if sec, err := strconv.ParseInt(fields[1], 10, 64); err == nil {
					bootTime = time.Unix(sec, 0)
				}
				break
			}
		}
	})
	return bootTime
}

// Exists reports whether a process with the given PID is currently present.
func Exists(pid int) bool {
	if pid <= 0 {
		return false
	}
	st, err := os.Stat(fmt.Sprintf("/proc/%d", pid))
	return err == nil && st.IsDir()
}

// AllPIDs returns a sorted list of currently visible process IDs.
func AllPIDs() []int {
	matches, err := filepath.Glob("/proc/[0-9]*")
	if err != nil {
		return nil
	}
	pids := make([]int, 0, len(matches))
	for _, m := range matches {
		if n, err := strconv.Atoi(filepath.Base(m)); err == nil {
			pids = append(pids, n)
		}
	}
	sortInts(pids)
	return pids
}

func sortInts(a []int) {
	for i := 1; i < len(a); i++ {
		for j := i; j > 0 && a[j] < a[j-1]; j-- {
			a[j], a[j-1] = a[j-1], a[j]
		}
	}
}

// ReadProcess collects the complete metadata snapshot for one PID. Missing or
// permission-denied fields are reported in Process.Error rather than failing.
func ReadProcess(pid int) model.Process {
	p := model.Process{PID: pid}
	if !Exists(pid) {
		p.Error = "process no longer exists"
		return p
	}
	base := fmt.Sprintf("/proc/%d", pid)

	// /proc/<pid>/stat — comm, state, ppid, starttime, threads.
	if data, err := os.ReadFile(base + "/stat"); err == nil {
		// comm may contain spaces and is wrapped in parentheses.
		txt := string(data)
		open := strings.IndexByte(txt, '(')
		closeIdx := strings.LastIndexByte(txt, ')')
		if open >= 0 && closeIdx > open {
			p.Name = txt[open+1 : closeIdx]
			fields := strings.Fields(txt[closeIdx+1:])
			// fields[0] is state, fields[1] is ppid after the ")" field.
			if len(fields) > 1 {
				p.State = fields[0]
				if n, err := strconv.Atoi(fields[1]); err == nil {
					p.PPID = n
				}
			}
			// After ")" fields[0] is overall field 3 (state), so overall
			// field 22 (starttime) is fields[19] and field 20 (threads) is
			// fields[17]. The old indices pointed at itrealvalue/nice.
			if len(fields) > 19 {
				if ticks, err := strconv.ParseInt(fields[19], 10, 64); err == nil {
					hertz := clockTicks()
					p.StartTime = BootTime().Add(time.Duration(float64(ticks)/hertz) * time.Second)
					d := time.Since(p.StartTime)
					if d < 0 {
						d = 0
					}
					p.Uptime = FormatDuration(d)
				}
			}
			if len(fields) > 17 {
				if n, err := strconv.Atoi(fields[17]); err == nil {
					p.Threads = n
				}
			}
		}
	}

	// /proc/<pid>/status — uid/gid and a reliable name.
	if data, err := os.ReadFile(base + "/status"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			kv := strings.SplitN(line, ":", 2)
			if len(kv) != 2 {
				continue
			}
			key, val := strings.TrimSpace(kv[0]), strings.TrimSpace(kv[1])
			switch key {
			case "Name":
				if p.Name == "" {
					p.Name = val
				}
			case "Uid":
				parts := strings.Fields(val)
				if len(parts) > 0 {
					if n, err := strconv.Atoi(parts[0]); err == nil {
						p.UID = n
					}
				}
			case "Gid":
				parts := strings.Fields(val)
				if len(parts) > 0 {
					if n, err := strconv.Atoi(parts[0]); err == nil {
						p.GID = n
					}
				}
			case "Threads":
				if n, err := strconv.Atoi(val); err == nil {
					p.Threads = n
				}
			}
		}
	}
	if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
		p.User = u.Username
	} else if p.UID == 0 {
		p.User = "root"
	} else {
		p.User = fmt.Sprintf("uid=%d", p.UID)
	}

	// cmdline (NUL separated).
	if data, err := os.ReadFile(base + "/cmdline"); err == nil {
		p.CmdlineRaw = string(data)
		parts := bytes.Split(data, []byte{0})
		args := make([]string, 0, len(parts))
		for _, part := range parts {
			if len(part) > 0 {
				args = append(args, shellQuote(string(part)))
			}
		}
		p.Cmdline = strings.Join(args, " ")
	}

	// Exact executable path: readlink -f /proc/<pid>/exe (with Go fallback).
	p.Executable = Executable(pid)
	p.DeletedImage = strings.Contains(p.Executable, "(deleted)")

	// cwd and root.
	if target, err := os.Readlink(base + "/cwd"); err == nil {
		p.CWD = target
	}
	if target, err := os.Readlink(base + "/root"); err == nil {
		p.Root = target
	}

	// File descriptors (only readable ones are listed).
	fds, _ := os.ReadDir(base + "/fd")
	p.FDCount = len(fds)
	limit := len(fds)
	if limit > 256 {
		limit = 256
	}
	for i := 0; i < limit; i++ {
		target, err := os.Readlink(fmt.Sprintf("%s/fd/%s", base, fds[i].Name()))
		if err != nil {
			continue
		}
		p.FDs = append(p.FDs, fds[i].Name()+" -> "+target)
		if strings.Contains(target, "(deleted)") {
			p.DeletedImage = true
		}
	}
	if len(fds) > limit {
		p.FDs = append(p.FDs, fmt.Sprintf("... %d more file descriptors", len(fds)-limit))
	}

	return p
}

// Executable resolves /proc/<pid>/exe entirely in Go. /proc/<pid>/exe is
// already an absolute canonical link, so EvalSymlinks gives the same result as
// readlink -f without depending on GNU coreutils (busybox/toybox differ).
func Executable(pid int) string {
	path := fmt.Sprintf("/proc/%d/exe", pid)
	target, err := os.Readlink(path)
	if err != nil {
		return "<unavailable: permission denied or process exited>"
	}
	if resolved, err := filepath.EvalSymlinks(target); err == nil && resolved != "" {
		return resolved
	}
	return target
}

// DeletedExecutables returns "(deleted)"-marked running binaries with user,
// command line and PID — a classic indicator of a replaced malicious binary.
func DeletedExecutables() []model.Process {
	var out []model.Process
	for _, pid := range AllPIDs() {
		exe, err := os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
		if err != nil || !strings.Contains(exe, "(deleted)") {
			continue
		}
		p := model.Process{PID: pid, Executable: exe, DeletedImage: true}
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
			parts := bytes.Split(data, []byte{0})
			args := make([]string, 0, len(parts))
			for _, v := range parts {
				if len(v) > 0 {
					args = append(args, string(v))
				}
			}
			p.Cmdline = strings.Join(args, " ")
		}
		if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid)); err == nil {
			for _, line := range strings.Split(string(data), "\n") {
				if strings.HasPrefix(line, "Uid:") {
					fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
					if len(fields) > 0 {
						if n, err := strconv.Atoi(fields[0]); err == nil {
							p.UID = n
						}
					}
				}
				if strings.HasPrefix(line, "Name:") {
					p.Name = strings.TrimSpace(strings.TrimPrefix(line, "Name:"))
				}
			}
		}
		if u, err := user.LookupId(strconv.Itoa(p.UID)); err == nil {
			p.User = u.Username
		}
		out = append(out, p)
	}
	return out
}

// NameForPID is a lightweight lookup used by the connection collector.
func NameForPID(pid int) string {
	if pid <= 0 {
		return ""
	}
	if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
		return strings.TrimSpace(string(data))
	}
	return ""
}

// UIDForPID reads the effective UID from /proc/<pid>/status cheaply.
func UIDForPID(pid int) int {
	if pid <= 0 {
		return -1
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return -1
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Uid:") {
			fields := strings.Fields(strings.TrimPrefix(line, "Uid:"))
			if len(fields) > 0 {
				if n, err := strconv.Atoi(fields[0]); err == nil {
					return n
				}
			}
		}
	}
	return -1
}

// ParentForPID reads PPID from /proc/<pid>/stat without a full snapshot.
func ParentForPID(pid int) int {
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0
	}
	txt := string(data)
	closeIdx := strings.LastIndexByte(txt, ')')
	if closeIdx < 0 {
		return 0
	}
	fields := strings.Fields(txt[closeIdx+1:])
	if len(fields) > 1 {
		if n, err := strconv.Atoi(fields[1]); err == nil {
			return n
		}
	}
	return 0
}

// InodeOwners maps socket inode numbers to the PIDs holding them. Scanning
// /proc/<pid>/fd is restricted to the current user's processes unless root.
func InodeOwners() map[string]int {
	owners := make(map[string]int)
	for _, pid := range AllPIDs() {
		entries, err := os.ReadDir(fmt.Sprintf("/proc/%d/fd", pid))
		if err != nil {
			continue
		}
		for _, e := range entries {
			target, err := os.Readlink(fmt.Sprintf("/proc/%d/fd/%s", pid, e.Name()))
			if err != nil {
				continue
			}
			if strings.HasPrefix(target, "socket:[") && strings.HasSuffix(target, "]") {
				inode := strings.TrimSuffix(strings.TrimPrefix(target, "socket:["), "]")
				if _, exists := owners[inode]; !exists {
					owners[inode] = pid
				}
			}
		}
	}
	return owners
}

func clockTicks() float64 { return sysutil.ClockTicks() }

func FormatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	h := int(d.Hours()) % 24
	m := int(d.Minutes()) % 60
	s := int(d.Seconds()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %02d:%02d:%02d", days, h, m, s)
	}
	return fmt.Sprintf("%02d:%02d:%02d", h, m, s)
}

func shellQuote(s string) string {
	if s == "" {
		return `""`
	}
	if strings.IndexFunc(s, func(r rune) bool {
		return r == ' ' || r == '\'' || r == '"' || r == '$' || r == '\\' || r == '`'
	}) < 0 {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
