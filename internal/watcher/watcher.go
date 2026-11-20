// Package watcher produces the step-by-step live activity feed. It samples
// process, socket, log and critical-file state on a short interval and emits
// an event whenever something appears, disappears or changes.
package watcher

import (
	"fmt"
	"os"
	"os/user"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"eyeofmx/internal/model"
	"eyeofmx/internal/netinfo"
	"eyeofmx/internal/procinfo"
	"eyeofmx/internal/sysutil"
)

const maxEvents = 3000

// Watcher owns the live event buffer and the sampling goroutine.
type Watcher struct {
	mu      sync.RWMutex
	events  []model.ActivityEvent
	stop    chan struct{}
	done    chan struct{}
	running bool

	pids      map[int]bool
	conns     map[string]model.Connection
	fileState map[string]int64
	logLines  map[string]bool
	tickCount int
}

// New creates an idle watcher.
func New() *Watcher {
	return &Watcher{
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
		pids:      map[int]bool{},
		conns:     map[string]model.Connection{},
		fileState: map[string]int64{},
		logLines:  map[string]bool{},
	}
}

// Start begins sampling. Calling Start twice is harmless.
func (w *Watcher) Start() {
	w.mu.Lock()
	if w.running {
		w.mu.Unlock()
		return
	}
	w.running = true
	w.stop = make(chan struct{})
	w.done = make(chan struct{})
	w.mu.Unlock()

	w.emitBoot()
	w.baseline()
	go w.loop()
}

// Stop ends the sampling goroutine.
func (w *Watcher) Stop() {
	w.mu.Lock()
	if !w.running {
		w.mu.Unlock()
		return
	}
	w.running = false
	close(w.stop)
	done := w.done
	w.mu.Unlock()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
	}
}

// Events returns a copy of the current event buffer, oldest first.
func (w *Watcher) Events() []model.ActivityEvent {
	w.mu.RLock()
	defer w.mu.RUnlock()
	out := make([]model.ActivityEvent, len(w.events))
	copy(out, w.events)
	return out
}

// Clear empties the visible buffer and re-baselines so the next tick only
// reports genuinely new activity.
func (w *Watcher) Clear() {
	w.mu.Lock()
	w.events = nil
	w.mu.Unlock()
	w.baseline()
}

func (w *Watcher) emit(category, severity, message, detail string) {
	e := model.ActivityEvent{
		Time: time.Now(), Category: category, Severity: severity,
		Message: message, Detail: detail,
	}
	w.mu.Lock()
	w.events = append(w.events, e)
	if len(w.events) > maxEvents {
		w.events = w.events[len(w.events)-maxEvents:]
	}
	w.mu.Unlock()
}

func (w *Watcher) emitBoot() {
	host, _ := os.Hostname()
	kernel := sysutil.KernelRelease()
	uptime := "unknown"
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		if sec, err := strconv.ParseFloat(strings.Fields(string(data))[0], 64); err == nil {
			uptime = procinfo.FormatDuration(time.Duration(sec) * time.Second)
		}
	}
	detail := fmt.Sprintf("host=%s kernel=%s boot=%s uptime=%s privileges=%s",
		host, kernel, procinfo.BootTime().Format("2006-01-02 15:04:05"), uptime,
		privilegeLabel())
	w.emit("BOOT", "INFO", "EyeOFmX live monitor started", detail)
	if !sysutil.IsRoot() {
		w.emit("SYSTEM", "NOTICE", "Limited privileges: some process and log data is unavailable",
			"Run EyeOFmX as root (sudo, doas or su) to inspect other users' /proc entries, /etc/shadow and protected logs.")
	}
}

func privilegeLabel() string {
	if sysutil.IsRoot() {
		return "root"
	}
	u, err := user.Current()
	if err == nil {
		return u.Username + " (unprivileged)"
	}
	return "unprivileged"
}

func (w *Watcher) baseline() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.pids = map[int]bool{}
	for _, pid := range procinfo.AllPIDs() {
		w.pids[pid] = true
	}
	w.conns = map[string]model.Connection{}
	for _, c := range netinfo.CollectLight() {
		w.conns[c.Key()] = c
	}
	w.fileState = map[string]int64{}
	for _, p := range watchedFiles() {
		if st, err := os.Stat(p); err == nil {
			w.fileState[p] = st.ModTime().UnixNano() ^ st.Size()
		}
	}
	w.logLines = map[string]bool{}
	for _, p := range sysutil.AuthLogPaths() {
		if lines, err := sysutil.ReadTail(p, 200); err == nil {
			for _, line := range lines {
				w.logLines[line] = true
			}
		}
	}
}

func watchedFiles() []string { return sysutil.CriticalFiles() }

func (w *Watcher) loop() {
	defer close(w.done)
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-w.stop:
			return
		case <-ticker.C:
			w.sample()
		}
	}
}

func (w *Watcher) sample() {
	w.tickCount++
	w.sampleProcesses()
	w.sampleConnections()
	w.sampleFiles()
	if w.tickCount%3 == 0 {
		w.sampleAuthLogs()
	}
}

func (w *Watcher) sampleProcesses() {
	current := map[int]bool{}
	for _, pid := range procinfo.AllPIDs() {
		current[pid] = true
	}
	w.mu.RLock()
	previous := w.pids
	w.mu.RUnlock()

	for pid := range current {
		if !previous[pid] {
			name := procinfo.NameForPID(pid)
			cmdline := ""
			if data, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
				cmdline = strings.ReplaceAll(strings.Trim(string(data), "\x00"), "\x00", " ")
			}
			ppid := procinfo.ParentForPID(pid)
			userName := ""
			if st, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); err == nil {
				if sys, ok := st.Sys().(*syscall.Stat_t); ok {
					if u, err := user.LookupId(strconv.Itoa(int(sys.Uid))); err == nil {
						userName = u.Username
					}
				}
			}
			detail := fmt.Sprintf("pid=%d ppid=%d user=%s command=%s", pid, ppid, userName, cmdline)
			sev := "INFO"
			if isShellOrInterpreter(name) {
				sev = "NOTICE"
			}
			w.emit("PROCESS", sev, "Process started: "+name, detail)
		}
	}
	for pid := range previous {
		if !current[pid] {
			w.emit("PROCESS", "INFO", fmt.Sprintf("Process exited: pid %d", pid),
				"The process is no longer present in /proc.")
		}
	}
	w.mu.Lock()
	w.pids = current
	w.mu.Unlock()
}

func (w *Watcher) sampleConnections() {
	conns := netinfo.CollectLight()
	current := make(map[string]model.Connection, len(conns))
	for _, c := range conns {
		current[c.Key()] = c
	}
	w.mu.RLock()
	previous := w.conns
	w.mu.RUnlock()

	for key, c := range current {
		if _, known := previous[key]; known {
			continue
		}
		verb := "Network connection opened"
		if strings.EqualFold(c.State, "LISTEN") {
			verb = "Listening socket opened"
		}
		detail := fmt.Sprintf("protocol=%s state=%s local=%s:%d remote=%s:%d pid=%d process=%s",
			c.Protocol, c.State, c.LocalAddr, c.LocalPort, c.RemoteAddr, c.RemotePort, c.PID, c.Process)
		sev := "INFO"
		if strings.EqualFold(c.State, "LISTEN") {
			sev = "NOTICE"
		}
		w.emit("NETWORK", sev, fmt.Sprintf("%s — %s:%d", verb, c.LocalAddr, c.LocalPort), detail)
	}
	for key, c := range previous {
		if _, stillOpen := current[key]; stillOpen {
			continue
		}
		w.emit("NETWORK", "INFO", fmt.Sprintf("Socket closed — %s:%d", c.LocalAddr, c.LocalPort),
			fmt.Sprintf("protocol=%s state=%s remote=%s:%d", c.Protocol, c.State, c.RemoteAddr, c.RemotePort))
	}

	w.mu.Lock()
	w.conns = current
	w.mu.Unlock()
}

func (w *Watcher) sampleFiles() {
	for _, p := range watchedFiles() {
		st, err := os.Stat(p)
		if err != nil {
			continue
		}
		now := st.ModTime().UnixNano() ^ st.Size()
		w.mu.RLock()
		old, known := w.fileState[p]
		w.mu.RUnlock()
		if known && old != now {
			w.emit("FILE", "WARN", "Critical file changed: "+p,
				fmt.Sprintf("mtime=%s size=%d mode=%s", st.ModTime().Format("2006-01-02 15:04:05"),
					st.Size(), st.Mode().String()))
		}
		w.mu.Lock()
		w.fileState[p] = now
		w.mu.Unlock()
	}
}

func (w *Watcher) sampleAuthLogs() {
	for _, p := range sysutil.AuthLogPaths() {
		lines, err := sysutil.ReadTail(p, 100)
		if err != nil {
			continue
		}
		w.mu.RLock()
		seen := w.logLines
		w.mu.RUnlock()
		newSeen := make(map[string]bool, len(seen)+len(lines))
		for k, v := range seen {
			newSeen[k] = v
		}
		for _, line := range lines {
			if line == "" || seen[line] {
				continue
			}
			newSeen[line] = true
			severity := "INFO"
			lower := strings.ToLower(line)
			if strings.Contains(lower, "fail") || strings.Contains(lower, "invalid user") ||
				strings.Contains(lower, "authentication failure") ||
				strings.Contains(lower, "audit:") || strings.Contains(lower, "selinux") {
				severity = "WARN"
			}
			if strings.Contains(lower, "accepted") || strings.Contains(lower, "session opened") ||
				strings.Contains(lower, "sudo:") {
				severity = "NOTICE"
			}
			w.emit("AUTH", severity, authMessage(line), fmt.Sprintf("source=%s %s", p, line))
		}
		if len(newSeen) > 4000 { // bound memory
			keys := make([]string, 0, len(newSeen))
			for k := range newSeen {
				keys = append(keys, k)
			}
			trimmed := make(map[string]bool)
			for _, k := range keys[len(keys)-2000:] {
				trimmed[k] = true
			}
			newSeen = trimmed
		}
		w.mu.Lock()
		w.logLines = newSeen
		w.mu.Unlock()
	}
}

func authMessage(line string) string {
	if len(line) > 120 {
		return line[:120] + "…"
	}
	return line
}

func isShellOrInterpreter(name string) bool {
	switch name {
	case "bash", "sh", "dash", "zsh", "fish", "python", "python3", "perl", "ruby", "nc", "ncat", "curl", "wget":
		return true
	}
	return strings.HasPrefix(name, "python")
}
