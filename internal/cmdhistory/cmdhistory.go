// Package cmdhistory reconstructs command history from common shell history
// files and from processes observed live by the activity watcher. It never
// modifies any history file.
package cmdhistory

import (
	"bufio"
	"os"
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"eyeofmx/internal/model"
)

// Collect reads shell histories for the current user (and for all home
// directories when running as root), optionally adding live observed commands.
func Collect(includeLive bool, live []model.ActivityEvent) []model.HistoryEntry {
	var out []model.HistoryEntry
	seen := map[string]bool{}

	home, _ := os.UserHomeDir()

	// Honour the variables the shells actually use instead of assuming the
	// default layout (common on Fedora, Arch and hardened setups).
	bashFile := strings.TrimSpace(os.Getenv("HISTFILE"))
	if bashFile == "" {
		bashFile = filepath.Join(home, ".bash_history")
	}
	zshHome := strings.TrimSpace(os.Getenv("ZDOTDIR"))
	if zshHome == "" {
		zshHome = home
	}
	fishData := strings.TrimSpace(os.Getenv("XDG_DATA_HOME"))
	if fishData == "" {
		fishData = filepath.Join(home, ".local", "share")
	}

	files := []string{
		bashFile,
		filepath.Join(zshHome, ".zsh_history"),
		filepath.Join(fishData, "fish", "fish_history"),
	}
	// Home directories come from the account database, not a /home/* glob, so
	// /root, /var/home, /users and service accounts are covered everywhere.
	for _, h := range homeDirs() {
		if h == home {
			continue
		}
		files = append(files,
			filepath.Join(h, ".bash_history"),
			filepath.Join(h, ".zsh_history"),
			filepath.Join(h, ".local", "share", "fish", "fish_history"),
		)
	}
	files = uniqueStrings(files)

	for _, path := range files {
		entries := readFile(path)
		for _, e := range entries {
			key := e.Source + "|" + strconv.Itoa(e.Line) + "|" + e.Text
			if seen[key] {
				continue
			}
			seen[key] = true
			out = append(out, e)
		}
	}

	if includeLive {
		for _, ev := range live {
			if ev.Category != "PROCESS" || !strings.HasPrefix(ev.Message, "Process started") {
				continue
			}
			cmd := extractDetail(ev.Detail, "command=")
			if cmd == "" {
				continue
			}
			out = append(out, model.HistoryEntry{
				Time: ev.Time, User: "live", Shell: "live",
				Source: "live process observation", Text: cmd,
			})
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Time.After(out[j].Time) })
	return out
}

// homeDirs lists every home directory declared in /etc/passwd. It is the
// distro-independent replacement for scanning only /home/* and /root.
func homeDirs() []string {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Split(s.Text(), ":")
		if len(fields) >= 6 && strings.HasPrefix(fields[5], "/") {
			out = append(out, fields[5])
		}
	}
	return uniqueStrings(out)
}

func uniqueStrings(in []string) []string {
	seen := make(map[string]bool, len(in))
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

func readFile(path string) []model.HistoryEntry {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	shell := "bash"
	base := filepath.Base(path)
	switch {
	case strings.Contains(base, "zsh"):
		shell = "zsh"
	case strings.Contains(base, "fish"):
		shell = "fish"
	}
	user := historyOwner(path)

	var out []model.HistoryEntry
	var pending time.Time
	lineNo := 0
	s := bufio.NewScanner(f)
	s.Buffer(make([]byte, 0, 64*1024), 2*1024*1024)
	var fishCmd string
	var fishTime time.Time
	for s.Scan() {
		lineNo++
		line := strings.TrimRight(s.Text(), "\r")
		if line == "" {
			continue
		}
		if shell == "fish" {
			switch {
			case strings.HasPrefix(line, "- cmd: "):
				fishCmd = strings.TrimPrefix(line, "- cmd: ")
			case strings.HasPrefix(line, "   when: "):
				if n, err := strconv.ParseInt(strings.TrimPrefix(line, "   when: "), 10, 64); err == nil {
					fishTime = time.Unix(n, 0)
				}
				if fishCmd != "" {
					out = append(out, model.HistoryEntry{Time: fishTime, User: user, Shell: shell, Source: path, Line: lineNo, Text: fishCmd})
					fishCmd, fishTime = "", time.Time{}
				}
			}
			continue
		}
		if shell == "zsh" && strings.HasPrefix(line, ": ") {
			// Extended history: ": <epoch>:<duration>;<command>"
			if idx := strings.Index(line, ";"); idx > 0 {
				meta := strings.Fields(line[2:idx])
				if len(meta) > 0 {
					if n, err := strconv.ParseInt(meta[0], 10, 64); err == nil {
						pending = time.Unix(n, 0)
					}
				}
				cmd := strings.TrimSpace(line[idx+1:])
				if cmd != "" {
					out = append(out, model.HistoryEntry{Time: pending, User: user, Shell: shell, Source: path, Line: lineNo, Text: cmd})
					pending = time.Time{}
				}
			}
			continue
		}
		if strings.HasPrefix(line, "#") {
			if n, err := strconv.ParseInt(strings.TrimPrefix(line, "#"), 10, 64); err == nil && n > 0 {
				pending = time.Unix(n, 0)
			}
			continue
		}
		t := pending
		if t.IsZero() {
			t = fileModTime(path)
		}
		out = append(out, model.HistoryEntry{Time: t, User: user, Shell: shell, Source: path, Line: lineNo, Text: line})
	}
	return out
}

func fileModTime(path string) time.Time {
	if st, err := os.Stat(path); err == nil {
		return st.ModTime()
	}
	return time.Time{}
}

func historyOwner(path string) string {
	// Prefer the real file owner from the inode; this works for homes under
	// /users, /var/home or any other layout.
	if st, err := os.Stat(path); err == nil {
		if sys, ok := st.Sys().(*syscall.Stat_t); ok {
			if u, err := user.LookupId(strconv.Itoa(int(sys.Uid))); err == nil {
				return u.Username
			}
		}
	}
	parts := strings.Split(filepath.Clean(path), string(filepath.Separator))
	for i, p := range parts {
		if p == "home" || p == "root" {
			if p == "root" {
				return "root"
			}
			if i+1 < len(parts) {
				return parts[i+1]
			}
		}
	}
	if u, err := os.UserHomeDir(); err == nil && strings.HasPrefix(path, u) {
		if name := filepath.Base(u); name != "" {
			return name
		}
	}
	return "user"
}

func extractDetail(detail, key string) string {
	if idx := strings.Index(detail, key); idx >= 0 {
		return strings.TrimSpace(detail[idx+len(key):])
	}
	return ""
}
