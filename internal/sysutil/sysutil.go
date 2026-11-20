// Package sysutil holds small shared helpers: privileged-user detection,
// timeout-bounded command execution and bounded file reads.
package sysutil

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"strings"
	"time"
)

// IsRoot reports whether the process has UID 0 (real sudo/root privileges).
func IsRoot() bool { return os.Geteuid() == 0 }

// Run executes a command with a deadline and returns combined output. An error
// is returned with whatever output was produced so callers can still show it.
func Run(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = commandEnv()
	out, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return string(out), errors.New("command timed out after " + timeout.String())
	}
	return string(out), err
}

// RunStdout executes a command with a deadline and returns stdout only.
func RunStdout(timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = commandEnv()
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if ctx.Err() != nil {
		return stdout.String(), errors.New("command timed out after " + timeout.String())
	}
	if err != nil && stderr.Len() > 0 {
		return stdout.String(), errors.New(strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), err
}

// commandEnv forces the C locale so English log tokens (Failed password,
// WARNING, FOUND, ufw block) are parseable on every distro, while preserving
// the rest of the user's environment.
func commandEnv() []string {
	env := append([]string(nil), os.Environ()...)
	for i, kv := range env {
		if strings.HasPrefix(kv, "LC_ALL=") {
			env[i] = "LC_ALL=C"
			return env
		}
	}
	return append(env, "LC_ALL=C")
}

// Available reports whether an executable is present in PATH.
func Available(name string) bool {
	_, err := exec.LookPath(name)
	return err == nil
}

// ReadTail returns at most the last n lines of a file. This is safe for large
// logs because it never loads the whole file into memory at once.
func ReadTail(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	const chunk = 64 * 1024
	var data []byte
	var buf [chunk]byte
	for {
		read, err := f.Read(buf[:])
		if read > 0 {
			data = append(data, buf[:read]...)
			if len(data) > chunk*8 { // cap memory; keep newest portion only
				data = data[len(data)-chunk*8:]
			}
		}
		if err != nil {
			break
		}
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}

// ReadLimited reads a file but refuses files larger than max bytes. It is used
// by the read-only file viewer so a huge or special file cannot hang the UI.
func ReadLimited(path string, max int64) (string, error) {
	st, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if st.Size() > max {
		return "", errors.New("file is larger than the viewer limit (" + humanSize(max) + ")")
	}
	data, err := os.ReadFile(path)
	return string(data), err
}

func humanSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strings.TrimSpace(strings.Join([]string{itoa(n), "B"}, " "))
	}
	d, u := n, "KiB"
	for _, next := range []string{"MiB", "GiB", "TiB"} {
		if d < unit*unit {
			break
		}
		d /= unit
		u = next
	}
	d /= unit
	return itoa(d) + " " + u
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [24]byte
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

// ScanLines is a convenience wrapper for bounded line iteration.
func ScanLines(text string, fn func(string)) {
	s := bufio.NewScanner(strings.NewReader(text))
	s.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for s.Scan() {
		fn(s.Text())
	}
}
