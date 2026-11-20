package procinfo

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestReadProcessSelf(t *testing.T) {
	p := ReadProcess(os.Getpid())
	if p.PID != os.Getpid() {
		t.Fatalf("pid = %d, want %d", p.PID, os.Getpid())
	}
	if p.PPID <= 0 {
		t.Errorf("ppid = %d, want > 0", p.PPID)
	}
	if p.Name == "" {
		t.Error("process name is empty")
	}
	if !filepath.IsAbs(p.Executable) {
		t.Errorf("executable is not absolute: %q", p.Executable)
	}
	if !strings.Contains(p.Cmdline, "test") {
		t.Errorf("cmdline does not contain 'test': %q", p.Cmdline)
	}
	if p.FDCount == 0 {
		t.Error("expected at least one open file descriptor")
	}
	if p.StartTime.IsZero() || p.Uptime == "" {
		t.Error("start time or uptime missing")
	}
}

func TestBootTime(t *testing.T) {
	if BootTime().IsZero() {
		t.Fatal("boot time not determined")
	}
}
