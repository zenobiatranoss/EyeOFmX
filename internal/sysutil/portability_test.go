package sysutil

import (
	"strings"
	"testing"
)

func TestToolList(t *testing.T) {
	tools := ToolList()
	if len(tools) == 0 {
		t.Fatal("expected a non-empty capability registry")
	}
	seen := map[string]bool{}
	for _, tool := range tools {
		if tool.Capability == "" {
			t.Error("tool with empty capability")
		}
		if seen[tool.Capability] {
			t.Errorf("duplicate capability %q", tool.Capability)
		}
		seen[tool.Capability] = true
		if tool.Available != (tool.Binary != "") {
			t.Errorf("inconsistent availability for %q", tool.Capability)
		}
	}
}

func TestPortabilityFacts(t *testing.T) {
	if KernelRelease() == "" {
		t.Error("kernel release is empty")
	}
	if Libc() == "" {
		t.Error("libc is empty")
	}
	if ClockTicks() <= 0 {
		t.Errorf("invalid clock ticks: %v", ClockTicks())
	}
	files := CriticalFiles()
	for _, required := range []string{"/etc/passwd", "/etc/group", "/etc/hosts"} {
		found := false
		for _, f := range files {
			if f == required {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("critical file %s missing", required)
		}
	}
}

func TestCommandEnvForcesEnglish(t *testing.T) {
	t.Setenv("LC_ALL", "ar_SA.UTF-8")
	env := commandEnv()
	found := false
	for _, kv := range env {
		if strings.HasPrefix(kv, "LC_ALL=") {
			found = true
			if kv != "LC_ALL=C" {
				t.Errorf("LC_ALL was not forced to C: %s", kv)
			}
		}
	}
	if !found {
		t.Error("LC_ALL missing from command environment")
	}
}
