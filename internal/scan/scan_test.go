package scan

import (
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"eyeofmx/internal/model"
)

func TestTrimEvidence(t *testing.T) {
	got := trimEvidence("  a\r\n b  ", 100)
	if got != "a\n b" {
		t.Fatalf("trimEvidence = %q", got)
	}
	long := strings.Repeat("x", 50)
	got = trimEvidence(long, 10)
	if !strings.HasSuffix(got, "[output truncated] ...") || !strings.HasPrefix(got, "xxxxxxxxxx") {
		t.Fatalf("expected bounded evidence, got %q", got)
	}
}

func TestOneLine(t *testing.T) {
	if got := oneLine("a\t b\n c", 100); got != "a b c" {
		t.Fatalf("oneLine = %q", got)
	}
	if got := oneLine(strings.Repeat("a", 50), 10); utf8.RuneCountInString(got) != 11 {
		t.Fatalf("oneLine did not bound length: %q", got)
	}
}

func TestFormatReportContainsAggregatedSections(t *testing.T) {
	r := model.ScanReport{
		Time: time.Date(2026, 11, 21, 12, 0, 0, 0, time.UTC),
		Host: "testhost", Mode: "Quick posture", Privilege: "root — full access",
		Kernel: "6.12", Init: "systemd", Libc: "glibc", Posture: "AT RISK",
		Duration: 2 * time.Second,
		Counts:   map[string]int{"HIGH": 1},
		Findings: []model.ScanFinding{{
			ID: "S001", Category: "ROOTKIT", Title: "rkhunter warning",
			Severity: "HIGH", Source: "rkhunter", Detail: "suspicious file",
			Evidence: "/tmp/x", Recommendation: "Investigate",
		}},
		Tools: []model.ScanToolResult{{Tool: "rkhunter", Command: "rkhunter --check", Status: "FINDINGS", Findings: 1, Raw: "Warning: test"}},
	}
	text := FormatReport(r)
	for _, want := range []string{
		"COMPREHENSIVE POSTURE REPORT", "testhost", "Posture   : AT RISK",
		"COVERAGE", "FINDINGS", "RAW TOOL OUTPUT", "rkhunter", "Warning: test",
	} {
		if !strings.Contains(text, want) {
			t.Errorf("report is missing %q", want)
		}
	}
}

func TestQuickOptionsAreCheap(t *testing.T) {
	o := Quick()
	if !o.NativeChecks || !o.OSQuery {
		t.Fatal("quick scan should include native checks and osquery")
	}
	if o.RootkitTools || o.AntiMalware || o.Integrity || o.Hardening {
		t.Fatal("quick scan must not start heavy external tools")
	}
	full := Full()
	if !full.RootkitTools || !full.AntiMalware || !full.Integrity || !full.Hardening {
		t.Fatal("full scan should enable every engine")
	}
}
