package etcaudit

import "testing"

func TestCuratedAudit(t *testing.T) {
	records := CuratedAudit()
	if len(records) < 20 {
		t.Fatalf("only %d curated records", len(records))
	}
	found := map[string]bool{}
	for _, r := range records {
		found[r.Path] = true
		if r.Risk == "" {
			t.Errorf("empty risk for %s", r.Path)
		}
	}
	for _, required := range []string{"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/hosts", "/tmp"} {
		if !found[required] {
			t.Errorf("missing checklist entry %s", required)
		}
	}
}

func TestHighlightPatterns(t *testing.T) {
	if len(HighlightPatterns("/etc/ssh/sshd_config")) == 0 {
		t.Fatal("expected sshd patterns")
	}
}
