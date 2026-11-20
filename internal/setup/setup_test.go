package setup

import (
	"strings"
	"testing"
)

func TestFamilyMapping(t *testing.T) {
	cases := []struct{ id, like, want string }{
		{"debian", "", "debian"},
		{"ubuntu", "debian", "debian"},
		{"linuxmint", "ubuntu debian", "debian"},
		{"fedora", "", "fedora"},
		{"rocky", "rhel fedora", "fedora"},
		{"arch", "", "arch"},
		{"manjaro", "arch", "arch"},
		{"opensuse-leap", "suse", "suse"},
		{"alpine", "", "alpine"},
		{"void", "", "void"},
		{"gentoo", "", "gentoo"},
		{"unknown", "", "unknown"},
	}
	for _, c := range cases {
		if got := family(c.id, c.like); got != c.want {
			t.Errorf("family(%q, %q) = %q, want %q", c.id, c.like, got, c.want)
		}
	}
}

func TestPackageMaps(t *testing.T) {
	want := map[string][]string{
		"debian": {"rkhunter", "chkrootkit", "lynis", "aide", "clamav", "clamav-freshclam", "clamav-daemon", "osquery"},
		"fedora": {"rkhunter", "chkrootkit", "lynis", "aide", "clamav", "clamav-freshclam"},
		"arch":   {"rkhunter", "lynis", "clamav"},
		"suse":   {"rkhunter", "chkrootkit", "lynis", "aide", "clamav"},
		"alpine": {"rkhunter", "chkrootkit", "lynis", "aide", "clamav"},
		"void":   {"rkhunter", "chkrootkit", "lynis", "aide", "clamav"},
	}
	for family, names := range want {
		packages, notes := packagesFor(family)
		got := make([]string, 0, len(packages))
		for _, p := range packages {
			got = append(got, p.Name)
		}
		if strings.Join(got, " ") != strings.Join(names, " ") {
			t.Errorf("packagesFor(%q) = %v, want %v", family, got, names)
		}
		if len(notes) == 0 && family != "debian" {
			t.Errorf("packagesFor(%q) has no notes", family)
		}
	}
	if packages, _ := packagesFor("gentoo"); len(packages) != 0 {
		t.Errorf("gentoo should be manual, got %v", packages)
	}
	if packages, notes := packagesFor("arch"); len(packages) != 3 ||
		!strings.Contains(strings.Join(notes, " "), "AUR") {
		t.Errorf("arch mapping or notes are wrong: %v / %v", packages, notes)
	}
}

func TestInstallCommands(t *testing.T) {
	pkgs := []Package{{Name: "rkhunter"}, {Name: "aide"}}
	for family, want := range map[string]string{
		"debian": "DEBIAN_FRONTEND=noninteractive apt-get install -y",
		"fedora": "dnf -y install",
		"arch":   "pacman -S --noconfirm --needed",
		"suse":   "zypper --non-interactive install",
		"alpine": "apk add --no-cache",
		"void":   "xbps-install -Sy",
	} {
		cmd := installCommand(family, pkgs)
		if !strings.Contains(cmd, want) ||
			!strings.Contains(cmd, "SETUP-OK: $p") ||
			!strings.Contains(cmd, "SETUP-FAILED: $p") ||
			!strings.Contains(cmd, "SETUP-DONE") ||
			!strings.Contains(cmd, "exit $status") {
			t.Errorf("installCommand(%q) = %q", family, cmd)
		}
	}
	if cmd := installCommand("debian", pkgs); !strings.Contains(cmd, "apt-get update") {
		t.Errorf("debian command has no apt-get update: %q", cmd)
	}
	if cmd := installCommand("gentoo", pkgs); cmd != "" {
		t.Errorf("gentoo should have no command, got %q", cmd)
	}
}

func TestParseResult(t *testing.T) {
	pkgs := []Package{{Name: "rkhunter", Tool: "rkhunter"}, {Name: "aide", Tool: "aide"}}
	out := "Setting up rkhunter (1.4.6) ...\nSETUP-OK: rkhunter\nE: Unable to locate package aide\nSETUP-FAILED: aide\nSETUP-DONE\n"
	installed, failed := ParseResult(out, pkgs)
	if len(installed) != 1 || installed[0] != "rkhunter" {
		t.Fatalf("installed = %v", installed)
	}
	if len(failed) != 1 || failed[0] != "aide" {
		t.Fatalf("failed = %v", failed)
	}
}

func TestShellQuote(t *testing.T) {
	if got := ShellQuote("it's ok"); got != "'it'\\''s ok'" {
		t.Fatalf("ShellQuote = %q", got)
	}
}

func TestBuildPlanOnHost(t *testing.T) {
	plan := BuildPlan()
	if plan.Distro.Family == "" {
		t.Fatal("empty distro family")
	}
	if plan.Command != "" && !strings.Contains(plan.Command, "SETUP-DONE") {
		t.Fatalf("unexpected command: %q", plan.Command)
	}
	if len(plan.AutoMissing)+len(plan.ManualMissing) != len(plan.Missing) {
		t.Fatalf("missing split mismatch: %+v", plan)
	}
}
