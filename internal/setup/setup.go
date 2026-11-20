// Package setup maps the running Linux distribution to the correct package
// names for the optional comprehensive-scan engines and builds one shell
// command that installs them. It never runs anything by itself: the GUI always
// asks the user for consent and performs elevation through the system's own
// authentication mechanism.
package setup

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"eyeofmx/internal/sysutil"
)

const (
	okPrefix     = "SETUP-OK: "
	failedPrefix = "SETUP-FAILED: "
)

// Distro is the result of reading /etc/os-release and normalising it to a
// package-manager family.
type Distro struct {
	ID      string
	IDLike  string
	Preview string
	Family  string // debian, fedora, arch, suse, alpine, void, gentoo, unknown
}

// Package is one optional scanning engine and the distribution package that
// provides it.
type Package struct {
	Name string
	Tool string
}

// Plan is the concrete installation proposal shown to the user. Missing lists
// every engine not currently in PATH; AutoMissing is the subset this plan can
// actually install, while ManualMissing needs a repository or AUR decision by
// the user.
type Plan struct {
	Distro        Distro
	Packages      []Package
	Command       string
	Notes         []string
	Missing       []string
	AutoMissing   []string
	ManualMissing []string
}

// Detect reads /etc/os-release without spawning a subprocess.
func Detect() Distro {
	values := map[string]string{}
	if data, err := os.ReadFile("/etc/os-release"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line == "" || strings.HasPrefix(line, "#") {
				continue
			}
			parts := strings.SplitN(line, "=", 2)
			if len(parts) != 2 {
				continue
			}
			values[parts[0]] = strings.Trim(strings.TrimSpace(parts[1]), "\"'")
		}
	}
	d := Distro{
		ID:      values["ID"],
		IDLike:  values["ID_LIKE"],
		Preview: values["PRETTY_NAME"],
	}
	d.Family = family(d.ID, d.IDLike)
	return d
}

func family(id, idLike string) string {
	id, idLike = strings.ToLower(id), strings.ToLower(idLike)
	switch {
	case id == "alpine":
		return "alpine"
	case id == "void":
		return "void"
	case id == "gentoo":
		return "gentoo"
	case strings.Contains(id, "arch") || strings.Contains(idLike, "arch"):
		return "arch"
	case strings.Contains(id, "suse") || strings.Contains(idLike, "suse"):
		return "suse"
	case strings.Contains(id, "fedora") || strings.Contains(idLike, "fedora") ||
		strings.Contains(id, "rhel") || strings.Contains(idLike, "rhel") ||
		strings.Contains(id, "centos"):
		return "fedora"
	case strings.Contains(id, "debian") || strings.Contains(idLike, "debian") ||
		strings.Contains(id, "ubuntu"):
		return "debian"
	}
	return "unknown"
}

// packagesFor returns the known-good package names for a family. Engines that
// are not in a family's default repositories are deliberately left out: adding
// EPEL, a third-party repository or the AUR would be a security decision for
// the user, so they are listed in Notes instead.
func packagesFor(f string) ([]Package, []string) {
	switch f {
	case "debian":
		return []Package{
			{"rkhunter", "rkhunter"},
			{"chkrootkit", "chkrootkit"},
			{"lynis", "lynis"},
			{"aide", "aide"},
			{"clamav", "ClamAV"},
			{"clamav-freshclam", "ClamAV"},
			{"clamav-daemon", "ClamAV"},
			{"osquery", "osquery"},
		}, nil
	case "fedora":
		return []Package{
				{"rkhunter", "rkhunter"},
				{"chkrootkit", "chkrootkit"},
				{"lynis", "lynis"},
				{"aide", "aide"},
				{"clamav", "ClamAV"},
				{"clamav-freshclam", "ClamAV"},
			}, []string{
				"osquery is not in the default Fedora repositories. Add the Palantir repository yourself if you want the osquery engine.",
				"On RHEL, Rocky and Alma systems rkhunter, chkrootkit and lynis come from EPEL; failed packages are reported individually and do not stop the rest.",
			}
	case "arch":
		return []Package{
				{"rkhunter", "rkhunter"},
				{"lynis", "lynis"},
				{"clamav", "ClamAV"},
			}, []string{
				"chkrootkit and aide are AUR packages on Arch. Install them with your AUR helper after reviewing the PKGBUILDs.",
				"osquery is an AUR package (osquery-bin) on Arch. Install it with your AUR helper if you want the osquery engine.",
			}
	case "suse":
		return []Package{
				{"rkhunter", "rkhunter"},
				{"chkrootkit", "chkrootkit"},
				{"lynis", "lynis"},
				{"aide", "aide"},
				{"clamav", "ClamAV"},
			}, []string{
				"chkrootkit and lynis can live in the openSUSE security repository; failed packages are reported individually and do not stop the rest.",
				"osquery availability varies by openSUSE release. Add a trusted repository yourself if you want the osquery engine.",
			}
	case "alpine":
		return []Package{
				{"rkhunter", "rkhunter"},
				{"chkrootkit", "chkrootkit"},
				{"lynis", "lynis"},
				{"aide", "aide"},
				{"clamav", "ClamAV"},
			}, []string{
				"Some scanners are in Alpine's community or testing repository. Enable the matching repository if a package reports as unavailable.",
				"osquery is not packaged for Alpine; the native checks remain available.",
			}
	case "void":
		return []Package{
				{"rkhunter", "rkhunter"},
				{"chkrootkit", "chkrootkit"},
				{"lynis", "lynis"},
				{"aide", "aide"},
				{"clamav", "ClamAV"},
			}, []string{
				"osquery availability varies by Void repository; failed packages are reported individually and do not stop the rest.",
			}
	case "gentoo":
		return nil, []string{
			"Gentoo uses USE flags. Install manually: app-forensics/rkhunter app-forensics/chkrootkit app-forensics/lynis app-forensics/aide app-antivirus/clamav.",
		}
	}
	return nil, []string{"No automatic package mapping is known for this distribution. Install rkhunter, chkrootkit, lynis, aide and clamav manually."}
}

// MissingEngines returns the human names of scanning engines whose binaries
// are not currently in PATH.
func MissingEngines() []string {
	checks := []struct {
		name string
		bins []string
	}{
		{"rkhunter", []string{"rkhunter"}},
		{"chkrootkit", []string{"chkrootkit"}},
		{"lynis", []string{"lynis"}},
		{"aide", []string{"aide"}},
		{"ClamAV", []string{"clamscan", "clamdscan"}},
		{"osquery", []string{"osqueryi"}},
	}
	var out []string
	for _, c := range checks {
		if sysutil.FirstAvailable(c.bins...) == "" {
			out = append(out, c.name)
		}
	}
	return out
}

// BuildPlan detects the distribution, chooses packages and produces one shell
// command. Each package is attempted separately so one unavailable package
// cannot abort the whole transaction.
func BuildPlan() Plan {
	d := Detect()
	packages, notes := packagesFor(d.Family)
	missing := MissingEngines()
	autoTools := map[string]bool{}
	for _, p := range packages {
		autoTools[p.Tool] = true
	}
	plan := Plan{
		Distro:   d,
		Packages: packages,
		Command:  installCommand(d.Family, packages),
		Notes:    notes,
		Missing:  missing,
	}
	for _, name := range missing {
		if autoTools[name] {
			plan.AutoMissing = append(plan.AutoMissing, name)
		} else {
			plan.ManualMissing = append(plan.ManualMissing, name)
		}
	}
	return plan
}

func installCommand(family string, packages []Package) string {
	if len(packages) == 0 {
		return ""
	}
	names := make([]string, 0, len(packages))
	for _, p := range packages {
		names = append(names, p.Name)
	}
	header := "status=0\n"
	if family == "debian" {
		header += "apt-get update || { echo \"SETUP-FAILED: apt-get update\"; status=1; }\n"
	}
	body := fmt.Sprintf("for p in %s; do\n  if %%s \"$p\"; then\n    echo \"%s$p\"\n  else\n    echo \"%s$p\"\n    status=1\n  fi\ndone\necho SETUP-DONE\nexit $status\n",
		strings.Join(names, " "), okPrefix, failedPrefix)
	var prefix string
	switch family {
	case "debian":
		prefix = "DEBIAN_FRONTEND=noninteractive apt-get install -y"
	case "fedora":
		prefix = "dnf -y install"
	case "arch":
		prefix = "pacman -S --noconfirm --needed"
	case "suse":
		prefix = "zypper --non-interactive install"
	case "alpine":
		prefix = "apk add --no-cache"
	case "void":
		prefix = "xbps-install -Sy"
	default:
		return ""
	}
	return header + fmt.Sprintf(body, prefix)
}

// ParseResult extracts per-package results from the installer's own markers.
// The command prints SETUP-OK / SETUP-FAILED for each attempted package, so the
// result does not depend on translated package-manager wording.
func ParseResult(output string, packages []Package) (installed, failed []string) {
	okSet := map[string]bool{}
	failedSet := map[string]bool{}
	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, okPrefix) {
			okSet[strings.TrimSpace(strings.TrimPrefix(line, okPrefix))] = true
		}
		if strings.HasPrefix(line, failedPrefix) {
			failedSet[strings.TrimSpace(strings.TrimPrefix(line, failedPrefix))] = true
		}
	}
	for _, p := range packages {
		switch {
		case failedSet[p.Name]:
			failed = append(failed, p.Name)
		case okSet[p.Name]:
			installed = append(installed, p.Name)
		}
	}
	sort.Strings(installed)
	sort.Strings(failed)
	return installed, failed
}

// ShellQuote quotes one argument for sh -c, used when re-launching the GUI as
// root with the original display environment.
func ShellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'"
}
