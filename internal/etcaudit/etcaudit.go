// Package etcaudit implements a curated audit of critical Linux configuration
// files and common persistence / privilege-escalation locations. All reads are
// read-only and permission failures are recorded rather than fatal.
package etcaudit

import (
	"fmt"
	"io/fs"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"eyeofmx/internal/model"
	"eyeofmx/internal/procinfo"
	"eyeofmx/internal/sysutil"
)

const viewerLimit = 4 << 20 // 4 MiB

type checklistItem struct {
	path, description, group string
}

// checklistItems adapts the curated list to the running system. systemd and
// glibc paths are only expected where they actually exist; OpenRC/runit/s6 and
// musl get their own equivalent locations instead of false HIGH findings.
func checklistItems() []checklistItem {
	items := []checklistItem{
		{"/etc/passwd", "Local account database — unexpected accounts indicate persistence", "identity"},
		{"/etc/group", "Local group database — watch for new privileged groups", "identity"},
		{"/etc/shadow", "Password hashes — must not be readable by non-root", "identity"},
		{"/etc/gshadow", "Group password hashes", "identity"},
		{"/etc/sudoers", "sudo policy — group/world write is critical", "privilege"},
		{"/etc/sudoers.d", "Additional sudo policy drop-in directory", "privilege"},
		{"/etc/crontab", "System crontab — commands run as root", "persistence"},
		{"/etc/cron.d", "Cron drop-in directory", "persistence"},
		{"/etc/cron.hourly", "Hourly cron scripts", "persistence"},
		{"/etc/cron.daily", "Daily cron scripts", "persistence"},
		{"/etc/cron.weekly", "Weekly cron scripts", "persistence"},
		{"/etc/cron.monthly", "Monthly cron scripts", "persistence"},
		{"/var/spool/cron/crontabs", "Per-user crontabs (Debian/Alpine layout)", "persistence"},
		{"/var/spool/cron", "Per-user crontabs (RHEL/Arch layout)", "persistence"},
		{"/etc/hosts", "Static name resolution — hijacking target", "network"},
		{"/etc/resolv.conf", "DNS resolver configuration — hijacking target", "network"},
		{"/etc/nsswitch.conf", "Name service switch order", "network"},
		{"/etc/ssh/sshd_config", "SSH daemon policy (root login, password auth)", "remote access"},
		{"/etc/ld.so.preload", "Dynamic linker preload — injected libraries (often malicious)", "injection"},
		{"/etc/rc.local", "Legacy boot script", "persistence"},
		{"/etc/profile", "Global shell profile", "persistence"},
		{"/etc/bash.bashrc", "Global bash rc file (Debian/Arch layout)", "persistence"},
		{"/etc/bashrc", "Global bash rc file (RHEL layout)", "persistence"},
		{"/etc/environment", "System-wide environment variables", "persistence"},
		{"/etc/pam.d", "PAM authentication configuration", "privilege"},
		{"/etc/login.defs", "Login and password policy defaults", "privilege"},
		{"/etc/inetd.conf", "Legacy inetd services (if present)", "remote access"},
		{"/etc/xinetd.conf", "Legacy xinetd services (if present)", "remote access"},
		{"/tmp", "World-writable temporary directory — must keep sticky bit", "runtime"},
		{"/var/tmp", "World-writable temporary directory — must keep sticky bit", "runtime"},
		{"/dev/shm", "Shared memory — executable files here are suspicious", "runtime"},
	}

	if sysutil.IsSystemd() {
		items = append(items, checklistItem{"/etc/systemd/system", "Systemd unit definitions — service persistence", "persistence"})
	} else {
		for _, p := range []string{"/etc/init.d", "/etc/conf.d", "/etc/sv", "/etc/rc.d"} {
			items = append(items, checklistItem{p, "Init-system service definitions — service persistence", "persistence"})
		}
	}

	if sysutil.Libc() == "musl" {
		matches, _ := filepath.Glob("/etc/ld-musl-*.path")
		for _, p := range matches {
			items = append(items, checklistItem{p, "Musl dynamic linker search path", "injection"})
		}
	} else {
		items = append(items,
			checklistItem{"/etc/ld.so.conf", "Dynamic linker configuration", "injection"},
			checklistItem{"/etc/ld.so.conf.d", "Dynamic linker configuration drop-ins", "injection"},
		)
	}
	return items
}

// CuratedAudit evaluates only the curated checklist (fast, no broad scans).
func CuratedAudit() []model.FileRecord {
	items := checklistItems()
	records := make([]model.FileRecord, 0, len(items))
	for _, item := range items {
		records = append(records, inspect(item.path, item.description, item.group))
	}
	return records
}

// Audit evaluates every curated path plus targeted filesystem scans.
func Audit() []model.FileRecord {
	records := CuratedAudit()
	records = append(records, scanSetuid()...)
	records = append(records, scanWorldWritableEtc()...)
	records = append(records, scanTempExecutables()...)
	records = append(records, scanDeletedBinaries()...)
	return records
}

// Refresh re-evaluates a single path (used after a manual refresh of one item).
func Refresh(path, description, group string) model.FileRecord {
	return inspect(path, description, group)
}

func inspect(path, description, group string) model.FileRecord {
	rec := model.FileRecord{Path: path, Description: description, GroupLabel: group, Risk: "INFO"}
	var st syscall.Stat_t
	if err := syscall.Lstat(path, &st); err != nil {
		if os.IsNotExist(err) {
			rec.Findings = append(rec.Findings, "path does not exist")
			if isRequired(path) {
				rec.Risk = "HIGH"
			}
		} else {
			rec.ReadError = err.Error()
			rec.Risk = "MEDIUM"
			rec.Findings = append(rec.Findings, "cannot stat: "+err.Error())
		}
		return rec
	}
	fillStat(&rec, path, &st)
	evaluate(&rec, st)
	if group != "scan" { // avoid reading arbitrary binaries during broad scans
		contentFindings(&rec)
	}
	return rec
}

func fillStat(rec *model.FileRecord, path string, st *syscall.Stat_t) {
	rec.Exists = true
	rec.IsDir = st.Mode&syscall.S_IFMT == syscall.S_IFDIR
	rec.Mode = modeString(st.Mode)
	rec.ModeOctal = fmt.Sprintf("%04o", st.Mode&07777)
	rec.UID, rec.GID = int(st.Uid), int(st.Gid)
	rec.Size, rec.Inode = st.Size, st.Ino
	rec.Modified = time.Unix(st.Mtim.Sec, st.Mtim.Nsec)
	rec.Changed = time.Unix(st.Ctim.Sec, st.Ctim.Nsec)
	rec.Accessed = time.Unix(st.Atim.Sec, st.Atim.Nsec)
	if u, err := user.LookupId(strconv.Itoa(rec.UID)); err == nil {
		rec.Owner = u.Username
	} else {
		rec.Owner = "uid=" + strconv.Itoa(rec.UID)
	}
	if g, err := user.LookupGroupId(strconv.Itoa(rec.GID)); err == nil {
		rec.Group = g.Name
	} else {
		rec.Group = "gid=" + strconv.Itoa(rec.GID)
	}
	_ = path
}

func modeString(mode uint32) string {
	var b strings.Builder
	switch mode & syscall.S_IFMT {
	case syscall.S_IFDIR:
		b.WriteByte('d')
	case syscall.S_IFLNK:
		b.WriteByte('l')
	case syscall.S_IFREG:
		b.WriteByte('-')
	case syscall.S_IFCHR:
		b.WriteByte('c')
	case syscall.S_IFBLK:
		b.WriteByte('b')
	case syscall.S_IFIFO:
		b.WriteByte('p')
	case syscall.S_IFSOCK:
		b.WriteByte('s')
	default:
		b.WriteByte('?')
	}
	bits := []struct {
		mask uint32
		char byte
	}{
		{syscall.S_IRUSR, 'r'}, {syscall.S_IWUSR, 'w'}, {syscall.S_IXUSR, 'x'},
		{syscall.S_IRGRP, 'r'}, {syscall.S_IWGRP, 'w'}, {syscall.S_IXGRP, 'x'},
		{syscall.S_IROTH, 'r'}, {syscall.S_IWOTH, 'w'}, {syscall.S_IXOTH, 'x'},
	}
	for _, bit := range bits {
		if mode&bit.mask != 0 {
			b.WriteByte(bit.char)
		} else {
			b.WriteByte('-')
		}
	}
	if mode&syscall.S_ISUID != 0 {
		b.WriteByte('s')
	}
	if mode&syscall.S_ISGID != 0 {
		b.WriteByte('s')
	}
	if mode&syscall.S_ISVTX != 0 {
		b.WriteByte('t')
	}
	return b.String()
}

func evaluate(rec *model.FileRecord, st syscall.Stat_t) {
	perm := st.Mode & 07777
	otherWrite := perm&0002 != 0
	groupWrite := perm&0020 != 0
	setuid := st.Mode&syscall.S_ISUID != 0
	setgid := st.Mode&syscall.S_ISGID != 0
	sticky := st.Mode&syscall.S_ISVTX != 0
	isDir := rec.IsDir

	raise := func(level, msg string) {
		rec.Findings = append(rec.Findings, msg)
		if riskRank(level) > riskRank(rec.Risk) {
			rec.Risk = level
		}
	}

	switch {
	case setuid || setgid:
		raise("HIGH", "setuid/setgid bit is set on a sensitive path")
	case otherWrite && !isDir:
		raise("CRITICAL", "world-writable regular file")
	case otherWrite && isDir && !sticky:
		raise("HIGH", "world-writable directory without sticky bit")
	case otherWrite && isDir && sticky:
		rec.Findings = append(rec.Findings, "world-writable directory with sticky bit (expected for temp directories)")
	case groupWrite && rec.UID == 0:
		raise("MEDIUM", "group-writable while owned by root")
	}

	switch rec.Path {
	case "/etc/shadow", "/etc/gshadow":
		// Group-readable shadow files are normal on many distros (for example
		// root:shadow on Debian/Alpine, root:root elsewhere). World access or
		// group write is the actual danger.
		if perm&0007 != 0 || perm&0020 != 0 {
			raise("CRITICAL", "shadow file is world-accessible or group-writable")
		} else if perm&0040 != 0 {
			rec.Findings = append(rec.Findings, fmt.Sprintf("group-readable by '%s' — verify this group is intentional", rec.Group))
		} else {
			rec.Findings = append(rec.Findings, "permission mode is acceptable for a shadow file")
		}
	case "/etc/sudoers", "/etc/sudoers.d":
		if perm&0022 != 0 {
			raise("HIGH", "sudo configuration is writable by group or others")
		}
	case "/etc/ld.so.preload":
		raise("HIGH", "dynamic linker preload file is present — verify every entry")
	case "/tmp", "/var/tmp", "/dev/shm":
		if !sticky && isDir {
			raise("HIGH", "temporary directory is missing its sticky bit")
		}
	}

	if rec.UID != 0 && isSensitive(rec.Path) {
		raise("MEDIUM", fmt.Sprintf("owned by non-root user '%s'", rec.Owner))
	}
	if !rec.Modified.IsZero() && time.Since(rec.Modified) < 24*time.Hour && isSensitive(rec.Path) {
		rec.Findings = append(rec.Findings, "modified within the last 24 hours")
	}
	if rec.ReadError != "" {
		raise("MEDIUM", "read error: "+rec.ReadError)
	}
}

func contentFindings(rec *model.FileRecord) {
	if rec.IsDir || !rec.Exists {
		return
	}
	text, err := sysutil.ReadLimited(rec.Path, viewerLimit)
	if err != nil {
		if os.IsPermission(err) {
			rec.ReadError = "permission denied (run EyeOFmX as root — sudo, doas or su — to inspect this file)"
			if riskRank("LOW") > riskRank(rec.Risk) {
				rec.Risk = "LOW"
			}
		} else {
			rec.ReadError = err.Error()
		}
		return
	}
	lower := strings.ToLower(text)
	switch rec.Path {
	case "/etc/ssh/sshd_config":
		for _, line := range strings.Split(text, "\n") {
			l := strings.ToLower(strings.TrimSpace(line))
			if strings.HasPrefix(l, "permitrootlogin") && !strings.Contains(l, "no") {
				rec.Findings = append(rec.Findings, "PermitRootLogin is not disabled: "+strings.TrimSpace(line))
				raiseRec(rec, "MEDIUM")
			}
			if strings.HasPrefix(l, "passwordauthentication") && strings.Contains(l, "yes") {
				rec.Findings = append(rec.Findings, "password authentication is enabled: "+strings.TrimSpace(line))
				raiseRec(rec, "LOW")
			}
		}
	case "/etc/passwd":
		for _, line := range strings.Split(text, "\n") {
			f := strings.Split(line, ":")
			if len(f) >= 3 && f[2] == "0" && f[0] != "root" {
				rec.Findings = append(rec.Findings, "additional UID 0 account: "+f[0])
				raiseRec(rec, "CRITICAL")
			}
		}
	case "/etc/ld.so.preload":
		if strings.TrimSpace(text) != "" {
			rec.Findings = append(rec.Findings, "preload libraries are configured: "+strings.TrimSpace(text))
		}
	case "/etc/hosts", "/etc/resolv.conf":
		if len(strings.TrimSpace(text)) == 0 {
			rec.Findings = append(rec.Findings, "file is empty")
			raiseRec(rec, "MEDIUM")
		}
	}
	if strings.Contains(lower, "/dev/shm") && (rec.Path == "/etc/fstab" || rec.GroupLabel == "persistence") {
		rec.Findings = append(rec.Findings, "references /dev/shm")
	}
}

func raiseRec(rec *model.FileRecord, level string) {
	if riskRank(level) > riskRank(rec.Risk) {
		rec.Risk = level
	}
}

func riskRank(level string) int {
	switch level {
	case "CRITICAL":
		return 4
	case "HIGH":
		return 3
	case "MEDIUM":
		return 2
	case "LOW":
		return 1
	}
	return 0
}

func isSensitive(path string) bool {
	return strings.HasPrefix(path, "/etc/") || strings.HasPrefix(path, "/var/spool/cron")
}

func isRequired(path string) bool {
	switch path {
	case "/etc/passwd", "/etc/group", "/etc/hosts", "/etc/resolv.conf", "/etc/nsswitch.conf",
		"/tmp", "/var/tmp", "/dev/shm", "/etc/profile":
		return true
	}
	if sysutil.IsSystemd() {
		if path == "/etc/systemd/system" {
			return true
		}
	} else {
		switch path {
		case "/etc/init.d", "/etc/conf.d", "/etc/sv", "/etc/rc.d":
			return true
		}
	}
	if sysutil.Libc() != "musl" && (path == "/etc/ld.so.conf" || path == "/etc/ld.so.conf.d") {
		return true
	}
	return false
}

// ReadFile returns file content for the read-only viewer, with a size guard.
func ReadFile(path string) (string, error) { return sysutil.ReadLimited(path, viewerLimit) }

// HighlightPatterns returns substrings that the viewer should mark as risky
// for a given file. This keeps risk highlighting out of the GUI layer.
func HighlightPatterns(path string) []string {
	base := filepath.Base(path)
	switch {
	case base == "sshd_config":
		return []string{"PermitRootLogin yes", "PasswordAuthentication yes", "PermitEmptyPasswords yes"}
	case base == "passwd", base == "group":
		return []string{":0:", "sudo", "wheel", "adm", "admin", "root"}
	case base == "sudoers" || strings.HasPrefix(path, "/etc/sudoers.d/"):
		return []string{"ALL=(ALL", "NOPASSWD", "!authenticate"}
	case base == "ld.so.preload" || strings.HasPrefix(base, "ld.so.conf") || strings.HasPrefix(base, "ld-musl-"):
		return []string{"/tmp/", "/var/tmp/", "/dev/shm/", "/home/"}
	case strings.Contains(path, "cron") || base == "crontab":
		return []string{"/tmp/", "/dev/shm/", "curl", "wget", "bash -i", "nc ", "/bin/sh"}
	case base == "hosts" || base == "resolv.conf" || base == "nsswitch.conf":
		return []string{"0.0.0.0", "nameserver", "hosts:"}
	case base == "profile" || base == "bashrc" || base == "bash.bashrc":
		return []string{"/tmp/", "/dev/shm/", "curl", "wget", "alias sudo"}
	}
	return []string{"/tmp/", "/dev/shm/", "curl ", "wget "}
}

// ---- targeted scans -------------------------------------------------------

// walkPaths is a portable replacement for GNU find. It uses only the Go
// standard library, so busybox/toybox find on Alpine and minimal images cannot
// silently disable a security scan.
func walkPaths(root string, skip map[string]bool, fn func(path string, info os.FileInfo, st *syscall.Stat_t, isDir bool)) {
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		isDir := d.IsDir()
		if isDir && path != root && skip[path] {
			return filepath.SkipDir
		}
		if !isDir && !d.Type().IsRegular() {
			return nil
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok {
			return nil
		}
		fn(path, info, st, isDir)
		return nil
	})
}

func scanSetuid() []model.FileRecord {
	out := []model.FileRecord{}
	skip := map[string]bool{"/proc": true, "/sys": true, "/dev": true, "/run": true}
	walkPaths("/", skip, func(path string, _ os.FileInfo, st *syscall.Stat_t, isDir bool) {
		if isDir || st.Mode&0111 == 0 || st.Mode&(syscall.S_ISUID|syscall.S_ISGID) == 0 {
			return
		}
		rec := inspect(path, "SUID/SGID binary — review privilege escalation surface", "scan")
		if rec.Risk == "INFO" {
			rec.Risk = "LOW"
			rec.Findings = append(rec.Findings, "setuid/setgid executable found (expected for some system tools)")
		}
		out = append(out, rec)
	})
	return out
}

func scanWorldWritableEtc() []model.FileRecord {
	out := []model.FileRecord{}
	walkPaths("/etc", nil, func(path string, _ os.FileInfo, st *syscall.Stat_t, _ bool) {
		if st.Mode&0002 == 0 {
			return
		}
		rec := inspect(path, "World-writable path under /etc", "scan")
		if len(rec.Findings) == 0 {
			rec.Findings = append(rec.Findings, "world-writable path under /etc")
		}
		raiseRec(&rec, "HIGH")
		out = append(out, rec)
	})
	return out
}

func scanTempExecutables() []model.FileRecord {
	out := []model.FileRecord{}
	for _, dir := range []string{"/tmp", "/var/tmp", "/dev/shm"} {
		walkPaths(dir, nil, func(path string, info os.FileInfo, st *syscall.Stat_t, isDir bool) {
			if isDir || st.Mode&0111 == 0 || time.Since(info.ModTime()) > 72*time.Hour {
				return
			}
			rec := inspect(path, "Recently modified executable in a temporary location", "scan")
			rec.Findings = append(rec.Findings, "executable file modified in the last 3 days in "+dir)
			raiseRec(&rec, "HIGH")
			out = append(out, rec)
		})
	}
	return out
}

func scanDeletedBinaries() []model.FileRecord {
	out := []model.FileRecord{}
	for _, p := range procinfo.DeletedExecutables() {
		out = append(out, model.FileRecord{
			Path:        p.Executable,
			Description: fmt.Sprintf("Running process PID %d (%s) uses a deleted image", p.PID, p.Name),
			Risk:        "HIGH",
			Exists:      false,
			Mode:        "?",
			Owner:       p.User,
			GroupLabel:  "scan",
			Findings: []string{
				"executable was replaced or removed while running",
				"command: " + p.Cmdline,
			},
		})
	}
	return out
}
