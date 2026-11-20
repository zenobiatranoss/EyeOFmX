# EyeOFmX

**Native Linux desktop monitoring and security inspection — portable across distributions**

> Created by **Zenobia** — **For NT Protection**. Not only Debian/MX Linux: it
> is built for all Linux distributions.

EyeOFmX is a high-utility GTK 3 desktop application written in Go. It shows
active sockets, listening ports, owning processes, critical `/etc` files, a live
activity feed, shell command history, structured findings from the security
tools already installed on your system, and a sixth tab with a brief aggregated
comprehensive posture report (rootkits, malware, suspicious files and major
attack classes).

- **Native GUI only** — no browser, no embedded web view, no local web server.
- **English-only UI** — every label, log line and message is in English.
- **Retro technical theme** — off-white workspace, monospace typography, sharp
  borders, dark near-black terminal panels for logs and command views.
- **Read-only inspection by design** — collectors never modify a file, socket,
  process or system configuration. Installing optional scanning engines is a
  separate action that always requires explicit confirmation and authentication.
- **Cross-distro by design** — Debian/Ubuntu/MX, RHEL/Fedora, Arch/Manjaro,
  openSUSE, Alpine/musl, Void and systemd or non-systemd systems are supported.
  Missing optional tools cause graceful degradation, never a crash.

---

## 1. Requirements

You need:

- a Linux desktop with **GTK 3** runtime and development headers,
- **Go 1.21 or newer** with cgo enabled,
- `pkg-config` and a C compiler.

Go 1.21+ is required. The application is built with the `gtk_3_20` tag, which
pins the gotk3 binding compile-time API level to GTK 3.20. It still runs against
GTK 3.24+ on any distribution. `CGO_CFLAGS` only silences GTK deprecation
warnings; it does not change behaviour.

### Distribution packages

| Distribution | Build dependencies |
|---|---|
| Debian / Ubuntu / MX / Linux Mint | `sudo apt install golang-go libgtk-3-dev pkg-config build-essential` |
| RHEL / Fedora / Rocky / Alma | `sudo dnf install golang gtk3-devel pkgconfig gcc` |
| Arch / Manjaro / Endeavour | `sudo pacman -S go gtk3 pkgconf base-devel` |
| openSUSE | `sudo zypper install go gtk3-devel pkgconfig gcc` |
| Alpine / postmarketOS (musl) | `sudo apk add go gtk3-dev pkgconf build-base` |
| Void Linux | `sudo xbps-install go gtk3-devel pkg-config gcc` |
| Gentoo | `sudo emerge dev-lang/go x11-libs/gtk3 pkgconf` |

The Makefile verifies the native dependencies with:

```bash
make check-deps
```

This checks `gtk+-3.0`, `gdk-3.0`, `glib-2.0` and `gobject-2.0` through
`pkg-config`, so it works regardless of how your distribution names its
development packages.

### Optional tools

EyeOFmX detects these at startup. None are required; every collector has a
pure-Go or `/proc` fallback where possible.

| Capability | Preferred tools | Fallback / notes |
|---|---|---|
| Socket statistics | `ss` (iproute2 / iproute) | direct `/proc/net/{tcp,tcp6,udp,udp6}` decoding |
| Socket owner | `lsof` | `/proc/<pid>/fd` inode mapping |
| System journal | `journalctl` | syslog/auth/secure/messages files; skipped when systemd is not active |
| Firewall status | `ufw`, `firewall-cmd`, `nft`, `iptables` | whichever answers; kernel firewall logs are also read |
| Structured queries | `osqueryi` | optional, off by default |
| System audit | `lynis` | optional, off by default; used by the comprehensive scan |
| File integrity | `aide` | optional, off by default; used by the comprehensive scan |
| Rootkit detection | `rkhunter`, `chkrootkit` | optional, off by default; used by the comprehensive scan |
| Anti-malware | `clamscan`, `clamdscan` | optional, off by default; used by the comprehensive scan |
| Audit / MAC status | `auditctl`, `sestatus`, `getenforce` | optional; reported as reduced coverage when missing |
| IP lookup | `whois` | IP classification plus reverse DNS via `getent` or Go's resolver |

On Debian-family systems many of these come from
`iproute2 lsof ufw whois`. On RHEL-family systems use
`iproute lsof firewalld nftables iptables whois`. On Arch use
`iproute2 lsof ufw nftables whois`. On Alpine use
`iproute2 lsof ufw nftables whois`. Install only what you want — the app adapts.

### Automatic tool installation

`eyeofmx -setup-plan` prints the exact proposal for the current host: detected
distribution, missing engines, package names, the generated command and notes.
The GUI offers the same proposal at startup when auto-installable engines are
missing. You can rerun it from **Tools → Install scanning tools (root)** or from
the **Install tools** button on the posture-scan tab.

| Distribution family | Packages installed automatically | Important notes |
|---|---|---|
| Debian / Ubuntu / MX / Linux Mint | `rkhunter chkrootkit lynis aide clamav clamav-freshclam clamav-daemon osquery` | All are in the default repositories. |
| Fedora / RHEL / Rocky / Alma | `rkhunter chkrootkit lynis aide clamav clamav-freshclam` | EPEL may be needed on RHEL clones. `osquery` needs the Palantir repository and is left to the user. |
| Arch / Manjaro / Endeavour | `rkhunter lynis clamav` | `chkrootkit`, `aide` and `osquery-bin` are AUR packages; review their PKGBUILDs and install them with your AUR helper. |
| openSUSE | `rkhunter chkrootkit lynis aide clamav` | Some tools may be in the security repository. `osquery` availability varies by release. |
| Alpine / postmarketOS | `rkhunter chkrootkit lynis aide clamav` | Some tools are in community or testing; enable the matching repository if one fails. No `osquery` package. |
| Void | `rkhunter chkrootkit lynis aide clamav` | `osquery` availability varies by repository. |
| Gentoo | none | USE flags and package atoms are distribution-specific; install manually. |

Each package is attempted in its own command, so one unavailable package cannot
abort the rest. The command prints `SETUP-OK` / `SETUP-FAILED` markers; the GUI
reports each result separately and does not guess from translated package-manager
text. No third-party repository or AUR helper is added automatically.

### Privileges

Run unprivileged for a normal desktop session; EyeOFmX starts and reports what
is hidden. Run as root when you need other users' `/proc` details, shadow files,
protected logs and shell histories:

```bash
sudo ./eyeofmx      # Debian/Ubuntu/MX, and most sudo-based systems
doas ./eyeofmx      # OpenBSD-style doas setups
su -c './eyeofmx'   # plain su
```

Installing tools is the one intentional exception to the read-only rule. It
never happens silently: the app first shows the exact command and asks for
confirmation, then authenticates with `pkexec` (the system polkit dialog) when
available, otherwise with a native GTK password dialog for `sudo` or `doas`.
The password is used only for that command and is never written to disk or
logged. After a successful install, the GUI offers to restart itself as root
with `-full-scan` so the new engines run immediately. If you decline, nothing is
installed.

---

## 2. Download and install a prebuilt package

You **do not need Go, source code or a build step**. Download the single file
that matches your distribution from the GitHub Releases page and install it
with your normal package manager.

| Distribution | Download | One command |
|---|---|---|
| Debian / Ubuntu / MX / Linux Mint | `eyeofmx_1.0.0_amd64.deb` | `sudo apt install ./eyeofmx_1.0.0_amd64.deb` |
| Fedora / RHEL / Rocky / Alma | `eyeofmx-1.0.0-1.x86_64.rpm` | `sudo dnf install ./eyeofmx-1.0.0-1.x86_64.rpm` |
| openSUSE | `eyeofmx-1.0.0-1.x86_64.rpm` | `sudo zypper install ./eyeofmx-1.0.0-1.x86_64.rpm` |
| Arch / Manjaro / Endeavour | `eyeofmx-1.0.0-1-x86_64.pkg.tar.zst` | `sudo pacman -U ./eyeofmx-1.0.0-1-x86_64.pkg.tar.zst` |
| Alpine / postmarketOS | `eyeofmx-1.0.0-r0-x86_64.apk` | `sudo apk add --allow-untrusted ./eyeofmx-1.0.0-r0-x86_64.apk` |
| Any other Linux with GTK 3 | `eyeofmx-1.0.0-x86_64.tar.gz` | extract, then `sudo install -m755 eyeofmx /usr/local/bin/` |

`aarch64` / `arm64` builds are published when available. Pick the file whose
architecture matches `uname -m`. Every package contains a binary compiled
against that distribution's GTK 3 ABI, so there are no runtime surprises. The
`.apk` is signed with the release build key; use `--allow-untrusted` only for
that first install, or import the key if your environment requires it.

After installation, launch it from the applications menu or with `eyeofmx`.
`eyeofmx -check` prints privileges, init, libc, kernel and detected tools.

Maintainers who want to produce the packages themselves can run:

```bash
VERSION=1.0.0 ./packaging/build.sh          # Docker + BuildKit: all targets
make package-deb                            # direct .deb on Debian-family host
make package-rpm                            # direct .rpm on Fedora/RHEL/openSUSE host
make package-generic                        # direct tarball on any host
```

See `packaging/README.md` for details and the GitHub Actions release workflow.

### Simple download website

A ready-made static download page lives in `site/`. It lists every package with
its size, SHA-256 and one-line install command, and it is generated
automatically from `dist/`:

```bash
./site/generate.sh        # or: make site
```

Upload the contents of `site/` to **GitHub Pages**, Netlify, Cloudflare Pages or
any ordinary static web host; visitors then download directly from one simple
page with no source code or build step. The included
`.github/workflows/release.yml` builds the packages, generates the site,
attaches files to the GitHub Release and deploys the site to GitHub Pages on
every `v*` tag. For site-only edits, `.github/workflows/site.yml` deploys `site/`
on every push to `main`/`master` without rebuilding packages. Enable Pages with
“GitHub Actions” as the source in repository settings.

Free hosting options:

- **GitHub Pages** — already wired; URL: `https://zenobiatranoss.github.io/EyeOFmX/`
- **Netlify Drop** — drag the `site/` folder to `app.netlify.com/drop`
- **Cloudflare Pages** — connect the repo, build command empty, output `site/`
- Any FTP host — upload the contents of `site/` into `public_html/` or `htdocs/`

The whole site including installers is about 9 MB, well within free-tier limits.

---

## 3. Build and run

```bash
cd EyeOFmX
go mod download        # or: go mod tidy
make build             # produces ./eyeofmx
```

Equivalent manual build:

```bash
CGO_CFLAGS="-Wno-deprecated-declarations" go build -tags gtk_3_20 -o eyeofmx ./cmd/eyeofmx
```

Useful targets:

```bash
make check-deps        # verify GTK 3 development files
make test              # unit tests
make vet               # go vet across all packages
make check             # tests + vet + non-GUI diagnostics
make clean             # remove the binary
sudo make install      # install to /usr/local/bin/eyeofmx
```

Run:

```bash
./eyeofmx              # reduced visibility, still fully functional
./eyeofmx -check       # non-GUI privilege/tool diagnostics
./eyeofmx -setup-plan  # print the detected tool-installation plan
./eyeofmx -scan        # non-GUI quick posture report
./eyeofmx -scan-full   # non-GUI full comprehensive report
./eyeofmx -full-scan   # start GUI and run the full scan immediately
./eyeofmx -version
```

Diagnostics print privileges, active init system, libc, kernel release and the
ordered capability list with the binary that provides each capability. This is
the quickest way to confirm detection on an unfamiliar distribution.

Copy `io.github.eyeofmx.desktop` into
`~/.local/share/applications/` for a desktop launcher. Keyboard shortcuts:
`F5` refreshes the active tab, `Ctrl+Q` quits.

---

## 4. Project structure

```
EyeOFmX/
├── cmd/eyeofmx/main.go             CLI entry point, diagnostics, GUI startup
├── internal/
│   ├── model/model.go              shared data types
│   ├── sysutil/                    portability layer
│   │   ├── sysutil.go              root detection, bounded subprocesses with
│   │   │                           LC_ALL=C, bounded reads and log tailing
│   │   ├── portability.go          tool registry, syslog paths, init/libc
│   │   │                           detection, critical-file list
│   │   ├── clock_cgo.go            USER_HZ via sysconf (no getconf needed)
│   │   └── clock_nocgo.go          non-GUI fallback for ClockTicks
│   ├── procinfo/procinfo.go        /proc metadata, native exe resolution,
│   │                               cmdline, UID/GID, start/uptime, FDs,
│   │                               deleted-image detection, socket owners
│   ├── netinfo/netinfo.go          ss parsing, native /proc/net decoding,
│   │                               lsof enrichment, TCP/UDP state mapping
│   ├── etcaudit/etcaudit.go        adaptive /etc checklist, risk evaluation,
│   │                               native WalkDir scans, read-only viewer data
│   ├── watcher/watcher.go          live 2-second sampler of processes, sockets,
│   │                               critical files and auth/syslog lines
│   ├── cmdhistory/cmdhistory.go    bash/zsh/fish history parsing plus live
│   │                               observed commands
│   ├── extlogs/extlogs.go          journal, syslog, firewall, fail2ban,
│   │                               osquery, lynis and aide normalisation
│   ├── scan/scan.go                comprehensive posture aggregation, tool
│   │                               parsers, native checks, report formatting
│   ├── setup/setup.go              distro detection, per-family package maps,
│   │                               install command builder and result parsing
│   └── gui/                        native GTK 3 interface
│       ├── gui.go                  window, menu, notebook, status, accelerators
│       ├── theme.go                retro technical CSS
│       ├── helpers.go              table/text-view/clipboard/dialog helpers
│       ├── install.go              consent, elevation, installer output and
│       │                           root full-scan restart
│       ├── connections.go          tab 1 — connections and process inspector
│       ├── files.go                tab 2 — /etc audit and read-only viewer
│       ├── live.go                 tab 3 — live activity feed
│       ├── history.go              tab 4 — command history terminal
│       ├── logs.go                 tab 5 — security log aggregator
│       └── scan.go                 tab 6 — comprehensive posture report
├── packaging/                      single-file package definitions
│   ├── build.sh                    builds all targets with Docker
│   ├── debian/                     .deb control + Dockerfile + local builder
│   ├── fedora/                     Fedora Dockerfile
│   ├── opensuse/                   openSUSE Dockerfile
│   ├── rpm/                        shared RPM spec + local builder
│   ├── arch/                       PKGBUILD + Dockerfile
│   ├── alpine/                     APKBUILD + Dockerfile
│   └── generic/                    portable prebuilt tarball
├── .github/workflows/              release.yml builds packages; site.yml deploys the page
├── site/                           simple static download website + generated files
├── LICENSE                         MIT license
├── Makefile                        cross-distro build/test/check/package targets
└── io.github.eyeofmx.desktop       desktop launcher
```

---

## 5. How portability is implemented

### 5.1 One source of truth

`internal/sysutil/portability.go` owns every distribution-dependent decision:

- **Tool registry** — capabilities map to ordered binary candidates
  (`ufw` → `firewall-cmd` → `nft` → `iptables`, etc.). GUI status, `-check`
  diagnostics and collectors all use the same `ToolList()`.
- **Log paths** — `SyslogPaths()`, `AuthLogPaths()`, `FirewallLogPaths()` and
  `Fail2banLogPaths()` cover Debian, RHEL, Arch, Alpine and syslog-ng layouts
  and keep only paths that actually exist.
- **Init detection** — `/run/systemd/system` decides whether journal entries are
  expected. On OpenRC/runit/s6 systems EyeOFmX reads syslog files instead.
- **Libc detection** — musl is detected from `/etc/ld-musl-*.path` or
  `/lib/ld-musl-*.so.1`; otherwise glibc is assumed.
- **Critical files** — the watcher watches `/etc/init.d`, `/etc/conf.d`,
  `/etc/sv` or `/etc/rc.d` on non-systemd systems, and musl linker paths on
  Alpine instead of inventing a missing `/etc/ld.so.conf` finding.

All subprocesses are launched with `LC_ALL=C`, so English log tokens such as
`Failed password`, `WARNING`, `FOUND` and `ufw block` parse correctly under any
user locale.

### 5.2 Connections and process inspector

`netinfo` runs `ss -H -n -tap` and `ss -H -n -uap` when iproute2 is present, so
TCP and UDP are never confused and service names never become port 0. Invalid
rows are dropped. If `ss` is missing or returns nothing usable, EyeOFmX decodes
`/proc/net/tcp`, `tcp6`, `udp` and `udp6` directly. Addresses are decoded with
`binary.NativeEndian`, which is correct on little-endian x86 and big-endian
architectures such as s390x. Socket inodes are mapped to PIDs by scanning
`/proc/<pid>/fd`; `lsof -nP -i` only enriches the result.

Process metadata comes straight from `/proc`. `/proc/<pid>/stat` is parsed with
the correct field indices (starttime and threads), `USER_HZ` comes from
`sysconf(_SC_CLK_TCK)` rather than the `getconf` binary, and `/proc/<pid>/exe`
is resolved in Go with `os.Readlink`/`EvalSymlinks` instead of GNU
`readlink -f`. Selecting a row shows endpoints, state, PID/PPID, process name,
exact executable, command line, user/UID/GID, start time, uptime, threads, cwd,
root, socket inode/FD, deleted-image status and descriptors.

Quick actions:

- **Inspect binary path** — Go-native `os.Lstat` metadata, no GNU `stat -c`.
- **Check related files** — descriptors, cwd and root.
- **Copy details** — whole inspection pane to clipboard.
- **Lookup IP info** — `whois` when installed, otherwise IP classification and
  reverse DNS through `getent` if present, then Go's resolver as fallback.

### 5.3 `/etc` and high-risk file audit

The curated checklist adapts to the running system: systemd units only appear
when systemd is active; OpenRC/runit/s6 directories and musl linker paths appear
when appropriate; both Debian and RHEL cron/bash layouts are included. Each
entry records mode, octal permission, owner/group, inode, size and timestamps.

Risk rules are practical and distribution-neutral:

- shadow files with world/group-write access → **CRITICAL**; group-readable by
  the expected shadow group is reported as a note, not a false finding
- world-writable regular file → **CRITICAL**
- SUID/SGID or world-writable `/etc` path → **HIGH**
- `/etc/ld.so.preload` present → **HIGH**
- missing sticky bit on `/tmp`, `/var/tmp`, `/dev/shm` → **HIGH**
- UID 0 account other than `root` in `/etc/passwd` → **CRITICAL**
- insecure `sshd_config` settings → **MEDIUM/LOW**

**Quick check** inspects only the curated list. **Full audit** adds native
`filepath.WalkDir` scans for SUID/SGID binaries, world-writable `/etc` paths,
recently modified executables in temp directories and deleted running images.
No `find` binary is required, so busybox/toybox systems are fully covered.

The right pane shows metadata and a **read-only** file viewer. Risky patterns
are highlighted. "Mask secrets" redacts password hashes by default.

### 5.4 Live activity feed

`watcher` samples every two seconds and emits timestamped events when:

- the kernel/boot event is registered at startup (host, kernel, boot time, uptime),
- a process appears or exits (PID, PPID, user, command),
- a socket opens, starts listening or closes,
- a critical file for the detected init/libc combination changes,
- a new line appears in any detected auth/syslog file (with severity).

Kernel release comes from `uname(2)` via `syscall.Uname`, not the `uname` binary.
The feed can be paused, cleared, filtered by category and searched, with
optional auto-scroll. All events stay in memory.

### 5.5 Command history

`cmdhistory` honours the variables the shells actually use: `HISTFILE` for bash,
`ZDOTDIR` for zsh and `XDG_DATA_HOME` for fish. When running as root, home
directories come from `/etc/passwd` rather than a `/home/*` glob, so `/root`,
`/var/home`, `/users` and service accounts are covered. Owners are read from
the file inode. Bash timestamps and zsh extended timestamps are parsed; live
observed commands can be included. Nothing is ever written back.

### 5.6 Security log aggregator

`extlogs` normalises output from tools you already trust:

| Source | Behaviour |
|---|---|
| journalctl | used only when systemd is active; otherwise an explanatory INFO entry is shown |
| syslog / auth.log / secure / messages | all existing paths are tailed with RFC3339 and year-rollover aware parsing |
| firewall | ufw, firewalld, nftables or iptables status; ufw/firewalld/kernel firewall logs |
| fail2ban | both common log locations |
| osqueryi | optional JSON process/port/user queries |
| lynis | optional quick audit |
| aide | optional integrity check |

Each line becomes a structured entry with source, severity (ALERT/WARN/NOTICE/
INFO/ERROR), tag (SSH, SUDO, FIREWALL, KERNEL, SERVICE, CRON, OSQUERY, LYNIS,
INTEGRITY) and full raw text. Filters combine search text, severity and source.
Lynis and AIDE are off by default because they can be slow.

### 5.7 Comprehensive posture scan

Tab 6 produces one brief report instead of a pile of separate tool logs. The
engines are aggregated into severity-ranked findings with source, evidence and a
recommended action, plus a per-tool coverage table that shows exactly which
engines were available:

| Engine | Attack / posture area |
|---|---|
| `rkhunter`, `chkrootkit` | rootkits, hidden processes, tampered system commands |
| `lynis` | hardening, permissions and service exposure |
| `aide` | file integrity — added, removed or changed files |
| `clamscan` / `clamdscan` | malware signatures in temporary locations |
| `osqueryi` | processes from temp paths, extra UID 0 accounts, cron persistence, exposed ports |
| native Go checks | UID 0 accounts, `ld.so.preload`, world-writable `/etc`, hidden/recent temp executables, deleted running images, shell/cron persistence, ASLR, firewall and audit/SELinux state |

`Quick posture` uses the fast native checks and osquery. `Full comprehensive`
adds every installed external engine; missing tools appear as `NOT INSTALLED`
coverage, never as an error. Rootkit and malware engines are opt-in because they
can take several minutes. All output is English, timeout-bounded and read-only.
The report can be copied or saved as plain text from the tab. The same scan is
available from the shell with `eyeofmx -scan` and `eyeofmx -scan-full`.

When engines are missing, **Install tools** uses the per-distribution map above,
asks for confirmation and root authentication, streams the package-manager
output into the tab, then offers to restart as root with `-full-scan`. This is
the only GUI action that changes the system; every collector remains read-only.

---

## 6. Permissions and failure handling

- Every collector is best-effort: permission errors become visible records or
  log entries, never panics.
- Subprocesses have timeouts (5 s to 240 s depending on tool), so a stuck tool
  cannot freeze the interface.
- Large files are never fully read into memory: log tailing is bounded and the
  file viewer refuses files above 4 MiB.
- All GUI mutations from background goroutines are marshalled through
  `glib.IdleAdd`, keeping GTK on its main thread.
- Table repopulation blocks the selection signal and defers callbacks, avoiding
  GTK reentrancy crashes during rapid refresh/filter cycles.
- Running unprivileged prints a startup warning and adds a notice to the live
  feed. The Tools menu lists init, libc, kernel and every detected capability.

---

## 7. Design notes

The interface deliberately avoids vanity metrics, animation and decoration.
Six task-oriented tabs cover connections, file audit, live activity, command
history, security logs and the comprehensive posture report. Tables have sharp
borders and monospace labels; only log, command, report and file-content panels
use the dark terminal theme. Inspection actions are direct reads or copy
operations — EyeOFmX does not kill processes, change firewall rules, edit files
or run remediation commands. The explicit, confirmed tool installer is the sole
exception.

Created by Zenobia. For NT Protection. License: MIT.
