// Package netinfo collects active sockets and listening ports. The primary
// source is iproute2 "ss"; /proc/net/{tcp,tcp6,udp,udp6} is used as a fallback
// and as a cross-check when ss is missing or cannot see process owners.
package netinfo

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"regexp"
	"strconv"
	"strings"
	"time"

	"eyeofmx/internal/model"
	"eyeofmx/internal/procinfo"
	"eyeofmx/internal/sysutil"
)

var userRe = regexp.MustCompile(`\("([^"]*)",pid=(\d+),fd=(\d+)\)`)

// Collect returns all observed TCP/UDP sockets, with process attribution when
// the current privileges allow it. It includes the optional (slower) lsof
// cross-check.
func Collect() []model.Connection { return collect(true) }

// CollectLight omits the lsof cross-check. It is used by the 2-second live
// watcher where low overhead matters more than finding every foreign owner.
func CollectLight() []model.Connection { return collect(false) }

func collect(withLSOF bool) []model.Connection {
	var out []model.Connection
	if sysutil.Available("ss") {
		// Separate TCP and UDP invocations keep the protocol unambiguous.
		// -n keeps numeric ports; service names would otherwise become port 0.
		if text, err := sysutil.RunStdout(6*time.Second, "ss", "-H", "-n", "-tap"); err == nil {
			out = append(out, parseSS(text, "tcp")...)
		}
		if text, err := sysutil.RunStdout(6*time.Second, "ss", "-H", "-n", "-uap"); err == nil {
			out = append(out, parseSS(text, "udp")...)
		}
	}
	// A non-iproute2 "ss" may print a header row or service names. Invalid
	// rows are dropped; if nothing usable remains, read the kernel tables.
	valid := out[:0]
	for _, c := range out {
		if c.LocalPort > 0 && c.State != "" && c.State != "State" {
			valid = append(valid, c)
		}
	}
	out = valid
	if len(out) == 0 {
		out = append(out, FromProc()...)
	}
	// lsof often sees sockets owned by other users when ss -p cannot.
	if withLSOF && sysutil.Available("lsof") {
		enrichWithLSOF(out)
	}
	dedupe(&out)
	return out
}

// Listening returns only sockets in LISTEN / UNCONN state.
func Listening(all []model.Connection) []model.Connection {
	var out []model.Connection
	for _, c := range all {
		if strings.EqualFold(c.State, "LISTEN") || strings.EqualFold(c.State, "UNCONN") {
			out = append(out, c)
		}
	}
	return out
}

func parseSS(text, defaultProto string) []model.Connection {
	var out []model.Connection
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		f := strings.Fields(line)
		if len(f) < 5 {
			continue
		}
		state := f[0]
		localHost, localPort := splitAddr(f[3])
		remoteHost, remotePort := splitAddr(f[4])
		proto := defaultProto
		if strings.HasPrefix(f[3], "[") || (strings.Count(f[3], ":") > 1 && !strings.HasPrefix(f[3], "0.0.0.0")) {
			proto += "6"
		}

		pid, fd, name := 0, "", ""
		if len(f) >= 6 {
			procField := strings.Join(f[5:], " ")
			if m := userRe.FindStringSubmatch(procField); len(m) == 4 {
				name = m[1]
				if n, err := strconv.Atoi(m[2]); err == nil {
					pid = n
				}
				fd = m[3]
			}
		}
		out = append(out, model.Connection{
			Protocol: proto, State: state,
			LocalAddr: localHost, LocalPort: localPort,
			RemoteAddr: remoteHost, RemotePort: remotePort,
			PID: pid, FD: fd, Process: name, Source: "ss", Raw: line,
		})
	}
	return out
}

// FromProc parses the kernel socket tables directly. It works even when ss is
// not installed; process attribution requires permission to read /proc/<pid>/fd.
func FromProc() []model.Connection {
	type spec struct {
		file  string
		proto string
	}
	specs := []spec{
		{"/proc/net/tcp", "tcp"}, {"/proc/net/tcp6", "tcp6"},
		{"/proc/net/udp", "udp"}, {"/proc/net/udp6", "udp6"},
	}
	var out []model.Connection
	owners := procinfo.InodeOwners()
	for _, sp := range specs {
		data, err := os.ReadFile(sp.file)
		if err != nil {
			continue
		}
		lines := strings.Split(string(data), "\n")
		for i, line := range lines {
			if i == 0 || strings.TrimSpace(line) == "" {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 10 {
				continue
			}
			lh, lp := procAddr(f[1])
			rh, rp := procAddr(f[2])
			state := tcpState(f[3])
			inode := f[9]
			pid := owners[inode]
			name := procinfo.NameForPID(pid)
			ppid := procinfo.ParentForPID(pid)
			out = append(out, model.Connection{
				Protocol: sp.proto, State: state,
				LocalAddr: lh, LocalPort: lp,
				RemoteAddr: rh, RemotePort: rp,
				PID: pid, PPID: ppid, Process: name,
				Inode: inode, Source: "/proc/net", Raw: line,
			})
		}
	}
	return out
}

func enrichWithLSOF(conns []model.Connection) {
	text, err := sysutil.RunStdout(8*time.Second, "lsof", "-nP", "-i")
	if err != nil || text == "" {
		return
	}
	type info struct {
		pid  int
		name string
		fd   string
	}
	byEndpoint := map[string]info{}
	for _, line := range strings.Split(text, "\n") {
		f := strings.Fields(line)
		if len(f) < 9 || f[0] == "COMMAND" {
			continue
		}
		pid, err := strconv.Atoi(f[1])
		if err != nil {
			continue
		}
		name := f[0]
		fd := strings.TrimSuffix(f[3], "u")
		node := f[7]
		addr := f[8]
		// (ESTABLISHED), (LISTEN), ...
		byEndpoint[node+"|"+addr] = info{pid, name, fd}
		byEndpoint[addr] = info{pid, name, fd}
	}
	for i := range conns {
		if conns[i].PID != 0 {
			continue
		}
		key := fmt.Sprintf("%s:%d->%s:%d",
			conns[i].LocalAddr, conns[i].LocalPort, conns[i].RemoteAddr, conns[i].RemotePort)
		if inf, ok := byEndpoint[key]; ok {
			conns[i].PID = inf.pid
			conns[i].Process = inf.name
			conns[i].FD = inf.fd
			conns[i].Source += "+lsof"
		}
	}
}

func dedupe(conns *[]model.Connection) {
	seen := make(map[string]bool, len(*conns))
	out := make([]model.Connection, 0, len(*conns))
	for _, c := range *conns {
		key := c.Protocol + "|" + c.State + "|" + c.LocalAddr + ":" + strconv.Itoa(c.LocalPort) + "|" +
			c.RemoteAddr + ":" + strconv.Itoa(c.RemotePort) + "|" + strconv.Itoa(c.PID)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, c)
	}
	*conns = out
}

func splitAddr(s string) (string, int) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		idx := strings.LastIndex(s, ":")
		if idx < 0 {
			return s, 0
		}
		host, portStr = s[:idx], s[idx+1:]
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		// Defensive: ss can print service names when -n is unavailable.
		if named, e := net.LookupPort("tcp", portStr); e == nil {
			port = named
		}
	}
	host = strings.Trim(host, "[]")
	if host == "*" || host == "" {
		host = "*"
	}
	return host, port
}

var tcpStates = map[string]string{
	"01": "ESTABLISHED", "02": "SYN-SENT", "03": "SYN-RECV", "04": "FIN-WAIT-1",
	"05": "FIN-WAIT-2", "06": "TIME-WAIT", "07": "CLOSE", "08": "CLOSE-WAIT",
	"09": "LAST-ACK", "0A": "LISTEN", "0B": "CLOSING", "0C": "NEW-SYN-RECV",
}

func tcpState(hexState string) string {
	if s, ok := tcpStates[strings.ToUpper(hexState)]; ok {
		return s
	}
	return "STATE-" + strings.ToUpper(hexState)
}

// procAddr decodes the host-byte-order hex address used by /proc/net/tcp and
// /proc/net/tcp6. Using NativeEndian keeps this correct on both little-endian
// (x86) and big-endian (s390x, some ARM) Linux systems.
func procAddr(s string) (string, int) {
	parts := strings.Split(s, ":")
	if len(parts) != 2 {
		return s, 0
	}
	port, _ := strconv.ParseUint(parts[1], 16, 16)
	raw, err := hex.DecodeString(parts[0])
	if err != nil {
		return s, int(port)
	}
	var ip net.IP
	switch len(raw) {
	case 4:
		v := binary.NativeEndian.Uint32(raw)
		ip = net.IPv4(byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
	case 16:
		ip = make(net.IP, 16)
		for i := 0; i < 4; i++ {
			v := binary.NativeEndian.Uint32(raw[i*4 : i*4+4])
			ip[i*4], ip[i*4+1], ip[i*4+2], ip[i*4+3] =
				byte(v>>24), byte(v>>16), byte(v>>8), byte(v)
		}
	default:
		return s, int(port)
	}
	return ip.String(), int(port)
}
