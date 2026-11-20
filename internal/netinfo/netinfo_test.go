package netinfo

import (
	"strings"
	"testing"
)

func TestParseSS(t *testing.T) {
	text := `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=681,fd=3))
ESTAB 0 0 192.168.1.10:43210 1.2.3.4:443 users:(("firefox",pid=1234,fd=88))`
	conns := parseSS(text, "tcp")
	if len(conns) != 2 {
		t.Fatalf("got %d connections, want 2", len(conns))
	}
	if conns[0].State != "LISTEN" || conns[0].LocalPort != 22 || conns[0].PID != 681 {
		t.Errorf("bad first row: %+v", conns[0])
	}
	if conns[1].RemoteAddr != "1.2.3.4" || conns[1].RemotePort != 443 || conns[1].Process != "firefox" {
		t.Errorf("bad second row: %+v", conns[1])
	}
	if conns[0].Protocol != "tcp" || conns[1].Protocol != "tcp" {
		t.Errorf("protocol mismatch: %+v", conns)
	}
}

func TestSplitAddr(t *testing.T) {
	host, port := splitAddr("[::1]:443")
	if host != "::1" || port != 443 {
		t.Errorf("got %s:%d, want ::1:443", host, port)
	}
	host, port = splitAddr("*:80")
	if host != "*" || port != 80 {
		t.Errorf("got %s:%d, want *:80", host, port)
	}
}

func TestProcAddr(t *testing.T) {
	host, port := procAddr("0100007F:1F90")
	if host != "127.0.0.1" || port != 8080 {
		t.Errorf("got %s:%d, want 127.0.0.1:8080", host, port)
	}
	if !strings.Contains(tcpState("0A"), "LISTEN") {
		t.Errorf("state 0A = %q", tcpState("0A"))
	}
}
