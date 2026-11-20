package extlogs

import "testing"

func TestClassify(t *testing.T) {
	cases := []struct{ msg, want string }{
		{"Failed password for invalid user admin from 10.0.0.1", "ALERT"},
		{"session opened for user ollama", "NOTICE"},
		{"unrelated informational line", "INFO"},
	}
	for _, c := range cases {
		got := classify(c.msg, "auth.log").Severity
		if got != c.want {
			t.Errorf("classify(%q) = %s, want %s", c.msg, got, c.want)
		}
	}
}

func TestParseSyslogLine(t *testing.T) {
	_, msg := parseSyslogLine("Nov 20 12:34:56 mxhost sshd[123]: Accepted password for user")
	if msg == "" {
		t.Fatal("empty parsed message")
	}
}
