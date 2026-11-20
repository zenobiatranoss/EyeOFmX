//go:build !linux || !cgo

package sysutil

import (
	"os"
	"os/exec"
	"strconv"
	"strings"
)

// ClockTicks is the portable fallback when cgo is unavailable. GTK itself
// requires cgo, so this is only a safety net for non-GUI tool builds.
func ClockTicks() float64 {
	if n, err := strconv.ParseFloat(os.Getenv("CLK_TCK"), 64); err == nil && n > 0 {
		return n
	}
	if n, err := strconv.ParseFloat(strings.TrimSpace(mustGetconf()), 64); err == nil && n > 0 {
		return n
	}
	return 100
}

func mustGetconf() string {
	out, err := exec.Command("getconf", "CLK_TCK").Output()
	if err != nil {
		return ""
	}
	return string(out)
}
