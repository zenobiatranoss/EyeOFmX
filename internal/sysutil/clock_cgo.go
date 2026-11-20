//go:build linux && cgo

package sysutil

/*
#include <unistd.h>
*/
import "C"

import (
	"os"
	"strconv"
)

// ClockTicks returns the kernel USER_HZ value used by /proc/<pid>/stat. Using
// sysconf avoids depending on the getconf binary (absent on minimal musl
// images) and is correct on architectures where USER_HZ is not 100.
func ClockTicks() float64 {
	if n, err := strconv.ParseFloat(os.Getenv("CLK_TCK"), 64); err == nil && n > 0 {
		return n
	}
	if n := C.sysconf(C._SC_CLK_TCK); n > 0 {
		return float64(n)
	}
	return 100
}
