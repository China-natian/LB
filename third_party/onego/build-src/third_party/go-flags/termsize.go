//go:build !windows && !plan9 && !appengine && !wasm && !aix
// +build !windows,!plan9,!appengine,!wasm,!aix

package flags

import (
	"golang.org/x/sys/unix"
)

func getTerminalColumns() int {
	// onego patch: upstream only probes stdin (fd 0) and falls back to 80
	// columns when stdin is not a tty (e.g. piped or detached). Probe
	// stdout/stderr as well so help keeps the real terminal width.
	for _, fd := range []int{0, 1, 2} {
		ws, err := unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
		if err == nil {
			return int(ws.Col)
		}
	}
	return 80
}
