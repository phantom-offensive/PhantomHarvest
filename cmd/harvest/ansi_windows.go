//go:build windows

package main

import (
	"golang.org/x/sys/windows"
)

// init flips ENABLE_VIRTUAL_TERMINAL_PROCESSING on the console's stdout
// and stderr handles so the ANSI escape sequences we emit (colours + box
// drawing) are interpreted by the terminal instead of printed as the
// literal bytes `←[2m` etc. This is needed for legacy cmd.exe and older
// PowerShell hosts; Windows Terminal / recent PowerShell already enable
// the bit, and the call is harmless there.
//
// We ignore errors — if we can't set the mode (e.g. stdout is
// redirected to a file) the user wanted plain output anyway.
func init() {
	enableVT(windows.Stdout)
	enableVT(windows.Stderr)
}

func enableVT(h windows.Handle) {
	var mode uint32
	if err := windows.GetConsoleMode(h, &mode); err != nil {
		return
	}
	windows.SetConsoleMode(h, mode|windows.ENABLE_VIRTUAL_TERMINAL_PROCESSING)
}
