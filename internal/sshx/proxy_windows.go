package sshx

import (
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

// proxyQuote quotes a ProxyCommand value for cmd.exe.
func proxyQuote(v string) (string, error) { return quoteCmd(v) }

// proxyCommand runs a ProxyCommand line with cmd.exe, the shell a Windows
// user writes it for: /d skips AutoRun commands, /v:off keeps !NAME! as
// text, and /s /c "LINE" runs LINE as typed. The command line is given
// whole, since Go's quoting of arguments is not the one cmd.exe reads.
// cmd.exe is the one in the Windows folder as Windows names it, never
// ComSpec or SystemRoot from the environment, which the caller sets.
func proxyCommand(line string) *exec.Cmd {
	shell := proxyShell()
	c := exec.Command(shell)
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: `"` + shell + `" /d /v:off /s /c "` + line + `"`}
	return c
}

// proxyShell is cmd.exe in the Windows folder Windows itself names.
func proxyShell() string {
	dir, err := windows.GetSystemDirectory()
	if err != nil || dir == "" {
		dir = `C:\Windows\System32` // Windows always answers; never the environment
	}
	return filepath.Join(dir, "cmd.exe")
}
