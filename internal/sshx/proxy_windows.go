package sshx

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
)

// proxyQuote quotes a ProxyCommand value for cmd.exe.
func proxyQuote(v string) (string, error) { return quoteCmd(v) }

// proxyCommand runs a ProxyCommand line with cmd.exe, the shell a Windows
// user writes it for: /d skips AutoRun commands, /v:off keeps !NAME! as
// text, and /s /c "LINE" runs LINE as typed. The command line is given
// whole, since Go's quoting of arguments is not the one cmd.exe reads.
func proxyCommand(line string) *exec.Cmd {
	shell := os.Getenv("ComSpec")
	if shell == "" {
		shell = filepath.Join(os.Getenv("SystemRoot"), "System32", "cmd.exe")
	}
	c := exec.Command(shell)
	c.SysProcAttr = &syscall.SysProcAttr{CmdLine: `"` + shell + `" /d /v:off /s /c "` + line + `"`}
	return c
}
