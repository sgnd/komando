//go:build !windows

package sshx

import "os/exec"

// proxyQuote quotes a ProxyCommand value for sh.
func proxyQuote(v string) (string, error) { return Q(v), nil }

// proxyCommand runs a ProxyCommand line with sh, like OpenSSH.
func proxyCommand(line string) *exec.Cmd { return exec.Command("/bin/sh", "-c", line) }
