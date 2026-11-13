package cli

import (
	"context"
	"path/filepath"
	"strings"
	"time"

	"github.com/sgnd/komando/internal/out"
	"github.com/sgnd/komando/internal/policy"
	"github.com/sgnd/komando/internal/sshx"
	"github.com/sgnd/komando/internal/store"
)

// Windows servers (docs/features/windows.md). A command that knows how to
// work on Windows marks its context with allowWindows before it reaches
// the servers; fanout and withClient refuse a Windows server to every
// other command, so no sh script is ever sent to PowerShell.

type windowsKey struct{}

// allowWindows marks ctx: the command handles Windows servers itself.
func allowWindows(ctx context.Context) context.Context {
	return context.WithValue(ctx, windowsKey{}, true)
}

func windowsAllowed(ctx context.Context) bool {
	ok, _ := ctx.Value(windowsKey{}).(bool)
	return ok
}

// windowsNames are the Windows servers among hosts.
func windowsNames(hosts []*store.Host) []string {
	var n []string
	for _, h := range hosts {
		if h.Windows() {
			n = append(n, h.Name)
		}
	}
	return n
}

// notOnWindows is the error for a command komando cannot run on Windows
// servers yet. what names the command ("pkg upgrade").
func notOnWindows(what string, names []string) *out.Error {
	return out.Errf(out.ExitUsage, "NOT_SUPPORTED",
		"run PowerShell with `komando exec "+names[0]+" -- ...` instead, or leave the Windows servers out of the target, for example TARGET,!os:windows ("+releaseSite+"/blob/main/docs/features/windows.md lists what works)",
		"%s does not work on Windows servers yet: %s", what, strings.Join(names, ", "))
}

// commandWord is a command's name as a person types it: "svc.start" is
// "svc start".
func commandWord(name string) string { return strings.ReplaceAll(name, ".", " ") }

// windowsGate lets a command reach the Windows servers among hosts when it
// supports them, and refuses it before anything runs when it does not.
func windowsGate(ctx context.Context, name string, hosts []*store.Host, supported bool) (context.Context, error) {
	names := windowsNames(hosts)
	if len(names) == 0 {
		return ctx, nil
	}
	if !supported {
		return ctx, notOnWindows(commandWord(name), names)
	}
	return allowWindows(ctx), nil
}

// refuseWindows is the guard of fanout and withClient: a Windows server
// is reached only by a command that marked its context.
func refuseWindows(ctx context.Context, h *store.Host) error {
	if h.Windows() && !windowsAllowed(ctx) {
		return notOnWindows("this command", []string{h.Name})
	}
	return nil
}

// sameOS refuses a target that picks Windows and other servers at once
// for a command written in one shell (exec, script).
func sameOS(hosts []*store.Host) (windows bool, err error) {
	names := windowsNames(hosts)
	if len(names) == 0 {
		return false, nil
	}
	if len(names) < len(hosts) {
		var others []string
		for _, h := range hosts {
			if !h.Windows() {
				others = append(others, h.Name)
			}
		}
		return true, out.Errf(out.ExitUsage, "MIXED_OS",
			"a command is written for one shell: run it twice, once with TARGET,os:windows (PowerShell) and once with TARGET,!os:windows (sh)",
			"the target picks Windows servers (%s) and other servers (%s)", strings.Join(names, ", "), strings.Join(others, ", "))
	}
	return true, nil
}

// targetWindows resolves target and says whether it is Windows servers
// only (true) or none (false); a mix is MIXED_OS.
func targetWindows(target string) (bool, error) {
	st, err := loadState()
	if err != nil {
		return false, err
	}
	hosts, err := resolveTargets(st, target)
	if err != nil {
		return false, nil // runFleet reports it
	}
	return sameOS(hosts)
}

// windowsRunCheck refuses what a Windows server cannot do in exec (and
// exec --script): there is no sudo and no terminal, and other commands that run
// through runFleet (logs, pkg, cron, fs rm ...) are sh scripts.
func windowsRunCheck(ctx context.Context, name string, hosts []*store.Host, o execOpts) (context.Context, error) {
	supported := name == "exec"
	ctx, err := windowsGate(ctx, name, hosts, supported)
	if err != nil || len(windowsNames(hosts)) == 0 {
		return ctx, err
	}
	if _, err := sameOS(hosts); err != nil {
		return ctx, err
	}
	switch {
	case o.sudo || o.sudoUser != "":
		return ctx, out.Errf(out.ExitUsage, "NOT_SUPPORTED", "Windows has no sudo: log in as a user with the rights the command needs (an administrator), for example `komando host edit "+hosts[0].Name+" --user Administrator`",
			"--sudo does not work on Windows servers")
	case o.pty:
		return ctx, out.Errf(out.ExitUsage, "NOT_SUPPORTED", "run it without --pty; for an interactive session a person uses `komando shell "+hosts[0].Name+"`",
			"--pty does not work on Windows servers: commands run in PowerShell without a terminal")
	}
	return ctx, nil
}

// psReadOnlyCheck is exec --read-only for PowerShell: it fails closed,
// refusing every command outside the small subset komando knows to only
// read (policy.PSReadOnly), and says whether a protected server still needs
// --yes (the command is not known to only read).
func psReadOnlyCheck(command string) (mutating bool, err error) {
	if why := policy.PSReadOnly(command); why != "" {
		return true, policyStop(out.Errf(out.ExitPolicy, "READ_ONLY_VIOLATION", "--read-only accepts only simple read commands on Windows; run it without --read-only so komando asks before it changes something",
			"--read-only on Windows, but komando cannot tell that the command only reads: %s", why))
	}
	return !policy.PSOnlyReads(command), nil
}

// osAttr is the selector value of a host's OS: os:windows, os:linux.
func osAttr(h *store.Host) string {
	if h.Windows() {
		return store.OSWindows
	}
	return "linux"
}

// psScriptCall runs a script file as a script block of its own, with the
// --arg values as its arguments: so param( ), [CmdletBinding()] and using
// come first in it, as PowerShell needs, and param( ) gets the values (the
// rest are $args). The block ends with its own trailer, as the file's last
// command decides the exit code; the line after it keeps the outer trailer
// from reading an error the script already handled.
func psScriptCall(body string, argv []string) string {
	var b strings.Builder
	b.WriteString("& ([scriptblock]::Create(" + sshx.PSQ(body+sshx.PSTrailer) + "))")
	for _, a := range argv {
		b.WriteString(" " + sshx.PSQ(a))
	}
	b.WriteString("\n$null = $null\n")
	return b.String()
}

// windowsScript is `komando exec --script` on Windows servers: the file is a
// PowerShell script, and --arg values are its arguments.
func windowsScript(ctx context.Context, target, file string, body []byte, interpreter string, argv []string, o execOpts, readOnly bool) error {
	if i := strings.ToLower(interpreter); i != "" && i != "powershell" && i != "pwsh" {
		return out.Errf(out.ExitUsage, "NOT_SUPPORTED", "on Windows servers a script is PowerShell: leave --interpreter out",
			"--interpreter %s does not work on Windows servers", interpreter)
	}
	if err := guardBody(string(body)); err != nil {
		return err
	}
	command := psScriptCall(string(body), argv)
	mutating := true
	if readOnly {
		var err error
		if mutating, err = psReadOnlyCheck(string(body)); err != nil {
			return err
		}
	}
	o.display = "script " + filepath.Base(file)
	return runFleet(ctx, "exec", target, command, nil, o, mutating)
}

// testWindowsHost is testHost for a Windows server: who komando logs in
// as, the computer's name, and whether the login is an administrator
// (Windows has no sudo).
func testWindowsHost(ctx context.Context, c *sshx.Client) (any, error) {
	t0 := time.Now()
	rr, err := sshx.Run(ctx, c, sshx.RunRequest{Command: `[Console]::Out.WriteLine([Security.Principal.WindowsIdentity]::GetCurrent().Name)
[Console]::Out.WriteLine($env:COMPUTERNAME)
$p = New-Object Security.Principal.WindowsPrincipal ([Security.Principal.WindowsIdentity]::GetCurrent())
[Console]::Out.WriteLine($p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))`, Timeout: 30 * time.Second, MaxOutput: 1 << 16})
	if err != nil {
		return nil, err
	}
	if rr.ExitCode != 0 {
		return nil, out.Errf(out.ExitRemote, "POWERSHELL_FAILED", "komando runs every command on Windows in Windows PowerShell (powershell.exe): check that it is on the PATH of the login user, and read the message",
			"the login check in PowerShell failed on %s (exit %d): %s", c.Host.Name, rr.ExitCode, dash(firstLine(rr.Stderr)))
	}
	o := rr.Stdout
	lines := strings.Split(strings.ReplaceAll(o, "\r", ""), "\n")
	r := testResult{OK: true, LatencyMS: time.Since(t0).Milliseconds(), OS: store.OSWindows, ServerVersion: windowsTransport(c)}
	if len(lines) >= 3 {
		r.RemoteUser, r.Hostname = lines[0], lines[1]
		b := strings.EqualFold(strings.TrimSpace(lines[2]), "true")
		r.Admin = &b
	}
	return r, nil
}

// windowsTransport names how komando reaches a Windows server.
func windowsTransport(c *sshx.Client) string {
	if c.Client != nil {
		return string(c.ServerVersion())
	}
	return "WinRM"
}
