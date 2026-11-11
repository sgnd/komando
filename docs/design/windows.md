# Design: Windows servers

Status: **built, 2026-11-10: Windows over SSH (OpenSSH) and over WinRM.**
How to use it: [docs/features/windows.md](../features/windows.md).

## Problem

Windows servers are reached two ways:

1. **OpenSSH**, built into Windows Server 2019 and later (an optional
   feature on 2016). komando's SSH code works as it is: keys, passwords,
   host keys, `--via` bastions, VPNs, `komando login`. But the remote
   shell is cmd.exe or PowerShell, not sh, so every command komando builds
   with sh syntax (`printf`, `[ -d ]`, `sudo`, `systemctl`) breaks.
2. **WinRM** (HTTP 5985, HTTPS 5986, NTLM, Basic or Kerberos), which most
   companies use for Ansible. It carries commands only: no SFTP, no
   tunnels. komando speaks it itself (see [WinRM](#winrm)).

## Decisions

### How a host is marked as Windows

`host add` and `host edit` take `--os windows` (and `--os linux`, the
default, to undo it). The host gets `"os": "windows"` in the inventory.

```bash
komando host add win1 Administrator@10.0.0.9 --os windows --ask-password
```

komando does not guess the OS from the server: a guess would need a
command, and the first command is the one that must already be right.

`os:windows` and `os:linux` are new selectors, so `all,!os:windows` picks
everything else.

### One shell: PowerShell

Every command on a Windows server runs in Windows PowerShell
(`powershell.exe`, present on every Windows Server). The command line is
always the same short bootstrap, given with `-EncodedCommand`; the script
itself is the first line of the command's input (base64), followed by the
values of secret environment variables, then the caller's own input:

- the script is never on a command line: cmd.exe cuts command lines at
  8191 characters, and other users can read command lines;
- quoting is only ever PowerShell's: `sshx.PSQ` puts a value in single
  quotes and doubles every quote, including the typographic ones (U+2018
  to U+201B) that PowerShell also reads as quotes. A value can never end
  the string early, so it cannot run code;
- env values from the vault are sent on the input, as on Linux, and read
  with `[Console]::In.ReadLine()`.

Exit codes work like sh: `exit N` gives N, a failed last command (a
cmdlet error or a program that exited non-zero) gives its code or 1, and
an uncaught `throw` gives 1. An error inside one statement does not stop
the script, as in any PowerShell script. Windows PowerShell writes its
errors as CLIXML when its output is not a console; komando turns them back
into text (`sshx.CleanPSError`).

There is no sudo on Windows: `--sudo` and `--pty` are refused. The
login's own rights apply, so log in as a user with the rights the work
needs.

### What works in the first version

| Command | On Windows |
|---------|-----------|
| `test` | logs in, says the user, the computer name and whether the login is an administrator |
| `exec`, `exec --script` | run PowerShell; `--read-only`, `--env`, `--dir`, `--stdin-file` work |
| `facts` | OS, build, support dates (Windows Server 2012 to 2025), CPU, memory, disk C:, uptime, IPs, pending and security updates (from the Windows Update cache), last hotfix, pending reboot, stopped automatic services, listening ports |
| `fs ls`, `stat`, `cat`, `write` | through PowerShell (WinRM has no SFTP); `fs write` keeps `--backup`, `-p`, `--append`, `--if-changed`, `--validate`, `--no-follow`, and replaces the file in one step (keeping its permissions) |
| `upload`, `download`, `cp` | single files, as base64 lines on the input and output |
| `svc status`, `list`, `start`, `stop`, `restart`, `enable`, `disable` | Windows services |
| `shell` | over SSH, the server's own shell |
| `host trust`, `login`, `tunnel`, `--via` through a Windows server | SSH as usual |

Everything else stops before it runs with `NOT_SUPPORTED` (exit 2) and a
hint: `pkg`, `user`, `cron`, `logs`, `docker`, `job`, `net`, `reboot`,
`fs replace`, `fs rm/mkdir/mv/chmod`, `sync`, folders in `cp -r`,
`--sudo`, `--mode`, `--owner`, `svc reload`. The guard sits in `fanout`
and `withClient`: a Windows server is reached only by a command that marks
its context with `allowWindows`, so a sh script is never sent to
PowerShell, whatever new command comes later.

A command for one shell (`exec`, `exec --script`) refuses a target that picks
Windows and Linux servers at once (`MIXED_OS`). Commands komando writes
itself (`facts`, `svc`, `test`, file commands) work on a mix: each server
gets its own script.

### Safety

The same rules apply, in PowerShell's words:

- **Deny rules** (`internal/policy/windows.go`), case-insensitive and also
  read without PowerShell's backtick escapes: a recursive delete of the
  system drive or a system folder (`Remove-Item -Recurse C:\`, `rd /s
  C:\Windows`), formatting or wiping disks (`Format-Volume`, `Clear-Disk`,
  `diskpart`), `Stop-Computer`, `Restart-Computer`, `shutdown /r`,
  stopping SSH or WinRM (`Stop-Service sshd`, `Disable-PSRemoting`),
  blocking all incoming traffic, deleting users, `powershell -enc`,
  `iwr ... | iex`, deleting shadow copies and boot settings, deleting a
  registry hive. They need `--allow-dangerous`.
- **`--read-only`** (`internal/policy/powershell.go`) fails closed: a
  command passes only when every part of it is in a small subset komando
  reads the same way PowerShell does. Statements (`;` or a new line) are
  pipelines of cmdlets from an explicit list (`psReadCommands`, not all of
  `Get-*`: `Get-Certificate` enrolls a certificate) or a few programs with
  the arguments that read (`psNatives`). Arguments are literals: plain
  ASCII barewords, `'...'` or `"..."` without `$`, full parameter names
  from `psSafeParams`, commas. The only script blocks are `Where-Object {
  $_.Prop -op value }` and `ForEach-Object { $_.Prop }`. Everything else
  is refused: any `$`, backtick, `@`, `&`, `>`, comment, `( )`, `[ ]`,
  keyword, alias or parameter not on the lists, `\\server` paths and
  characters outside plain ASCII. A denylist over a hand-written tokenizer
  kept leaking where PowerShell reads a script differently. What passes
  only reads, so a protected server skips `--yes` for it.
- Protected hosts, the audit log, secret masking in output, `--dry-run`
  and the approval window are the same code as for Linux servers.

### Not verified on real Windows

The tests run komando's PowerShell for real against PowerShell 7 in a
Linux container (`internal/cli/windows_pwsh_test.go`, opt-in), and every
script is parsed by PowerShell. That checks the bootstrap, quoting, exit
codes and the file scripts. Windows PowerShell 5.1 itself, Windows
OpenSSH, WinRM with NTLM, services, CIM, Windows Update and the registry
were not run on a real Windows server.

## WinRM

`internal/winrm` is komando's own WinRM client: WS-Management SOAP over
`net/http` and `encoding/xml` (Create a shell, Command, Send the input,
Receive the output until the command is Done, Signal and Delete). It runs
the same PowerShell bootstrap as SSH, so every Windows command above works
the same way over both. NTLM comes from `github.com/Azure/go-ntlmssp`
(MIT, only `golang.org/x/crypto` under it); no other library is needed.
`masterzen/winrm` (Apache-2.0) was looked at and left out: it brings
several more modules (Kerberos, XPath, UUID) for what is about 400 lines.

- **Address**: `winrm://USER@HOST[:PORT]`, options in the query like conn
  URLs: `auth=basic` (default NTLM, which never sends the password),
  `tls=skip-verify` (no certificate check), `tls=off` (plain HTTP, port
  5985), `ca=secret:NAME` (the PEM of a private CA; the check stays on).
  The host gets `"transport": "winrm"` and a `winrm` block; `os` is
  `windows`. `host edit --unset transport` goes back to SSH.
- **TLS** is checked by default against this computer's CAs (and the CA
  from `ca=`), with TLS 1.2 or later; port 5986.
- **Password** from `--password-ref` (or `--ask-password`); WinRM has no key
  login, so `--key` and `--identity` are refused.
- **Refused**: Basic over plain HTTP (the password would travel in clear,
  `INSECURE_PROTOCOL`). NTLM over plain HTTP is allowed with a warning:
  komando does not encrypt WinRM messages itself, so the server must allow
  unencrypted traffic, and commands and output are readable on the way.
- **`--via`**: the HTTPS connection goes through the VPN or the SSH
  bastions of the path, like a tunnel (the last bastion opens the TCP
  connection). A WinRM server cannot be a jump host itself.
- **Commands only**: `shell`, tunnels, `host trust`, `login` and
  `host ssh-command` need SSH and stop with `NOT_SUPPORTED`
  (`sshx.Options.WinRM` is set only by the commands that run PowerShell).
- **Not in this version**: Kerberos, CredSSP, NTLM message encryption over
  HTTP, client certificates.

Tests: the client against an `httptest` WS-Management server (HTTPS with a
private CA, an unknown CA, skip-verify, a wrong password, SOAP faults, the
Receive timeout fault, cancelling a command, NTLM offered and the password
never sent), and `exec`/`test` through it end to end. NTLM against a real
Windows server was not run.
