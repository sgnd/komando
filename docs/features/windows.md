# Windows servers

Manage Windows servers next to your Linux ones: run PowerShell, copy
files, and start and stop services. [All docs](README.md)

This page is about Windows servers that komando manages. To run komando
itself on a Windows computer, see [Install on Windows](install.md#install-on-windows).

## Add a Windows server

```bash
komando credential password add win-admin --user Administrator   # the password is typed hidden
komando host ssh add win1 10.0.0.9 --os windows --credential win-admin
komando test win1                                   # can komando log in? is it an administrator?
komando host ssh exec win1 --read-only -- 'Get-ComputerInfo | Select-Object OsName, OsVersion'   # what the server is
```

Typed alone at your terminal, `komando host ssh add` (or `komando host
winrm add`) asks for each part.

komando reaches Windows over OpenSSH (`host ssh`) or WinRM (`host winrm`).
Pick WinRM when the server already has it on, for example for Ansible.
WinRM carries commands only (see [Over WinRM](#over-winrm)).

### Over OpenSSH

OpenSSH is built into Windows Server 2019 and later. Turn it on once on
the server (as an administrator, in PowerShell):

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service sshd -StartupType Automatic
```

Then add the server with `--os windows`. Everything else is as for Linux
servers: a credential that holds a key or a password (`--credential`),
`--via` a bastion, `--protected`.

```bash
komando credential key create win-deploy --user deploy@corp.local
komando host ssh add win3 10.0.0.10 --os windows --credential win-deploy --via bastion
komando host ssh edit win3 --os windows    # a server you added before
```

A domain user is written `user@domain`, for example `deploy@corp.local`,
in the credential's `--user`.

### Over WinRM

Give the address as `winrm://USER@HOST` and a credential that holds the
password. komando uses HTTPS (port 5986), checks the server's certificate,
and logs in with NTLM, which never sends the password itself.

```bash
komando host winrm add win2 winrm://Administrator@10.0.0.9 --credential win-admin
komando host winrm add win3 'winrm://deploy@corp.local@win3.corp.local' --credential win3-pass --via bastion
komando host winrm edit win2 --address 'winrm://10.0.0.9?ca=credential:corp-ca'   # the server's certificate is from your own CA
```

TODO(cut): `host winrm exec` ships only when its Windows session meets the
same promises as `host ssh exec` (S-10.4); it waits on row C359. The
commands below that name `host winrm` are the planned form until then.

Options go after `?`, joined with `&`:

| Option | Means |
|--------|-------|
| `ca=credential:NAME` | the certificate comes from your own CA: store its PEM as a credential (the check stays on) |
| `auth=basic` | Basic login (local accounts only) instead of NTLM; over plain HTTP (`tls=off`) it is refused (`WINRM_INSECURE`) |
| `tls=skip-verify` | do not check the certificate (komando warns: anyone in between can pose as the server) |
| `tls=off` | plain HTTP on port 5985: commands and output travel unencrypted, and the server must allow it |
| `:PORT` | another port than 5986 (5985 with `tls=off`) |

TODO(cut): how a CA's PEM is stored as a credential, and the typed flags
that replace these URL options, wait on O-09 and the `host winrm` leaf
options (PR B).

`auth=basic`, `tls=skip-verify` and `tls=off` give up a protection of the
password or of the server check, so an AI agent that sets one (with `host
winrm add`, `host winrm edit --address` or `import`) needs your yes in komando's
window (`SAFETY_SETTING` without it). A server that has the setting
already asks nothing again.

`--via` works: the connection goes through the bastion or VPN. WinRM
carries commands only, so `shell`, tunnels and `host ssh trust` need
OpenSSH. To switch a server to SSH, remove it (`komando host winrm remove
win2`) and add it again with `komando host ssh add`. Use NTLM with a domain user,
over HTTPS (see [Limits](#limits) for what WinRM does not do).

On the server, `winrm quickconfig -transport:https` (as an administrator)
turns on WinRM over HTTPS.

### Pick Windows servers

To pick only Windows servers, or everything else, use `os:windows` and
`os:linux`:

```bash
komando host ssh exec os:windows --read-only -- 'Get-Uptime'
komando host ssh exec 'all,!os:windows' --read-only -- uptime
```

## Run PowerShell

On a Windows server, `host ssh exec` and `host ssh exec --script` run PowerShell (Windows
PowerShell, `powershell.exe`, which every Windows Server has).

```bash
komando host ssh exec win1 --read-only -- 'Get-Service | Where-Object Status -eq Running'
```

```bash
komando host ssh exec win1 -e APP_ENV=prod -C 'C:\app' -- '.\migrate.exe'
komando host ssh exec win1 --script ./deploy.ps1 --arg staging  # --arg values go to param( ) or $args
```

- The exit code works as in sh: `exit 3` gives 3, and a failed last command
  (an error, or a program that exited non-zero) makes it non-zero.
- `--read-only` accepts only simple read commands on Windows (see below).
- Input from `--stdin-file` is read with `[Console]::In.ReadToEnd()`.
- A long run: `exec` prints a session ID, and `komando host ssh exec win1
  --attach ID` comes back to it. TODO(cut): how that session works on a
  Windows server (folder, log, `--stop`, `--remove`) waits on row C359.
- Windows has no sudo: `--sudo` and `--pty` are refused. Log in as a user
  with the rights the work needs (an administrator for services).
- One command is written for one shell, so a target that picks Windows and
  Linux servers at once is refused (`MIXED_OS`). Run it twice, with
  `TARGET,os:windows` and `TARGET,!os:windows`.

### `--read-only` on Windows

`--read-only` on a Windows server fails closed: komando accepts only a
small part of PowerShell that it reads exactly as PowerShell does, and
refuses everything else, even a command that would only read. A command
it accepts never changes anything, so a protected server does not ask for
`--yes`.

What it accepts:

- Commands from a fixed list, joined with `|` and separated by `;` or new
  lines:
  - files and the registry: `Get-ChildItem`, `Get-Item`,
    `Get-ItemProperty`, `Get-ItemPropertyValue`, `Get-Content`,
    `Get-Location`, `Get-PSDrive`, `Get-PSProvider`, `Get-Acl`,
    `Get-FileHash`, `Test-Path`, `Select-String`, `Set-Location`,
    `Push-Location`, `Pop-Location`;
  - the system: `Get-Process`, `Get-Service`, `Get-EventLog`,
    `Get-WinEvent`, `Get-HotFix`, `Get-ComputerInfo`, `Get-Date`,
    `Get-TimeZone`, `Get-Culture`, `Get-Uptime`, `Get-Counter`,
    `Get-CimInstance`, `Get-CimClass`, `Get-WmiObject`,
    `Get-ScheduledTask`, `Get-ScheduledTaskInfo`, `Get-WindowsFeature`,
    `Get-LocalUser`, `Get-LocalGroup`, `Get-LocalGroupMember`, `Get-Disk`,
    `Get-Volume`, `Get-Partition`, `Get-PhysicalDisk`, `Get-SmbShare`,
    `Get-Website`, `Get-WebBinding`, `Get-IISSite`, `Get-IISAppPool`;
  - the network: `Get-NetTCPConnection`, `Get-NetUDPEndpoint`,
    `Get-NetIPAddress`, `Get-NetIPConfiguration`, `Get-NetAdapter`,
    `Get-NetRoute`, `Get-NetFirewallRule`, `Get-NetFirewallProfile`,
    `Get-DnsClientServerAddress`, `Get-DnsClientCache`, `Resolve-DnsName`,
    `Test-Connection`, `Test-NetConnection`;
  - PowerShell itself: `Get-Command`, `Get-Member`, `Get-Alias`,
    `Get-Module`, `Get-ExecutionPolicy`, `Get-Host`, `Get-History`;
  - shaping the output: `Select-Object`, `Where-Object`, `ForEach-Object`,
    `Sort-Object`, `Group-Object`, `Measure-Object`, `Get-Unique`,
    `Format-Table`, `Format-List`, `Format-Wide`, `Out-String`, `Out-Host`,
    `Out-Null`, `ConvertTo-Json`, `ConvertTo-Csv`, `Write-Output`,
    `Write-Host`;
  - their usual aliases (`gci`, `ls`, `dir`, `gc`, `cat`, `gsv`, `gps`,
    `select`, `where`, `?`, `%`, `sort`, `ft`, `fl`, ...);
  - `hostname`, `quser`, and `whoami`, `ipconfig`, `systeminfo`,
    `tasklist`, `netstat` with the switches that only show something
    (`ipconfig /all`, `netstat -ano`, `whoami /groups`).
- Arguments that are plain values: words such as `C:\inetpub`, `W3SVC`,
  `*.log` or `50`; `'...'` and `"..."` strings with no `$` inside; commas
  between values (`Select-Object Name, Status`); parameters written in
  full from a list of safe ones (`-Recurse`, `-Tail`, `-First`,
  `-Property`, `-LogName`, `-Filter`, `-Force`, `-eq`, ...).
- Two kinds of script block: `Where-Object { $_.Status -eq 'Running' }`
  (properties of `$_` compared with a value, joined with `-and` or `-or`)
  and `ForEach-Object { $_.Name }`.

```bash
komando host ssh exec win1 --read-only -- 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5'
komando host ssh exec win1 --read-only -- 'Get-Content C:\app\web.config -Tail 50'
komando host ssh exec win1 --read-only -- 'Get-WinEvent -LogName System -MaxEvents 20 | Format-List'
komando host ssh exec win1 --read-only -- 'Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'
```

What it refuses (`READ_ONLY_VIOLATION`, with the reason): any `$`
(variables, `$( )`), backtick, `@` (here-strings, splatting), `&`,
redirection (`>`, `2>$null`), comments, `( )`, `[ ]` and .NET calls,
`=`, keywords (`if`, `foreach`, `exit`), `.\script.ps1` and programs by
path, commands, aliases and parameters not on the lists (also shortened
parameter names, `-Name:value`, `-ComputerName`, `-Credential`,
`-ScriptBlock`), `ForEach-Object Name` (a name may call a method), paths
to another computer (`\\server\share`), and any character outside plain
ASCII (typographic quotes and dashes).

When a command is refused, run it without `--read-only`: komando then
treats it as a change, so a protected server asks before it runs.

The safety rules have Windows forms: `Remove-Item -Recurse C:\`,
`Format-Volume`, `Stop-Computer`, `Restart-Computer`, `Stop-Service sshd`
(or WinRM) and more need `--allow-dangerous`, as `rm -rf /` does.

## Files

Paths are Windows paths: `C:\inetpub\app.config` or `C:/inetpub/app.config`.
`~` and an empty path are the login user's profile folder. Put a path with
backslashes in single quotes in your shell.

There is no file command. Read and edit with PowerShell through `exec`:

```bash
komando host ssh exec win1 --read-only -- 'Get-ChildItem C:\inetpub\logs -Recurse'
komando host ssh exec win1 --read-only -- 'Get-FileHash C:\app\web.config'
komando host ssh exec win1 --read-only -- 'Get-Content C:\app\app.log -Tail 50'
komando host ssh exec win1 -- 'Copy-Item C:\app\web.config C:\app\web.config.bak'
```

Before you change a file, copy it (the last line above), change it with
one targeted command, then read it back. Lost: komando no longer
validates, backs up or undoes a file edit for you. To undo, copy the
`.bak` back with `Copy-Item`.

The Windows safety rules above still stop the dangerous forms. TODO(cut): whether a
Windows form of the `rm-files` rule (deleting files) exists waits on the
C323 rules list.

Copy files with `komando copy`:

```bash
komando copy ./tool.exe 'win1:C:\tools\'
komando copy 'win1:C:\app\app.log' ./logs/
```

- `copy` moves single files. Folders (`-r`), `--sync`, `--sudo`, `--mode`
  and `--owner` do not work on Windows yet.
- TODO(cut): `copy` to and from a WinRM server waits on O-43.

## Services

Services are PowerShell too. The name is the service name (`W3SVC`) or its
display name.

```bash
komando host ssh exec win1 --read-only -- 'Get-Service | Where-Object Status -eq Running'
komando host ssh exec win1 --read-only -- 'Get-Service W3SVC, sshd'
komando host ssh exec win1 -- 'Restart-Service W3SVC'
komando host ssh exec win1 -- 'Set-Service MyApp -StartupType Automatic; Start-Service MyApp'
```

Stopping or disabling `sshd` or WinRM (`Stop-Service`, `Set-Service
-StartupType Disabled`) needs `--allow-dangerous`: it locks you out.
Restarting the computer needs it too:

```bash
komando host ssh exec win1 --dry-run -- 'Restart-Computer'
```

Lost: komando no longer reboots several servers one at a time and checks
each boot ID. Reboot them one by one, and check that each came back with
`komando test NAME`.

## What works on Windows

| Works | Not yet |
|-------|--------------------------------------|
| `test`, `host ssh exec` (also `--script`, `--attach`), `host ssh shell` | `--sudo`, `--pty` |
| PowerShell through `exec` for files, services, logs, users, packages and the network | `copy` of folders (`-r`), `--sync`, `--mode`, `--owner` |
| `copy` of single files | `host winrm exec` (when it ships) |
| `host ssh trust`, `host ssh tunnel`, `--via` through a Windows server (SSH only) | `shell`, tunnels, `host ssh trust` over WinRM |

A copy option that is not there yet stops with `NOT_SUPPORTED` before
anything runs. For everything else, run PowerShell with `exec`, for example
`Get-WinEvent -LogName System -MaxEvents 50` for logs, or
`Restart-Computer` (with `--allow-dangerous`) for a restart.

## Limits

- komando's PowerShell scripts are tested with PowerShell 7 on Linux, not
  on a real Windows server: Windows PowerShell 5.1, Windows OpenSSH, WinRM
  with NTLM, services and Windows Update have not been run there. Please
  report anything that does not work.
- WinRM logs in with a password only: a credential that holds a key and
  `--proxy-command` are refused. Use `--via` to go through a bastion.
- Kerberos, CredSSP, client certificates and WinRM's own message encryption
  over plain HTTP are not supported.
- WinRM carries commands only: `shell`, tunnels and `host ssh trust` need
  OpenSSH.
- Windows has no sudo: `--sudo` and `--pty` are refused.
- A target that picks Windows and other servers at once is refused for
  `exec` (`MIXED_OS`).
- `--read-only` accepts only the small part of PowerShell listed above.
- komando runs PowerShell without your profile (`-NoProfile`).

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `NOT_SUPPORTED` | the command or option does not work on Windows servers yet | run PowerShell with `komando host ssh exec SERVER -- ...`, or leave them out: `TARGET,!os:windows` |
| `MIXED_OS` | the target picks Windows and other servers | run it twice, with `TARGET,os:windows` and `TARGET,!os:windows` |
| `READ_ONLY_VIOLATION` | the PowerShell is not in the small part `--read-only` accepts | drop `--read-only`; a protected server then asks first |
| `POWERSHELL_FAILED` | komando could log in but PowerShell did not answer | check that `powershell.exe` is on the login user's PATH |
| `WINRM_TLS` | the server's WinRM certificate is not trusted | from your company's CA: add `?ca=credential:NAME` to the address |
| `WINRM_INSECURE` | Basic login over plain HTTP would send the password unencrypted | use HTTPS, or NTLM (leave `auth=basic` out) |
| `AUTH_FAILED` over WinRM | wrong user or password, or the user may not use WinRM | check them; Basic login works for local accounts only, and the user must be an administrator or in Remote Management Users |

- **Pending updates are unknown**: Windows does not let many remote logins
  search Windows Update. `Get-HotFix` still shows the last installed update.
- **A command works in your own PowerShell but not through komando**:
  komando runs PowerShell without your profile (`-NoProfile`), so aliases
  and modules from your profile are not there.
