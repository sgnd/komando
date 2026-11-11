# Windows servers

Manage Windows servers next to your Linux ones: run PowerShell, read and
write files, copy files, and start and stop services. [All docs](README.md)

## Quick start

```bash
komando host add win1 Administrator@10.0.0.9 --os windows --ask-password
komando test win1                                   # can komando log in? is it an administrator?
komando facts win1                                  # Windows version, support, updates, ports
komando exec win1 --read-only -- Get-Service W3SVC  # simple read commands
komando svc restart win1 W3SVC --wait 10            # Windows services
komando fs cat win1 'C:\inetpub\wwwroot\web.config'
komando upload win1 ./site.zip 'C:\deploy\'
```

## Add a Windows server

komando reaches Windows over OpenSSH or WinRM. Both give the same
commands; pick WinRM when the server already has it on, for example for
Ansible.

### Over OpenSSH

OpenSSH is built into Windows Server 2019 and later. Turn it on once on
the server (as an administrator, in PowerShell):

```powershell
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
Start-Service sshd; Set-Service sshd -StartupType Automatic
```

Then add the server with `--os windows`. Everything else is as for Linux
servers: a key (`--key`), a password (`--ask-password` or
`--password-ref`), `--via` a bastion, `--protected`.

```bash
komando host add win1 Administrator@10.0.0.9 --os windows --ask-password
komando host add win4 deploy@corp.local@10.0.0.10 --os windows --key deploy --via bastion
komando host edit win3 --os windows        # a server you added before
```

A domain user is written `user@domain`, e.g.
`deploy@corp.local@10.0.0.10`.

### Over WinRM

Give the address as `winrm://USER@HOST` and a password. komando uses HTTPS
(port 5986), checks the server's certificate, and logs in with NTLM, which
never sends the password itself.

```bash
komando host add win2 winrm://Administrator@10.0.0.9 --ask-password
komando host add win3 'winrm://deploy@corp.local@win3.corp.local' --password-ref secret:win3 --via bastion
komando host edit win2 --address 'winrm://10.0.0.9?ca=secret:corp-ca'   # the server's certificate is from your own CA
```

Options go after `?`, joined with `&`:

| Option | Means |
|--------|-------|
| `ca=secret:NAME` | the certificate comes from your own CA: store its PEM with `komando secret set NAME < ca.crt` (the check stays on) |
| `auth=basic` | Basic login (local accounts only; HTTPS only) instead of NTLM |
| `tls=skip-verify` | do not check the certificate (komando warns: anyone in between can pose as the server) |
| `tls=off` | plain HTTP on port 5985: commands and output travel unencrypted, and the server must allow it |
| `:PORT` | another port than 5986 (5985 with `tls=off`) |

`--via` works: the connection goes through the bastion or VPN. WinRM
carries commands only, so `shell`, tunnels, `host trust` and `login` need
OpenSSH. To switch a server back to SSH: `komando host edit win2 --unset
transport`. Kerberos is not supported yet: use NTLM with a domain user.

On the server, `winrm quickconfig -transport:https` (as an administrator)
turns on WinRM over HTTPS.

### Pick Windows servers

To pick only Windows servers, or everything else, use `os:windows` and
`os:linux`:

```bash
komando facts os:windows
komando exec 'all,!os:windows' --read-only -- uptime
```

## Run PowerShell

On a Windows server, `exec` and `exec --script` run PowerShell (Windows
PowerShell, `powershell.exe`, which every Windows Server has).

```bash
komando exec win1 --read-only -- 'Get-Service | Where-Object Status -eq Running'
komando exec win1 -e APP_ENV=prod -C 'C:\app' -- '.\migrate.exe'
komando exec win1 --script ./deploy.ps1 --arg staging  # --arg values go to param( ) or $args
```

- The exit code works as in sh: `exit 3` gives 3, and a failed last command
  (an error, or a program that exited non-zero) makes it non-zero.
- `--read-only` accepts only simple read commands on Windows (see below).
- Input from `--stdin-file` is read with `[Console]::In.ReadToEnd()`.
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
komando exec win1 --read-only -- 'Get-Process | Sort-Object CPU -Descending | Select-Object -First 5'
komando exec win1 --read-only -- 'Get-Content C:\app\web.config -Tail 50'
komando exec win1 --read-only -- 'Get-WinEvent -LogName System -MaxEvents 20 | Format-List'
komando exec win1 --read-only -- 'Get-ItemProperty HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion'
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

```bash
komando fs ls win1 'C:\inetpub\logs' -r --max 200
komando fs stat win1 'C:\app\web.config' --sha256
komando fs cat win1 'C:\app\app.log' --tail 50
komando fs write win1 'C:\app\web.config' --from ./web.config --backup --if-changed
komando upload @windows ./tool.exe 'C:\tools\'
komando download win1 'C:\app\app.log' --to ./logs/
```

- `fs ls` leaves out hidden files unless `--all`.
- `fs write` writes a new file next to the old one, then swaps it in one
  step, so the file keeps its permissions (ACL). `--backup`, `-p`,
  `--append`, `--if-changed`, `--no-follow` and `--validate` work.
  `--validate` takes PowerShell, with `%s` for the new file, and runs in a
  PowerShell of its own: `--validate 'Test-Json (Get-Content %s -Raw)'`.
- `upload`, `download` and `cp` copy single files. Folders (`-r`), `--sudo`,
  `--mode` and `--owner` do not work on Windows yet.

## Services

```bash
komando svc list win1 --state running         # running, stopped, or --failed
komando svc status win1 W3SVC sshd
komando svc restart win1 W3SVC --wait 10      # fails unless it runs within 10s
komando svc enable win1 MyApp --now           # start automatically, and start now
```

The name is the service name (`W3SVC`) or its display name. `--failed`
lists services that should start automatically but stopped with an error.
`svc reload` has no Windows form.

## What works on Windows

| Works | Not yet (stops with `NOT_SUPPORTED`) |
|-------|--------------------------------------|
| `test`, `facts`, `exec`, `script`, `shell` | `pkg`, `user`, `cron`, `logs`, `docker`, `net`, `reboot` |
| `fs ls`, `stat`, `cat`, `write` | `fs replace`, `fs rm`, `mkdir`, `mv`, `chmod`, `sync` |
| `upload`, `download`, `cp` (single files) | `job`, `cp -r`, `svc reload` |
| `svc status`, `list`, `start`, `stop`, `restart`, `enable`, `disable` | `--sudo`, `--pty`, `--mode`, `--owner` |
| `host trust`, `login`, `tunnel`, `--via` through a Windows server (SSH only) | `shell`, tunnels, `host trust` over WinRM |

For the rest, run PowerShell with `exec`, for example
`Get-WinEvent -LogName System -MaxEvents 50` for logs, or
`Restart-Computer` (with `--allow-dangerous`) for a restart.

## Troubleshooting

- **`POWERSHELL_FAILED`**: komando could log in but PowerShell did not
  answer. Check that `powershell.exe` is on the login user's PATH.
- **`pending updates unknown`** in `facts`: Windows does not let many remote
  logins search Windows Update. The last installed update is still shown.
- **`WINRM_TLS`**: the server's certificate is not trusted. If it comes
  from your company's CA, add `?ca=secret:NAME` to the address (above).
- **`AUTH_FAILED` over WinRM**: check the user and password; Basic login
  works for local accounts only, and the user must be allowed to use WinRM
  (an administrator, or the Remote Management Users group).
- **A command works in your own PowerShell but not through komando**:
  komando runs PowerShell without your profile (`-NoProfile`), so aliases
  and modules from your profile are not there.
