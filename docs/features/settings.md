# Settings and files

Change komando's settings, and find out where it keeps its data.
[All features](README.md)

## Quick start

```bash
komando config show                          # every setting: KEY VALUE DEFAULT ALLOWED, and file locations
komando config get parallel
komando config set parallel 20
komando config set default_timeout 10m
komando doctor                               # check the setup, the inventory and its security
```

## Settings

| Key | What it controls | Values | Default |
|-----|------------------|--------|---------|
| `host_key_policy` | what happens with a server komando has not seen before | `accept-new` (remember it), `strict` (refuse it), `off` (needs `--yes`) | `accept-new` |
| `default_user` | login name when a server has none | a login name; empty = your own user name | (empty) |
| `default_timeout` | how long a command may run on each server | a duration above 0 (`30s`, `5m`, `1h`) | `5m` |
| `connect_timeout` | how long to wait for a server to answer | a duration above 0 | `15s` |
| `parallel` | how many servers to work on at once | 1 or more | `10` |
| `max_output_bytes` | output kept per stream per server | 1024 or more | `262144` (256 KiB) |
| `audit` | keep the audit log | `on`, `off` (needs `--yes`) | `on` |
| `audit_sql` | how SQL text is kept in the audit log | `full`, `hash`, `off` (needs `--yes`) | `full` |
| `audit_syslog` | also send each audit record to a log server (a SIEM) | `udp://HOST:514`, `tcp://HOST:514`, `tls://HOST:6514`, `off` (changing it needs `--yes`) | `off` |
| `vpn_idle` | close a VPN that komando started after this long unused | a duration; `0` = never close | `30m` |

```bash
komando config set host_key_policy strict    # refuse servers you have not trusted yet
komando config set audit_sql hash            # keep SQL text out of the history
komando config set vpn_idle -- 0             # a value that starts with - goes after --
komando config set audit_syslog tls://siem.example:6514 --yes   # also send the audit to a log server
```

With `audit_syslog` set, each audit record also goes to the log server as it
is written: syslog (RFC 5424, facility authpriv, program `komando`, message
id `audit`, the record's JSON as the message) over UDP, TCP or TLS. The
local log stays the record: a log server that does not answer is said once
on stderr, and the command goes on. A copy on another machine keeps the
history even if someone with your user account rewrites the local file.

Negative values are refused. Every change is recorded in `komando audit`
with the old and the new value.

Most settings also have a flag for one run: `--timeout`,
`--connect-timeout`, `--parallel` (`-P`), `--max-output` and
`--host-key-policy`.

## Environment variables

| Variable | What it does |
|----------|--------------|
| `KOMANDO_HOME` | where komando keeps its data (default `~/.komando`) |
| `KOMANDO_VAULT_PASS` | a passphrase for the vault, instead of the `vault.key` file |
| `KOMANDO_ACTOR` | the name recorded in `komando audit` (for example `claude`) |
| `KOMANDO_OUTPUT` | default output: `json` or `text` |
| `NO_COLOR` | turn off colours in status lines |

Variables for password managers and cloud logins are listed in
[Servers](servers.md).

## Where komando keeps its data

Everything is in `~/.komando/` (change it with `KOMANDO_HOME`). Files are
readable only by you (folder 0700, files 0600).

| File | Contains |
|------|----------|
| `state.json` | servers, conns, VPNs, keys, your own recipes, settings, and the jobs, tunnels and VPN sessions komando started |
| `vault.json` | encrypted secrets |
| `vault.key` | the vault's key (not there when you use `KOMANDO_VAULT_PASS` or `komando secret keychain`) |
| `keys/` | SSH keys made by `komando key gen` |
| `known_hosts` | remembered server fingerprints |
| `audit.jsonl` | history of every action |
| `vpn/` | VPN logs and the state of built-in VPN clients |
| `tunnels/` | logs of background tunnels |
| `bitwarden-device` | the device id komando shows to Bitwarden or Vaultwarden |

Back this folder up and keep it private. If other people or backups can
reach it, run `komando secret keychain`: it moves the vault's key out of
`vault.key` into the OS keychain (the macOS keychain, or the Secret Service
on Linux through `secret-tool`), so a copy of this folder no longer opens
the vault (`--off --yes` moves it back). Or set `KOMANDO_VAULT_PASS` to a
passphrase of 15 or more characters **before** you store your first secret.
`komando doctor` warns when you have done neither. To move to another computer, use `komando export` (no passwords)
instead of copying the folder.
