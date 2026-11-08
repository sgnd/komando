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
komando update --dry-run                     # is there a newer komando?
```

## Settings

| Key | What it controls | Values | Default |
|-----|------------------|--------|---------|
| `host_key_policy` | what happens with a server komando has not seen before | `accept-new` (remember it and show its fingerprint), `strict` (refuse it until you run `komando host trust`), `off` (needs `--yes`) | `accept-new` |
| `default_user` | login name when a server has none | a login name; empty = your own user name | (empty) |
| `default_timeout` | how long a command may run on each server | a duration above 0 (`30s`, `5m`, `1h`) | `5m` |
| `connect_timeout` | how long to wait for a server to answer | a duration above 0 | `15s` |
| `parallel` | how many servers to work on at once | 1 or more | `10` |
| `max_output_bytes` | output kept per stream per server | 1024 or more | `262144` (256 KiB) |
| `audit` | keep the audit log | `on`, `off` (needs `--yes`) | `on` |
| `audit_sql` | how SQL text is kept in the audit log | `full`, `hash`, `off` (needs `--yes`) | `full` |
| `audit_syslog` | also send each audit record to a central log server (a SIEM) | `udp://HOST:514`, `tcp://HOST:514`, `tls://HOST:6514`, `off` (changing it needs `--yes`) | `off` |
| `mask_personal` | where AI agents see email addresses, phone numbers, card numbers and IBANs hidden (see [Personal data](safety.md#personal-data)) | `protected`, `all`, `off` (showing more needs `--yes`) | `protected` |
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
| `KOMANDO_HOME` | where komando keeps its data (default `~/.komando`). For an AI agent, another folder needs a person's yes on every command (see [Safety](safety.md#seatbelts-for-ai-agents)); if you keep the data elsewhere, make `~/.komando` a link to it instead |
| `KOMANDO_VAULT_PASS` | optional: the vault's passphrase, instead of the `vault.key` file. A new vault takes it at your first secret; `komando secret passphrase` adds or changes it later (see below) |
| `KOMANDO_ACTOR` | the name recorded in `komando audit` (for example `claude`) |
| `KOMANDO_OUTPUT` | default output: `json` or `text` |
| `KOMANDO_AGENT`, `AI_AGENT` | mark the caller as an AI agent, for agents komando does not know by their own variables: output hides secrets and `--yes`, `--allow-dangerous` and `--reveal` need a person to allow them (see [Safety](safety.md#seatbelts-for-ai-agents)). Any value counts, also `0` or empty |
| `NO_COLOR` | turn off colors in status lines |

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

Back this folder up and keep it private. Then run `komando secret keychain`:
it moves the vault's key out of `vault.key` into the OS keychain (the macOS
keychain through `/usr/bin/security`, or the Secret Service on Linux through
`secret-tool` in `/usr/bin`, `/bin` or `/usr/local/bin`: komando never looks
for them in `PATH`), so a copy of this folder no longer opens the vault.
Nothing is re-encrypted, so it works before or after your first secret
(`--off --yes` moves it back). This is the recommended setup;
`komando doctor` warns until it is done.

`KOMANDO_VAULT_PASS` is the other way, mainly for a computer without a
keychain (a Linux server without `secret-tool`). A new vault takes its mode
at your first secret: with the variable set to 15 or more characters, it
gets that passphrase. Setting or changing the variable on its own does
nothing to a vault that exists already; `komando secret passphrase` does
that (below). A passphrase vault needs the same passphrase in every shell
and background process.

To change the passphrase, or to give a passphrase to a vault whose key is in
`vault.key` or the keychain, run `komando secret passphrase` in your terminal.
It asks for the new passphrase twice (hidden, 15 or more characters) and
re-encrypts every secret under it; if one cannot be decrypted, nothing
changes. When `KOMANDO_VAULT_PASS` holds the new value already, it asks for
the current one. The old `vault.key` or keychain item is removed only after
the new vault is saved and read back. Then put the new passphrase in
`KOMANDO_VAULT_PASS` wherever you set it, and restart background tunnels and
VPN sessions: they still hold the old key. `--off --yes` goes back to a new
random key in `vault.key`. Only a person at a terminal can run it, never an
AI agent. A `KOMANDO_VAULT_PASS` changed without it opens none of the
secrets (nothing is lost: set the old value again); `komando doctor` says so.

To move to another computer, use `komando export` (no passwords) instead of
copying the folder.

## Update komando

```bash
komando update --dry-run   # is there a newer version? (changes nothing)
komando update             # install the newest release
sudo komando update        # komando is in /usr/local/bin, which only root may change
komando update v0.6.0      # install this version
```

`update` downloads the release for this computer from GitHub, checks it
against `checksums.txt` from the same release, runs the new program once to
make sure it works here, and only then puts it in place of the old one. If
anything fails, the old komando stays as it was. A komando that is running
right now keeps working; the next command starts the new version.

- Run as you, the update goes into the audit log like any other change. As
  root (`sudo komando update`) it writes nothing in `~/.komando`, so no file
  there ends up belonging to root.
- Afterwards, run `komando guide install` (without `sudo`): the skill your
  AI agents read comes with komando and changes with it.
- Going back to an older version needs a person's yes (for an AI agent:
  `--yes` and the "Allow once" window), because an older komando may lack
  safety checks the newer one has. Without a VERSION, `update` never goes
  back, even when the newest release is older than the komando you run.
- A komando built from source (`make build`, `go build`) is not replaced
  (`SOURCE_BUILD`): build it again instead.
- When GitHub answers with an error (HTTP 5xx) or the connection drops, it
  tries twice more. `--timeout` (default 10 minutes) limits the whole update.
- It honours `HTTPS_PROXY`. `sudo` drops that variable; keep it with
  `sudo --preserve-env=HTTPS_PROXY komando update`.

| Error | What to do |
|-------|------------|
| `NOT_WRITABLE` (exit 8) | the folder belongs to root: run the `sudo` command the hint gives (it names komando by its full path) |
| `VERSION_NOT_FOUND` (exit 3) | no such release, or none for this computer; see the [list of releases](https://github.com/sgnd/komando/releases) |
| `RELEASES_UNREACHABLE` (exit 4) | GitHub cannot be reached: check the internet connection and `HTTPS_PROXY` |
| `TIMEOUT` (exit 7) | the download was slower than `--timeout`; nothing was changed. Try `komando update --timeout 30m` |
| `CHECKSUM_MISMATCH`, `BAD_RELEASE` (exit 1) | the download is damaged or does not run here; nothing was changed. Try again, and report it if it happens again |

## Ask for a code before an agent's risky command

When an AI agent adds `--yes`, `--allow-dangerous` or `--reveal`, komando
opens an "Allow once" window on your screen (see [Safety](safety.md)). To
need more than a click, turn on an approval code: the window then also asks
for the 6-digit code from the authenticator app on your phone.

```bash
komando config approval-code             # shows a secret to add to your authenticator app
komando config approval-code --off --yes # turn it off again
```

Only a person at a terminal can turn it on.
