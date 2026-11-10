# Settings and files

Change komando's settings, see where it keeps its data, and update komando
itself. [All features](README.md)

## Quick start

```bash
komando config show                          # every setting: KEY VALUE DEFAULT ALLOWED, and file locations
komando config get parallel
komando config set parallel 20
komando config set default_timeout 10m
komando doctor                               # check the setup, the inventory and its security (also: do AI agents have this version's skill?)
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
| `login_for` | how long `komando login HOST` keeps a server's login for later commands, an AI agent's too | a duration, e.g. `2h`; an AI agent needs a person's yes to make it longer | `8h` |
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
local log stays the record: when the log server does not answer, komando
says so once on stderr and the command goes on. A copy on another machine keeps the
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
| `KOMANDO_VAULT_PASS` | optional: the vault's passphrase, instead of a key in the keychain or in `vault.key`. A new vault takes it at your first secret; `komando secret passphrase` adds or changes it later (see below) |
| `KOMANDO_KEYCHAIN` | `off`: komando uses no keychain, and a new vault keeps its key in `vault.key` (CI runners, containers, test runs). On a Mac, a path to a keychain file to use instead of the login keychain |
| `KOMANDO_ACTOR` | the name recorded in `komando audit` (for example `claude`) |
| `KOMANDO_OUTPUT` | default output: `json` or `text` |
| `KOMANDO_EXPERIMENTAL` | turn on features still being tested, by name (`ssm`: komando's own AWS Session Manager client, see [Servers](servers.md)) |
| `KOMANDO_EXPERIMENTAL_VPN` | turn on VPN kinds still being tested (`fortinet,pulse`, or `all`; see [VPNs](vpn.md)) |
| `KOMANDO_IPSEC_DEBUG` | `1` writes the IPsec exchange to the VPN's log, to find why a server does not answer |
| `KOMANDO_AGENT`, `AI_AGENT` | mark the caller as an AI agent, for agents komando does not know by their own variables: output hides secrets and `--yes`, `--allow-dangerous` and `--reveal` need a person to allow them (see [Safety](safety.md#seatbelts-for-ai-agents)). Any value counts, also `0` or empty |
| `NO_COLOR` | turn off colors in status lines |

Variables for password managers and cloud logins are listed in
[Servers](servers.md).

## Where komando keeps its data

Everything is in `~/.komando/` (change it with `KOMANDO_HOME`). Files are
readable only by you (folder 0700, files 0600).

A folder komando makes new keeps your data sealed in one file:

| File | Contains |
|------|----------|
| `store.db` | servers, conns, VPNs, keys, recipes, settings, secrets, remembered server fingerprints and the history of every action, each record sealed (AES-256-GCM). Only a random ID, the kind, a version and the time of a change can be read without the key |
| `store.key` | the store's key, only where there is no keychain (not there when the key is in the keychain or you use `KOMANDO_VAULT_PASS`) |
| `runtime.json` | the jobs, tunnels, server logins and VPN sessions komando started |
| `vpn/`, `tunnels/` | VPN and tunnel logs, and the state of built-in VPN clients |

Copy `store.db` only with komando running nothing, or a copy taken during a
change may be broken.

When the store's key is in the OS keychain, the keychain also remembers
how many changes the store has had. An older copy of `store.db` put back
(from a backup, or by someone) stops every command with `STORE_OLD_COPY`,
because its servers, rules, secrets or pinned host keys may be old.
`komando doctor` and dry runs still work. If you restored the folder on
purpose, run `komando doctor --accept-old-copy` in your own terminal. With
the key in `store.key` or a passphrase there is nothing to compare with,
and `komando doctor` says so. The same three ways keep its key as the vault's key
below: `komando secret keychain` and `komando secret passphrase` move and
change it, and `komando doctor` says which one is in use.

A folder from an earlier komando keeps its files as they were:

| File | Contains |
|------|----------|
| `state.json` | servers, conns, VPNs, keys, your own recipes and settings |
| `runtime.json` | the jobs, tunnels, server logins and VPN sessions komando started |
| `vault.json` | encrypted secrets |
| `vault.key` | the vault's key, only where there is no keychain (not there when the key is in the keychain or you use `KOMANDO_VAULT_PASS`) |
| `keys/` | SSH keys made by `komando key gen` |
| `known_hosts` | remembered server fingerprints |
| `audit.jsonl` | history of every action |
| `vpn/` | VPN logs and the state of built-in VPN clients |
| `tunnels/` | logs of background tunnels |
| `bitwarden-device` | the device id komando shows to Bitwarden or Vaultwarden |

Back this folder up and keep it private.

### Where the vault's key lives

A new vault keeps its key in the OS keychain (the macOS keychain through
`/usr/bin/security`, or the Secret Service on Linux through `secret-tool` in
`/usr/bin`, `/bin` or `/usr/local/bin`: komando never looks for them in
`PATH`), so a copy of this folder does not open the vault. komando makes the
key at your first secret, reads it back, and only then counts on it. A key
the keychain already holds for this folder (from a vault you moved aside) is
used, never replaced.

komando stores a new key only when the keychain says it holds nothing for
this folder. On Linux a locked collection hides its keys from a lookup
(and KeePassXC hides them from a search too), while `secret-tool store`
asks to unlock the default collection and then overwrites an item there.
So komando first asks the Secret Service, through `gdbus` or `busctl` from
the same system folders, whether the default collection is unlocked, and
only then checks that `secret-tool search --all` lists no item.

Where the keychain cannot keep the key or cannot tell (a Linux server without
`secret-tool` or a desktop session, a default collection that is locked,
no `gdbus` or `busctl`, a Mac reached over SSH with its keychain locked, an
item for this folder that stays locked, a container, a keychain that does
not answer within a few seconds), the key goes into `vault.key` and
`komando doctor` warns. One case it cannot see: an item in a KeePassXC
database other than the default one, while that database is locked.

A vault keeps its key where it is: one made before komando used the
keychain still has `vault.key`. Run `komando secret keychain` to move the
key into the keychain. Nothing is re-encrypted, so it works before or after
your first secret (`--off --yes` moves it back). On Linux it stops, and
asks you to unlock the keychain, while the default collection is locked.
It refuses when the keychain already holds another key for this folder
(most likely the only key of a vault you moved aside): put that vault back,
or delete the item from the keychain yourself once no vault needs it. A
vault whose key is in the keychain opens only where that keychain is
unlocked: on a Mac you reach over SSH, unlock it first
(`security unlock-keychain`), or use a passphrase.

### A passphrase instead of the keychain

`KOMANDO_VAULT_PASS` is the other way to protect the vault, mainly for a
computer without a keychain (a Linux server without `secret-tool`). A new
vault takes its mode at your first secret: with the variable set to 15 or
more characters, it gets that passphrase. Setting or changing the variable on its own does
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

To move to another computer, see [Move to another computer](import.md#move-to-another-computer):
`komando export` (no passwords), or the whole folder once the vault has a
passphrase.

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
