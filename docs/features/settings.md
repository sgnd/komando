# Settings and files

Change komando's settings, and see where it keeps its data and the key
that opens it. [All docs](README.md)

## Change a setting

```bash
komando config show                          # every setting: KEY VALUE DEFAULT ALLOWED, and where the files are
komando config get parallel
komando config set parallel 20
komando config set default_timeout 10m
komando doctor                               # check the setup, the inventory and its security
```

Typed alone, `komando config set` asks for the setting, then its value.

`config set` says what changed:

```text
parallel: 10 → 20
```

In JSON, `config show` gives each setting in `data.keys`.

## Settings

| Key | What it controls | Values | Default |
|-----|------------------|--------|---------|
| `host_key_policy` | what happens with a server komando has not seen before | `accept-new` (remember it and show its fingerprint), `strict` (refuse it until you run `komando host trust`), `off` (turns a check off) | `accept-new` |
| `default_user` | login name when a server has none | a login name; empty = your own user name | (empty) |
| `default_timeout` | how long a command may run on each server | a duration above 0 (`30s`, `5m`, `1h`) | `5m` |
| `connect_timeout` | how long to wait for a server to answer | a duration above 0 | `15s` |
| `parallel` | how many servers to work on at once | 1 or more | `10` |
| `max_output_bytes` | output kept per stream per server | 1024 or more | `262144` (256 KiB) |
| `audit` | keep the audit log | `on`, `off` (turns a check off) | `on` |
| `audit_sql` | how SQL text is kept in the audit log | `full`, `hash` (a SHA-256, so repeated queries can be matched), `off` (turns a check off) | `full` |
| `audit_syslog` | also send each audit record to a central log server (a SIEM) | `udp://HOST:514`, `tcp://HOST:514`, `tls://HOST:6514`, `off` (any change turns a check off) | `off` |
| `mask_personal` | where AI agents see email addresses, phone numbers, card numbers and IBANs hidden (see [Personal data](safety.md#personal-data)) | `protected`, `all`, `off` (showing more turns a check off) | `protected` |
| `login_for` | how long `komando login SERVER` keeps a server's login for later commands, an AI agent's too | a duration, such as `2h`; an AI agent needs a person's yes to make it longer | `8h` |
| `vpn_idle` | close a VPN that komando started after this long with no command and no open connection through it | a duration; `0` = never close. Making it longer, or `0`, asks first (an AI agent needs a person's yes) | `30m` |

A change that turns a check off asks you first at your terminal
(`This turns off a komando safety check: ... Continue? [y/N]`); an AI agent
or a script adds `--yes` after a person agrees. See
[What needs a yes](safety.md#what-needs-a-yes).

```bash
komando config set host_key_policy strict    # refuse servers you have not trusted yet
komando config set audit_sql hash            # keep SQL text out of the history
komando config set vpn_idle 0                # never close a VPN for being unused
komando config set audit_syslog tls://siem.example:6514   # also send the audit to a log server (komando asks first)
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
`--host-key-policy`. Left out, the flag takes the setting: `komando
schema` shows such a flag with `"default": "0"` (not given) and
`"default_from": "setting:default_timeout"` (the setting it reads).

## Ask for a code before an agent's risky command

When an AI agent adds `--yes`, `--allow-dangerous` or `--reveal`, komando
opens an "Allow once" window on your screen (see
[Safety](safety.md#when-you-are-at-the-terminal)). To need more than a
click, turn on an approval code: the window then also asks for the 6-digit
code from the authenticator app on your phone.

```bash
komando config approval-code             # shows a secret to add to your authenticator app
komando config approval-code --off       # turn it off again (komando asks first)
```

On a Linux or BSD desktop the code is required: another of your programs
could press the window's buttons there, so without the code komando opens
no window and the agent asks you to run the command yourself.

Only a person at a terminal can turn it on: the secret is shown once,
there. Turning it off is a yes like any other safety change, so for an AI
agent it needs the window and the code too. `komando config show` says
whether it is on.

On Windows the window counts only a click or key press from a real mouse or
keyboard: another program cannot press "Allow once" for you. This also
means a screen reader or other tool that presses buttons for you cannot
press it. On macOS a program that has Accessibility permission (System
Settings, Privacy & Security) can click buttons in any window, this one
included. Do not give that permission to a terminal an agent works in, or
turn on the approval code.

## Environment variables

| Variable | What it does |
|----------|--------------|
| `KOMANDO_HOME` | where komando keeps its data (default `~/.komando`, on Windows `%USERPROFILE%\.komando`). For an AI agent, another folder needs a person's yes on every command (see [Safety](safety.md#seatbelts-for-ai-agents)); if you keep the data elsewhere, make `~/.komando` a link to it instead |
| `KOMANDO_VAULT_PASS` | optional: the vault's passphrase, instead of a key in the keychain or in `store.key`. A new vault takes it at your first secret; `komando secret passphrase` adds or changes it later (see [below](#a-passphrase-instead-of-the-keychain)) |
| `KOMANDO_KEYCHAIN` | `off`: komando uses no keychain, and a new vault keeps its key in `store.key` (CI runners, containers, test runs); for an AI agent it does not turn off the store's change count, the old-copy check. On a Mac, a path to a keychain file to use instead of the login keychain |
| `KOMANDO_ACTOR` | the name recorded in `komando audit` (for example `claude`) |
| `KOMANDO_OUTPUT` | default output: `json` or `text` |
| `KOMANDO_AGENT`, `AI_AGENT` | mark the caller as an AI agent, for agents komando does not know by their own variables: output hides secrets and `--yes`, `--allow-dangerous` and `--reveal` need a person to allow them (see [Safety](safety.md#seatbelts-for-ai-agents)). Any value counts, also `0` or empty |
| `KOMANDO_NO_DIALOG` | any value: never show the approval window, as over SSH. An AI agent's `--yes`, `--allow-dangerous` or `--reveal` is then refused, and the agent asks you to run the command in your own terminal |
| `CI` | a CI job (any value but `false` or `0`): komando never asks anything, even on a terminal |
| `KOMANDO_EXPERIMENTAL` | turn on features still being tested, by name (`ssm`: komando's own AWS Session Manager client, see [Servers](servers.md)) |
| `KOMANDO_EXPERIMENTAL_VPN` | turn on VPN kinds still being tested (`fortinet,pulse`, or `all`; see [VPNs](vpn.md)) |
| `KOMANDO_IPSEC_DEBUG` | `1` writes the IPsec exchange to the VPN's log, to find why a server does not answer |
| `NO_COLOR` | turn off colors in status lines |

Variables for password managers and cloud logins are listed in
[Servers](servers.md).

komando takes `KOMANDO_VAULT_PASS` and the password managers' unlock
variables (`KOMANDO_KDBX_PASSWORD`, `KOMANDO_KDBX_KEYFILE`,
`KOMANDO_BW_PASSWORD`, `KOMANDO_BW_CLIENT_SECRET`, `OP_CONNECT_TOKEN`,
`VAULT_TOKEN`, `BAO_TOKEN`) out of its environment when it starts: the
programs it runs do not inherit them, and its background tunnels, VPN
sessions and logins get them on their input instead.

## Where komando keeps its data

Everything is in `~/.komando/` (on Windows `%USERPROFILE%\.komando`;
change it with `KOMANDO_HOME`). Only you can read it:

- **macOS and Linux:** the folder is mode 0700 and the files 0600.
- **Windows:** file modes do nothing there, so komando gives the folder an
  access list of its own: your user and the system only, passed on to
  every file inside. `komando doctor` warns about any file someone else
  can open, and prints the `icacls` commands that fix it.

komando keeps your data sealed in one file:

| File | Contains |
|------|----------|
| `store.db` | servers, conns, VPNs, keys, recipes, settings, secrets, remembered server fingerprints and the history of every action, each record sealed (AES-256-GCM). Only a random ID, the kind, a version and the time of a change can be read without the key |
| `store.key` | the store's key, only where there is no keychain (not there when the key is in the keychain or you use `KOMANDO_VAULT_PASS`) |
| `runtime.json` | the jobs, tunnels, server logins and VPN sessions komando started (sealed with the store's key) |
| `runtime.pids` | only the process IDs of komando's own background work, so it can tell whether they still run without opening the store |
| `vpn/`, `tunnels/` | VPN and tunnel logs, and the state of built-in VPN clients |

Copy `store.db` only with komando running nothing, or a copy taken during a
change may be broken. Back this folder up and keep it private.

komando reads only `store.db`. A folder that had a store (`store.key` or
`runtime.pids` is there, or the keychain keeps its change count) but lost
`store.db` stops with `STATE_CORRUPT` until you put `store.db` back from a
backup.

When the store's key is in the OS keychain, the keychain also remembers
how many changes the store has had. An older copy of `store.db` put back
(from a backup, or by someone) stops every command with `STORE_OLD_COPY`,
because its servers, rules, secrets or pinned host keys may be old.
`komando doctor` and dry runs still work. If you restored the folder on
purpose, run `komando doctor --accept-old-copy` in your own terminal. With
the key in `store.key` or a passphrase there is nothing to compare with,
and `komando doctor` says so.

### Where the vault's key lives

The store's key is kept in one of three ways: in the OS keychain, in
`store.key`, or made from a passphrase. `komando doctor` says which one is
in use, and `komando secret keychain` and `komando secret passphrase` move
and change it (see [Secrets](secrets.md#where-they-are-kept-and-the-key)).

A new vault keeps its key in the OS keychain, so a copy of this folder does
not open the vault:

- **macOS:** the keychain, through `/usr/bin/security`.
- **Linux:** the Secret Service, through `secret-tool` in `/usr/bin`, `/bin`
  or `/usr/local/bin`.
- **Windows:** Credential Manager, as a credential for your user on this
  computer only (it does not roam to other computers).

komando never looks for these tools in `PATH`. It makes the key at your
first secret, reads it back, and only then counts on it. A key the keychain
already holds for this folder (from a vault you moved aside) is used, never
replaced.

komando stores a new key only when the keychain says it holds nothing for
this folder. On Linux a locked collection hides its keys from a lookup
(and KeePassXC hides them from a search too), while `secret-tool store`
asks to unlock the default collection and then overwrites an item there.
So komando first asks the Secret Service, through `gdbus` or `busctl` from
the same system folders, whether the default collection is unlocked, and
only then checks that `secret-tool search --all` lists no item.

Where the keychain cannot keep the key or cannot tell, the key goes into
`store.key` and `komando doctor` warns. That happens on:

- a Linux server without `secret-tool` or a desktop session, a default
  collection that is locked, or no `gdbus` or `busctl`;
- a Mac reached over SSH with its keychain locked, or a Mac user with no
  default keychain (a changed `HOME`, as under `sudo -E`, a sandbox or CI:
  komando asks `security default-keychain` first, so macOS shows no
  "Keychain Not Found" dialog);
- a Windows computer without Credential Manager;
- an item for this folder that stays locked, a container, or a keychain
  that does not answer within a few seconds.

A vault whose key is in `store.key` keeps it there until you move it: run
`komando secret keychain`. Nothing is re-encrypted, so it works before or
after your first secret (`--off` moves it back, and komando asks first).
Only a person at a terminal can run it: an AI agent or a script gets
`NEEDS_PERSON`, since the keychain may ask to be unlocked. On Linux it
stops, and asks you to unlock the keychain, while the default collection
is locked. It refuses when the keychain already holds another key for this
folder (most likely the only key of a vault you moved aside): put that
vault back, or delete the item from the keychain yourself once no vault
needs it. A vault whose key is in the keychain opens only where that
keychain is unlocked: on a Mac you reach over SSH, unlock it first
(`security unlock-keychain`), or use a passphrase.

When the keychain does not answer within a few seconds, komando still reads
the store but changes nothing: a command that would change something stops
with `KEYCHAIN_SLOW`. Try again in a moment.

### A passphrase instead of the keychain

`KOMANDO_VAULT_PASS` is the other way to protect the vault, mainly for a
computer without a keychain (a Linux server without `secret-tool`). A new
vault takes its mode at your first secret: with the variable set to 15 or
more characters, it gets that passphrase. Setting or changing the variable
on its own does nothing to a vault that exists already;
`komando secret passphrase` does that. A passphrase vault needs the same
passphrase in every shell and background process.

To change the passphrase, or to give a passphrase to a vault whose key is in
`store.key` or the keychain, run `komando secret passphrase` in your terminal.
It asks for the new passphrase twice (hidden, 15 or more characters) and
re-encrypts every secret under it; if one cannot be decrypted, nothing
changes. When `KOMANDO_VAULT_PASS` holds the new value already, it asks for
the current one. The old `store.key` or keychain item is removed only after
the new vault is saved and read back. Then put the new passphrase in
`KOMANDO_VAULT_PASS` wherever you set it, and restart background tunnels and
VPN sessions: they still hold the old key. `--off` goes back to a new
random key in `store.key` (komando asks first). Only a person at a terminal
can run it, never an AI agent. A `KOMANDO_VAULT_PASS` changed without it
opens none of the secrets (nothing is lost: set the old value again);
`komando doctor` says so.

To move to another computer, see [Move to another computer](import.md#move-to-another-computer):
`komando export` (no passwords), or the whole folder once the vault has a
passphrase.

## Update komando

To update komando itself, see [Install, update, remove](install.md#update).

## Limits

- The keychain keeps the key away from someone who copies this folder. It
  does not keep it away from other programs you run yourself, and that
  includes an AI agent with a shell:
  - **macOS:** komando reads the item through `/usr/bin/security`, so any
    program of your user can read it the same way, with no prompt. It could
    also lower the change count komando keeps there, and then put back an
    old copy of `store.db` without `STORE_OLD_COPY`. Only a signed komando
    that keeps its items for itself can close this.
  - **Windows:** Credential Manager gives the item to any program of your
    user.
  - **Linux:** while the keychain is unlocked, `secret-tool` gives the item
    to any program of your user.
- komando's rules (masked secrets, the approval window, protected servers)
  hold for an AI agent that uses komando. A program that runs as your own
  user and ignores those rules can open the vault itself, whichever way the
  key is kept: it reads `store.key`, asks the keychain for the item as
  komando does, or reads `KOMANDO_VAULT_PASS` from the shell that started
  it. Only two things stop such a program: running it as another OS user
  (or in a container or virtual machine without your home folder and
  keychain), or the signed komando Mac app, which keeps the key for itself.
- One case komando cannot see when it stores a new key: an item in a
  KeePassXC database other than the default one, while that database is
  locked.

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `SAFETY_SETTING` (exit 6) | the change turns one of komando's checks off | at your terminal komando asks first; an AI agent or a script adds `--yes` after a person agrees |
| `STORE_OLD_COPY` (exit 6) | an older copy of `store.db` was put back | if you restored it on purpose, run `komando doctor --accept-old-copy` in your own terminal; otherwise find out who put it back |
| `STATE_CORRUPT` (exit 1) | `store.db` is missing in a folder that had a store, or does not open with the key; or `runtime.json` does not open | for `store.db`: put the folder back from a backup, then `komando doctor --accept-old-copy` in your own terminal; for `runtime.json`: move it away and connect again (it holds only running VPNs, logins, jobs and tunnels) |
| `KEYCHAIN_SLOW` (exit 1) | the keychain did not answer in time, so nothing was changed | run it again in a moment; `komando doctor` if it keeps happening |
| `VAULT_LOCKED`, `VAULT_DECRYPT`, `VAULT_KEY` (exit 1) | the vault does not open | see [Secrets](secrets.md#troubleshooting) |
| `AUDIT_UNAVAILABLE` (exit 1) | the audit log cannot be written, so nothing runs | `komando doctor` shows why |
