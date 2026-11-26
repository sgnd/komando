# Secrets

Save a password, key passphrase or token once, then point to it as
`credential:NAME` instead of typing it. komando shows a saved value only to a
person who asks with `--reveal` (`secret show`, `key show`), at a terminal
or after "Allow once" in komando's window, and never to an AI agent.

## Save a password and use it

```bash
komando secret set web1-pass                          # type or paste it after the prompt, nothing is shown
komando host edit web1 --password-ref credential:web1-pass
komando test web1
komando secret list                                   # names, when they changed, what uses them
```

Typed alone, `komando secret set` asks for the name, then the value
(hidden).

## Save one

At your terminal, `komando secret set NAME` asks for the value and hides it
as you type or paste:

```text
Paste or type the value for web1-pass, then press Enter (it stays hidden):
```

Paste it *after* the prompt appears. Text typed before it appears was
already shown on the screen, so komando does not use it, and says so:
`Note: what was typed before this question showed was not used.` If that
text was the secret, clear the screen and type it again. A value of
several lines (a key, a certificate) goes in on stdin:

```bash
komando secret set web1-pass                   # asks, hidden
komando secret set db-pass --from-env DB_PASS  # from an environment variable
pbpaste | komando secret set vpn-pass          # from the clipboard (xclip -o on Linux)
komando secret set tls-key < server.key        # a value of several lines
```

- A value on the command line (`komando secret set NAME VALUE`) is refused
  with `SECRET_IN_ARGS`: it would stay in your shell history.
- A paste of more than one line at the prompt stops with `USAGE` and
  stores nothing: the shell would otherwise run the other lines.
- An empty value (an empty pipe, an empty variable, Enter at the prompt)
  stops with `USAGE` and stores nothing.
- From a pipe, the line break at the end is not part of the value. Spaces
  are kept; komando warns when the value starts or ends with one.
- `secret set` on a name that exists replaces its value. When a protected
  server or conn uses it, komando asks you first; an AI agent or a script
  adds `--yes` after a person agrees.
- `secret set NAME --new` only stores a new secret: when NAME is in the
  vault already, it stops with `SECRET_EXISTS` (exit 8) and the stored
  value stays. The value comes in as without `--new`. When several
  komando commands store the same name with `--new` at once, exactly one
  stores it and the others stop with `SECRET_EXISTS`. With `--dry-run` it
  says the same: `SECRET_EXISTS` for a taken name, `"action":
  "would_store"` for a free one.

```bash
komando secret set api-token --new --from-env TOKEN   # never replaces one
```

## Use one

Every `--password-ref`, `--sudo-ref`, `--passphrase-ref` and VPN key flag
takes a reference:

```bash
komando host edit web1 --sudo-ref credential:web1-sudo
komando conn add prod-db postgres://app@10.0.0.5/shop --password-ref credential:prod-db-pass
komando key add work ~/.ssh/id_work --passphrase-ref credential:work-pass
komando exec web1 --env DB_PASS=credential:prod-db-pass -- ./migrate.sh
komando fs replace web1 /srv/app/.env --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{credential:prod-db-pass}}' --backup
```

A flag that komando keeps with a server, a service, a VPN or a key
(`--password-ref`, `--sudo-ref`, `--psk-ref`, `--passphrase-ref`) takes
`credential:NAME` only; another store there is refused with
`BAD_REFERENCE`. For one command (`--env`, and `db user add` and `passwd`),
a reference can also read a password your team keeps elsewhere: `env:VAR`,
`file:PATH`, HashiCorp Vault or OpenBao (`vault:PATH#FIELD`), AWS, Google
and Azure secret managers (`aws-sm:`, `gcp-sm:`, `azure-kv:`), 1Password
Connect (`op://`), Bitwarden or Vaultwarden (`bw://`) and KeePass files
(`kdbx:`). See [Passwords from your password manager](servers.md#passwords-from-your-password-manager)
for each one and the login it uses. komando reads such a value only when it
needs it and never stores it.

## Run a program on this computer with one

```bash
komando secret run --env PGPASSWORD=credential:prod-db-pass -- psql -h 10.0.0.5 -U app shop
komando secret run -e AWS_SECRET_ACCESS_KEY=credential:aws-ci -e AWS_REGION=eu-west-1 -- terraform plan
```

`komando secret run` starts the program after `--` on this computer, with the
`--env` values in its environment. komando reads `credential:NAME` from the
vault right before the program starts, so the value is never in the command
line or your shell history. The program starts without a shell, and gets
your environment without komando's own `KOMANDO_*` variables and the
values that unlock the vault.

- A vault value the program prints shows as `[credential:NAME]`.
- komando exits with the program's exit code. On Linux and macOS, a
  program ended by signal N makes komando exit 128+N (143 for `SIGTERM`),
  as a shell does.
- `SIGTERM` or `SIGHUP` to komando goes on to the program, so it does not
  run on with the secrets. Ctrl-C at the terminal reaches the program by
  itself, once. A second Ctrl-C ends komando at once and ends the program
  first. On Windows komando ends the program.
- On Linux the program gets `SIGTERM` when komando dies, even by
  `SIGKILL`. On macOS and Windows a komando killed that way leaves the
  program running with the secrets.
- komando waits 3 seconds after the program exits for its output to end.
  A background process the program left behind that still holds the
  output is cut off then, and komando exits.
- Output lines longer than 256 KiB are cut, but never inside a hidden
  value up to 1 MiB or a masked pattern such as `password=...`. A private
  key open at the cut is hidden from its `BEGIN` line through its `END`
  line (at most 16 KiB more).
- The audit log records the program's path, the variable names and the
  secret names, never a value.
- `--dry-run` shows the program's path and which secret goes into which
  variable, and reads no value. It asks nobody: the approval the real run
  needs is in `meta.would_need` and `meta.would_be_blocked`.
- A reference of any form (`credential:`, `env:`, `file:`, `vault:`, `op://`,
  ...) in the program's arguments is refused: put it in `--env`. A
  `file://` URL is not a reference and passes. This is a guard against
  mistakes, not a security boundary: komando never resolves a reference in
  the arguments. It finds `credential:` anywhere, but the other forms only at
  the start of an argument or after an `=`, so `-penv:PW` is passed on as
  written.
- An AI agent needs a person's yes for every secret (`SECRET_DESTINATION`):
  the program could print a value in a form masking does not know. The
  window names the secrets, the program's full path, the other `--env`
  variables, and says when any program of yours could replace the program.
- In an AI agent's run with secrets, the program gets `HOME`, `USER` and
  `LOGNAME` from your account (`USERPROFILE` on Windows), not from the
  agent's environment, plus `LANG`, `LC_*`, `TERM`, `TMPDIR`, `TZ`, the
  Windows system folders, a system `PATH` and its `--env` values. A pager,
  editor, askpass helper or proxy the agent set could otherwise hand the
  values on.
- In that run the agent's plain `--env` values may add variables but never
  replace one komando sets (`HOME`, `PATH`, `USER`, `LANG`, `LC_*`, ...,
  in any case), and may not set what decides which code or settings the
  program loads (`USAGE`): `LD_PRELOAD`, `DYLD_*`, `NODE_OPTIONS`,
  `PYTHON*`, `BASH_ENV`, a pager (`*PAGER`), `EDITOR`, `VISUAL`, an askpass
  helper, an rc file (`PSQLRC`, `*RC`), a proxy (`*_proxy`), `GIT_*`,
  `SSH_*`, `XDG_*`, a tool's config file (`KUBECONFIG`, `DOCKER_CONFIG`,
  `*_CONFIG_FILE`, `AWS_*_FILE`, `NPM_CONFIG_*`), a toolchain that picks
  binaries (`CC`, `CXX`, `GOFLAGS`, `GOTOOLCHAIN`, `CARGO_*`,
  `RUSTC_WRAPPER`, `JAVA_HOME`, `MAVEN_OPTS`, `GRADLE_OPTS`) and the like.
  Variables such as `PGHOST`, `AWS_REGION` or `TF_VAR_*` pass. The window shows the plain `--env` values.
- On Linux, when your account is not in `/etc/passwd` (only LDAP or sssd
  knows it), komando cannot read your account's `HOME`. The program then
  gets an empty temporary `HOME` that komando removes afterwards, and
  komando says so on stderr.
- If the program file changes between the check and the start, komando
  stops (`TOOL_MISSING`) and the program does not run. On Linux komando
  starts the file it checked, through the open file.
- Accepted risk: a program in a folder any program of yours can write
  (Homebrew's, npm's, `~/.local/bin`) is not refused, because that is where
  tools like `wrangler` live. For an AI agent the window names its full
  path and warns that it can be replaced, and the person decides.
- A secret that a protected server, conn or VPN uses asks a person at a
  terminal too, as a change on a protected server does.

## Check one

```bash
komando secret show web1-pass      # does it exist, what uses it, a warning about spaces (no value)
komando secret check web1-pass     # type the value you think it is: match or how they differ
```

`secret check` never shows either value: it says whether they match, or
whether they differ only in spaces at the ends, only in upper and lower
case, or in length. Only a person can run it.

## See a value again

```bash
komando secret show web1-pass --reveal            # print it (a person, at a terminal)
komando secret show web1-pass --reveal | pbcopy   # or copy it
komando key show deploy --reveal > deploy.key     # the private key of a key komando made
```

- **At a terminal** komando prints the value: you typed the command.
- **From a program without a terminal**, such as the Komando Mac app (not
  released yet), komando first asks you in its own window, naming the
  secret, the command and the programs that started it ("Started from:
  Komando"). It shows the value only after **Allow once**: on macOS
  followed by Touch ID, an Apple Watch or your login password; elsewhere, with `komando config
  approval-code` on, the window also asks for the 6-digit code. A Linux or BSD desktop gets
  that window only with the approval code, and with no screen it stops
  with `REVEAL_NEEDS_TERMINAL`: run it in a terminal.
- **An AI agent never gets a value or a private key**, not even with your
  yes: komando refuses with `REVEAL_NEEDS_TERMINAL` and opens no window. The
  agent uses `credential:NAME` in a command instead. A key through `ssh-gate`
  (the iPhone and iPad app) is refused too.
- A dry run shows no value and asks nobody.
- Every value shown goes in the audit log, as `secret.reveal` or
  `key.reveal`, with how you allowed it (`via`: `terminal` or `window`) and
  the programs that started komando (`started_from`); every refusal goes
  there too, with the secret's or key's name. The value never does.
- `key show --reveal` prints only keys komando made (`key gen`), which it
  keeps in its sealed store; for a key added from a file it names that file.

## Rename, copy and remove

```bash
komando secret rename vpn-password office-vpn-pass --dry-run   # what would change
komando secret rename vpn-password office-vpn-pass             # every server, conn, key and VPN follows
komando secret cp db-pass db-pass-old                          # a copy; nothing else changes
komando secret rm old-pass other-old-pass                      # all of them, or none
```

- `secret rename` points every server, conn, key and VPN that used `credential:OLD`
  at `credential:NEW` in the same step (conn URL options such as
  `?ca=credential:OLD` too). Scripts and files of your own are not changed.
- When NEW exists, add `--overwrite`; what uses NEW then gets the value of
  OLD. When a protected server or conn uses NEW, komando asks you first
  (`--yes` for an AI agent or a script).
- `secret rm` is refused while anything uses a name (`SECRET_IN_USE` lists
  what does); point those at another secret first, or rename it.
- A deleted secret has no copy, so at your terminal you type the secret's
  name first (several: how many). An AI agent or a script adds
  `--allow-dangerous` after a person agrees (`POLICY_BLOCKED` otherwise).

## Where they are kept, and the key

Secrets are sealed with AES-256-GCM in `~/.komando/store.db`. The key that
opens them is in the OS keychain (macOS keychain, Linux Secret Service,
Windows Credential Manager), or in `~/.komando/store.key` where there is no
keychain, or comes from a passphrase in `KOMANDO_VAULT_PASS`.

```bash
komando doctor                       # which of the three is in use, and any warning
komando secret keychain              # move the key from store.key into the keychain
komando secret keychain --off        # move it back into store.key (komando asks first)
komando secret passphrase            # give the store a passphrase, or change it
komando secret passphrase --off      # back to a random key in store.key (komando asks first)
komando secret passphrase --dry-run
```

komando uses the keychain on its own only when a new store makes its key,
and to keep the store's change count beside a key that is there. It leaves
the keychain alone with `KOMANDO_KEYCHAIN=off` (CI, containers, test runs),
where there is no keychain tool, and on a Mac whose user has no default
keychain (a changed `HOME`): the key then goes into `store.key`, and
`komando doctor` says so. It never makes macOS ask where to keep it.
An AI agent's `KOMANDO_KEYCHAIN=off` still lets komando read and raise the
change count: an agent cannot switch off the old-copy check that way. Nor
can an agent point komando at another keychain: its `KOMANDO_KEYCHAIN`
path (a keychain file on a Mac) is not used, so its calls keep the key and
the count in the login keychain. A store whose key is in your own keychain
file is opened only by your commands.

These commands change where the key is, so only a person at a terminal runs
them (`NEEDS_PERSON` for an AI agent or a script); `--dry-run` previews them
for anyone. `--off` turns a check off, so komando asks first; a script adds
`--yes`. Details: [Settings and files](settings.md#where-the-vaults-key-lives).

komando takes `KOMANDO_VAULT_PASS` and the password managers' unlock
variables out of its environment when it starts, so no program it runs
inherits them (see [Environment variables](settings.md#environment-variables)).

## For AI agents

An agent never sees a value: output shows `[credential:NAME]` or `[hidden]`.

| The agent wants to | It runs | Or it gets |
|---|---|---|
| store a password the user knows | asks the user to run `komando secret set NAME` | `NEEDS_PERSON` |
| store a token a program made | `echo "$TOKEN" \| komando secret set NAME` or `--from-env VAR` | |
| preview a change | the same command with `--dry-run` | `meta.would_be_blocked` names what the real run needs |
| use a secret | `credential:NAME` in a flag | `SECRET_DESTINATION`: a person allows where it goes |
| rename, copy, remove | `secret rename`, `secret cp`, `secret rm` | |
| read or compare a value | asks the user (`secret show --reveal`, `key show --reveal`, `secret check`) | `REVEAL_NEEDS_TERMINAL`, `NEEDS_PERSON` |

The agent never asks for a password in the chat: the hint names the
command the user runs in their own terminal.

## Limits

- Hiding a value in a server's output is a best effort (see
  [Safety](safety.md#limits)).
- A vault value that is a common word (such as `shared`) is hidden
  wherever that word appears, komando's own notes included. That is the
  safe side: the value never shows. `secret set`, `import`, `vpn add` and
  `doctor` warn about a value of only letters shorter than 10 characters,
  or a common password; use a longer value, or add digits or symbols.
- A secret from a password manager (`vault:`, `op://` ...) is read when
  needed and never stored, so that manager must be reachable each time.
- A vault whose key is in the keychain opens only where that keychain is
  unlocked. A copied folder opens its secrets only with a passphrase (see
  [Move to another computer](import.md#copy-the-folder-everything-with-passwords)).
- Anything that runs as your own user can reach the key; see
  [Settings and files](settings.md#limits).

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `SECRET_IN_ARGS` (exit 2) | the value was on the command line | `komando secret set NAME`, then type it after the prompt |
| `USAGE` (exit 2) | an empty value, or a paste of several lines | type it again, or give several lines on stdin: `komando secret set NAME < FILE` |
| `SECRET_NOT_FOUND`, `SECRET_UNRESOLVED` (exit 3) | no secret by that name, or a reference that cannot be read | `komando secret list` |
| `SECRET_EXISTS` (exit 8) | `secret rename` or `secret cp` to a name that is taken, or `secret set --new` of a name that is stored | pick another name; to replace it, add `--overwrite` (rename, cp) or run `komando secret set NAME` without `--new` |
| `SECRET_IN_USE` (exit 8) | `secret rm` of a secret something still uses | point those at another secret, or `secret rename` it |
| `SECRET_MISMATCH` (exit 1) | `secret check`: the value you typed is not the stored one | `data.difference` says how they differ; `komando secret set NAME` stores the right one |
| `NEEDS_PERSON` (exit 6) | only a person can do this (`secret set` for an agent, `secret check`, `secret keychain`, `secret passphrase`) | the person runs it in their own terminal |
| `VAULT_LOCKED` (exit 1) | the vault has a passphrase and `KOMANDO_VAULT_PASS` is not set | set `KOMANDO_VAULT_PASS` in the shell that runs komando (an AI agent asks the user) |
| `VAULT_DECRYPT` (exit 1) | `KOMANDO_VAULT_PASS` is not this vault's passphrase | set the right one; nothing was lost. `komando doctor` says which mode is in use |
| `VAULT_KEY` (exit 1) | the key is missing: `store.key` is gone, or the keychain item is on another computer | restore `~/.komando/store.key` from a backup, or run `komando secret keychain` on the computer whose keychain holds the key |
| `KEYCHAIN_SLOW` (exit 1) | the keychain did not answer in time, so nothing was changed | run it again in a moment; `komando doctor` if it keeps happening |
| `KEYCHAIN_FAILED` (exit 5) | the keychain could not be read, so komando could not check that the store is the newest copy; nothing was changed | a person unlocks the keychain (an AI agent asks the user), then run it again; on a computer with no working keychain, a person sets `KOMANDO_KEYCHAIN=off` |
