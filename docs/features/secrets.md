# Secrets

Save a password, key passphrase or token once, then point to it as
`secret:NAME` instead of typing it. komando never prints a saved value.

## Save a password and use it

```bash
komando secret set web1-pass                          # type or paste it after the prompt, nothing is shown
komando host edit web1 --password-ref secret:web1-pass
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

## Use one

Every `--password-ref`, `--sudo-ref`, `--passphrase-ref` and VPN key flag
takes a reference:

```bash
komando host edit web1 --sudo-ref secret:web1-sudo
komando conn add prod-db postgres://app@10.0.0.5/shop --password-ref secret:prod-db-pass
komando key add work ~/.ssh/id_work --passphrase-ref secret:work-pass
komando exec web1 --env DB_PASS=secret:prod-db-pass -- ./migrate.sh
komando fs replace web1 /srv/app/.env --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:prod-db-pass}}' --backup
```

A reference can also read a password your team keeps elsewhere: `env:VAR`,
`file:PATH`, HashiCorp Vault or OpenBao (`vault:PATH#FIELD`), AWS, Google
and Azure secret managers (`aws-sm:`, `gcp-sm:`, `azure-kv:`), 1Password
Connect (`op://`), Bitwarden or Vaultwarden (`bw://`) and KeePass files
(`kdbx:`). See [Passwords from your password manager](servers.md#passwords-from-your-password-manager)
for each one and the login it uses. komando reads such a value only when it
needs it and never stores it.

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
- **From a program without a terminal**, such as the Komando Mac app,
  komando first asks you in its own window, naming the secret, the command
  and the programs that started it ("Started from: Komando"). It shows the
  value only after **Allow once**; with `komando config approval-code` on,
  the window also asks for the 6-digit code. A Linux or BSD desktop gets
  that window only with the approval code, and with no screen it stops
  with `REVEAL_NEEDS_HUMAN`: run it in a terminal.
- **An AI agent never gets a value or a private key**, not even with your
  yes: komando refuses with `REVEAL_NEEDS_HUMAN` and opens no window. The
  agent uses `secret:NAME` in a command instead. A key through `ssh-gate`
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

- `secret rename` points every server, conn, key and VPN that used `secret:OLD`
  at `secret:NEW` in the same step (conn URL options such as
  `?ca=secret:OLD` too). Scripts and files of your own are not changed.
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

An agent never sees a value: output shows `[secret:NAME]` or `[hidden]`.

| The agent wants to | It runs | Or it gets |
|---|---|---|
| store a password the user knows | asks the user to run `komando secret set NAME` | `NEEDS_PERSON` |
| store a token a program made | `echo "$TOKEN" \| komando secret set NAME` or `--from-env VAR` | |
| preview a change | the same command with `--dry-run` | `meta.would_be_blocked` names what the real run needs |
| use a secret | `secret:NAME` in a flag | `SECRET_DESTINATION`: a person allows where it goes |
| rename, copy, remove | `secret rename`, `secret cp`, `secret rm` | |
| read or compare a value | asks the user (`secret show --reveal`, `key show --reveal`, `secret check`) | `REVEAL_NEEDS_HUMAN`, `NEEDS_PERSON` |

The agent never asks for a password in the chat: the hint names the
command the user runs in their own terminal.

## Limits

- Hiding a value in a server's output is a best effort (see
  [Safety](safety.md#limits)).
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
| `SECRET_EXISTS` (exit 8) | `secret rename` or `secret cp` to a name that is taken | pick another name, or add `--overwrite` |
| `SECRET_IN_USE` (exit 8) | `secret rm` of a secret something still uses | point those at another secret, or `secret rename` it |
| `SECRET_MISMATCH` (exit 1) | `secret check`: the value you typed is not the stored one | `data.difference` says how they differ; `komando secret set NAME` stores the right one |
| `NEEDS_PERSON` (exit 6) | only a person can do this (`secret set` for an agent, `secret check`, `secret keychain`, `secret passphrase`) | the person runs it in their own terminal |
| `VAULT_LOCKED` (exit 1) | the vault has a passphrase and `KOMANDO_VAULT_PASS` is not set | set `KOMANDO_VAULT_PASS` in the shell that runs komando (an AI agent asks the user) |
| `VAULT_DECRYPT` (exit 1) | `KOMANDO_VAULT_PASS` is not this vault's passphrase | set the right one; nothing was lost. `komando doctor` says which mode is in use |
| `VAULT_KEY` (exit 1) | the key is missing: `store.key` is gone, or the keychain item is on another computer | restore `~/.komando/store.key` from a backup, or run `komando secret keychain` on the computer whose keychain holds the key |
| `KEYCHAIN_SLOW` (exit 1) | the keychain did not answer in time, so nothing was changed | run it again in a moment; `komando doctor` if it keeps happening |
| `KEYCHAIN_FAILED` (exit 5) | the keychain could not be read, so komando could not check that the store is the newest copy; nothing was changed | a person unlocks the keychain (an AI agent asks the user), then run it again; on a computer with no working keychain, a person sets `KOMANDO_KEYCHAIN=off` |
