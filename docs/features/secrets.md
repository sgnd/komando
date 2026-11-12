# Secrets

Save a password, key passphrase or token once, then point to it as
`secret:NAME` instead of typing it. komando never prints a saved value.

## Quick start

```bash
komando secret set web1-pass                          # type or paste it after the prompt, nothing is shown
komando host edit web1 --password-ref secret:web1-pass
komando test web1
komando secret list                                   # names, when they changed, what uses them
```

## Save one

At your terminal, `komando secret set NAME` asks for the value and hides it
as you type or paste. Paste it *after* the prompt appears. A paste of more
than one line (a key, a certificate) stores nothing; give such a value on
stdin instead:

```bash
komando secret set web1-pass                   # asks, hidden
komando secret set db-pass --from-env DB_PASS  # from an environment variable
pbpaste | komando secret set vpn-pass          # from the clipboard (xclip -o on Linux)
komando secret set tls-key < server.key        # a value of several lines
```

- A value on the command line (`komando secret set NAME VALUE`) is refused
  with `SECRET_IN_ARGS`: it would stay in your shell history.
- An empty value (an empty pipe, an empty variable, Enter at the prompt)
  stores nothing.
- From a pipe, the line break at the end is not part of the value. Spaces
  are kept; komando warns when the value starts or ends with one.
- `secret set` on a name that exists replaces its value. When a protected
  server or conn uses it, komando asks first (`--yes` in a script).

## Use one

Every `--password-ref`, `--sudo-ref`, `--passphrase-ref` and VPN key flag
takes a reference:

```bash
komando host edit web1 --sudo-ref secret:web1-sudo
komando conn add app-db postgres://app@10.0.0.5/shop --password-ref secret:app-db-pass
komando key add work ~/.ssh/id_work --passphrase-ref secret:work-pass
komando exec web1 --env DB_PASS=secret:app-db-pass -- ./migrate.sh
komando fs replace web1 /srv/app/.env --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:app-db-pass}}' --backup
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
komando secret check web1-pass    # type the value you think it is: match or how they differ
```

`secret check` never shows either value: it says whether they match, or
whether they differ only in spaces at the ends, only in upper and lower
case, or in length. Only a person can run it. A person at a terminal can
print a value with `komando secret show NAME --reveal` (for example piped
into `pbcopy`).

## Rename, copy and remove

```bash
komando secret rename vpn-password office-vpn-pass --dry-run   # what would change
komando secret rename vpn-password office-vpn-pass             # every server, conn, key and VPN follows
komando secret cp db-pass db-pass-old                      # a copy; nothing else changes
komando secret rm old-pass other-old-pass                  # all of them, or none
```

- `secret rename` points every server, conn, key and VPN that used `secret:OLD`
  at `secret:NEW` in the same step (conn URL options such as
  `?ca=secret:OLD` too). Scripts and files of your own are not changed.
- When NEW exists, add `--overwrite`; what uses NEW then gets the value of OLD.
- `secret rm` is refused while anything uses a name (`SECRET_IN_USE` lists
  what does); point those at another secret first, or rename it.

## Where they are kept, and the key

Secrets are sealed with AES-256-GCM in `~/.komando/store.db`. The key that
opens them is in the OS keychain, or in `~/.komando/store.key` where there is
no keychain, or comes from a passphrase in `KOMANDO_VAULT_PASS`.

```bash
komando doctor                     # which of the three is in use, and any warning
komando secret keychain            # move the key from store.key into the keychain
komando secret passphrase          # give the store a passphrase, or change it
komando secret passphrase --dry-run
```

komando uses the keychain on its own only when a new store makes its key,
and to keep the store's change count beside a key that is there. It leaves
the keychain alone with `KOMANDO_KEYCHAIN=off` (CI, containers, test runs),
where there is no keychain tool, and on a Mac whose user has no default
keychain (a changed `HOME`): the key then goes into `store.key`, and
`komando doctor` says so. It never makes macOS ask where to keep it.

Both commands change where the key is, so only a person at a terminal runs them;
`--dry-run` previews them for anyone. Details: [Settings and files](settings.md#where-the-vaults-key-lives).

## For AI agents

An agent never sees a value: output shows `[secret:NAME]` or `[hidden]`.

| The agent wants to | It runs | Or it gets |
|---|---|---|
| store a password the user knows | asks the user to run `komando secret set NAME` | `NEEDS_PERSON` |
| store a token a program made | `echo "$TOKEN" \| komando secret set NAME` or `--from-env VAR` | |
| preview a change | the same command with `--dry-run` | `meta.would_be_blocked` names what the real run needs |
| use a secret | `secret:NAME` in a flag | `SECRET_DESTINATION`: a person allows where it goes |
| rename, copy, remove | `secret rename`, `secret cp`, `secret rm` | |
| read or compare a value | asks the user (`secret show --reveal`, `secret check`) | `REVEAL_NEEDS_HUMAN`, `NEEDS_PERSON` |

The agent never asks for a password in the chat: the hint names the
command the user runs in their own terminal.
