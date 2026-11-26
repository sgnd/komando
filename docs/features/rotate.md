# Rotate keys and passwords, and when someone leaves

Change a key or a password everywhere komando uses it, in the right order,
and take away access when someone leaves. [All docs](README.md)

## Rotate an SSH key

Make the new key, put it on the servers, point the servers at it, check
that every server logs in with it, and only then take the old one away:

```bash
komando credential key create deploy-2 --user deploy          # a new key pair, sealed in komando's store
komando credential key install deploy-2 @web     # put its public key on the servers
komando host ssh edit @web --credential deploy-2              # komando logs in with it from then on
komando test @web                                             # every server still logs in
komando credential key uninstall deploy @web --dry-run   # how many lines the old key has
komando credential key uninstall deploy @web     # take the old key off the servers
komando credential key remove deploy                          # and out of komando (refused while a server uses it)
```

TODO(cut): the argument shape of `credential key install` and `uninstall`
for a key komando holds (the form above is a proposal) waits on the
credential key leaf options (PR B).

Typed alone, `komando credential key install` asks for the servers, then
the key.

`credential key uninstall` stops before it removes the key komando itself
still logs in with (you would lock yourself out): at your terminal you type
the name to go on; an AI agent or a script adds `--allow-dangerous` after a
person agrees.

## Rotate a server's password

Change the password on the server as you always do, then give komando the
new one. `credential password edit` replaces the value under the same
name, so every server that uses it follows:

```bash
komando credential password edit web1-pass                    # type the new one, hidden
komando test web1
```

A password several servers share is one credential: edit it once.
`komando credential list` shows each credential and what uses it.

## Rotate a database password

Store the new password as a new credential, let the database take it,
point the entry at it, check, then remove the old one:

```bash
komando credential password add prod-db-pass-2 --user app                 # the new password, typed once
komando database postgres shell prod-db                                   # a person changes it in the database
komando database postgres edit prod-db --credential prod-db-pass-2        # komando logs in with it from then on
komando test prod-db
komando credential password remove prod-db-pass                           # the old one
```

On a protected entry, `edit` asks you first at your terminal; an AI agent
or a script adds `--yes` after a person agrees (see
[Safety](safety.md#what-needs-a-yes)).

A password never goes into a query or onto a command line, so a person
sets it in the database from the `shell`. TODO(cut): a ready-made snippet
that sets a database user's password from a credential waits on its row.

## When someone leaves

1. Take their SSH key off every server, by its public key:

   ```bash
   komando credential key uninstall all --public-key-file ~/keys/alice.pub --dry-run
   komando credential key uninstall all --public-key-file ~/keys/alice.pub
   ```

   TODO(cut): `--public-key-file` on `uninstall` waits on the credential
   key leaf options (PR B). Until then, remove the line from the server's
   `~/.ssh/authorized_keys` with `komando host ssh exec`.

2. Lock their own account on the servers (or remove it later). Locking an
   account is a plain command; deleting it is stopped by the `userdel`
   rule:

   ```bash
   komando host ssh exec all --sudo -- usermod -L -e 1 alice
   ```

3. Change every password they knew: `komando credential list` shows each
   credential; rotate them as above.
4. Did they know the vault's passphrase? Give it a new one:
   `komando config vault passphrase` (then set the new `KOMANDO_VAULT_PASS`
   wherever you use it).
5. See what they did with komando:

   ```bash
   komando audit list --actor alice --since 30d
   ```

`--actor` matches the name in `KOMANDO_ACTOR`, the AI agent (`claude`,
`codex` ...) or the computer account that ran komando.

## Limits

- `credential key remove` is refused while a server still uses the key:
  point those servers at the new key first (`komando host ssh edit
  TARGET --credential NEW`).
- `credential key uninstall` removes the key from `~/.ssh/authorized_keys`
  of the login user, or of `--user NAME` (with sudo). Keys in other users'
  files stay.
- Lost: `host ca revoke`, the never-trust list of host CAs. A stolen signed
  key cannot be cut off without replacing the CA. The workaround is to
  remove the CA (`komando credential certificate remove NAME`) and sign
  every key again. This is a security gap.
- `audit list --actor` finds only what was done through komando.

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `POLICY_BLOCKED` (exit 6) | `credential key uninstall` of the key komando logs in with | point the servers at another key with `komando host ssh edit TARGET --credential NEW` first |
| `KEY_IN_USE` (exit 8) | `credential key remove` of a key a server still uses | point the server at another key first |
| `KEY_EXISTS` (exit 8) | `credential key create` to a name that is taken | choose another name, or `komando credential key remove NAME` first |
| `PROTECTED_TARGET` (exit 6) | a change on a protected server or entry | at your terminal komando asks first; a script adds `--yes` |
| `AUTH_FAILED` (exit 4) | the new key or password does not log in | check it before you remove the old one; see [Results and errors](output.md#troubleshooting) |
