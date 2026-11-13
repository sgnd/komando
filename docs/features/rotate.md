# Rotate keys and passwords, and when someone leaves

Change a key or a password everywhere komando uses it, in the right order,
and take away access when someone leaves. [All docs](README.md)

## Rotate an SSH key

Make the new key, put it on the servers, check that every server logs in
with it, and only then take the old one away:

```bash
komando key gen deploy-2                          # a new key pair, sealed in komando's store
komando key deploy deploy-2 @web --set-default    # on the servers, and komando logs in with it from then on
komando test @web                                 # every server still logs in
komando key revoke deploy @web --dry-run          # how many lines the old key has
komando key revoke deploy @web                    # take the old key off the servers
komando key rm deploy                             # and out of komando (refused while a server uses it)
```

Typed alone, `komando key deploy` asks for the key, then the servers.

`key revoke` stops before it removes the key komando itself still logs in
with (you would lock yourself out): at your terminal you type the name to
go on; an AI agent or a script adds `--allow-dangerous` after a person
agrees.

## Rotate a server's password

Change the password on the server as you always do, then give komando the
new one. It replaces the old value under the same name, so every server
that uses it follows:

```bash
komando host edit web1 --ask-password        # type the new one (stored as secret:web1-pass)
komando test web1
```

A password several servers share: `komando secret set NAME` with the
secret's name (`komando secret list` shows what uses each one).

## Rotate a database password

Store the new password under a new name, let the database take it, point
the conn at it, check, then remove the old one:

```bash
komando secret set prod-db-pass-2                                 # the new password, typed once
komando db user passwd prod-db app --password-ref secret:prod-db-pass-2
komando conn edit prod-db --password-ref secret:prod-db-pass-2    # komando logs in with it from then on
komando test prod-db
komando secret rm prod-db-pass                                    # the old one
```

On a protected conn, `db user passwd` and `conn edit` ask you first at your
terminal; an AI agent or a script adds `--yes` after a person agrees (see
[Safety](safety.md#what-needs-a-yes)).

## When someone leaves

1. Take their SSH key off every server, by its public key file or line:

   ```bash
   komando key revoke ~/keys/alice.pub all --dry-run
   komando key revoke ~/keys/alice.pub all
   ```

2. Lock their own account on the servers (or remove it later):

   ```bash
   komando user lock all alice
   ```

3. Change every password they knew: `komando secret list` shows each secret
   and what uses it; rotate them as above.
4. Did they know the vault's passphrase? Give it a new one:
   `komando secret passphrase` (then set the new `KOMANDO_VAULT_PASS`
   wherever you use it).
5. See what they did with komando:

   ```bash
   komando audit --actor alice --since 30d
   ```

`--actor` matches the name in `KOMANDO_ACTOR`, the AI agent (`claude`,
`codex` ...) or the computer account that ran komando.

## Limits

- `key rm` is refused while a server still uses the key: point those
  servers at the new key first (`key deploy --set-default` does it).
- `key revoke` removes the key from `~/.ssh/authorized_keys` of the login
  user, or of `--user NAME` (with sudo). Keys in other users' files stay.
- `audit --actor` finds only what was done through komando.

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `POLICY_BLOCKED` (exit 6) | `key revoke` of the key komando logs in with | deploy another key with `--set-default` first |
| `KEY_IN_USE` (exit 8) | `key rm` of a key a server still uses | point the server at another key first |
| `KEY_EXISTS` (exit 8) | `key gen` to a name that is taken | choose another name, or `komando key rm NAME` first |
| `PROTECTED_HOST`, `PROTECTED_TARGET` (exit 6) | a change on a protected server or conn | at your terminal komando asks first; a script adds `--yes` |
| `AUTH_FAILED` (exit 4) | the new key or password does not log in | check it before you remove the old one; see [Results and errors](output.md#troubleshooting) |
