# Rotate keys and passwords, and when someone leaves

Change a key or a password everywhere komando uses it, in the right order,
and take away access when someone leaves. [All features](README.md)

## Rotate an SSH key

Make the new key, put it on the servers, check that every server logs in
with it, and only then take the old one away:

```bash
komando key gen deploy-2026                          # a new key pair
komando key deploy deploy-2026 @web --set-default    # on the servers, and komando logs in with it from now on
komando test @web                                    # every server still logs in
komando key revoke deploy @web --dry-run             # how many lines the old key has
komando key revoke deploy @web                       # take the old key off the servers
komando key rm deploy                                # and out of komando (refused while a server uses it)
```

`key revoke` refuses to remove the key komando itself still logs in with
(you would lock yourself out) unless you add `--allow-dangerous`.

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
komando secret set app-db-pass-2                                  # the new password, typed once
komando db user passwd app-db app --password-ref secret:app-db-pass-2
komando conn edit app-db --password-ref secret:app-db-pass-2      # komando logs in with it from now on
komando test app-db
komando secret rm app-db-pass                                     # the old one
```

On a protected conn, `db user passwd` and `conn edit` need `--yes`.

## When someone leaves

1. Take their SSH key off every server, by its public key file or line:

   ```bash
   komando key revoke ~/keys/budi.pub all --dry-run
   komando key revoke ~/keys/budi.pub all
   ```

2. Lock their own account on the servers (or remove it later):

   ```bash
   komando user lock @prod budi
   ```

3. Change every password they knew: `komando secret list` shows each secret
   and what uses it; rotate them as above.
4. Did they know the vault's passphrase? Give it a new one:
   `komando secret passphrase` (then set the new `KOMANDO_VAULT_PASS`
   wherever you use it).
5. See what they did with komando:

   ```bash
   komando audit --actor budi --since 30d
   ```

`--actor` matches the name in `KOMANDO_ACTOR`, the AI agent (`claude`,
`codex` ...) or the computer account that ran komando.
