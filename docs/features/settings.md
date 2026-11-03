# Settings and files

Settings, and where komando keeps its data. [All features](README.md)

```bash
komando config show                          # KEY VALUE DEFAULT ALLOWED
komando config get parallel
komando config set parallel 20
komando config set default_timeout 10m
komando config set host_key_policy strict    # accept-new (default) | strict | off (off needs --yes)
komando config set audit_sql hash            # full (default) | hash | off: keep SQL text out of the history
```

| Key | Values | Default |
|-----|--------|---------|
| `host_key_policy` | `accept-new`, `strict`, `off` (off needs `--yes`) | `accept-new` |
| `default_user` | a login name; empty = your own user name | |
| `default_timeout` | a duration above 0 (`30s`, `5m`, `1h`) | `5m` |
| `connect_timeout` | a duration above 0 | `15s` |
| `parallel` | 1 or more | `10` |
| `max_output_bytes` | 1024 or more | `262144` |
| `audit` | `on`, `off` (off needs `--yes`) | `on` |
| `audit_sql` | `full`, `hash`, `off` (off needs `--yes`) | `full` |
| `vpn_idle` | a duration; `0` = never close | `30m` |

A value that starts with `-` goes after `--`: `komando config set vpn_idle -- 0`
(negative values are refused anyway). Every change is in `komando audit`
with the old and new value.

Everything is stored in `~/.komando/` (change with `KOMANDO_HOME`):

| File | Contains |
|------|----------|
| `state.json` | servers, conns, keys, settings |
| `vault.json`, `vault.key` | encrypted secrets and their key |
| `keys/` | SSH keys made by `komando key gen` |
| `known_hosts` | remembered server fingerprints |
| `audit.jsonl` | history of every action |
| `bitwarden-device` | this computer's device id for Bitwarden/Vaultwarden |

Back this folder up and keep it private. Set `KOMANDO_VAULT_PASS` before
the first secret if you prefer a passphrase over the `vault.key` file.
