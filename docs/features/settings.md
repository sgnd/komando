# Settings and files

Settings, and where komando keeps its data. [All features](README.md)

```bash
komando config show
komando config set parallel 20
komando config set default_timeout 10m
komando config set host_key_policy strict    # accept-new (default) | strict | off (off needs --yes)
komando config set audit_sql hash            # full (default) | hash | off: keep SQL text out of the history
```

Everything is stored in `~/.komando/` (change with `KOMANDO_HOME`):

| File | Contains |
|------|----------|
| `state.json` | servers, conns, keys, settings |
| `vault.json`, `vault.key` | encrypted secrets and their key |
| `keys/` | SSH keys made by `komando key gen` |
| `known_hosts` | remembered server fingerprints |
| `audit.jsonl` | history of every action |

Back this folder up and keep it private. Set `KOMANDO_VAULT_PASS` before
the first secret if you prefer a passphrase over the `vault.key` file.
