# Settings and files

Settings, and where komando keeps its data. [All features](README.md)

```bash
komando config show                          # KEY VALUE DEFAULT ALLOWED
komando config get parallel
komando config set parallel 20
komando config set default_timeout 10m
komando config set host_key_policy strict    # accept-new (default) | strict | off (off needs --yes)
komando config set audit_sql hash            # full (default) | hash | off: keep SQL text out of the history
komando config set audit_syslog tls://siem.example:6514 --yes   # also send the audit to a log server
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
| `audit_syslog` | `udp://HOST:514`, `tcp://HOST:514`, `tls://HOST:6514`, `off` (changing it needs `--yes`) | `off` |
| `vpn_idle` | a duration; `0` = never close | `30m` |

A value that starts with `-` goes after `--`: `komando config set vpn_idle -- 0`
(negative values are refused anyway). Every change is in `komando audit`
with the old and new value.

With `audit_syslog` set, each audit record also goes to a log server (a
SIEM) as it is written: syslog (RFC 5424, facility authpriv, program
`komando`, message id `audit`, the record's JSON as the message), over UDP,
TCP or TLS (octet-counted, RFC 5425). The local log stays the record: a log
server that does not answer is said once on stderr, and the command goes on.
A copy on another machine is what keeps the history when someone with your
user account rewrites the local file.

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
