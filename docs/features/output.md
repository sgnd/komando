# Results and errors

How komando answers, exit codes, and fixing common errors. [All features](README.md)

## Reading the results

In a terminal you get readable text. When another program (like an AI agent)
runs komando, it gets one JSON object instead. Force either with `-o text` or
`-o json`.

```json
{
  "ok": false,
  "command": "exec",
  "data": { "results": [ { "host": "web1", "ok": false, "exit_code": 3, "stdout": "", "stderr": "…" } ] },
  "error": { "code": "FAILED", "message": "host web1 failed", "hint": "…" },
  "meta": { "version": "0.1.0", "duration_ms": 211 }
}
```

`error.hint` always says what to try next. When a target picked things the
command cannot work with, `meta.skipped` lists them with the reason (also
when the command then fails).

| Exit code | Meaning |
|-----------|---------|
| 0 | success |
| 1 | general error |
| 2 | wrong command or flag |
| 3 | not found (server, file, key…) |
| 4 | cannot connect or log in |
| 5 | the command failed on the server |
| 6 | blocked for safety |
| 7 | timed out |
| 8 | edit precondition failed (text not found / not unique) |

The full machine-readable reference is `komando schema`.

## Where am I? (status lines)

When you type a command yourself, komando says on one line where you are
working, before it connects. It does this for the commands you stay inside:
`shell`, `db shell`, `cluster forward` and `logs --follow`.

```
komando: shell on web1 (deploy@10.0.1.5) via vpn office → bastion1
komando: shell on prod-web1 (root@10.0.0.5) · PROTECTED
komando: psql on app-db (read-only) via bastion1
komando: forwarding 127.0.0.1:8080 → svc/api:80 on prod-k8s (Ctrl-C stops)
komando: following logs on web1, web2 (Ctrl-C stops)
```

`via` is the way there: the VPN first, then the bastions. A protected
server or database says `PROTECTED`, in red unless `NO_COLOR` is set. When a
`shell` or `db shell` ends, one more line says how:
`komando: left web1 (exit 0, 12m)`, or `komando: connection to web1 lost after 3m`.
When a command connects a VPN by itself, komando says it stays up and how to
stop it.

These lines go to stderr and only to a person at a terminal. Agents, scripts
and pipes never get them, and the JSON output does not change.

## What is still running? (`komando status`)

Some things keep running after the command that started them: a VPN (from
`vpn up`, or connected by a command), a tunnel, a job on a server.
`komando status` lists them all:

```
KIND    NAME    DETAIL                                     SINCE
vpn     office  used 3m ago, closes in 26m if unused       42m
tunnel  t-3f2a  127.0.0.1:5433 → app-db                    2h
job     j-81c2  web1: pg_dump app | gzip > /backup/app...  15m
jobs run on their servers: `komando job list --refresh` shows which still run
```

It contacts nothing, so it is quick and works offline. A job stays on the
list until `komando job rm`; whether it still runs is known on its server,
which `komando job list --refresh` asks. Agents get the same as JSON
(`vpns`, `tunnels`, `jobs`).

## Will my scripts keep working?

Every JSON answer has `meta.contract` (now `1`). Within a contract, komando
only adds fields, error codes and commands; it never renames or removes
them, and renamed commands and flags keep working as aliases. If that ever
has to change, `meta.contract` goes up and the changelog says what changed.

## Troubleshooting

| Error | Usually means | Try |
|-------|---------------|-----|
| `AUTH_FAILED` | wrong user, key or password | `komando host show NAME`, `komando key deploy` |
| `CONNECTION_REFUSED` / `CONNECT_TIMEOUT` | server down, wrong port, firewall | check address and port, `--connect-timeout 30s` |
| `HOSTKEY_MISMATCH` | server rebuilt — or someone intercepting | confirm with your provider, then `komando host trust NAME --reset` |
| `SECRET_UNRESOLVED` | stored password or env var missing | `komando secret list` |
| `sudo: a password is required` | sudo needs a password | `komando host edit NAME --sudo-ref secret:NAME` |
| `POLICY_BLOCKED` | looks destructive | double-check; a human may add `--allow-dangerous` |
| `PROTECTED_HOST` / `PROTECTED_TARGET` | a change to something marked protected | a human may add `--yes` |
| `SAFETY_SETTING` | a change that turns a seatbelt off | a human may add `--yes` |
| `SENSITIVE_FILE` | an AI agent tried to copy a secret file (`.env`, a private key) here | read it with `komando fs cat` (values hidden); a human may allow `--reveal` |
| `HIDDEN_VALUE` | the text holds `[hidden]` or `[secret:NAME]` | change one line with `fs replace`, set a secret with `{{secret:NAME}}` |
| `NO_MATCHING_TARGETS` | the target picked only things this command can't use | follow the hint (e.g. use `komando db` for a database) |
| `TARGET_NOT_FOUND` / `TARGET_EMPTY` | a typo in a name, group or tag | the hint suggests the closest match; `komando list` |
| `TIMEOUT` | took too long | `--timeout 30m` or use `komando job start` |

`komando doctor` checks your local setup.
