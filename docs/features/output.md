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
| `NO_MATCHING_TARGETS` | the target picked only things this command can't use | follow the hint (e.g. use `komando db` for a database) |
| `TARGET_NOT_FOUND` / `TARGET_EMPTY` | a typo in a name, group or tag | the hint suggests the closest match; `komando list` |
| `TIMEOUT` | took too long | `--timeout 30m` or use `komando job start` |

`komando doctor` checks your local setup.
