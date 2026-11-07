# Results and errors

How komando answers, what the exit codes mean, how to fix common errors,
and how to see what is still running. [All features](README.md)

## Quick start

```bash
komando exec web1 -- uptime              # readable text in a terminal
komando exec web1 -o json -- uptime      # one JSON object (what agents get)
komando status                           # VPNs, tunnels and jobs still running
komando schema exec                      # every flag and exit code, machine-readable
komando doctor                           # check the local setup
```

## Text or JSON

In a terminal you get readable text. When another program (such as an AI
agent or a script) runs komando through a pipe, it gets one JSON object
instead. Force either with `-o text` or `-o json`, or set `KOMANDO_OUTPUT`.
`--pretty` indents the JSON.

An agent or script that only wants to read what ran on a server can ask
for text too: `komando exec web1 --read-only -o text -- cat /etc/hosts`
prints the server's output as it is. komando's exit code stays its own (5
when the command exits non-zero), not the command's. With several servers,
each one gets a block headed `=== web1 [ok exit=0]` (or `[FAILED exit=1]`,
`[skipped]` ...). Use JSON when you need each server's exit code or error
as data.

```json
{
  "ok": false,
  "command": "exec",
  "data": {
    "command": "uptime",
    "results": [ { "host": "web1", "ok": false, "exit_code": 3, "stdout": "", "stderr": "…" } ],
    "summary": { "total": 1, "ok": 0, "failed": 1, "failed_hosts": ["web1"] }
  },
  "error": { "code": "FAILED", "message": "host web1 failed", "hint": "…" },
  "meta": { "contract": 1, "version": "v0.3.0", "duration_ms": 211 }
}
```

| Field | Meaning |
|-------|---------|
| `ok` | `true` only when everything succeeded |
| `command` | the command, dotted (`exec`, `db.query`, `svc.restart`) |
| `data` | the result. Commands that run on many servers use `data.results[]` (one per server) and `data.summary`. Each result names its server in `host` (`exec`, `facts`, `test`, `cp` ...). `test` results also have `name`, the same value, kept for older scripts: use `host` |
| `error` | `{code, message, hint}` when `ok` is false. `data` can still be there when only some servers failed (`PARTIAL_FAILURE`) |
| `error.hint` | always says what to try next |
| `null` | komando could not find out (for example `facts` without the rights to read something). It never stands in for `0` or `false` |
| `meta` | `contract`, `version`, `duration_ms`; `dry_run` and `would_be_blocked` on a dry run; `skipped` when the target picked things this command cannot use, with the reason (also when the command then fails) |

## Exit codes

| Code | Meaning | Examples |
|------|---------|----------|
| 0 | success | |
| 1 | general error | `AUDIT_UNAVAILABLE` |
| 2 | wrong command, flag or value | `USAGE`, `HIDDEN_VALUE`, `NEEDS_TERMINAL` |
| 3 | not found | `TARGET_NOT_FOUND`, `FILE_NOT_FOUND`, `TOOL_MISSING` |
| 4 | cannot connect or log in, or the connection broke | `AUTH_FAILED`, `HOSTKEY_MISMATCH`, `VPN_LOGIN_REQUIRED`, `CONNECTION_LOST` |
| 5 | the command failed on the server | `FAILED`, `ROLLOUT_FAILED` |
| 6 | blocked for safety | `POLICY_BLOCKED`, `PROTECTED_HOST`, `WRITE_REQUIRES_FLAG` |
| 7 | timed out | `TIMEOUT`, `ROLLOUT_TIMEOUT` |
| 8 | a precondition failed or something is in the way | `fs replace` text not found or not unique, `PORT_IN_USE`, `FILE_TOO_LARGE` |

When several servers fail, the exit code is the worst one. The full
machine-readable reference is `komando schema`.

## Troubleshooting

| Error | Usually means | Try |
|-------|---------------|-----|
| `AUTH_FAILED` | wrong user, key or password | `komando host show NAME`, `komando key deploy` |
| `KEY_PASSPHRASE_REQUIRED` | the SSH key is encrypted | `komando key edit NAME --passphrase-ref secret:NAME` |
| `CONNECTION_REFUSED`, `CONNECT_TIMEOUT` | server down, wrong port, firewall | check the address and port; `--connect-timeout 30s` |
| `HOSTKEY_MISMATCH` | the server was rebuilt, or someone is intercepting | confirm with your provider first, then `komando host trust NAME --reset --yes` (a person decides; an agent reports it) |
| `SECRET_UNRESOLVED` | the stored password or environment variable is missing | `komando secret list` |
| `SECRET_IN_USE` | `secret rm` of a secret that something still uses | point them elsewhere, or rename it with `komando secret mv OLD NEW` |
| `SECRET_EXISTS` | `secret mv` or `secret cp` to a name that is taken | pick another name, or add `--overwrite` |
| `SECRET_MISMATCH` | `secret check`: the value entered is not the stored one | `data.difference` says how they differ; `komando secret set NAME` stores the right one |
| `sudo: a password is required` | sudo needs a password | `komando host edit NAME --sudo-ref secret:NAME` |
| `VPN_LOGIN_REQUIRED` | the VPN needs a person's login (MFA, sudo) | a person runs `komando vpn up NAME` once |
| `AWS_LOGIN_REQUIRED` | the AWS SSO login has expired | a person runs `komando login aws --profile NAME` |
| `POLICY_BLOCKED` | the command looks destructive | double-check it; a person may add `--allow-dangerous` |
| `PROTECTED_HOST`, `PROTECTED_TARGET` | a change to something marked protected | a person may add `--yes` |
| `SAFETY_SETTING` | a change that turns a seatbelt off | a person may add `--yes` |
| `WRITE_REQUIRES_FLAG` | a database, cache or cluster command that changes data | `--write --dry-run`, then `--write` |
| `SENSITIVE_FILE` | an AI agent tried to copy a secret file (`.env`, a private key) here | read it with `komando fs cat` (values hidden); a person may allow `--reveal` |
| `HIDDEN_VALUE` | the text holds `[hidden]` or `[secret:NAME]` | change one line with `fs replace`; set a secret with `{{secret:NAME}}` |
| `NO_MATCHING_TARGETS` | the target picked only things this command can't use | follow the hint (for example, use `komando db` for a database) |
| `TARGET_NOT_FOUND`, `TARGET_EMPTY` | a typo in a name, group or tag | the hint suggests the closest match; `komando list` |
| `PARTIAL_FAILURE` | some servers failed, others did not | read `data.results` for each server's exit code and stderr |
| `PORT_IN_USE` | the local port is taken | pick another port, or `0` for a free one |
| `NEEDS_TERMINAL` | an interactive command (`shell`) run by a program | agents use `exec`, `cluster exec` or `job` |
| `CONNECTION_LOST` | the link broke while the command ran; it may still be running, or may have finished | check with a read-only command before running it again; use `komando job start` over a shaky link ([details](commands.md#when-the-connection-drops)) |
| `TIMEOUT` | the command took too long | `--timeout 30m`, or `komando job start` for long work |

`komando doctor` checks your local setup, the inventory and its security.

## Where am I? (status lines)

When you type a command yourself, komando prints one line saying where you
are working, before it connects. It does this for the commands you stay
inside: `shell`, `db shell`, `cluster shell`, `cluster forward`,
`logs --follow` and `cluster logs -f`.

```text
komando: shell on web1 (deploy@10.0.1.5) via vpn office → bastion1
komando: shell on prod-web1 (root@10.0.0.5) · PROTECTED
komando: psql on app-db (read-only) via bastion1
komando: forwarding 127.0.0.1:8080 → svc/api:80 on prod-k8s (Ctrl-C stops)
komando: following logs on web1, web2 (Ctrl-C stops)
```

- `via` is the way there: the VPN first, then the bastions.
- A protected server or database says `PROTECTED`, in red unless `NO_COLOR`
  is set.
- When a `shell` or `db shell` ends, one more line says how:
  `komando: left web1 (exit 0, 12m)` or
  `komando: connection to web1 lost after 3m`.
- When a command connects a VPN by itself, komando says that the VPN stays
  up and how to stop it.

These lines go to stderr, and only to a person at a terminal. Agents,
scripts and pipes never get them, and the JSON output does not change.

## What is still running? (`komando status`)

Some things keep running after the command that started them: a VPN (from
`vpn up`, or connected by a command), a tunnel, or a job on a server.
`komando status` lists them all:

```text
KIND    NAME    DETAIL                                     SINCE
vpn     office  used 3m ago, closes in 26m if unused       42m
tunnel  t-3f2a  127.0.0.1:5433 → app-db                    2h
job     j-81c2  web1: pg_dump app | gzip > /backup/app...  15m
jobs run on their servers: `komando job list --refresh` shows which still run
```

It contacts nothing, so it is quick and works offline. A job stays on the
list until `komando job rm`. Whether it still runs is known only on its
server, which `komando job list --refresh` asks. Agents get the same as JSON
(`vpns`, `tunnels`, `jobs`). An idle VPN closes after `vpn_idle` (see
[Settings](settings.md)).

### Show it in your shell prompt (optional)

`komando prompt` prints a short note such as `vpn:office tun:2`, or nothing
when nothing is running, so your prompt can show it all the time. Add it
yourself; komando never changes your shell files.

zsh (also with oh-my-zsh), in `~/.zshrc`:

```zsh
setopt PROMPT_SUBST
RPROMPT='$(komando prompt)'
```

bash, in `~/.bashrc`:

```bash
PS1='$(p=$(komando prompt); [ -n "$p" ] && echo "[$p] ")'"$PS1"
```

starship, in `~/.config/starship.toml`:

```toml
[custom.komando]
command = "komando prompt"
when = true
```

It only reads komando's state file (no network, nothing written, never an
error), so it is safe to run on every prompt. It is a quick hint: a VPN
that crashed a moment ago can still show until the next komando command.
`komando status` is the full check.

## Will my scripts keep working?

Every JSON answer has `meta.contract` (now `1`). Within a contract, komando
only adds fields, error codes and commands; it never renames or removes
them, and renamed commands and flags keep working as aliases. If that ever
has to change, `meta.contract` goes up and the [changelog](../../CHANGELOG.md)
says what changed.
