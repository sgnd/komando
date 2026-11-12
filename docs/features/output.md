# Results and errors

How komando answers, what the exit codes mean, how to fix common errors,
and how to see what is still running. [All docs](README.md)

## Quick start

```bash
komando exec web1 -- uptime              # readable text in a terminal
komando exec web1 -o json -- uptime      # one JSON object (what agents get)
komando status                           # VPNs, tunnels and jobs still running
komando schema exec                      # every flag of exec, machine-readable
komando schema fs.ls                     # an old name or command ID: shows the command it runs (fs list)
komando schema                           # also every exit code and error code
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
  "error": { "code": "FAILED", "message": "server web1 failed", "hint": "…" },
  "meta": { "contract": 1, "version": "v0.12.0", "duration_ms": 211 }
}
```

| Field | Meaning |
|-------|---------|
| `ok` | `true` only when everything succeeded |
| `command` | the command, dotted (`exec`, `db.query`, `svc.restart`) |
| `data` | the result. Commands that run on many servers use `data.results[]` (one per server) and `data.summary`. Each result names its server in `host` (`exec`, `facts`, `test`, `cp` ...). `test` results also have `name`, the same value, kept for older scripts: use `host` |
| `error` | `{code, message, hint}` when `ok` is false. `data` can still be there when servers failed (`PARTIAL_FAILURE`) |
| `error.hint` | always says what to try next. Most codes give their own hint; when one gives none, komando puts in a general hint for the exit code (for example, exit 7 suggests `--timeout` or `komando job start`) |
| `null` | komando could not find out (for example `facts` without the rights to read something). It never stands in for `0` or `false` |
| `meta` | `contract`, `version`, `duration_ms`; `dry_run` and `would_be_blocked` on a dry run; `skipped` when the target picked things this command cannot use, with the reason (also when the command then fails); `host_keys_pinned` when the command trusted a server's SSH host key for the first time (`host`, `address`, `key_type`, `fingerprint`), for the person to compare with the server's own; `deprecated` (`used`, `now`) when the command used an old flag or argument shape that still works; `truncated` when a list stopped at `--limit` and there is more (`--limit 0` shows all) |

## Exit codes

| Code | Meaning | Examples |
|------|---------|----------|
| 0 | success | |
| 1 | general error | `AUDIT_UNAVAILABLE` |
| 2 | wrong command, flag or value | `USAGE`, `HIDDEN_VALUE`, `NEEDS_TERMINAL` |
| 3 | not found | `TARGET_NOT_FOUND`, `FILE_NOT_FOUND`, `TOOL_MISSING`, `SECRET_NOT_FOUND`, `SECRET_UNRESOLVED` |
| 4 | cannot connect or log in, or the connection broke | `AUTH_FAILED`, `NO_AUTH`, `HOSTKEY_MISMATCH`, `VPN_LOGIN_REQUIRED`, `CONNECTION_LOST` |
| 5 | the command failed on the server | `FAILED`, `ROLLOUT_FAILED` |
| 6 | blocked for safety | `POLICY_BLOCKED`, `PROTECTED_HOST`, `WRITE_REQUIRES_FLAG` |
| 7 | timed out | `TIMEOUT`, `CONNECT_TIMEOUT` (the server did not answer within `--connect-timeout`), `ROLLOUT_TIMEOUT` |
| 8 | a precondition failed or something is in the way | `fs replace` text not found or not unique, `PORT_IN_USE`, `FILE_TOO_LARGE` |

When several servers fail, the exit code is the worst one. The full
machine-readable reference is `komando schema`.

## Troubleshooting

The table below has the errors people meet most. Every code komando gives,
with its exit code, an example message and the usual next step, is in
[Error codes](error-codes.md), and in `komando schema` under `error_codes`:

```bash
komando schema -o json | python3 -c 'import json,sys; [print(c["code"], c["exit"], c.get("example","")) for c in json.load(sys.stdin)["data"]["error_codes"]]'
```

| Error | Usually means | Try |
|-------|---------------|-----|
| `AUTH_FAILED` | wrong user, key or password; or the server asks for a two-factor code and no person is at a terminal to answer it (the message quotes its question) | `komando host show NAME`; a changed password: `komando secret set NAME`; a two-factor login: `komando login NAME` once in your terminal (it asks the code and keeps the login, 8h; an AI agent asks the user to run it) |
| `NO_AUTH` | the server has no key, identity or password, ssh-agent holds no key, and no person is at a terminal to type a password (the message says if `~/.ssh/id_ed25519` is encrypted and not loaded) | `ssh-add` (or `ssh-add ~/.ssh/id_ed25519`), or save a password: `komando secret set NAME`, then `komando host edit NAME --password-ref secret:NAME` (or `--key KEY`); start ssh-agent first if `SSH_AUTH_SOCK` is not set |
| `KEY_PASSPHRASE_REQUIRED` | the server's key (`--key` or `--identity`) is encrypted, has no passphrase in the vault, and ssh-agent does not hold it (komando uses the agent's copy, as `ssh` does) | `ssh-add PATH`, or store the passphrase: `komando secret set NAME`, `komando key add NAME PATH --passphrase-ref secret:NAME`, then `komando host edit HOST --key NAME --unset identity` (for a `--key` key: `komando key edit NAME --passphrase-ref secret:NAME`) |
| `CONNECTION_REFUSED`, `CONNECT_TIMEOUT`, `DNS_ERROR` | the server is down, the address or port is wrong, a firewall drops the connection, or nothing listens on the port | `komando host show NAME` to check the address and port; a slow link: `--connect-timeout 30s`; a private server: add `--via BASTION` or a VPN |
| `HOSTKEY_MISMATCH` | the server was rebuilt, or someone is intercepting; the message shows the pinned fingerprint and the one the server shows now | compare the new fingerprint with the server's console or your provider first, then `komando host trust NAME --reset --yes`, or `@group` for many at once (a person decides; an agent reports it) |
| `SECRET_UNRESOLVED` | the stored password or environment variable is missing | `komando secret list` |
| `SECRET_IN_USE` | `secret rm` of a secret that something still uses | point them elsewhere, or rename it with `komando secret rename OLD NEW` |
| `SECRET_EXISTS` | `secret rename` or `secret cp` to a name that is taken; `vpn add` whose keys would go into a secret that exists (`NAME-key`, `NAME-psk`, `NAME-config`) and is not that VPN's own | pick another name, or add `--overwrite` (`secret rename`, `secret cp`); for `vpn add`, pick another VPN name or move the secret away with `komando secret rename` |
| `NAME_TAKEN` | a new name (from `host rename`, `rename --starts-with`, ...) is used already; for `rename` the message lists every clash, and nothing was renamed | pick other names, or rename or remove what is in the way; `--dry-run` shows the whole list first |
| `NOTHING_TO_RENAME` | `rename --starts-with`: no name starts with OLD | check the spelling and case with `komando list` and `komando secret list` |
| `GROUP_EXISTS` | `group rename` to the name of another group | pick another name, or merge them: `komando group add NEW @OLD`, then `komando group rm OLD` |
| `KEY_FILE_EXISTS` | `key gen` or `key rename`: a file of that name is in `~/.komando/keys` | move it away, or pick another name |
| `SECRET_MISMATCH` | `secret check`: the value entered is not the stored one | `data.difference` says how they differ; `komando secret set NAME` stores the right one |
| `sudo: a password is required` | sudo needs a password | `komando secret set NAME`, then `komando host edit HOST --sudo-ref secret:NAME` |
| `VPN_LOGIN_REQUIRED` | the VPN needs a person's login (MFA) | a person runs `komando vpn up NAME` once |
| `AWS_LOGIN_REQUIRED` | the AWS SSO login has expired | a person runs `komando login aws --profile NAME` |
| `AZURE_LOGIN_REQUIRED` | no Azure login was found (for an Azure Container Registry) | set a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), run on Azure with a managed identity, or a person runs `az login` |
| `GCP_LOGIN_REQUIRED` | the Google login has run out (for Google Artifact Registry) | a person runs `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` to a key file |
| `POLICY_BLOCKED` | the command looks destructive | double-check it; a person may add `--allow-dangerous` |
| `PROTECTED_HOST`, `PROTECTED_TARGET` | a change to something marked protected | a person may add `--yes` |
| `SAFETY_SETTING` | a change that turns a seatbelt off | a person may add `--yes` |
| `SECRET_DESTINATION` | an AI agent asked to send a secret somewhere new (`{{secret:NAME}}`, `--env K=secret:NAME`, a password on a new address) | tell the user which secret goes where; a person may add `--yes` |
| `NEEDS_PERSON` | an AI agent asked for something only a person can do: type a password into `secret set`, compare one with `secret check`, set the approval code | the agent asks the user to run the command in their own terminal; no flag lets an agent do it |
| `HOSTKEY_REVOKED` | the server shows a host key that was revoked (an `@revoked` line `komando seal` carried over) | treat the server as compromised; nothing was sent |
| `NEEDS_SEAL` | the komando folder holds the files of an earlier komando, not yet moved into the sealed store | the agent asks the user to run `komando seal` in their own terminal; every other command stops until then |
| `WRITE_REQUIRES_FLAG` | a database, cache or cluster command that changes data | `--write --dry-run`, then `--write` |
| `SENSITIVE_FILE` | an AI agent tried to copy a secret file (`.env`, a private key) here | read it with `komando fs cat` (values hidden); a person may allow `--reveal` |
| `HIDDEN_VALUE` | the text holds `[hidden]` or `[secret:NAME]` | change one line with `fs replace`; set a secret with `{{secret:NAME}}` |
| `NO_MATCHING_TARGETS` | the target picked only things this command can't use | follow the hint (for example, use `komando db` for a database) |
| `TARGET_NOT_FOUND`, `HOST_NOT_FOUND`, `CONN_NOT_FOUND`, `TARGET_EMPTY` | a typo in a name, group or tag (`exec` says `HOST_NOT_FOUND`, `test` and `list` say `TARGET_NOT_FOUND`: the same problem) | the hint suggests the closest match; `komando list` |
| `HOSTKEY_UNKNOWN` | host keys are strict and this server's key is not pinned yet; the message shows its fingerprint | compare it with what the server's owner sees, then `komando host trust NAME` |
| `VAULT_LOCKED`, `VAULT_DECRYPT`, `VAULT_KEY` | the vault cannot be opened: no passphrase, a wrong one, or its key file is gone | set `KOMANDO_VAULT_PASS` in the shell that runs komando; `komando doctor` says which |
| `IMPORT_INCOMPLETE` | an import brought most things in but refused some (see `skipped`) | fix those entries in the file and import again |
| `PARTIAL_FAILURE` | the command ran on several servers and at least one failed (with one server you get that server's own code, such as `CONNECTION_REFUSED`) | read `data.results` for each server's exit code and stderr |
| `USAGE` | a wrong command, flag or value; also `komando` alone or a group such as `komando db` without its sub-command, when piped | the message says what is wrong, often with "did you mean"; the hint gives an example or lists the sub-commands |
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
- On a terminal that cannot show them (`TERM=dumb`, or a locale such as
  `LANG=C` that is not UTF-8), komando writes the marks in its own lines (errors,
  hints, warnings) in ASCII: `+` for ✓, `x` for ✗, `*` for ●, `->` for →,
  `-` for ·. A result (a file, a row, a log line) is always shown as it is.
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
tunnel  t1108-195255-ab12cd34  127.0.0.1:5433 → app-db      2h
job     j1108-193010-9f8e7d6c  web1: tar czf /backup/www.tgz…  15m
jobs run on their servers: `komando job list --refresh` shows which still run
```

It contacts nothing, so it is quick and works offline. A job stays on the
list until `komando job rm`. Whether it still runs is known only on its
server, which `komando job list --refresh` asks. Agents get the same as JSON
(`vpns`, `logins`, `tunnels`, `jobs`). An idle VPN closes after `vpn_idle` (see
[Settings](settings.md)).

### Show it in your shell prompt (optional)

`komando status --short` prints a short note such as `vpn:2 tun:1` (how many VPNs and tunnels are up), or nothing
when nothing is running, so your prompt can show it all the time. Add it
yourself; komando never changes your shell files.

zsh (also with oh-my-zsh), in `~/.zshrc`:

```zsh
setopt PROMPT_SUBST
RPROMPT='$(komando status --short)'
```

bash, in `~/.bashrc`:

```bash
PS1='$(p=$(komando status --short); [ -n "$p" ] && echo "[$p] ")'"$PS1"
```

starship, in `~/.config/starship.toml`:

```toml
[custom.komando]
command = "komando status --short"
when = true
```

It only reads komando's state file (no network, nothing written, never an
error, no JSON), so it is safe to run on every prompt. `komando prompt` is
its old name and keeps working. It is a quick hint: a VPN
that crashed a moment ago can still show until the next komando command.
`komando status` is the full check.

## Will my scripts keep working?

Every JSON answer has `meta.contract` (now `1`). Within a contract, komando
only adds fields, error codes and commands; it never renames or removes
them, and renamed commands and flags keep working as aliases. If that ever
has to change, `meta.contract` goes up and the [changelog](../../CHANGELOG.md)
says what changed.
