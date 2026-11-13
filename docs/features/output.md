# Results and errors

How komando answers, what the exit codes mean, how to fix common errors,
and how to see what is still running. [All docs](README.md)

## Read a result

```bash
komando exec web1 -- uptime              # readable text in a terminal
komando exec web1 -o json -- uptime      # one JSON object (what agents get)
komando status                           # VPNs, logins, tunnels and jobs still running
komando doctor                           # check the local setup
```

In a terminal you get readable text. When another program (such as an AI
agent or a script) runs komando through a pipe, it gets one JSON object
instead. Force either with `-o text` or `-o json`, or set `KOMANDO_OUTPUT`.
`--pretty` indents the JSON.

An agent or script that only wants to read what ran on a server can ask
for text too: `komando exec web1 --read-only -o text -- cat /etc/hosts`
prints the server's output as it is. komando's exit code stays its own (5
when the command exits non-zero), not the command's. With several servers,
each one gets a block headed `=== web1 [ok, exit 0]` (or `[failed: exit 1]`,
`[skipped]` ...). Use JSON when you need each server's exit code or error
as data.

Text from servers, databases and pods is made safe for your terminal
first: colours stay, but escape sequences that move the cursor, set the
window title or write the clipboard, hidden text (`ESC[8m`), other control
characters and bidi overrides (`U+202E`, which shows text in another order
than it runs) are printed as `\e`, `\xNN` and `\u202e`. A carriage return
stays, so progress bars work, except on a line that starts with a server's
or pod's name (`[web1] ...`): there it shows as `\r`, so a server cannot
print over the name. JSON keeps the bytes as they are, escaped the JSON
way.

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
  "meta": { "contract": 1, "version": "…", "duration_ms": 211 }
}
```

| Field | Meaning |
|-------|---------|
| `ok` | `true` only when everything succeeded |
| `command` | the command's ID: its words joined by dots (`exec`, `db.query`, `fs.list`, `secret.show`). `komando audit --command` takes the same IDs |
| `data` | the result. Commands that run on many servers use `data.results[]` (one per server) and `data.summary`. Each result names its server in `host` (`exec`, `facts`, `test`, `cp` ...) |
| `error` | `{code, message, hint}` when `ok` is false. `data` can still be there when servers failed (`PARTIAL_FAILURE`) |
| `error.thing` | for a code several kinds of item share (`KEY_NOT_FOUND`, `NOT_FOUND`, `CONN_NOT_FOUND`, `REGISTRY_NOT_FOUND`, `K8S_NOT_FOUND`): which one it is about, such as `ssh_key` or `cache_key`. Left out otherwise. [Error codes](error-codes.md#codes-shared-by-several-things) lists every value |
| `error.suggestion` | for a typo: the name komando thinks you meant (a command, a server, a flag). The hint is then the whole command line with it in place. A word from another tool (`ps`, `kubectl`, `psql`) gets the komando command that does that job. Left out otherwise |
| `error.hint` | always says what to try next. Most codes give their own hint; when one gives none, komando puts in a general hint for the exit code (for example, exit 7 suggests `--timeout` or `komando job start`) |
| `null` | komando could not find out (for example `facts` without the rights to read something). It never stands in for `0` or `false` |
| `meta` | `contract`, `version`, `duration_ms`; `dry_run` and `would_be_blocked` on a dry run, `would_need` (every approval flag the real run needs) and `not_simulated` (steps the dry run could not try without making them, such as a MySQL DDL statement or sqlite's VACUUM); `skipped` when the target picked things this command cannot use, with the reason (also when the command then fails); `host_keys_pinned` when the command trusted a server's SSH host key for the first time (`host`, `address`, `key_type`, `fingerprint`), for the person to compare with the server's own; `truncated` when a list stopped at `--limit` and there is more (`--limit 0` shows all) |

## Exit codes

| Code | Meaning | Examples |
|------|---------|----------|
| 0 | success | |
| 1 | general error | `AUDIT_UNAVAILABLE` |
| 2 | wrong command, flag or value | `USAGE`, `HIDDEN_VALUE`, `NEEDS_TERMINAL` |
| 3 | not found | `TARGET_NOT_FOUND`, `FILE_NOT_FOUND`, `TOOL_MISSING`, `SECRET_NOT_FOUND`, `SECRET_UNRESOLVED` |
| 4 | cannot connect or log in, or the connection broke | `AUTH_FAILED`, `NO_AUTH`, `HOSTKEY_MISMATCH`, `VPN_LOGIN_REQUIRED`, `CONNECTION_LOST` |
| 5 | the command failed on the server | `FAILED`, `ROLLOUT_FAILED` |
| 6 | blocked for safety | `POLICY_BLOCKED`, `PROTECTED_HOST`, `WRITE_REQUIRES_FLAG`, `DECLINED` |
| 7 | timed out | `TIMEOUT`, `CONNECT_TIMEOUT` (the server did not answer within `--connect-timeout`), `ROLLOUT_TIMEOUT` |
| 8 | a precondition failed or something is in the way | `NO_MATCH` and `AMBIGUOUS_MATCH` (`fs replace` text not found or not unique), `PORT_IN_USE`, `FILE_TOO_LARGE`, `KEY_EXISTS` |

When several servers fail, the exit code is the worst one. The full
machine-readable reference is `komando schema`; `komando help exit-codes`
and `komando help output` print a short version at the terminal.

## What is still running, and where am I?

`komando status` lists the VPNs, logins, tunnels and jobs still running
(see [See what is still running](commands.md#see-what-is-still-running)),
and the line komando prints before `shell` and similar commands is in
[Where am I?](commands.md#where-am-i-status-lines).

## Will my scripts keep working?

Every JSON answer has `meta.contract`. Within a contract, komando only adds
fields, error codes and commands; it never renames or removes them. If that
ever has to change, `meta.contract` goes up and the
[changelog](../../CHANGELOG.md) says what changed.

## Reference: `komando schema`

```bash
komando schema exec                      # every flag of exec, machine-readable
komando schema secret.show               # a command by its ID, as the JSON names it
komando schema                           # also every exit code and error code
```

Each command in `komando schema` has a `kind` (`read`, `change` or
`depends`) and a `confirm` list from komando's rule table: first the tier
it always has, then each tier it reaches only sometimes, with the flag an
agent or a script adds and when, for example
`[{"tier":"change"},{"tier":"dangerous","flag":"--allow-dangerous","when":"with --remove-home"}]`.
Tiers are `read`, `change`, `dangerous` (`--allow-dangerous`), `safety`
(`--yes`) and `person` (no flag: a person at a terminal runs it). A change
on a protected server or conn also needs a yes; the target decides that,
so it is not listed. See [What needs a yes](safety.md#what-needs-a-yes).

## Troubleshooting

The table below has the errors people meet most. Every code komando gives,
with its exit code, an example message and the usual next step, is in
[Error codes](error-codes.md), and in `komando schema` under `error_codes`:

```bash
komando schema -o json | python3 -c 'import json,sys; [print(c["code"], c["exit"], c.get("example","")) for c in json.load(sys.stdin)["data"]["error_codes"]]'
```

For a stop for safety (exit 6): at your terminal komando asks you first; an
AI agent or a script adds `--yes` (or `--allow-dangerous`) after a person
agrees. See [Safety](safety.md#when-you-are-at-the-terminal).

| Error | Usually means | Try |
|-------|---------------|-----|
| `AUTH_FAILED` | wrong user, key or password; or the server asks for a two-factor code and no person is at a terminal to answer it (the message quotes its question) | `komando host show NAME`; a changed password: `komando secret set NAME`; a two-factor login: `komando login NAME` once in your terminal (it asks the code and keeps the login, 8h; an AI agent asks the user to run it) |
| `NO_AUTH` | the server has no key, identity or password, ssh-agent holds no key, and no person is at a terminal to type a password (the message says if `~/.ssh/id_ed25519` is encrypted and not loaded) | `ssh-add` (or `ssh-add ~/.ssh/id_ed25519`), or save a password: `komando secret set NAME`, then `komando host edit NAME --password-ref secret:NAME` (or `--key KEY`); start ssh-agent first if `SSH_AUTH_SOCK` is not set |
| `KEY_PASSPHRASE_REQUIRED` | the server's key (`--key` or `--identity`) is encrypted, has no passphrase in the vault, and ssh-agent does not hold it (komando uses the agent's copy, as `ssh` does) | `ssh-add PATH`, or store the passphrase: `komando secret set NAME`, `komando key add NAME PATH --passphrase-ref secret:NAME`, then `komando host edit HOST --key NAME --unset identity` (for a `--key` key: `komando key edit NAME --passphrase-ref secret:NAME`) |
| `KEY_EXISTS` | `key gen`, `key add` or `key rename` to a key name that is taken | choose another name, or `komando key rm NAME` first |
| `CONNECTION_REFUSED`, `CONNECT_TIMEOUT`, `DNS_ERROR` | the server is down, the address or port is wrong, a firewall drops the connection, or nothing listens on the port | `komando host show NAME` to check the address and port; a slow link: `--connect-timeout 30s`; a private server: add `--via BASTION` or a VPN |
| `HOSTKEY_MISMATCH` | the server was rebuilt, or someone is intercepting; the message shows the pinned fingerprint and the one the server shows now | compare the new fingerprint with the server's console or your provider first, then `komando host trust NAME --reset` in a terminal, or `@group` for many at once (only a person replaces a key; an agent reports it and gets `NEEDS_PERSON`) |
| `HOSTKEY_UNKNOWN` | host keys are strict and this server's key is not pinned yet; the message shows its fingerprint | compare it with what the server's owner sees, then `komando host trust NAME` |
| `HOSTKEY_REVOKED` | the server shows a host key on komando's list of revoked keys | treat the server as compromised and tell its owner; nothing was sent |
| `SECRET_UNRESOLVED` | the stored password or environment variable is missing | `komando secret list` |
| `SECRET_IN_USE` | `secret rm` of a secret that something still uses | point them elsewhere, or rename it with `komando secret rename OLD NEW` |
| `SECRET_EXISTS` | `secret rename` or `secret cp` to a name that is taken; `vpn add` whose keys would go into a secret that exists (`NAME-key`, `NAME-psk`, `NAME-config`) and is not that VPN's own | pick another name, or add `--overwrite` (`secret rename`, `secret cp`); for `vpn add`, pick another VPN name or move the secret away with `komando secret rename` |
| `SECRET_MISMATCH` | `secret check`: the value entered is not the stored one | `data.difference` says how they differ; `komando secret set NAME` stores the right one |
| `NAME_TAKEN` | a new name (from `host rename`, `rename --starts-with`, ...) is used already; for `rename` the message lists every clash, and nothing was renamed | pick other names, or rename or remove what is in the way; `--dry-run` shows the whole list first |
| `NOTHING_TO_RENAME` | `rename --starts-with`: no name starts with OLD | check the spelling and case with `komando list` and `komando secret list` |
| `GROUP_EXISTS` | `group rename` to the name of another group | pick another name, or merge them: `komando group add NEW @OLD`, then `komando group rm OLD` |
| `sudo: a password is required` | sudo needs a password | `komando secret set NAME`, then `komando host edit HOST --sudo-ref secret:NAME` |
| `VPN_LOGIN_REQUIRED` | the VPN needs a person's login (MFA) | a person runs `komando vpn up NAME` once |
| `AWS_LOGIN_REQUIRED` | the AWS SSO login has expired | a person runs `komando login aws --profile NAME` |
| `AZURE_LOGIN_REQUIRED` | no Azure login was found (for an Azure Container Registry) | set a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), run on Azure with a managed identity, or a person runs `az login` |
| `GCP_LOGIN_REQUIRED` | the Google login has run out (for Google Artifact Registry) | a person runs `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` to a key file |
| `POLICY_BLOCKED` | the command looks destructive | double-check it; at your terminal you type the name of what goes, a script adds `--allow-dangerous` |
| `PROTECTED_HOST`, `PROTECTED_TARGET` | a change to something marked protected | at your terminal komando asks; a script adds `--yes` |
| `SAFETY_SETTING` | a change that turns a seatbelt off | at your terminal komando asks; a script adds `--yes` |
| `SECRET_DESTINATION` | an AI agent asked to send a secret somewhere new (`{{secret:NAME}}`, `--env K=secret:NAME`, a password on a new address) | tell the user which secret goes where; once they agree, add `--yes` |
| `NEEDS_PERSON` | an AI agent asked for something only a person can do: type a password into `secret set`, compare one with `secret check`, set the approval code | the agent asks the user to run the command in their own terminal; no flag lets an agent do it |
| `DECLINED` | a person answered no to komando's question | nothing was changed; run it again to be asked again |
| `WRITE_REQUIRES_FLAG` | a database, cache or cluster command that changes data | `--write --dry-run`, then `--write` |
| `SENSITIVE_FILE` | an AI agent tried to copy a secret file (`.env`, a private key) here | read it with `komando fs cat` (values hidden); a person may allow `--reveal` |
| `HIDDEN_VALUE` | the text holds `[hidden]` or `[secret:NAME]` | change one line with `fs replace`; set a secret with `{{secret:NAME}}` |
| `SECRET_INPUT_INVALID` | an AI agent's arguments, script or file hold the value of a secret in the vault (audited) | use `{{secret:NAME}}`; a value the user gave the agent goes in with `secret set` first |
| `NO_MATCHING_TARGETS` | the target picked only things this command can't use | follow the hint (for example, use `komando db` for a database) |
| `TARGET_NOT_FOUND`, `HOST_NOT_FOUND`, `CONN_NOT_FOUND`, `TARGET_EMPTY` | a typo in a name, group or tag (`exec` says `HOST_NOT_FOUND`, `test` and `list` say `TARGET_NOT_FOUND`: the same problem) | the hint suggests the closest match; `komando list` |
| `VAULT_LOCKED`, `VAULT_DECRYPT`, `VAULT_KEY` | the vault cannot be opened: no passphrase, a wrong one, or its key is gone | see [Secrets](secrets.md#troubleshooting); `komando doctor` says which |
| `IMPORT_INCOMPLETE` | an import brought most things in but refused some (see `skipped`) | fix those entries in the file and import again |
| `PARTIAL_FAILURE` | the command ran on several servers and at least one failed (with one server you get that server's own code, such as `CONNECTION_REFUSED`) | read `data.results` for each server's exit code and stderr |
| `USAGE` | a wrong command, flag or value; also `komando` alone or a group such as `komando db` without its sub-command, when piped | the message says what is wrong, often with "did you mean"; the hint gives an example or lists the sub-commands |
| `PORT_IN_USE` | the local port is taken | pick another port, or `0` for a free one |
| `NEEDS_TERMINAL` | an interactive command (`shell`) run by a program | agents use `exec`, `cluster exec` or `job` |
| `CONNECTION_LOST` | the link broke while the command ran; it may still be running, or may have finished | check with a read-only command before running it again; use `komando job start` over a shaky link ([details](commands.md#when-the-connection-drops)) |
| `TIMEOUT` | the command took too long | `--timeout 30m`, or `komando job start` for long work |

`komando doctor` checks your local setup, the inventory and its security.
