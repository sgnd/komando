# Results and errors

How komando answers, what the exit codes mean, how to fix common errors,
and how to see what is still running. [All docs](README.md)

## Read a result

```bash
komando host ssh exec web1 -- uptime              # readable text in a terminal
komando host ssh exec web1 -o json -- uptime      # one JSON object (what agents get)
komando status                                    # VPNs, kept logins, tunnels and exec sessions still running
komando doctor                           # check the local setup
```

In a terminal you get readable text. When another program (such as an AI
agent or a script) runs komando through a pipe, it gets one JSON object
instead. Force either with `-o text` or `-o json`, or set `KOMANDO_OUTPUT`.
`--pretty` indents the JSON.

An agent or script that only wants to read what ran on a server can ask
for text too: `komando host ssh exec web1 --read-only -o text -- cat /etc/hosts`
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
print over the name. In JSON, `data` keeps the bytes as they are, escaped
the JSON way: it is the file, the row or the output itself. The words
komando writes about a result are made safe there too, because whoever
reads the JSON shows them to a person: `error.message`, `error.hint` and
`error.suggestion` (also in the error objects of a result, one per
server), `meta.warnings`, `meta.skipped`, `meta.would_be_blocked` and the
`name` and `detail` of `doctor`'s checks. Invisible format characters
(zero-width spaces, word joiners, tag characters) show as `\uNNNN` there
too. This is for display: it changes the text, so compare codes, not
messages.

```json
{
  "ok": false,
  "command": "host.ssh.exec",
  "data": {
    "command": "uptime",
    "results": [ { "host": "web1", "ok": false, "exit_code": 3, "stdout": "", "stderr": "…" } ],
    "summary": { "total": 1, "ok": 0, "failed": 1, "failed_hosts": ["web1"] }
  },
  "error": { "code": "FAILED", "message": "server web1 failed", "hint": "…" },
  "meta": { "contract": 2, "version": "…", "duration_ms": 211 }
}
```

| Field | Meaning |
|-------|---------|
| `ok` | `true` only when everything succeeded |
| `command` | the command's ID: its words joined by dots (`host.ssh.exec`, `database.postgres.query`, `storage.s3.object.list`, `credential.password.show`). `komando audit list --command` takes the same IDs |
| `data` | the result. Commands that run on many servers use `data.results[]` (one per server) and `data.summary`. Each result names its server in `host` (`host.ssh.exec`, `test`, `copy` ...). A command that ran on one entry names it with its type's own word: `agent`, `audit`, `cache`, `cloud`, `cluster`, `config`, `credential`, `database`, `group`, `host`, `policy`, `queue`, `registry`, `snippet`, `storage` or `vpn`. A record in an export file carries a `type` field |
| `error` | `{code, message, hint}` when `ok` is false. `data` can still be there when servers failed (`PARTIAL_FAILURE`) |
| `error.suggestion` | for a typo: the name komando thinks you meant (a command, a server, a flag). The hint is then the whole command line with it in place. A word from another tool (`ps`, `kubectl`, `psql`) gets the komando command that does that job. Left out otherwise |
| `error.hint` | always says what to try next. Most codes give their own hint; when one gives none, komando puts in a general hint for the exit code (for example, exit 7 suggests `--timeout`, or `exec`, which runs in a session you can come back to with `--attach ID`) |
| `null` | komando could not find out (for example a value the server would not let komando read). It never stands in for `0` or `false` |
| `meta` | `contract`, `version`, `duration_ms`; `dry_run` and `would_be_blocked` on a dry run, `would_need` (every approval flag the real run needs) and `not_simulated` (steps the dry run could not try without making them, such as a MySQL DDL statement or sqlite's VACUUM); `skipped` when the target picked things this command cannot use, with the reason (also when the command then fails): in a mixed group, the members of another provider are named there, as `{name, reason}`; `host_keys_pinned` when the command trusted a server's SSH host key for the first time (`host`, `address`, `key_type`, `fingerprint`), for the person to compare with the server's own; `truncated` when a list stopped at `--limit` and there is more (`--limit 0` shows all); `body_sha256` when the command sent a script or content: its full SHA-256, whose first 16 hex characters the approval window shows ([what each command's hash covers](safety.md#history)) |

## Exit codes

| Code | Meaning | Examples |
|------|---------|----------|
| 0 | success | |
| 1 | general error | `AUDIT_UNAVAILABLE` |
| 2 | wrong command, flag or value | `USAGE`, `HIDDEN_VALUE`, `NEEDS_TERMINAL` |
| 3 | not found | `TARGET_NOT_FOUND`, `FILE_NOT_FOUND`, `TOOL_MISSING`, `SECRET_NOT_FOUND`, `SECRET_UNRESOLVED` |

TODO(cut): the error code names that carry `SECRET` and the exit code for skipped members of a mixed group wait on the error catalog (generated at the cut) and O-30.
| 4 | cannot connect or log in, or the connection broke | `AUTH_FAILED`, `NO_AUTH`, `HOSTKEY_MISMATCH`, `VPN_LOGIN_REQUIRED`, `CONNECTION_LOST` |
| 5 | the command failed on the server | `FAILED`, `ROLLOUT_FAILED` |
| 6 | blocked for safety | `POLICY_BLOCKED`, `PROTECTED_TARGET`, `WRITE_REQUIRES_FLAG`, `DECLINED` |
| 7 | timed out | `TIMEOUT`, `CONNECT_TIMEOUT` (the server did not answer within `--connect-timeout`), `ROLLOUT_TIMEOUT` |
| 8 | a precondition failed or something is in the way | `PORT_IN_USE`, `FILE_TOO_LARGE`, `KEY_EXISTS` |

When several servers fail, the exit code is the worst one. The full
machine-readable reference is `komando schema`; [Error codes](error-codes.md)
lists every code.

## What is still running, and where am I?

`komando status` lists the VPNs, kept logins, tunnels and exec sessions still running
(see [See what is still running](commands.md#see-what-is-still-running)),
and the line komando prints before `shell` and similar commands is in
[Where am I?](commands.md#where-am-i-status-lines).

## Will my scripts keep working?

Every JSON answer has `meta.contract`. Within a contract, komando only adds
fields, error codes and exit codes to the JSON envelope; it never renames or
removes them. Command and flag names are not part of the contract: komando
is used internally for now, so a renamed command or flag keeps no old name,
and the changelog lists each one. The field that names the entry a command
ran on is the entry's type word (`host`, `database`, ...). If the envelope
ever has to change, `meta.contract` goes up and the
[changelog](../../CHANGELOG.md) says what changed.
TODO(cut): the new `meta.contract` value waits on the release pull request.

## Reference: `komando schema`

```bash
komando schema host.ssh.exec             # every flag of exec, machine-readable
komando schema credential.password.show  # a command by its ID, as the JSON names it
komando schema                           # also every exit code and error code
```

Each command in `komando schema` has a `kind` (`read`, `change` or
`depends`) and a `confirm` list from komando's rule table: first the tier
it always has, then each tier it reaches only sometimes, with the flag an
agent or a script adds and when, for example
`[{"tier":"change"},{"tier":"dangerous","flag":"--allow-dangerous","when":"with --delete-file"}]`.
Tiers are `read`, `change`, `dangerous` (`--allow-dangerous`), `safety`
(`--yes`) and `person` (no flag: a person at a terminal runs it). A change
on a protected entry also needs a yes; the target decides that,
so it is not listed. See [What needs a yes](safety.md#what-needs-a-yes).

`komando schema` lists the credential store providers (`vault`, `aws-sm`, `gcp-sm`, `azure-kv`, `onepassword`, `bitwarden`, `keepass`, `env`, `file`) under `credential_stores`.

Each provider's `add` command lists its own flags, so a program can build its add form from `komando schema host.ssh.add` (and `database.postgres.add`, `vpn.wireguard.add` and the rest).
TODO(cut): `add_kinds`, `url_schemes`, `url_example` and `default_port` wait on the schema built from the capability table (PR B).

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
| `AUTH_FAILED` | wrong user, key or password; or the server asks for a two-factor code and no person is at a terminal to answer it (the message quotes its question) | `komando host ssh show NAME`; a changed password: `komando credential password edit NAME`; a two-factor login: `komando test NAME` once in your terminal (it asks the code and keeps the login, 8h; an AI agent asks the user to run it) |
| `NO_AUTH` | the server has no key, identity or password, ssh-agent holds no key, and no person is at a terminal to type a password (the message says if `~/.ssh/id_ed25519` is encrypted and not loaded) | `ssh-add` (or `ssh-add ~/.ssh/id_ed25519`), or save a password: `komando credential password add NAME --user USER`, then `komando host ssh edit NAME --credential NAME` (or a key credential); start ssh-agent first if `SSH_AUTH_SOCK` is not set |
| `KEY_PASSPHRASE_REQUIRED` | the server's key is encrypted, its credential holds no passphrase, and ssh-agent does not hold it (komando uses the agent's copy, as `ssh` does) | `ssh-add PATH`, or give the key credential its passphrase with `komando credential key edit NAME`, then `komando host ssh edit HOST --credential NAME` |
| `KEY_EXISTS` | `credential key create`, `credential key add` or `credential key rename` to a key name that is taken | choose another name, or `komando credential key remove NAME` first |
| `CONNECTION_REFUSED`, `CONNECT_TIMEOUT`, `DNS_ERROR` | the server is down, the address or port is wrong, a firewall drops the connection, or nothing listens on the port | `komando host ssh show NAME` to check the address and port; a slow link: `--connect-timeout 30s`; a private server: add `--via BASTION` or a VPN |
| `HOSTKEY_MISMATCH` | the server was rebuilt, or someone is intercepting; the message shows the pinned fingerprint and the one the server shows now | compare the new fingerprint with the server's console or your provider first, then `komando host ssh trust NAME --reset` in a terminal, or `@group` for many at once (only a person replaces a key; an agent reports it and gets `NEEDS_PERSON`) |
| `HOSTKEY_UNKNOWN` | host keys are strict and this server's key is not pinned yet; the message shows its fingerprint | compare it with what the server's owner sees, then `komando host ssh trust NAME` |
| `HOSTKEY_REVOKED` | the server shows a host key on komando's list of revoked keys | treat the server as compromised and tell its owner; nothing was sent |
| `SECRET_UNRESOLVED` | the stored password or environment variable is missing | `komando credential list` |
| `SECRET_IN_USE` | `credential KIND remove` of a credential that something still uses | point them elsewhere, or rename it with `komando credential KIND rename OLD NEW` |
| `SECRET_EXISTS` | `credential KIND rename` to a name that is taken; `vpn PROVIDER add` whose keys would go into a credential that exists (`NAME-key`, `NAME-psk`, `NAME-config`) and is not that VPN's own | pick another name, or add `--overwrite` (`credential KIND rename`); for `vpn PROVIDER add`, pick another VPN name or move the credential away with `komando credential KIND rename` |
| `NAME_TAKEN` | a new name (from `host ssh rename` and the other `rename` commands) is used already | pick another name, or rename or remove what is in the way |
| `GROUP_EXISTS` | `group rename` to the name of another group | pick another name |
| `sudo: a password is required` | sudo needs a password | `komando credential password add NAME --user USER`, then `komando host ssh edit HOST --sudo-credential NAME` |
| `VPN_LOGIN_REQUIRED` | the VPN needs a person's login (MFA) | a person runs `komando vpn wireguard start office` (the provider and name of that VPN) once |
| `AWS_LOGIN_REQUIRED` | the AWS SSO login has expired | a person runs `komando test NAME` |
| `AZURE_LOGIN_REQUIRED` | no Azure login was found (for an Azure Container Registry) | set a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), run on Azure with a managed identity, or a person runs `az login` |
| `GCP_LOGIN_REQUIRED` | the Google login has run out (for Google Artifact Registry) | a person runs `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` to a key file |
| `POLICY_BLOCKED` | the command looks destructive | double-check it; at your terminal you type the name of what goes, a script adds `--allow-dangerous` |
| `PROTECTED_TARGET` | a change to something marked protected | at your terminal komando asks; a script adds `--yes` |
| `SAFETY_SETTING` | a change that turns a seatbelt off | at your terminal komando asks; a script adds `--yes` |
| `SECRET_DESTINATION` | an AI agent asked to send a secret somewhere new (`--env K=credential:NAME`, a credential on a new address) | tell the user which credential goes where; once they agree, add `--yes` |
| `NEEDS_PERSON` | something only a person can do: type a password (`credential password add`, a credential made with `--ask`), the person step of `komando test`, set the approval code. An AI agent and a script get it alike | ask the user to run the command in their own terminal; no flag lets a program do it |
| `DECLINED` | a person answered no to komando's question | nothing was changed; run it again to be asked again |
| `WRITE_REQUIRES_FLAG` | a database, cache or cluster command that changes data | `--write --dry-run`, then `--write` |
| `SENSITIVE_FILE` | an AI agent tried to copy a secret file (`.env`, a private key) here | read it with `komando host ssh exec NAME --read-only -- cat FILE` (values hidden); a person may allow `--reveal` |
| `HIDDEN_VALUE` | the text holds `[hidden]` or `[credential:NAME]` | do not send it back; ask a person for the real value |
| `NO_MATCHING_TARGETS` | the target picked only things this command can't use | follow the hint |
| `TARGET_NOT_FOUND` | a typo in an entry name, whatever the command | the hint suggests the closest match; `komando list` |
| `TARGET_EMPTY` | a group, tag or pattern picked nothing | `komando list GROUP` shows what it picks |
| `VAULT_LOCKED`, `VAULT_DECRYPT`, `VAULT_KEY` | the vault cannot be opened: no passphrase, a wrong one, or its key is gone | see [Credentials](credentials.md#troubleshooting); `komando doctor` says which |
| `IMPORT_INCOMPLETE` | an import brought most things in but refused some (see `skipped`) | fix those entries in the file and import again |
| `PARTIAL_FAILURE` | the command ran on several servers and at least one failed (with one server you get that server's own code, such as `CONNECTION_REFUSED`, or `COMMAND_FAILED` when its command exited non-zero) | read `data.results` for each server's exit code and stderr |
| `USAGE` | a wrong command, flag or value; also `komando` alone or a group such as `komando database` without its sub-command, when piped | the message says what is wrong, often with "did you mean"; the hint gives an example or lists the sub-commands |
| `PORT_IN_USE` | the local port is taken | pick another port, or `0` for a free one |
| `NEEDS_TERMINAL` | an interactive command (`shell`) run by a program | agents use `exec` or `cluster kubernetes exec` |
| `CONNECTION_LOST` | the link broke while the command ran; it may still be running, or may have finished | `exec` runs in a session on the server: come back with `komando host ssh exec NAME --attach ID` ([details](commands.md#when-the-connection-drops)) |
| `TIMEOUT` | the command took too long | `--timeout 30m`; a long run survives a drop, so come back with `exec --attach ID` |

`komando doctor` checks your local setup, the inventory and its security.

In `-o json`, a doctor check that one komando command puts right has
`fix`: the words to run, as a list (`["komando", "database", "postgres", "edit",
"db2", "--protected"]`). The `detail` says the same in prose. A program that
offers the fix reads `fix` and never takes a command out of `detail`.
A check has `fix` only when one command puts it right whatever else is
true, and that command asks nothing: a check with several ways out, one
that needs a value or a passphrase from you, one only you can judge
(two entries that look the same), or a name that could be read as a flag,
has none.
