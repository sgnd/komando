# Safety

The seatbelts komando puts on every command, and what to do when one stops
you. [All features](README.md) · [Security standards](security-standards.md)

## Quick start

```bash
komando host edit web1 --protected        # production: changes need --yes
komando policy check 'rm -rf /var/www'    # would this be blocked? (exit 6 if so)
komando policy list                       # every rule, built-in and your own
komando audit -o text                     # what was done, by whom
komando audit verify                      # was the history edited outside komando?
```

## The seatbelts

| Seatbelt | What it does |
|----------|--------------|
| **Dangerous-command filter** | Blocks commands such as `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh`, flushing the firewall and stopping SSH, on your servers, in pods and in databases. See them all with `komando policy list`. |
| **Protected servers and conns** | Any change needs `--yes`. That includes re-pointing them (address, port, user, key, password, `--via`), replacing a secret they use, removing them and turning protection off. Commands that only look can say so with `--read-only` and run without `--yes`. Anything at the same address (a `user@address` target, a second name, a second conn to the same database server) is protected too. |
| **Read-only by default** | `db query`, `cache run` and `cluster run` only read unless you add `--write`. For databases, the database itself enforces it. |
| **Dry run** | `--dry-run` shows what would run and whether it would be blocked (`meta.would_be_blocked`). It is never blocked itself. |
| **Safety settings** | Turning off the audit log or server identity checks, removing a deny rule, or an AI agent setting a `--proxy-command` (a program on this computer) needs `--yes`. |
| **Server identity** | If a server's fingerprint changes, komando refuses to connect (`HOSTKEY_MISMATCH`). |
| **Safe edits** | File edits replace exactly the text you name, write the whole file at once (never half-written), and can keep a `.bak` backup. |
| **Encrypted vault** | Passwords are encrypted with AES-256-GCM. Only names are ever shown. Only a person at a terminal can see a value (`secret get --reveal`). |
| **Secrets hidden in output** | If a vault secret shows up in what a server sends back (a `.env` file, a log line, `env`), komando prints `[secret:NAME]` instead, also when it is base64- or URL-encoded. Values shorter than 6 characters are not hidden. |
| **History** | Every action is in `komando audit` (see [below](#history)). |

## Seatbelts for AI agents

komando recognises Claude Code, Codex, Gemini CLI and Cursor by the
environment variables they set, and adds these rules for them:

| Seatbelt | What it does |
|----------|--------------|
| **A person allows the risky flags** | When an agent adds `--yes`, `--allow-dangerous` or `--reveal`, komando opens a window on your screen with the exact command. It runs only when you click **Allow once**. The agent cannot click it. With no screen (an SSH session, a server), the agent is refused and asks you to run the command in your own terminal. |
| **Secrets hidden from agents** | Passwords, keys and tokens in any output (a `.env` file, `env`, a log line, a database row, a Kubernetes Secret, private keys, password hashes) show as `[hidden]`. You and your scripts see the real values. |
| **Agents can still set secrets** | `fs replace --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:db}}'` puts the vault value on the server without the agent seeing it. Text that still holds `[hidden]` is never written over a real file (`HIDDEN_VALUE`). |
| **Secret files stay on the server** | An agent cannot copy a file that is secret by its name (`.env`, private keys, `credentials`, `shadow`, ...) to this computer (`SENSITIVE_FILE`); folder copies leave them out. It can read them with `fs cat`, masked. |
| **Guard on this computer** | `komando guide install` adds a guard to Claude Code. Before Claude reads a file or runs a shell command, komando checks it and stops reading `~/.komando`, private keys, `.env` files and credential stores (`~/.kube`, `~/.aws/credentials`, the keychain), listing all environment variables, and running `ssh`/`scp` around komando. Skip it with `--no-guard`. |

Scripts and you at your terminal use the flags as before.

## When a seatbelt stops you

| Error | Exit | What to do |
|-------|------|------------|
| `POLICY_BLOCKED` | 6 | Check the command. A person may re-run it with `--allow-dangerous`. |
| `PROTECTED_HOST`, `PROTECTED_TARGET` | 6 | A change to something protected. A person may add `--yes`; commands that only look can add `--read-only`. |
| `SAFETY_SETTING` | 6 | A change that turns a seatbelt off. A person may add `--yes`. |
| `WRITE_REQUIRES_FLAG` | 6 | The query or command changes data. Try `--write --dry-run`, then `--write`. |
| `SENSITIVE_FILE` | 6 | An agent tried to copy a secret file here. Read it with `fs cat` (values hidden). |
| `REVEAL_NEEDS_HUMAN` | 6 | Only a person can see secret values. |
| `HIDDEN_VALUE` | 2 | The text holds `[hidden]` or `[secret:NAME]`. Change one line with `fs replace`, using `{{secret:NAME}}`. |
| `HOSTKEY_MISMATCH` | 4 | The server's identity changed. Never "fix" it blindly; see [Results and errors](output.md#troubleshooting). |
| `AUDIT_UNAVAILABLE` | 1 | The audit log cannot be written, so nothing runs. `komando doctor` shows why. |

When you type a command yourself in a terminal, komando asks instead of
failing: `[y/N]` for a protected target, and typing the target's name for a
dangerous command. Agents and scripts never see these questions; they need
the flags.

Secrets are never accepted as command arguments, because they would land in
your shell history (`SECRET_IN_ARGS`). `komando secret set NAME` asks for
the value; you can also use `--from-env VAR` or a pipe.

## Add your own rules

```bash
komando policy deny 'terraform\s+destroy'           # a Go regular expression
komando policy list                                  # built-in and custom rules, with ids
komando policy allow 'terraform\s+destroy' --yes     # remove it again
komando policy allow custom-0 --yes                  # or remove it by its id
komando policy check 'terraform destroy'             # exit 6 when it would be blocked
komando policy check --for postgres 'delete from users'   # rate SQL or Redis instead
```

Built-in rules cannot be removed. `policy check` exits 6 when the command
would be blocked, so it works in an `if`. `--for` rates a statement for a
conn kind: `postgres`, `mysql`, `sqlite` or `redis`.

## History

Every action is in the audit log: time, who ran it, which AI agent asked,
whether a person allowed it, the targets and the command. Every change to
the inventory and to safety settings is there too: servers, conns, groups,
keys, secrets (names only), `config set` (old and new value) and
`policy deny/allow`.

```bash
komando audit -o text                 # one line per entry, newest 50
komando audit -n 0                    # all entries
komando audit --failed                # only failed or blocked actions
komando audit --target @prod          # only these servers or conns
komando audit --command exec          # only one command family
komando audit verify                  # check the chain
```

Each record carries the hash of the one before, so `komando audit verify`
(and `komando doctor`) notice a record that was edited, added or removed
outside komando. If the audit log cannot be written, komando refuses to run
(`AUDIT_UNAVAILABLE`). Set `KOMANDO_ACTOR` to choose the name recorded for
you or your agent. To keep SQL text out of the history, see `audit_sql` in
[Settings](settings.md).

## What this does not stop

An AI agent runs as your own user on your computer. The approval window,
the masking and the guard stop mistakes and prompt injection (a web page or
a file telling the agent to leak something). They do not stop a program
that deliberately hides what it is or edits the guard away: nothing that
runs as you can. So:

- give komando, and so your agent, an SSH user with only the permissions it needs;
- mark production with `komando host edit NAME --protected`;
- set a vault passphrase (`KOMANDO_VAULT_PASS`) if other people or backups
  can reach `~/.komando`.

The dangerous-command filter catches common accidents; it is not a complete
security boundary. Masking is a best effort: a secret under an unusual name,
or shorter than the text around it, can still slip through.
