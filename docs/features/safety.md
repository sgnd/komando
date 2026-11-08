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
| **Protected servers and conns** | Any change needs `--yes`. That includes re-pointing them (address, port, user, key, password, `--via`), replacing a secret they use, removing them and turning protection off. Commands that only look can say so with `--read-only` and run without `--yes`. Anything at the same address (a `user@address` target, a second name, a name that resolves to the same IP, a second conn to the same database server) is protected too. |
| **Read-only by default** | `db query`, `cache run` and `cluster run` only read unless you add `--write`. For databases, the database itself enforces it. |
| **Dry run** | `--dry-run` shows what would run and whether it would be blocked (`meta.would_be_blocked`). It is never blocked itself. It never opens the approval window, so for an AI agent `--reveal` does not count in a dry run (output stays masked), and an agent's preview connects with `--host-key-policy off` ignored. |
| **Safety settings** | Turning off the audit log or server identity checks, removing a deny rule, or an AI agent setting a `--proxy-command` (a program on this computer) needs `--yes`. |
| **Server identity** | If a server's fingerprint changes, komando refuses to connect (`HOSTKEY_MISMATCH`). |
| **Safe edits** | File edits replace exactly the text you name, write the whole file at once (never half-written), and can keep a `.bak` backup. |
| **Encrypted vault** | Passwords are encrypted with AES-256-GCM. Only names are ever shown. Only a person at a terminal can see a value (`secret get --reveal`). `secret mv` and `secret cp` rename and copy inside the vault, so a value never has to be shown or typed again. `secret check` lets a person compare a value without showing it. The approval code's key can only be changed with `komando config approval-code` (`RESERVED_SECRET`). |
| **Secrets hidden in output** | If a vault secret shows up in what a server sends back (a `.env` file, a log line, `env`), komando prints `[secret:NAME]` instead, also when it is base64- or URL-encoded. Values shorter than 6 characters are not hidden. |
| **History** | Every action is in `komando audit` (see [below](#history)). |

## Seatbelts for AI agents

komando recognizes Claude Code, Codex, Gemini CLI and Cursor by the
environment variables they set (a variable that is there counts, whatever
its value, also `0` or empty), and adds these rules for them. For any other
agent, set `KOMANDO_AGENT=1` (or `AI_AGENT=1`) in the environment it runs
commands in, so these rules apply to it too:

| Seatbelt | What it does |
|----------|--------------|
| **A person allows the risky flags** | When an agent adds `--yes`, `--allow-dangerous` or `--reveal`, komando opens a window on your screen with the whole command, why komando stops it (the matched rule, the protected servers), the servers it runs on and, when the command line does not show it, the program on this computer it lets run. It runs only when you click **Allow once**. Line breaks, tabs, control characters, long runs of spaces and characters that draw nothing show as escapes (`$'a:\n  b: 1'`, `\u3164`), which your shell reads back as the same text. A command that cannot be shown whole (longer than 500 characters, invalid text, or with bidi or zero-width characters) gets no window: the agent is told to make it shorter or ask you to run it. The agent cannot click it. With `komando config approval-code`, the window also asks for the 6-digit code from your authenticator app, so a click alone is not enough. With no screen (an SSH session, a server), the agent is refused and asks you to run the command in your own terminal. |
| **Secrets hidden from agents** | Passwords, keys and tokens in any output (a `.env` file, `env`, a log line, a database row, a Kubernetes Secret, `requirepass` in `redis.conf`, private keys, password hashes) show as `[hidden]`. You and your scripts see the real values. |
| **Personal data hidden from agents** | On protected servers and conns, email addresses, phone numbers, card numbers and IBANs in what an agent reads (a database row, a cache value, a log line, a file) show as `[hidden: email]`, `[hidden: phone]`, `[hidden: card]` and `[hidden: iban]`. See [Personal data](#personal-data). |
| **Agents can still set secrets** | `fs replace --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:db}}' --yes` puts the vault value on the server without the agent seeing it, once you allow it in the window. Text that still holds `[hidden]` is never written over a real file (`HIDDEN_VALUE`). An agent can rename a secret with `secret mv` (every reference follows) without seeing it. |
| **A person decides where a secret goes** | Once a value is on a server the agent controls, it could come back in a form komando does not recognise (reversed, in hex, cut in pieces). So when an agent sends a secret somewhere, it needs `--yes`, and the window names the secret and the place (`SECRET_DESTINATION`): `{{secret:NAME}}` in `fs write` and `fs replace`, `exec --env K=secret:NAME` and `job start --env`, `db user add` and `db user passwd`, and a password or pre-shared key reference (`secret:`, `env:`, `file:`, ...) that `host add`, `host edit`, `conn add`, `conn edit`, `vpn add`, `vpn edit` or an import attaches to a server, conn or VPN, or a server, conn or VPN with one that moves to another address, port, VPN server, `--via` path or proxy command. Edits that keep the place (a tag, a user name) ask nothing. A dry run never asks: it keeps `{{secret:NAME}}` as it is and says what the real run would need. |
| **A person decides about weaker connections** | An agent that adds a conn whose URL turns the network protection down, or edits one so that it does, needs `--yes` and your yes in the window (`SAFETY_SETTING`): `sslmode=disable`, `allow` or `prefer` (PostgreSQL), `tls=false`, `preferred` or `skip-verify` (MySQL), `tls=false` or `tls=skip-verify` (registry, FTPS), `insecure=1` (FTP), and going from `rediss://`, `memcacheds://` or an `https` endpoint to one without TLS. |
| **The usual data folder** | `KOMANDO_HOME` moves komando's data. In a new folder komando would know none of your protected servers, deny rules or pinned host keys, and would write the audit log there. So an agent's command with a `KOMANDO_HOME` other than `~/.komando` needs `--yes` and your yes in the window, every time (`SAFETY_SETTING`). If you keep komando's data elsewhere, make `~/.komando` a link to that folder: a link to the same folder counts as `~/.komando`. |
| **No guessing a secret** | `secret check`, which says whether a value is the stored one, is for people only (`NEEDS_PERSON`): for an agent it would answer yes or no to guesses. `secret get` tells an agent only whether the value starts or ends with a space, never its length or a hash of it (a hash of a short password can be guessed offline). |
| **Secret files stay on the server** | An agent cannot copy a file that is secret by its name (`.env`, private keys, `credentials`, `shadow`, ...) to this computer (`SENSITIVE_FILE`); folder copies leave them out. It can read them with `fs cat`, masked. Any other text file an agent downloads (`download`, `sync`, `storage download`, also `--to -`) is saved the way `fs cat` shows it, with secret values as `[hidden]`, and the result says `masked`; such a copy is never uploaded back (`HIDDEN_VALUE`). Binary files and files over 16 MB are copied as they are. |
| **Secret files stay on this computer** | komando does not read `~/.komando`, private keys, credential stores or files that are secret by name for an agent when a command takes a local file (`--stdin-file`, `script FILE`, uploads, `sync`, `fs write --from`, `db --file`, `cluster -f`) (`SENSITIVE_FILE`); folder uploads and `sync` check each file and leave those out. That holds for the same file by another name: a link, a hard link, or other upper and lower case on macOS. You allow a project secret such as `.env` with `--reveal`; komando's own data and `/proc/PID/environ` never go. Imports (`komando import kubeconfig`, `pgpass`, `docker`, ...) may read credential files, because they put the secrets into komando's vault, which the agent never sees. A `file:` or `env:` password reference cannot point at komando's data, a private key, a credential store or the password of a secret store either. No reference, for anyone, reads the approval code's key (`RESERVED_SECRET`). |
| **Guard on this computer** | `komando guide install` adds a guard to Claude Code, and to Cursor, Gemini CLI and Codex where you use them. Before the agent reads a file or runs a shell command, komando checks it and stops reading `~/.komando`, private keys, `.env` files and credential stores (`~/.kube`, `~/.aws/credentials`, the keychain), listing all environment variables, changing or clearing the variables komando knows an agent by (`CLAUDECODE=0`, `unset`, `env -u`, `env -i`, `read`, `sudo komando`) or `KOMANDO_HOME`, searching or archiving a folder that holds them (`grep -r ~`, `tar -C ~ ...`), and running `ssh`/`scp` around komando. It reads relative paths from the agent's working folder, follows `cd`, and counts a glob such as `~/.komand?/*` as the path it could match; quoted patterns (`grep '.*' f`) are not globs. Skip it with `--no-guard`. |

Scripts and you at your terminal use the flags as before.

## When a seatbelt stops you

| Error | Exit | What to do |
|-------|------|------------|
| `POLICY_BLOCKED` | 6 | Check the command. A person may re-run it with `--allow-dangerous`. |
| `PROTECTED_HOST`, `PROTECTED_TARGET` | 6 | A change to something protected. A person may add `--yes`; commands that only look can add `--read-only`. |
| `SAFETY_SETTING` | 6 | A change that turns a seatbelt off. A person may add `--yes`. |
| `SECRET_DESTINATION` | 6 | An agent asked to send a secret somewhere new (see [above](#seatbelts-for-ai-agents)). Tell the user which secret goes where; a person may add `--yes`. |
| `WRITE_REQUIRES_FLAG` | 6 | The query or command changes data. Try `--write --dry-run`, then `--write`. |
| `READ_ONLY_VIOLATION` | 6 | `--read-only` was given, but the command changes something. Drop `--read-only`; a person may confirm with `--yes`. |
| `CONFIRM_REQUIRED` | 6 | A change that touches many entries (for example deleting a group). Check them first, then a person may add `--yes`. |
| `OPEN_BIND` | 6 | A tunnel would listen on an address other machines can reach. Keep the default 127.0.0.1, or a person may add `--yes`. |
| `UNSAFE_BACKUP` | 6 | The backup file holds a client command, not SQL, that could run programs where the restore runs. Remove that line if the dump is not trusted. |
| `SENSITIVE_FILE` | 6 | An agent tried to copy a secret file here, or to have komando read one here. Read it with `fs cat` (values hidden); a person may allow `--reveal` for a project file. |
| `REVEAL_NEEDS_HUMAN` | 6 | Only a person can see secret values. |
| `NEEDS_PERSON` | 6 | Only a person can do this (`secret check`, setting up `config approval-code`). Ask them to run it in their own terminal. |
| `HIDDEN_VALUE` | 2 | The text holds `[hidden]` or `[secret:NAME]`. Change one line with `fs replace`, using `{{secret:NAME}}`. |
| `HOSTKEY_MISMATCH` | 4 | The server's identity changed. Never "fix" it blindly; see [Results and errors](output.md#troubleshooting). |
| `AUDIT_UNAVAILABLE` | 1 | The audit log cannot be written, so nothing runs. `komando doctor` shows why. |

When you type a command yourself in a terminal, komando asks instead of
failing: `[y/N]` for a protected target, and typing the target's name for a
dangerous command. Agents and scripts never see these questions; they need
the flags.

Secrets are never accepted as command arguments, because they would land in
your shell history (`SECRET_IN_ARGS`). `komando secret set NAME` asks for
the value after the prompt appears (text typed before it was already shown
on the screen, so komando does not use it); you can also use `--from-env VAR`
or a pipe.

## Add your own rules

```bash
komando policy deny 'terraform\s+destroy'           # a Go regular expression
komando policy list                                  # built-in and custom rules, with ids
komando policy allow 'terraform\s+destroy' --yes     # remove it again
komando policy allow custom-0 --yes                  # or remove it by its id
komando policy check 'terraform destroy'             # exit 6 when it would be blocked
komando policy check --for postgres 'delete from users'   # rate SQL or Redis instead
```

A rule matches the command the way the shell reads it, so quotes and
backslashes inside a word (`r\m`, `/e""tc`) do not hide it. A custom
pattern that is not a valid regular expression blocks every command until
you fix or remove it; `komando doctor` and `policy list` name it.

Built-in rules cannot be removed. `policy check` exits 6 when the command
would be blocked, so it works in an `if`. `--for` rates a statement for a
conn kind: `postgres`, `mysql`, `sqlite`, `redis` or `memcached`.

## Personal data

Customer data in production should not end up in an AI model. On protected
servers and conns, an AI agent sees personal data hidden in what it reads
from them: `db query` rows (also with `--csv`), `cache get` and `cache run`,
`storage cat`, `fs cat`, `exec`, `logs` and the other commands that show
data from a server or resource. komando's own inventory (server addresses,
conn URLs) is never hidden.

| Shown as | What komando looks for |
|----------|------------------------|
| `[hidden: email]` | an email address (not `git@...` or `noreply@...`) |
| `[hidden: phone]` | a phone number in international form: `+`, the country code, 8 to 15 digits |
| `[hidden: card]` | a payment card number: a card network's first digits, its length, and a valid check digit |
| `[hidden: iban]` | an IBAN with valid check digits |
| `[hidden: column]` | any value in a database column you name (below) |

```bash
komando config set mask_personal all             # on every server and conn
komando conn edit staging-db --option mask_personal=on   # on this conn, whatever the setting
komando conn edit shop-db --option 'mask_columns=name address birth_date'
komando config set mask_personal protected --yes  # back to the default
```

- **`mask_personal`**: `protected` (the default), `all`, or `off`. Showing
  agents more (`all` to `protected`, or `off`) needs `--yes`.
- **`mask_columns`**: names and street addresses have no shape komando can
  find, so name the columns that hold them, split by spaces. Setting it
  also turns personal data hiding on for that conn.
- **A person decides**: with `--reveal`, which a person allows in the
  approval window, the agent sees the real values for that one command.
- **Never written back**: a `db query --write`, `cache set` or
  `cache run --write`, and a file write, that still holds `[hidden: ...]`
  stops with `HIDDEN_VALUE`, so a masked value never replaces a real one.
- It is a best effort: a phone number written without `+`, or personal
  data in an image or a binary file, is not found. Hide whole columns
  where it matters.

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
komando audit --since 2h              # everything in the last two hours
komando audit --since yesterday --until today   # all of yesterday
komando audit verify                  # check the chain
```

Each record carries the hash of the one before, so `komando audit verify`
(and `komando doctor`) notice a record that was edited, added or removed
outside komando. If the audit log cannot be written, komando refuses to run
(`AUDIT_UNAVAILABLE`). Set `KOMANDO_ACTOR` to choose the name recorded for
you or your agent. An agent's environment can set that name to anything, so
its records keep the agent itself (`agent`) and your computer account, read
from the system (`os_user`), and mark the name as the one it claims
(`actor_claimed`); `komando audit -o text` shows it as `Claude Code (as claude)`. To keep SQL text out of the history, see `audit_sql` in
[Settings](settings.md).

## What this does not stop

An AI agent runs as your own user on your computer. The approval window,
the masking and the guard stop mistakes and prompt injection (a web page or
a file telling the agent to leak something). They do not stop a program
that deliberately hides what it is or edits the guard away: nothing that
runs as you can. The guard reads shell lines as text; a script that builds a
path from pieces, or starts komando without the agent's variables from
another language, gets past it. So:

- give komando, and so your agent, an SSH user with only the permissions it needs;
- mark production with `komando host edit NAME --protected`;
- move the vault key into the OS keychain (`komando secret keychain`), so
  other people or backups that reach `~/.komando` cannot open the vault.

The dangerous-command filter catches common accidents; it is not a complete
security boundary. Masking is a best effort: a secret under an unusual name,
or shorter than the text around it, can still slip through.
