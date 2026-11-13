# Safety

The seatbelts komando puts on every command, who is asked before a risky
one runs, and what to do when one stops you.
[All docs](README.md) · [Security standards](security-standards.md)

## Protect production

Mark a server or conn as protected, and komando asks before every change on
it:

```bash
komando host edit web1 --protected        # komando asks before every change on web1
komando conn edit prod-db --protected     # the same for a database
komando policy check 'rm -rf /'           # would this be blocked? (exit 6 if so)
komando audit -o text                     # what was done, and by whom
```

Typed alone, `komando host edit` asks for the server, then what to change.

When you change web1 later, komando asks first:

```text
web1 (protected): this command changes it. Continue? [y/N]
```

An AI agent or a script is not asked: it adds `--yes` after a person
agrees (see [When you are at the terminal](#when-you-are-at-the-terminal)).

## The seatbelts

| Seatbelt | What it does |
|----------|--------------|
| **Dangerous-command filter** | Blocks commands such as `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh`, flushing the firewall and stopping SSH, on your servers, in pods and in databases. See them all with `komando policy list`. |
| **Protected servers and conns** | Any change on it needs a yes. For the entry itself that means re-pointing it (address, port, user, key, password, `--via`), replacing a secret it uses, renaming it, removing it and turning protection off; its tags, groups, labels and notes change without one. Commands that only look can say so with `--read-only` and run without a yes. Anything at the same address and port (a `user@address` target, a second name, a name that resolves to the same IP, a second conn to the same database server) is protected too, whichever VPN or bastion it goes through. With many targets, komando checks all of them before it runs anything: one protected target stops the whole command before the first one runs (at a terminal, komando asks once), and the error names every protected target. A command never stops halfway because of protection. |
| **Read-only by default** | `db query`, `cache run` and `cluster run` only read unless you add `--write`. For databases, the database itself enforces it. |
| **Dry run** | `--dry-run` shows what would run and whether it would be blocked (`meta.would_be_blocked`). It is never blocked itself. It never opens the approval window, so for an AI agent `--reveal` does not count in a dry run (output stays masked), and an agent's preview connects with `--host-key-policy off` ignored. |
| **Safety settings** | Turning off the audit log or server identity checks, moving the vault key out of the keychain, removing a deny rule, or an AI agent setting a `--proxy-command` (a program on this computer) needs a yes. |
| **Server identity** | If a server's fingerprint changes, komando refuses to connect (`HOSTKEY_MISMATCH`). |
| **Safe edits** | File edits replace exactly the text you name, write the whole file at once (never half-written), and can keep a `.bak` backup. As root (`--sudo`), komando follows no link another server user made, and does not write into a folder another user can change, since that user could swap the file for a link while root writes (`SHARED_FOLDER_CONFLICT`). |
| **Sealed vault** | Passwords are sealed with AES-256-GCM, with the key in the OS keychain (or, where there is none, in a file beside the store; `komando doctor` warns). Only names are ever shown. Only a person at a terminal can see a value (`secret show --reveal`). `secret rename` and `secret cp` rename and copy inside the vault, so a value never has to be shown or typed again. `secret check` lets a person compare a value without showing it. The approval code's key can only be changed with `komando config approval-code` (`RESERVED_SECRET`). See [Secrets](secrets.md). |
| **Secrets hidden in output** | If a vault secret shows up in what a server sends back (a `.env` file, a log line, `env`), komando prints `[secret:NAME]` instead, also when it is base64- or URL-encoded. Values shorter than 6 characters are not hidden. So that this hiding cannot tell an AI agent which of its guesses is a secret, an agent's arguments, script or input that hold a vault value are refused before anything runs (`SECRET_INPUT_INVALID`, a dry run too) and written to the audit log. A guess the agent has a server decode first cannot be caught. |
| **History** | Every action is in `komando audit` (see [below](#history)). |

## When you are at the terminal

Who is asked depends on who runs the command:

- **You, at a terminal:** komando asks you first, and runs the command
  only after your answer.
- **An AI agent or a script:** komando never asks. The command stops with
  exit 6 and a code (`PROTECTED_HOST`, `POLICY_BLOCKED` ...), and the hint
  names the flag the real run needs: `--yes`, or `--allow-dangerous` for a
  step that cannot be undone. The agent or script adds that flag after a
  person agrees.
- **An AI agent that adds the flag:** komando opens an "Allow once" window
  on your screen, and the command runs only when you click it (see
  [Seatbelts for AI agents](#seatbelts-for-ai-agents)). A script's flag
  counts as it is.
- **A CI job** (`CI` set) is never a person, even on a terminal: nothing
  is asked there.

At a terminal komando asks in one of three ways:

- A change on a protected server, conn or VPN:
  `web1 (protected): this command changes it. Continue? [y/N]`.
- A step that cannot be undone: `This <what it does>.`, and you type the
  name of what goes: the key, file, secret, topic or image when one goes
  (`Type the name session:42 to continue`), how many when several go
  (`Type 37 (objects under daily/ in backups) to continue`), or the
  server's or conn's name for a step on the whole target (a reboot, a
  restore, a command the filter blocks). Never the word yes. On a
  protected target the same question says so, and your answer covers the
  protection too: komando asks once.
- A change that turns off one of komando's own checks (`config set audit
  off`, `host_key_policy off`, removing a deny rule, going back to an
  older komando):
  `This turns off a komando safety check: <what>. Continue? [y/N]`.

More about the questions:

- A `--proxy-command` or a cluster's login program that matches a rule
  says `Blocked by policy: ...` and asks you to type the server's or
  conn's name to run it anyway, this once.
- When komando asked you for a missing argument, it asks `Run it? [y/N,
  d = --dry-run first]` before the command runs. One that cannot be
  undone (deleting data or files, a reboot, stopping sshd, `sync
  --delete`) then asks you to type the name of what goes, once. `cron
  rm`, `pkg rm` and `db kill` need nothing more from an AI agent, but
  you type the name of what goes instead of answering `Run it?`. One rule
  table decides which: every command that stops an AI agent as dangerous
  asks you for the name.
- No is the default; Enter or Ctrl-D is a no, and nothing runs. A no
  exits 6, like a stop: `Cancelled. Nothing was changed.` (`DECLINED`
  when komando asked before the command ran, else the stop's own code).
  Ctrl-C stops komando there instead: `Stopped.`, exit 1 (`CANCELLED`).
- A yes counts for that one command only, as `--yes` or
  `--allow-dangerous` would, and `komando audit` records it with
  `confirm: tty` and what you said yes to.
- Some stops have no flag and are never asked: `HOSTKEY_MISMATCH`,
  `NEEDS_PERSON`, `SSH_GATE_READ_ONLY`, `SSH_GATE_REFUSED`,
  `STORE_OLD_COPY` and `REVEAL_NEEDS_HUMAN`. Only a person runs those
  commands, in their own terminal.

Every stop a flag lifts has the same hint, naming every flag the real run
needs: an AI agent reads `check with --dry-run, ask the user; once they
agree, run it again with --yes`, a script gets its own command line with
the flags filled in.

## What needs a yes

Every command has a risk tier. The tier says what an AI agent or a script
must add, and what komando asks you at your terminal. A command not in the
table below only reads, or makes a change you can undo.

<!-- tiers: made by TestTiersDoc from risk.go; KOMANDO_UPDATE_TIERS=1 writes it -->

| Tier | What | An AI agent or a script needs | A person at a terminal |
|---|---|---|---|
| read | looks only | nothing | nothing |
| change | can be undone, or only komando's own list | nothing | typed in full: runs; filled in: `Run it?` |
| protected | a change on a protected server, conn or VPN | `--yes` (PROTECTED_HOST, PROTECTED_TARGET) | `NAME (protected): ... Continue? [y/N]` |
| dangerous | cannot be undone, or an outage | `--allow-dangerous` (POLICY_BLOCKED) | types the name of what goes, the count, or the target |
| safety | weakens komando's own checks | `--yes` (SAFETY_SETTING, OPEN_BIND, SECRET_DESTINATION) | `This turns off a komando safety check: ... Continue? [y/N]` |
| person | only a person at a terminal | no flag: NEEDS_PERSON and friends | the command itself |

Every row of the rule table (`risk.go`). A command without a row has its
kind's tier: read, or change. "when the ..." rows are decided at run time.

| Command | When | Tier | Flag |
|---|---|---|---|
| `queue purge` | always | dangerous | `--allow-dangerous` |
| `queue rm` | always | dangerous | `--allow-dangerous` |
| `cache rm` | always | dangerous | `--allow-dangerous` |
| `storage rm` | always | dangerous | `--allow-dangerous` |
| `cluster rm` | always | dangerous | `--allow-dangerous` |
| `cluster scale` | REPLICAS is 0 | dangerous | `--allow-dangerous` |
| `registry rm` | always | dangerous | `--allow-dangerous` |
| `registry prune` | always | dangerous | `--allow-dangerous` |
| `db restore` | always | dangerous | `--allow-dangerous` |
| `db user rm` | always | dangerous | `--allow-dangerous` |
| `db kill` | a person types the name of what goes | change |  |
| `fs rm` | always | dangerous | `--allow-dangerous` |
| `docker rm` | always | dangerous | `--allow-dangerous` |
| `docker prune` | always | dangerous | `--allow-dangerous` |
| `user rm` | with --remove-home | dangerous | `--allow-dangerous` |
| `user rm` | always | dangerous | `--allow-dangerous` |
| `secret rm` | always | dangerous | `--allow-dangerous` |
| `key rm` | with --delete-file, for a key komando made | dangerous | `--allow-dangerous` |
| `pkg rm` | a package the server needs (openssh-server, sudo, systemd, ...) | dangerous | `--allow-dangerous` |
| `pkg rm` | a person types the name of what goes | change |  |
| `cron rm` | a person types the name of what goes | change |  |
| `reboot` | always | dangerous | `--allow-dangerous` |
| `svc stop` | the unit is ssh or sshd | dangerous | `--allow-dangerous` |
| `svc disable` | the unit is ssh or sshd | dangerous | `--allow-dangerous` |
| `sync` | with --delete | dangerous | `--allow-dangerous` |
| `exec` | when the command matches a destructive rule | dangerous | `--allow-dangerous` |
| `job start` | when the command matches a destructive rule | dangerous | `--allow-dangerous` |
| `recipe run` | when the recipe's command matches a destructive rule | dangerous | `--allow-dangerous` |
| `docker exec` | when the command matches a destructive rule | dangerous | `--allow-dangerous` |
| `docker raw` | when the docker command deletes or stops something | dangerous | `--allow-dangerous` |
| `docker compose` | when the compose command deletes or stops something | dangerous | `--allow-dangerous` |
| `cluster exec` | when the command matches a destructive rule | dangerous | `--allow-dangerous` |
| `cluster run` | when the kubectl command deletes something | dangerous | `--allow-dangerous` |
| `cache run` | when the cache command deletes data (FLUSHALL, ...) | dangerous | `--allow-dangerous` |
| `db query` | when the SQL deletes data (DROP, DELETE without WHERE, ...) | dangerous | `--allow-dangerous` |
| `db explain` | with --analyze, when the SQL deletes data | dangerous | `--allow-dangerous` |
| `pkg upgrade` | with --security, when an update would remove a package the server needs | dangerous | `--allow-dangerous` |
| `key revoke` | when it is the key komando logs in with | dangerous | `--allow-dangerous` |
| `host edit` | when --proxy-command matches a destructive rule | dangerous | `--allow-dangerous` |
| `host add` | when --proxy-command matches a destructive rule | dangerous | `--allow-dangerous` |
| `import` | when an imported ProxyCommand matches a destructive rule | dangerous | `--allow-dangerous` |
| `policy rm` | always | safety | `--yes` |
| `config set` | when the setting turns a check off (audit, keychain, host key policy, ...) | safety | `--yes` |
| `host edit` | with --protected=false | safety | `--yes` |
| `conn edit` | with --protected=false | safety | `--yes` |
| `vpn edit` | with --protected=false | safety | `--yes` |
| `vpn edit` | with --mfa=false | safety | `--yes` |
| `update` | when it installs an older version | safety | `--yes` |
| `tunnel start` | when it listens on an open address (OPEN_BIND) | safety | `--yes` |
| `secret keychain` | when it turns the keychain off | safety | `--yes` |
| `host add` | with --proxy-command, when an AI agent runs it (the proxy command runs on this computer) | safety | `--yes` |
| `host edit` | with --proxy-command, when an AI agent runs it (the proxy command runs on this computer) | safety | `--yes` |
| `import` | when an AI agent imports a server with a proxy command (it runs on this computer; without --yes the server is left out) | safety | `--yes` |
| `import` | SOURCE kubeconfig, when an AI agent imports a context whose login runs a program or sends a file of this computer | safety | `--yes` |
| `recipe add` | with --overwrite --read-only, when it makes an existing recipe read-only | safety | `--yes` |
| `host trust` | when an AI agent pins a first host key while host keys are strict | safety | `--yes` |
| `guide uninstall` | when it removes komando's guard from an AI agent's settings | safety | `--yes` |
| `config approval-code` | always | person |  |
| `secret passphrase` | always | person |  |
| `secret check` | always | person |  |
| `shell` | always | person |  |
| `db shell` | always | person |  |
| `cluster shell` | always | person |  |
| `login` | always | person |  |
| `login aws` | always | person |  |
| `ssh-gate` | always | person |  |
| `host ssh-command` | always | person |  |
| `secret keychain` | without --off (moving the key into the keychain) | person |  |
| `host trust` | with --reset, when a key is pinned | person |  |
| `group rm` | GROUP alone: deleting a group of more than 3 members (CONFIRM_REQUIRED) | change | `--yes` |

<!-- end of tiers -->

## Seatbelts for AI agents

komando recognizes Claude Code, Codex, Gemini CLI and Cursor by the
environment variables they set (a variable that is there counts, whatever
its value, also `0` or empty), and adds these rules for them. For any other
agent, set `KOMANDO_AGENT=1` (or `AI_AGENT=1`) in the environment it runs
commands in, so these rules apply to it too. Scripts and you at your
terminal are not affected by them.

| Seatbelt | What it does |
|----------|--------------|
| **A person allows the risky flags** | When an agent adds `--yes`, `--allow-dangerous` or `--reveal`, komando opens a window on your screen with the whole command, why komando stops it (the matched rule, the protected servers), the servers it runs on and, when the command line does not show it, the program on this computer it lets run. For `exec --script FILE`, `job start --script FILE` and `exec --stdin-file FILE` it also shows the file's SHA-256 and every line of it, never a part: a file longer than 40 lines (long lines wrapped at 100 characters) or 16 KB, one that is not valid text or holds bidi or zero-width characters, and one that looks like it holds a password, key or token gets no window, and the agent asks you to run the command yourself. It runs only when you click **Allow once**. Line breaks, tabs, control characters, long runs of spaces and characters that draw nothing show as escapes (`$'a:\n  b: 1'`, `\u3164`), which your shell reads back as the same text. A command that cannot be shown whole (longer than 500 characters, invalid text, or with bidi or zero-width characters) gets no window: the agent is told to make it shorter or ask you to run it. The agent cannot click it. With `komando config approval-code`, the window also asks for the 6-digit code from your authenticator app, so a click alone is not enough (see [Settings](settings.md#ask-for-a-code-before-an-agents-risky-command)). On a Linux or BSD desktop (X11 or Wayland), where another of your programs can press the window's buttons, the code is required: without it komando opens no window, and the agent asks you to turn the code on or to run the command yourself (macOS and Windows keep the plain window). With no screen (an SSH session, a server, `KOMANDO_NO_DIALOG` set), the agent is refused and asks you to run the command in your own terminal. A window nobody answers closes after 2 minutes; the agent is told nobody answered (not that you clicked Deny) and asks you whether to try again. |
| **Secrets hidden from agents** | Passwords, keys and tokens in any output (a `.env` file, `env`, a log line, a database row, a Kubernetes Secret, `requirepass` in `redis.conf`, private keys, password hashes) show as `[hidden]`. You and your scripts see the real values. |
| **Personal data hidden from agents** | On protected servers and conns, email addresses, phone numbers, card numbers and IBANs in what an agent reads (a database row, a cache value, a log line, a file) show as `[hidden: email]`, `[hidden: phone]`, `[hidden: card]` and `[hidden: iban]`. See [Personal data](#personal-data). |
| **Agents can still set secrets** | `fs replace --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:db}}' --yes` puts the vault value on the server without the agent seeing it, once you allow it in the window. Text that still holds `[hidden]` is never written over a real file (`HIDDEN_VALUE`). An agent can rename a secret with `secret rename` (every reference follows) without seeing it. |
| **A person decides where a secret goes** | Once a value is on a server the agent controls, it could come back in a form komando does not recognise (reversed, in hex, cut in pieces). So when an agent sends a secret somewhere, it needs `--yes`, and the window names the secret and the place (`SECRET_DESTINATION`): `{{secret:NAME}}` in `fs write` and `fs replace`, `exec --env K=secret:NAME` and `job start --env`, `db user add` and `db user passwd`, and a password or pre-shared key reference (`secret:`, `env:`, `file:`, ...) that `host add`, `host edit`, `conn add`, `conn edit`, `vpn add`, `vpn edit` or an import attaches to a server, conn or VPN, or a server, conn or VPN with one that moves to another address, port, VPN server, `--via` path or proxy command. Edits that keep the place (a tag, a user name) ask nothing. A dry run never asks: it keeps `{{secret:NAME}}` as it is and says what the real run would need. |
| **A person decides about weaker connections** | An agent that adds a conn whose URL turns the network protection down, or edits one so that it does, needs `--yes` and your yes in the window (`SAFETY_SETTING`): `sslmode=disable`, `allow` or `prefer` (PostgreSQL), `tls=false`, `preferred` or `skip-verify` (MySQL), `encrypt=false`, `encrypt=disable` or `tls=skip-verify` (SQL Server), `tls=false` or `tls=skip-verify` (Oracle, ClickHouse, registry, FTPS), `tls=skip-verify` or `insecure=1` (Kafka, RabbitMQ, NATS, SQS, Pub/Sub), `insecure=1` (FTP, Redis, memcached), an `http://` endpoint (BigQuery), and going from `rediss://`, `memcacheds://` or an `https` endpoint to one without TLS. |
| **The usual data folder** | `KOMANDO_HOME` moves komando's data. In a new folder komando would know none of your protected servers, deny rules or pinned host keys, and would write the audit log there. So an agent's command with a `KOMANDO_HOME` other than `~/.komando` needs `--yes` and your yes in the window, every time (`SAFETY_SETTING`). If you keep komando's data elsewhere, make `~/.komando` a link to that folder: a link to the same folder counts as `~/.komando`. |
| **No guessing a secret** | `secret check`, which says whether a value is the stored one, is for people only (`NEEDS_PERSON`): for an agent it would answer yes or no to guesses. `secret show` tells an agent only whether the value starts or ends with a space, never its length or a hash of it (a hash of a short password can be guessed offline). |
| **Secret files stay on the server** | An agent cannot copy a file that is secret by its name (`.env`, private keys, `credentials`, `shadow`, ...) to this computer (`SENSITIVE_FILE`); folder copies leave them out. It can read them with `fs cat`, masked. Any other text file an agent downloads (`download`, `sync`, `storage download`, also `--to -`) is saved the way `fs cat` shows it, with secret values as `[hidden]`, and the result says `masked`; such a copy is never uploaded back (`HIDDEN_VALUE`). Binary files and files over 16 MB are copied as they are. |
| **Secret files stay on this computer** | komando does not read `~/.komando`, private keys, credential stores or files that are secret by name for an agent when a command takes a local file (`--stdin-file`, `script FILE`, uploads, `sync`, `fs write --from`, `db --file`, `cluster -f`) (`SENSITIVE_FILE`); folder uploads and `sync` check each file and leave those out. That holds for the same file by another name: a link, a hard link, or other upper and lower case on macOS. You allow a project secret such as `.env` with `--reveal`; komando's own data and `/proc/PID/environ` never go. Imports (`komando import kubeconfig`, `pgpass`, `docker`, ...) may read credential files, because they put the secrets into komando's vault, which the agent never sees. A `file:` or `env:` password reference cannot point at komando's data, a private key, a credential store or the password of a secret store either. No reference, for anyone, reads the approval code's key (`RESERVED_SECRET`). |
| **Guard on this computer** | `komando guide install` adds a guard to Claude Code, and to Cursor, Gemini CLI and Codex where you use them. Before the agent reads a file or runs a shell command, komando checks it and stops reading `~/.komando`, private keys, `.env` files and credential stores (`~/.kube`, `~/.aws/credentials`, the keychain), listing all environment variables, changing or clearing the variables komando knows an agent by (`CLAUDECODE=0`, `unset`, `env -u`, `env -i`, `read`, `sudo komando`) or `KOMANDO_HOME`, searching or archiving a folder that holds them (`grep -r ~`, `tar -C ~ ...`), and running `ssh`/`scp` around komando. It reads relative paths from the agent's working folder, follows `cd`, and counts a glob such as `~/.komand?/*` as the path it could match; quoted patterns (`grep '.*' f`) are not globs. Skip it with `--no-guard`. |

## Add your own rules

```bash
komando policy deny 'terraform\s+destroy'           # a Go regular expression; prints its id
komando policy list                                  # built-in and custom rules, with ids
komando policy rm 'terraform\s+destroy'              # remove it again
komando policy rm custom-1a2b3c4d                    # or remove it by its id
komando policy check 'terraform destroy'             # exit 6 when it would be blocked
komando policy check --conn-kind postgres 'delete from users'   # rate SQL, Redis or MongoDB instead
```

A rule matches the command the way the shell reads it, so quotes and
backslashes inside a word (`r\m`, `/e""tc`) do not hide it. A custom
pattern that is not a valid regular expression blocks every command until
you fix or remove it; `komando doctor` and `policy list` name it.

Built-in rules cannot be removed. A custom rule's id (`custom-` and eight
letters and digits) is made from its pattern, so it stays the same when
another rule is removed. A pattern that matches empty text (`.*`) is
refused: it would block every command. Removing a rule turns a check off,
so komando asks first (a script adds `--yes`).

`policy check` exits 6 when the command would be blocked, so it works in an
`if`. `--conn-kind` rates a statement for a conn kind instead: `postgres`,
`mysql`, `sqlserver`, `oracle`, `clickhouse`, `snowflake`, `bigquery`,
`sqlite`, `redis`, `memcached` or `mongodb` (a command document as JSON).
It exits 6 too when the statement is destructive, which `db query` and
`cache run` refuse without `--allow-dangerous`.

## Personal data

Customer data in production should not end up in an AI model. On protected
servers and conns, an AI agent sees personal data hidden in what it reads
from them: `db query` rows (also with `-o csv`), `cache get` and `cache run`,
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
komando conn edit prod-db --option 'mask_columns=name address birth_date'
komando config set mask_personal protected       # back to the default (komando asks first)
```

- The `mask_personal` setting is `protected` (the default), `all`, or
  `off`. Showing agents more (`all` to `protected`, or `off`) turns a
  check off, so komando asks first; a script adds `--yes`.
- Names and street addresses have no shape komando can find, so name the
  columns that hold them in `mask_columns`, split by spaces. Setting it
  also turns personal data hiding on for that conn.
- A person decides when an agent sees the real values: with `--reveal`,
  which a person allows in the approval window, the agent sees them for
  that one command.
- A masked value is never written back: a `db query --write`, `cache set`
  or `cache run --write`, and a file write, that still holds
  `[hidden: ...]` stops with `HIDDEN_VALUE`.

## History

Every action is in the audit log: time, who ran it, which AI agent asked,
whether a person allowed it, the targets and the command. Every change to
the inventory and to safety settings is there too: servers, conns, groups,
keys, secrets (names only), `config set` (old and new value) and
`policy deny` and `policy rm`.

```bash
komando audit -o text                 # one line per entry, newest 50
komando audit -n 0                    # all entries
komando audit --failed                # only failed or blocked actions
komando audit --target @web           # only these servers or conns
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
(`actor_claimed`); `komando audit -o text` shows it as
`Claude Code (as claude)`. To keep SQL text out of the history, see
`audit_sql` in [Settings](settings.md#settings).

## A key that runs komando and nothing else

To reach komando on this computer from another device (the Komando app on
your phone, another computer), give that device's SSH key only komando:
`komando ssh-gate line` prints the line for `~/.ssh/authorized_keys`.

```bash
komando ssh-gate line --name phone ~/phone.pub                  # may read and change
komando ssh-gate line --name phone-read --read-only ~/phone.pub  # only reads
```

The line starts with `restrict,command="/full/path/komando ssh-gate --name
phone"`. Add it to `~/.ssh/authorized_keys` of the account komando runs as,
instead of the key's plain line. `restrict` turns off port, agent and X11
forwarding and the terminal (OpenSSH 7.2 or later). For that key, sshd then
runs `komando ssh-gate` whatever the key asks for, and:

| Seatbelt | What it does |
|----------|--------------|
| **Only komando** | The key's command must be one komando command (`ssh HOST komando list -o json`), with at most `KOMANDO_AGENT=NAME` before it. ssh-gate splits it into words like a shell, but runs no shell and expands nothing: an unquoted `;`, `\|`, `&`, `>`, `<`, `$`, backquote or line break is refused, and so is `$` or a backquote inside double quotes (`SSH_GATE_SYNTAX`); put such an argument in single quotes. Any other program, a login shell, `scp` or `sftp` is refused too (`SSH_GATE_REFUSED`). |
| **komando treats it as an AI agent** | Secret values stay `[hidden]`. `--reveal` and `--allow-dangerous` are refused, and so are commands for a person at a terminal (`shell`, `db shell`, `cluster shell`, `secret passphrase`, `secret check`, `login aws`, `config approval-code`). `--yes` on a protected target needs a person on this computer, which the key is not: change protected servers here. No approval window opens for a key. |
| **Nothing written here** | Every key, read-only or not, runs commands on servers, never one that writes on this computer: a file it saved here could be `~/.ssh/authorized_keys` or a shell startup file. So `download`, `db dump`, `storage download` (except `--to -`), `export --to`, and `cp` or `sync` to a folder here are refused, and so is any change to komando's own setup: servers, conns, VPNs, groups, settings, policy rules, secrets, keys, recipes, `guide install`, `import`, `host trust`, `tunnel start` and `stop`, and `update` (`SSH_GATE_REFUSED`). Change those here, as a person. Every key, read-only too, is also refused every command, reads included, on a target that is this computer as written: a sqlite conn, which is a file here (`VACUUM INTO`, `ATTACH` and `db restore` write any file), and a server, conn or cluster at `localhost`, a `127.x` or `::1` address, a loopback interface (`fe80::1%lo0`) or this computer's name. Through such a target `exec` would be a shell here (`--read-only` is a filter, not a sandbox), `logs --file`, `fs cat` and `fs list` would read any file here, a private key too, and Postgres `COPY TO PROGRAM` or `pg_read_file`, Redis `CONFIG SET dir` and a Kubernetes `hostPath` volume run programs or read and write files here. For a conn every host in its URL counts, a list (`a,b`), Postgres `?host=` and `?hostaddr=`, and a socket path. `cluster run -- cp POD:PATH DST` and `key deploy --set-default` are refused too. A change on a target the gate cannot find is refused; a read runs, unless the name is `localhost` or a loopback address (`cert check https://localhost`). A change komando adds later is refused until it is known to act on servers only. |
| **Read-only keys** | With `--read-only` the key runs only commands komando counts as reads (the `kind` in `komando schema`): `exec` (also with `--script`), `job start`, `docker exec` and `cluster exec` need `--read-only`, `db query`, `cache run` and `cluster run` no `--write`, `db explain` no `--analyze`, `pkg upgradable` no `--refresh`, `pkg security` no `--refresh`, and a recipe must be marked read-only. `storage link` and `cluster forward` are changes (`kind: change`), since they hand out access or open a port here: a read-only key is refused them (`SSH_GATE_READ_ONLY`), a full key runs them. |
| **Every command in the history** | Each command a key runs or is refused is in `komando audit`: the key's name (`ssh_gate`), what it sent (`ssh_command`, secret-looking values hidden), the address it came from (`client`) and, when refused, why. What the command then changes is recorded as from `ssh-gate key NAME`. This record is written even when the `audit` setting is off; when it cannot be written, nothing runs. In `komando audit` text, line breaks and terminal escapes in what a key sent show as `\n` and `\x1b`, so a key cannot add or hide rows. |

Give each device its own key and name, so `komando audit` tells them apart
and you can remove one line to lock one device out. The key reaches komando
as the account it logs in to: use that account for komando only, or one
with only the permissions komando needs.

## Limits

An AI agent runs as your own user on your computer. The approval window,
the masking and the guard stop mistakes and prompt injection (a web page or
a file telling the agent to leak something). They do not stop a program
that deliberately hides what it is or edits the guard away: nothing that
runs as you can. The guard reads shell lines as text; a script that builds a
path from pieces, or starts komando without the agent's variables from
another language, gets past it. So:

- give komando, and so your agent, an SSH user with only the permissions it needs;
- mark production with `komando host edit NAME --protected`;
- keep the vault key in the OS keychain (move a key from `store.key` there
  with `komando secret keychain`), so other people or backups that reach
  `~/.komando` cannot open the vault;
- give another device's SSH key only komando, with `komando ssh-gate line`.

More limits:

- The dangerous-command filter catches common accidents; it is not a
  complete security boundary.
- Masking is a best effort: a secret under an unusual name, or shorter
  than the text around it, can still slip through. Values shorter than 6
  characters are not hidden.
- Personal data hiding is a best effort too: a phone number written
  without `+`, or personal data in an image or a binary file, is not
  found. Hide whole columns where it matters.
- ssh-gate sees only the address komando keeps for a target (and, for a
  Kubernetes conn, the conn's URL, not the server in its stored
  kubeconfig). A key cannot name a target itself: `u@HOST` or an IP that
  is not in your list is refused (`SSH_GATE_REFUSED`), because it could be
  this computer's own address. But a listed server, conn or cluster that
  is this same computer under another name or address (its LAN IP, a DNS
  name, a tunnel or port forward that leads back here) cannot be told
  apart, and any key, read-only too, would read files or get a shell here
  through it (`exec THAT-HOST --read-only -- 'nc -e /bin/sh ...'`). Do
  not list this computer in komando that way: `--read-only` does not make
  it safe.
- Secrets are never accepted as command arguments, because they would land
  in your shell history (`SECRET_IN_ARGS`). `komando secret set NAME` asks
  for the value after the prompt appears; see [Secrets](secrets.md#save-one).

## Troubleshooting

At your terminal komando asks you first; an AI agent or a script adds
`--yes` (or `--allow-dangerous`) after a person agrees. The codes below are
what an agent or a script gets.

| Error | Exit | What it means | What to do |
|-------|------|---------------|------------|
| `POLICY_BLOCKED` | 6 | The command looks destructive. | Check the command. At a terminal komando asks you to type the name of what goes; a script adds `--allow-dangerous` after a person agrees. |
| `PROTECTED_HOST`, `PROTECTED_TARGET` | 6 | A change to something protected. | At a terminal komando asks `[y/N]`; a script adds `--yes` (an AI agent's `--yes` opens the approval window). Commands that only look can add `--read-only`. |
| `SAFETY_SETTING` | 6 | A change that turns a seatbelt off. | At a terminal komando asks `[y/N]`; a script adds `--yes` (an AI agent's `--yes` opens the approval window). |
| `SECRET_DESTINATION` | 6 | An agent asked to send a secret somewhere new (see [above](#seatbelts-for-ai-agents)). | Tell the user which secret goes where; once they agree, add `--yes`. |
| `OPEN_BIND` | 6 | A tunnel would listen on an address other machines can reach. | Keep the default 127.0.0.1, or add `--yes` after a person agrees. |
| `CONFIRM_REQUIRED` | 6 | A change that touches many entries (deleting a group). | Check them first, then add `--yes` after a person agrees. |
| `WRITE_REQUIRES_FLAG` | 6 | The query or command changes data. | Try `--write --dry-run`, then `--write`. |
| `READ_ONLY_VIOLATION` | 6 | `--read-only` was given, but the command changes something. | Drop `--read-only`; a person may confirm with `--yes`. |
| `DB_BYTES_LIMIT` | 6 | A BigQuery query would read more bytes than `--max-bytes` allows, so it did not run. | Select fewer columns or filter more; raise `--max-bytes` only if the person agrees to the cost. |
| `SQL_STRING_RULES` | 6 | The ClickHouse user reads queries in another dialect, so komando cannot check them. | Use a user whose settings keep `dialect = 'clickhouse'`. |
| `UNSAFE_BACKUP` | 6 | The backup file holds a client command, not SQL, that could run programs where the restore runs. | Remove that line if the dump is not trusted. |
| `SENSITIVE_FILE` | 6 | An agent tried to copy a secret file here, or to have komando read one here. | Read it with `fs cat` (values hidden); a person may allow `--reveal` for a project file. |
| `REVEAL_NEEDS_HUMAN` | 6 | Only a person can see secret values. | Ask the person to run the command in their own terminal. |
| `REVEAL_NEEDS_PERSON` | 6 | An AI agent asked for `--reveal`. | Run it without `--dry-run`: komando asks the person in a window on their screen. |
| `NEEDS_PERSON` | 6 | Only a person can do this: `secret set` and `secret check` for an agent, `secret keychain`, `secret passphrase`, `doctor --accept-old-copy`, `login aws`, `host ssh-command` for an agent, setting up `config approval-code`, replacing a pinned host key with `host trust --reset`. | Ask them to run it in their own terminal. A `--dry-run` still shows the plan. |
| `STORE_OLD_COPY` | 6 | An older copy of `store.db` was put back. | No flag clears it. If you restored it on purpose, run `komando doctor --accept-old-copy` in your own terminal (see [Settings](settings.md#where-komando-keeps-its-data)). |
| `DECLINED` | 6 | You answered no to komando's question. | Nothing was changed; run it again to be asked again. |
| `SSH_GATE_REFUSED`, `SSH_GATE_READ_ONLY` | 6 | An SSH key limited by `komando ssh-gate` asked for something it may not run (see [above](#a-key-that-runs-komando-and-nothing-else)). | No flag allows it: a person runs it on the komando computer. |
| `SSH_GATE_SYNTAX` | 2 | The key's command is not one komando command. | Put an argument with `;`, `\|`, `$`, a backquote and the like in single quotes: `$` and backquotes are refused even in double quotes. |
| `SSH_GATE_PATH` | 1 | `komando ssh-gate line` cannot tell komando's full path, which the line needs. | Run it by its full path, such as `/usr/local/bin/komando ssh-gate line ...`. |
| `SHARED_FOLDER_CONFLICT` | 8 | A write as root (`--sudo`) into a folder another server user can change. | Write the file as that user instead; the hint gives the `exec --sudo-user` command. |
| `HIDDEN_VALUE` | 2 | The text holds `[hidden]` or `[secret:NAME]`. | Change one line with `fs replace`, using `{{secret:NAME}}`. |
| `SECRET_INPUT_INVALID` | 2 | An AI agent's arguments, `--script`, `--stdin-file` or SQL file hold the value of a secret in the vault. Refused before anything runs, a dry run too, and written to the audit log. | The agent uses `{{secret:NAME}}`; a value you gave it goes in with `komando secret set NAME` first. |
| `SECRET_IN_ARGS` | 2 | A secret value was given on the command line. | Run `komando secret set NAME` and type it after the prompt, or use `--from-env VAR` or a pipe. |
| `HOSTKEY_MISMATCH` | 4 | The server's identity changed. | Never "fix" it blindly; see [Results and errors](output.md#troubleshooting). |
| `AUDIT_UNAVAILABLE` | 1 | The audit log cannot be written, so nothing runs. | `komando doctor` shows why. |
