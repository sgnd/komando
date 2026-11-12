# komando UX guide

Status: **in effect, 2026-11-02.** This document sets the rules for every
command, flag, message, and output. New features must follow it. A command
that breaks these rules is a bug.
The big goal is in [vision.md](vision.md).

In short: **one way to do each thing, words people understand, safe when
in doubt, and every error tells you the next step.**

## 1. Command grammar

```
komando <noun> <verb> <TARGET> [args] [flags]
komando db query app-db "select 1"
komando storage upload backups ./dump.sql.gz
```

- **Noun** = a work area in human words: `host`, `conn`, `db`,
  `cache`, `queue`, `storage`, `cluster`, `registry`, `secret`, `vpn`.
  Product names are only aliases (`s3`, `redis`, `sql`, `k8s`, `kafka`).
- **Verbs** come from the standard list below. A new verb may only be added
  if none of the existing ones fits, and it must be recorded here.
- **The noun's own item comes first, then TARGET** (S-1.2): `key deploy
  NAME TARGET`, `recipe run NAME TARGET`, `group add GROUP TARGET...`.
  Commands without an item start with TARGET: `svc restart TARGET
  UNIT...`. Commands with neither take no TARGET (`host list`, `secret
  set NAME`).
- **Argument words have one meaning** (S-4.2): TARGET picks one or more of
  the kinds the command serves, SERVER is exactly one server, CONN one conn
  of the command's family, NAME an item of the command's own noun, USER an
  account, KEY a cache key, OBJECT a storage object, CONSUMER a queue
  consumer group, TYPE/NAME a cluster object, and `-- COMMAND...` or
  `-- ARGS...` what runs. A required flag shows in the usage line with an
  UPPERCASE value (`db restore CONN --from FILE`).
- Cross-area commands that are used often may live at the top level (`exec`,
  `logs`, `cp`, `list`, `test`), but only as shortcuts with the same
  shape.

### Standard verbs

| Verb | Meaning | Accepted aliases | Risk |
|---|---|---|---|
| `list` | list items in the **komando inventory** (host, conn, secret, job) | `ls` | read |
| `ls` | list the **contents inside** a target (files, objects, keys, pods) | `list` | read |
| `show` | details of one inventory item | none | read |
| `get` | read the **value** of one item inside a target (key, small object, secret) | none | read |
| `status` / `info` | state of the target (version, health, memory) | none | read |
| `logs` | logs | none | read |
| `test` | check connection and login | none | read |
| `add` | add to the inventory | none | none |
| `edit` | change the inventory | none | none |
| `rm` | remove | `remove`, `delete`, `del` | destructive if data is lost |
| `set` | write one value | none | write |
| `upload` / `download` | move files between this computer and the target | `put` / `get` | write / read |
| `run` | send a raw command in that area's own language (Redis, kubectl), still classified (`cache run`, `cluster run`, and `recipe run` for a saved recipe) | none | depends on content |
| `query` | the same for SQL and MongoDB: `db query` (databases use `query`, not `run`) | none | read unless `--write` |
| `start` / `stop` / `restart` | start, stop, restart | none | write |
| `dump` / `restore` | back up and restore | none | write / destructive |
| `import` / `export` | move configuration in and out | none | none |
| `mv` | rename an inventory item and update everything that refers to it (`host`, `conn`, `vpn`, `key`, `secret`, `group mv`); `fs mv` moves a file on a server | none | none (inventory) / write (`fs`) |
| `cp` | copy an inventory item to a new name (`secret cp`) | none | none |
| `check` | test something against a rule and report, changing nothing (`cert check`, `net check`, `policy check`, `secret check`) | none | read |
| `inspect` / `describe` | everything about one object inside a target (`docker inspect`, `registry inspect`; `cluster describe` and `queue describe`, the word kubectl uses) | none | read |
| `prune` | delete old or unused things by a rule (`docker prune`, `registry prune`) | none | destructive |
| `restore` | put back a backup (`db restore`, `fs restore`) | none | destructive / write |
| `kill` | stop something that runs now (`job kill`, `db kill`) | none | write |
| `wait` | wait until a job ends (`job wait`) | none | read |
| `up` / `down` | connect and disconnect a VPN | none | none (this computer) |
| `gen` / `deploy` / `revoke` | SSH keys: make one, put it on servers, take it off (`key gen`, `key deploy`, `key revoke`); `cluster deploy` sets an image, `db user revoke` takes a right away | none | write |
| `trust` | pin a server's SSH host key (`host trust`) | none | none (this computer) |
| `install` | install komando files into another program's folder (skill for AI agents: `guide install`) | none | write (local files) |
| `uninstall` | take out what `install` put in (`guide uninstall`) | none | write (local files) |
| `update` | replace the komando program with a newer release, or the version named (`komando update`; added 2026-11-08) | none | write (the komando program); an older version needs `--yes` |

Words an area's own tool uses are kept as they are, so people who know
that tool find them: `scale`, `apply`, `rollback`, `history`, `events`,
`forward` (kubectl), `ps`, `pull`, `compose`, `raw` (Docker; `run` would
read as `docker run`), `daemon-reload`, `upgradable`, `upgrade`, `lock`,
`unlock`, `peek`, `purge`, `send`, `grant`, `passwd`. A few inventory words
have one home only: `conn kinds` (the kinds `conn add` takes),
`host ssh-command` (the `ssh` line for a server), `secret keychain` and
`secret passphrase` (where the vault key is kept). A new verb still needs a
row here, or a place in this list.

Rule: **`rm` is always the main word.** `remove`, `delete`, and `del` are only
aliases, so that anyone who types them still succeeds.

## 2. Targets and selectors (apply to hosts and conns)

Owner decision (2026-11-02): **selectors pick everything**, servers and
conns alike, because komando is now universal.

| Selector | Picks |
|---|---|
| `NAME` | one host or conn (the name is unique across both) |
| `web-*`, `db-?` | glob on names |
| `@GROUP` | all members of the group |
| `tag:T`, `label:K=V` | everything that has that tag or label |
| `kind:postgres`, `kind:host`, `kind:db` | everything of that kind, or of that command family (`db`, `cache`, `queue`, `storage`, `cluster`, `registry`) |
| `os:windows`, `os:linux` | servers by system (Windows, or everything else) |
| `all` | everything |
| `a,b,!c` | combination; `!` excludes |
| `user@addr:port` | ad-hoc host (hosts only; conns must be registered) |

How commands use the selector result:

1. **Commands that look** (`list`, `test`, `show`, `audit`) use everything
   that was picked.
2. **Commands that act** use the members they can serve
   (`exec` → host; `db` → sql conn; `cache` → kv conn). The rest are reported in
   `meta.skipped` with the reason, not silently ignored.
3. If **none** can be served, the command fails with
   `NO_MATCHING_TARGETS` (exit 3) and a hint that names the right command
   (e.g. "app-db is a database; use `komando db query app-db`").
4. A selector that matches nothing is always an error, never a success
   with zero results. A typo (`@prdo`) gets "did you mean `@prod`?".
5. Results are always ordered by name, so they are stable for people and agents.
6. **Safety checks run for the whole batch before anything
   runs.** If one protected target needs `--yes`, the whole batch stops
   and names every such target. There is no "stopped halfway because it was blocked".
7. `db query` runs against one database; a selector that picks several is
   refused with a clear message.

## 3. Flags

### Global flags whose meaning never changes

| Flag | Meaning |
|---|---|
| `-o, --output json\|text` | output format (automatic: text in a terminal, json when piped); `db query` also takes `csv` and `tsv` |
| `--dry-run` | show what would happen, without changing anything |
| `--write` | allow changes in raw commands (`db query`, `cache run`, `cluster run`) |
| `--yes` | confirm a change on a protected target |
| `--allow-dangerous` | allow a command blocked by policy, for this command only |
| `--timeout` | time limit per target |
| `--parallel` | how many targets at once |

### Standard flag names

| Need | Flag | Notes |
|---|---|---|
| how many | `-n, --limit` | log lines, items, keys, SQL rows; in `cluster`, `--limit` has no short form (`-n` is the namespace there) |
| a safety cap | `--max-remove`, `--max-bytes`, `--max-output` | the run is refused above it; never `--limit` |
| recursive | `-r, --recursive` | always lowercase `-r` |
| keep following (logs) | `-f, --follow` | on the log streamers `-f` is follow, like `tail -f` and `kubectl logs -f` |
| input file | `-f, --file` | a file a tool reads (`db query -f`, `docker compose -f`, `cluster apply -f`); in `logs`, `-f` is for follow |
| to/from a local file | `--to` / `--from` | |
| replace what exists | `--overwrite` | replaces `--force` |
| named parameters | `--var KEY=VALUE` | for recipes |
| positional parameters | `--arg VALUE` | for `$1`/`?` in SQL and script arguments |
| group / tag | `-g, --group` / `-t, --tag` | |
| search text | `--grep` | no short letter, because `-g` = group |
| filter the inventory | `--target SELECTOR` | replaces `--host` in `audit` and `job list` |
| root rights | `--sudo` / `--no-sudo` | see the sudo rule below |
| raw command changes nothing | `--read-only` | see the polarity rules |
| time | `--since`, `--until`, `--ttl`, `--expires`, `--wait`, `--warn`, `--older-than`, `--interval`, `--timeout` | one duration type: Go format (`10m`, `2h`) or days (`7d`); a bare number only as `0`. `--since`/`--until` also take `today`, `yesterday` or a date. `svc`/`reboot --wait 10` (bare seconds) is a retired shape that still works |
| size | `--max-bytes`, `--max-output` | one bytes type: bytes, or `KB`/`MB`/`GB`/`KiB`/`MiB`/`GiB`, where KB = KiB = 1024 |
| KEY=VALUE | `-e, --env`, `--label`, `--option`, `--var`, `--header` | one pair per use, repeatable, never split on commas; a second `KEY=` after a comma is a usage error |

### Reserved short flags

A short letter means the same long flag wherever it appears, inside the
scope given here (S-5.14 of the command standard).
`TestStandardShorthands` (`internal/cli/shorthand_test.go`) walks the
command tree and checks every letter against this table. A new short
flag needs a row here first, with a well-known tool that uses the letter
the same way. A letter that means something else on a command today is
retired there with a usage error naming the new flag, unless every input
that works today still means the same or fails.

| Letter | Long flag | Scope | From |
|---|---|---|---|
| `-o` | `--output` | global | kubectl |
| `-P` | `--parallel` | global | xargs -P |
| `-y` | `--yes` | global; never after `--` | apt, gcloud |
| `-h` | `--help` | global | |
| `-v` | `--version` | root only | |
| `-a` | `--all` | read commands only: `docker ps`, `fs ls`, `user list`, `db activity`, `cache info`, `cluster helm values`, `guide`; `docker prune -a` kept (docker's own) | ls, docker ps |
| `-A` | `--all-namespaces` | cluster | kubectl |
| `-c` | `--container` | any `--container`; `--cmd` only on `exec` and `job start` | kubectl |
| `-C` | `--dir` | any `--dir`; `--comment` only on `key gen` | git, make |
| `-e` | `--env` | any `--env` | docker |
| `-f` | `--follow` on the log streamers (`logs`, `svc logs`, `docker logs`, `cluster logs`); `--file` elsewhere | | tail, kubectl apply |
| `-g` | `--group` | add, edit and import | |
| `-l` | `--selector` | cluster | kubectl |
| `-n` | `--namespace` in cluster (a number is refused: `--limit N`, or `--namespace=N`); `--limit` elsewhere; on `storage rm` the retired spelling of `--max-remove` | | kubectl, head |
| `-p` | `--parents` on writers (`cp`, `upload`, `fs write`, `fs replace`; a no-op on `fs mkdir`); `--priority` on journal readers | | mkdir, journalctl |
| `-r` | `--recursive` | everywhere | cp |
| `-s` | `--sudo` | everywhere | |
| `-t` | `--tag` | add and edit | |
| `-u` | `--unit` | the logs commands | journalctl |
| `-b`, `-D`, `-L`, `-R` | bits; dynamic, local, remote | `key gen`; `tunnel start` | ssh-keygen, ssh |

Never a short letter for `--allow-dangerous`, `--reveal`, `--write`,
`--dry-run`, `--port`, `--user`, `--label`, or a bool `--all` on a
command that changes things (`fs replace`, `tunnel stop`, `vpn down`,
`logout`). An unknown letter gets a did-you-mean: the habit of another
tool (`-n`, `-it`, `-L`, `-w`), else the long flags with that letter.

### Polarity rules (important for safety)

- **Anything unknown is treated as a change.** Raw commands whose content
  cannot be proven safe (`exec`, `exec --script`, `recipe run`, `docker exec`)
  are treated as *write*, unless marked `--read-only`.
- **If the server can enforce read-only, the default is read-only** and it needs
  `--write` (`db query`, `cache run`). `cluster run` follows the same
  default: it only reads unless `--write`.
- Commands with a clear verb (`storage upload`, `svc restart`)
  do not need `--write`; the verb is already a statement of intent.

### Sudo rule

System-level commands (`svc`, `pkg`, `user`, `recipe`) use sudo automatically
when needed, and this can be turned off with `--no-sudo`. Other commands (`exec`,
`fs`, `cp`, `logs`, `cron`, `docker`) do not use sudo unless given
`--sudo`. One rule, one flag per command.

## 4. Output

- **One JSON envelope** on stdout when piped. Neat text in a
  terminal. Progress and prompts **always go to stderr**, never to stdout.
- Color only in a terminal, and it respects `NO_COLOR`.
- Lists are sorted by name, as one list: a KIND or TYPE column tells
  kinds apart, never the order. Rows a server sends in its own order are
  sorted too. Only lists without names keep another order: jobs and
  tunnels by start time, crontab lines as in the file, `audit` by time.
- Many targets: `data.results[]` per target (sorted by name), a summary
  `data.summary` (`ok`, `failed`), and skipped targets in
  `meta.skipped[]`. Top-level `ok` is `false` if any one failed; the exit code
  uses the worst one.
- Large results are cut with `truncated: true` and a hint that suggests
  `--limit`, `WHERE`, or a prefix. There is never unlimited output.
- Times in JSON are always UTC RFC3339. Text for people shows local
  time with its zone.
- Binary values → `{"base64": "..."}`. Big numbers → strings. `null` and
  an empty string are kept distinct.
- Text for people fits in 80 columns; long columns are cut with `…`
  and shown in full with `-o json`.

## 5. Errors

Every error has a `code` (stable, UPPER_CASE), a `message` (what
happened, in simple words), and a `hint` (the exact command to
run next).

- Typo in a command, name, or selector → "did you mean ...".
- Errors from the server (SQL, Redis, S3, k8s) are passed on as they are in
  `message`, with the original code in `data` (`sqlstate`, HTTP code).
- If a command cannot be undone or a dry-run is not possible, say
  so plainly. Do not pretend.

## 6. Confirmation and safety

One rule table (`internal/cli/risk.go`) says what each command and flag
combination needs; the stops, the person's questions, `komando schema`'s
`confirm` and this table all come from it (command-standard S-7.1, S-7.2).

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
| `pkg security` | with --apply, when an update would remove a package the server needs | dangerous | `--allow-dangerous` |
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
| `config approval-code` | always | person |  |
| `secret passphrase` | always | person |  |
| `secret check` | always | person |  |
| `shell` | always | person |  |
| `db shell` | always | person |  |
| `cluster shell` | always | person |  |
| `login` | always | person |  |
| `login aws` | always | person |  |
| `ssh-gate` | always | person |  |
| `host trust` | with --reset, when a key is pinned | person |  |
| `group rm` | GROUP alone: deleting a group of more than 3 members (CONFIRM_REQUIRED) | change | `--yes` |

<!-- end of tiers -->

- **Agents and scripts**: a stop gives exit 6 and a hint naming every flag
  the real run needs; a dry run lists them in `meta.would_need`.
- **People at a terminal** (stdin and stderr are both terminals, and no AI
  agent runs komando): komando asks `prod-db (protected): this command
  changes it. Continue? [y/N]`. A step that cannot be undone asks once to
  type the name of what goes (or how many, or the target for a
  whole-target step; never "yes"), and on a protected target that one
  answer covers the protection too. The answer is read from the terminal,
  not from piped stdin, so an agent cannot answer it. A question is one
  typed line with a safe default. A choice (a VPN login's realm, say)
  shows its options as numbered lines and takes the number or the name; a
  wrong answer is asked again, up to 3 times.
- **Logins ask a person, as ssh does** (2026-11-09). What an SSH or VPN
  login asks that komando cannot answer from the vault (a password when
  none is stored, a one-time code, any other question) goes to the person
  at the terminal, with the server's name (`web1: Verification code:`),
  hidden unless the server lets it show; one question at a time. A stored
  password still goes out once, only to a hidden password question.
  Agents and scripts are never asked: they get `NO_AUTH` or `AUTH_FAILED`
  and a hint that sends a person to run the command.
- **A value only the person knows is typed by the person.** An agent that
  runs `secret set NAME` without a value gets `NEEDS_PERSON`: it asks the
  user to run the command in their own terminal, never for the password in
  the chat.
- `--allow-dangerous` and `--yes` apply to one command only and
  are recorded in the audit.
- **No way around it.** Removing, replacing, or turning off protected
  on a protected target needs `--yes`. Turning off the audit log, the host key check, or
  removing a deny rule needs `--yes` (`SAFETY_SETTING`).
- **Fail closed**: if the audit cannot be written, the change is refused.
- **Ctrl-C midway** cancels the command's work: the transaction is rolled
  back, temporary files are deleted, and the command fails with
  `CANCELLED` (`interrupted`), exit 1. A command that records its error
  in the audit records `CANCELLED`.
- **Ctrl-C at a question** stops the question at once, puts the terminal
  back as it was (echo on again after a hidden prompt) and ends the line.
  At a `[y/N]` question or a typed name it is a no: the command stops with
  `cancelled: ...`, hint `nothing was changed`, exit 6. At a hidden prompt
  (a secret, a VPN password) it is `CANCELLED` (`interrupted`), exit 1.
  Every later question in the same command gets no answer, at once.
  Ctrl-D at a question that shows what is typed is an empty answer, which
  is a no.
- **A paste of more than one line at a hidden prompt** is refused (`USAGE`,
  exit 2) and nothing is stored or sent. The other lines are thrown away,
  so the shell cannot run them (and show the secret) once komando ends.

## 7. Secrets

- Secrets never appear in command arguments, URLs, the audit, or output
  (except `secret get --reveal` at a person's request).
- Ways to enter a secret: hidden prompt, `--from-env VAR`, or stdin.
  **A value as a positional argument is refused**, because it is saved in shell
  history and visible in `ps`.
- A ref that cannot be read (empty `env:X`, missing file, file permissions
  too loose) → an error with the ref name, without its value.

## 8. Inventory and names

- Names: letters, digits, `-`, `_`, `.`; 1–63 characters; start with a letter or
  digit (already in effect). Unique across hosts and conns, ignoring
  upper/lower case.
- Words that have a meaning as a selector (`all`) are refused as names.
- Rename updates everything that refers to it (groups, `--via`, recipes).
  Remove is refused (`HOST_IN_USE`, `SECRET_IN_USE`, `KEY_IN_USE`, ...) if it is still in use, with the list of users.
- State is written atomically under a file lock, so two komando processes running
  at the same time do not overwrite each other. A state schema change makes a backup first.

## 9. Migration

- `komando import SOURCE` with `--dry-run` and `--overwrite`. Importing again
  is safe (idempotent): identical items are skipped, different ones are reported.
- Unsupported fields are **reported**, not silently dropped.
- Names that clash between sources (e.g. `web1` in ssh-config and kubeconfig)
  get a suggested name, and are not overwritten.
- Secrets from any source go into the vault, then are referred to with `secret:`.

## 10. Help and ease of use

- **Person mode is commands, not a menu** (owner decision 2026-11-12,
  vision.md decision 5). `komando` with no arguments: for a person at a
  terminal, the commands by group with START first (and, with nothing
  added, how to add the first server); for agents and scripts the first
  steps; piped, one `USAGE` envelope (see Streams and scripts). Help topics:
  `komando help safety|environment|exit-codes|output`.
- **A typed command asks for what is missing**, only when `promptable()`:
  stdin, stdout and stderr are terminals, no AI agent, `CI` unset or
  false, `TERM` not dumb, output text. The line is filled in before cobra
  runs (internal/cli/prompter_fill.go): missing positionals in Use order,
  required flags, and optional values a formHint marks `need` (db query's
  SQL without --file). One line per question, labelled with the real name
  (`CONN (database):`, `--old:`), `?` for the hint's help, the default in
  brackets, a wrong answer explained and asked again (3 times). Lists come
  from the inventory (formPickRows); a number picks, text narrows, a
  selector or a new name is taken as typed. One item that is not protected
  is used and said; a protected one is never picked; none says how to add
  one. Then `$ komando ...` (the line that runs, as typed). A read runs at
  once; a change asks `Run it? [y/N, d = --dry-run first]`, a delete for
  good asks to type the name, a protected target leaves it to its own
  `[y/N]`. The questions never add `--yes`, `--allow-dangerous`,
  `--reveal` or `--write`. A command typed in full runs as it always did;
  what agents and scripts get is pinned by TestAgentGolden.
- `host add`, `conn add`, `vpn add` and each family's add typed alone ask
  that kind's own questions (form_kinds.go, form_<family>.go): kind, name,
  address or URL parts, login, production; never a password (the command
  asks it, hidden, `--ask-password`); a pasted `user:password@` is never
  drawn. After a failed test the next steps are three commands.
- After a command a person ran ends well: `Next time: <line>` when komando
  asked for something, `Next:` from the formHint's `next` (each area
  keeps its lines in its form hints file, at most three), and the show
  commands in `showKinds` (`host show`, `conn show`, `vpn show`, `group
  list GROUP`, `key show`, `job status`, `secret get`, `config get`) end
  with that item's commands from `itemCommands`. All on stderr, only at
  a person's terminal.
- Every command has at least one real example in `--help`.
- Shell completion completes host, conn, group, and tag names from the inventory.
- `komando guide` (for agents) and `docs/features/` (for people, one file per feature) are always
  updated in the same commit as the feature.
- Renaming a command or flag: the old name keeps working as an alias
  for one minor release, with a warning on stderr, then it is removed.
- `TestConventions` (`internal/cli/conventions_test.go`) guards part of
  the naming rules: retired flag names, the `rm` and
  `list`/`ls` aliases, an example on every command and the length of the
  one-line help. The verb list in section 1 is kept by review: no test
  checks it.

## 11. No overlapping features

Owner decision (2026-11-02). **One need, one command.** Before
adding a command or flag, first check whether something already does it.
If it exists, extend the old one. Do not create a new one.

- One concept has one name in all areas (e.g. path = `--via`, not
  `--via` here and `--jump` there).
- A "per area" version of a general command may only exist as an **alias** that
  calls the general command. There must not be two implementations.
- Things that differ by **scale** (one item vs many at once) may exist,
  but both use the same code.

Current overlaps, and the decision:

| Now | Decision |
|---|---|
| `host --jump` and `conn --via` | ✅ `--via` for everything ([network.md](network.md)) |
| `host test`, `conn test`, `test` | ✅ only `test`; `host test`/`conn test` = `test` for one kind |
| `host list`, `conn list`, `list` | ✅ only `list`; `host list`/`conn list` = `list kind:host` / `list kind:conn` |
| `svc logs`, `docker logs`, `logs --unit/--container` | ✅ only `logs`; `svc logs` and `docker logs` are aliases that call it |
| `ops run` (built-in recipes) and `snippet run` (your own recipes) | ✅ one `recipe` (a word that is easier to understand); the old names `ops` and `snippet` are gone |
| `cp` (server) and `storage upload/download` | ✅ `upload`/`download` for servers (SFTP) and storage; `cp` and `storage upload/download` call them |
| `script` and `exec` | ✅ `exec --script FILE`; `script` is an old name for one release |
| `group add/rm` and `edit --add-group/--rm-group` | keep both (many vs one), same code |
| `host import/export` and `import ssh-config\|komando`, `export` | ✅ only `import` and `export` (one file format, komando-export/1); `host import/export` are old names for one release |
| `prompt` and `status` | ✅ `status --short`; `prompt` is an old name for one release |

## 12. Every native CLI feature can be used

Owner decision (2026-11-02): komando must be as strong as the original tool. The way
to do it is not to copy every feature of that tool, but three paths that are the same in all areas:

1. **Commands komando understands** (`db schema`, `cache get`, `storage ls`): structured
   output, safe, easy to use. For most daily work.
2. **A raw path in the native language**, still classified, read-only by
   default, and audited: `exec` (shell), `db query` (any SQL), `cache run`
   (any Redis command), `cluster run -- <kubectl args>`. Anything
   the original tool can do can be done through here.
3. **The native tool on your laptop, through the komando path**: `komando tunnel start
   app-db` gives a local port for TablePlus/`psql`, `komando shell` opens
   interactive SSH, and `komando db shell app-db` opens komando's own SQL
   shell with the password from the vault and the `--via` path, with no password on screen.

Paths 2 and 3 do not count as overlapping with path 1: they are emergency doors
that exist on purpose, with the same safeguards.

## 13. Output contract (v1.0)

Agents depend on the shape of komando's output, so that shape is frozen
as **contract version 1** (`meta.contract` in every response,
`contract` in `komando schema`).

Within one contract version:

- The envelope (`ok`, `command`, `data`, `error`, `meta`), field names, error codes
  and exit codes are **never renamed or removed**. Only additions are allowed:
  new fields, new error codes, new commands.
- Renamed commands and flags keep working as aliases (see
  section 10), so old scripts do not break.
- Breaking changes (renaming a field, changing the meaning of an exit code)
  raise `meta.contract` to 2 and are written in the CHANGELOG.

`TestConventions` and the e2e tests guard part of these rules.

## Anti-slop checklist

Output that looks busy but says little ("slop") wastes a person's
attention and an agent's tokens. Check every new command and every review
against this list. It follows the [Command Line Interface
Guidelines](https://clig.dev) and the rules above.

**Words**
- [ ] Counts are words: `countOf(n, "server")` gives "1 server" / "3
  servers"; `failedOf` gives "1 of 3 failed", "both failed", "all 5
  failed". Never `server(s)`, never "2 of 2 failed".
- [ ] A change says what happened first, in words: `added web2`,
  `changed web2`, `web2: nothing to change`, `would add web2 (dry run)`.
  Not "Success!", not `action: added` buried in a list of fields.
- [ ] No emoji, banners, boxes or ASCII art. `✓`/`✗`/`!` in `doctor` and
  `●` per server are the only symbols, and each carries meaning.
- [ ] Booleans for people are `yes` or `-` in tables, not `true`/`false`.
- [ ] Times for people are local with the zone; JSON keeps UTC RFC3339.

**Errors**
- [ ] One line of message, no stack trace, no raw library text with
  embedded newlines.
- [ ] A typo in a command, flag, name or selector gets "did you mean".
- [ ] The hint is the exact next command, or the command's own example
  and `--help`. Not one hint shared by every command, not a question.
- [ ] One target that fails gives its own error code, not
  `PARTIAL_FAILURE`.

**Help**
- [ ] `komando` alone: the commands by group for a person at a terminal;
  otherwise the first steps, a dozen lines at most. A command typed with
  something missing asks a person for it, and nobody else.
- [ ] Every command has at least one real example (`examples.go` or its
  own `Example`). `TestConventions` fails without one, and
  `TestExamplesParse` fails when an example names a command or flag that
  does not exist.
- [ ] `Short` is one sentence fragment, no full stop, and does not repeat
  the command name: 64 characters at most for a top-level command, 80
  for others (`TestConventions`). The detail goes in Long (or `details`
  in `examples.go`).
- [ ] A sub-command's `--help` lists only the global flags that matter
  there; `komando --help` lists them all.

**Streams and scripts**
- [ ] Data on stdout; progress, prompts, warnings and the error in text
  mode on stderr.
- [ ] Piped output is one JSON envelope, never mixed with text, also for
  `komando` alone and a group command without its sub-command.
- [ ] Nothing asks a question when stdin or stdout is not a terminal.
- [ ] Color only in a terminal and never with `NO_COLOR`.
- [ ] The exit code is honest: non-zero whenever `ok` is false.

## Edge case list

This checklist is used for every feature and every review.

**Targets and network**
- `--via` host is down, slow, or its host key changed (`HOSTKEY_MISMATCH`, never skipped automatically)
- IPv6 addresses (`[2001:db8::1]:22`), DNS failure, wrong port, silent firewall (timeout, not hanging)
- Bastion chains with more than one hop; corporate proxy
- TLS with a self-signed certificate: an explicit option per conn, never silently turned off
- 500 targets at once: `--parallel` limit, output stays ordered, one failure does not stop the others (unless `--fail-fast`)

**Credentials**
- Secret ref missing, env empty, file unreadable, vault locked in a non-interactive session
- Expired token (AWS session, kube exec plugin): a clear error with how to renew it
- Password in the URL during `conn add` or `import`: refused, hint to `secret set`

**Safety**
- Dangerous commands in disguise: comments, mixed case, odd spacing, multi-statement, `rename-command` in Redis
- Unknown commands are treated as write
- One protected target inside a batch: the whole batch stops before it starts
- `--yes` given but not needed: still runs, gives no extra permission
- Dry-run not possible (MySQL DDL, `VACUUM`): reported, not executed
- Audit fails to write: the change is refused

**Data and output**
- Very large results, binary values, non-UTF-8 text, `NULL`, numbers > 2^53, time zones
- Narrow terminal, output piped to `less` or `head` (SIGPIPE is not treated as an error)
- Partial failure across many targets: an honest exit code and summary

**Files and transfer**
- Destination file already exists: not overwritten without `--overwrite`
- Download interrupted: write to a temporary file then rename; never leave a half-written file
- Trailing slash in a path (`dir` vs `dir/`): its meaning is written clearly in `--help`, the same for `cp` and `storage`
- `~` in local vs remote paths, spaces and unicode in file names, symlinks, very large files (progress on stderr)

**Processes**
- More than ~2 minutes → `job`; connection drops while a job runs; orphan jobs are cleaned up
- Ctrl-C: rollback, clean up, `CANCELLED` (exit 1); at a question, a no
  with echo back on
- Two komando processes running at the same time on the same state

**Per area**
- **db**: long locks (`lock_timeout`), read-only replicas, connection limits, restore into the wrong database (protected + retype the name)
- **cache**: `KEYS` on a large cache (use `SCAN`), Redis cluster (`MOVED`), sentinel, database numbers
- **storage**: buckets with versioning (delete markers), "folders" that are really prefixes, multipart upload, links with a maximum lifetime of 7 days
- **cluster**: default namespace, kubeconfig context, exec auth plugins that need another binary, `apply` always with a diff and `--dry-run=server` first
- **registry**: Docker Hub rate limits, tag vs digest (deleting a digest also deletes other tags)

**Migration and versions**
- `~/.ssh/config` with `Include`, `Match`, and wildcards; kubeconfig with many contexts
- Importing again, clashing names, unsupported fields
- JSON contract changes: new fields are allowed, old fields are not removed before a major version
