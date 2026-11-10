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
- **TARGET is always the first argument** after the verb, except for commands
  that have no target (`host list`, `secret set`).
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
| `run` | send a raw command in that area's own language (SQL, Redis), still classified | `query` for SQL | depends on content |
| `start` / `stop` / `restart` | start, stop, restart | none | write |
| `dump` / `restore` | back up and restore | none | write / destructive |
| `import` / `export` | move configuration in and out | none | none |
| `install` | install komando files into another program's folder (skill for AI agents: `guide install`) | none | write (local files) |
| `update` | replace the komando program with a newer release, or the version named (`komando update`; added 2026-11-08) | none | write (the komando program); an older version needs `--yes` |

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
| `kind:postgres`, `kind:host` | everything of that kind |
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
| `-o, --output json\|text` | output format (automatic: text in a terminal, json when piped) |
| `--dry-run` | show what would happen, without changing anything |
| `--write` | allow changes in raw commands (`db query`, `cache run`, `cluster run`) |
| `--yes` | confirm a change on a protected target |
| `--allow-dangerous` | allow a command blocked by policy, for this command only |
| `--timeout` | time limit per target |
| `--parallel` | how many targets at once |

### Standard flag names

| Need | Flag | Notes |
|---|---|---|
| how many | `-n, --limit` | log lines, items, keys, SQL rows |
| recursive | `-r, --recursive` | always lowercase `-r` |
| keep following (logs) | `-f, --follow` | `-f` is **only** for follow, like `tail -f` and `kubectl logs -f` |
| input file | `--file` | `-f` only when the original tool uses it (`db query -f`, `docker compose -f`); in `logs`, `-f` is for follow |
| to/from a local file | `--to` / `--from` | |
| replace what exists | `--overwrite` | replaces `--force` |
| named parameters | `--var KEY=VALUE` | for recipes and snippets |
| positional parameters | `--arg VALUE` | for `$1`/`?` in SQL and script arguments |
| group / tag | `-g, --group` / `-t, --tag` | |
| search text | `--grep` | no short letter, because `-g` = group |
| filter the inventory | `--target SELECTOR` | replaces `--host` in `audit` and `job list` |
| root rights | `--sudo` / `--no-sudo` | see the sudo rule below |
| raw command changes nothing | `--read-only` | see the polarity rules |
| time | `--since`, `--until`, `--ttl`, `--expires` | Go duration format (`10m`, `2h`) or RFC3339 |

### Polarity rules (important for safety)

- **Anything unknown is treated as a change.** Raw commands whose content
  cannot be proven safe (`exec`, `script`, `snippet`, `docker exec`)
  are treated as *write*, unless marked `--read-only`.
- **If the server can enforce read-only, the default is read-only** and it needs
  `--write` (`db query`, `cache run`). `cluster run` follows the same
  default: it only reads unless `--write`.
- Commands with a clear verb (`storage upload`, `svc restart`)
  do not need `--write`; the verb is already a statement of intent.

### Sudo rule

System-level commands (`svc`, `pkg`, `user`, `ops`) use sudo automatically
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

- **Agents and scripts**: changes on a protected target fail without `--yes`
  (exit 6), with a hint.
- **People at a terminal** (stdin and stderr are both terminals, and no AI
  agent runs komando): komando asks `prod-db is protected. Change it
  anyway? [y/N]`. For destructive commands on a protected target, the
  target name must be typed again. The answer is read from the terminal,
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
- Rename updates everything that refers to it (groups, `--via`, jump, snippets).
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

- `komando` with no arguments: for a person at a terminal, a menu (arrow
  keys and Enter) that runs the same commands they could type; for agents,
  scripts and any flag the first three steps, not a wall of text; piped, one
  `USAGE` envelope (see Streams and scripts).
- The menu picks a thing first, then what to do with it
  (internal/cli/menu.go). With nothing added: Add a server, Bring in my SSH
  servers (when ~/.ssh/config has new ones), Set up my AI agent, Settings
  and help. After that the rows keep one order and never move: Servers,
  Databases and services, VPNs, Running now (only while something runs),
  Add something, Check everything, History and undo, Settings and help.
  Picking a server, group, database, cache, queue, storage, cluster,
  registry or VPN shows that kind's tasks (menuTask), each one a komando
  command with the item already answered. Esc goes back one step, `?`
  explains the screen, q quits. Disconnecting a VPN and Reboot ask first,
  with No on top. `TestMenuEveryCommandHasAHome` fails when a command has no
  task and no reason in `menuCLIOnly`.
- Every task opens its command's questions directly (internal/cli/form*.go):
  Add has hand-made forms per kind; every other command gets questions from
  its Use line and flags, made plainer by a formHint. A form asks one
  question at a time (answers so far stay on screen), checks each answer
  with the same rules the command uses, and ends on a review that shows the
  exact command lines, with the rarer flags under More options. A read with
  nothing left to ask runs at once. Forms never hold a secret (the command
  asks with --ask-password) and never add --yes, --allow-dangerous or
  --reveal. `host add`, `conn add` and `vpn add` alone at a person's
  terminal open the same form; with any argument or flag, or for an agent,
  nothing changes.
- Every command has at least one real example in `--help`.
- Shell completion completes host, conn, group, and tag names from the inventory.
- `komando guide` (for agents) and `docs/features/` (for people, one file per feature) are always
  updated in the same commit as the feature.
- Renaming a command or flag: the old name keeps working as an alias
  for one minor release, with a warning on stderr, then it is removed.
- The naming rules for commands and flags are guarded by `TestConventions`
  (`internal/cli/conventions_test.go`).

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
| `svc logs`, `docker logs`, `logs --unit/--container` | ✅ only `logs`; `svc logs` and `docker logs` become aliases |
| `ops run` (built-in recipes) and `snippet run` (your own recipes) | ✅ one `recipe` (a word that is easier to understand); `ops` and `snippet` become other names |
| `cp` (server) and `storage upload/download` | ✅ `upload`/`download` for servers (SFTP) and storage; `cp` and `storage upload/download` become aliases |
| `group add/rm` and `edit --add-group/--rm-group` | keep both (many vs one), same code |

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
- [ ] `komando` alone: a menu for a person at a terminal; otherwise the
  first steps, a dozen lines at most.
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
