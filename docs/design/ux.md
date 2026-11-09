# komando UX guide

Status: **in effect, 2026-11-02.** This document sets the rules for every
command, flag, message, and output. New features must follow it. If an
old command breaks these rules, the fix is listed in the [Backlog](#fix-backlog).
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
  `cache`, `storage`, `cluster`, `registry`, `secret`. Product names are only
  aliases (`s3`, `redis`, `sql`, `k8s`).
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
| `show` | details of one inventory item | `info` | read |
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

## 3. Flags

### Global flags whose meaning never changes

| Flag | Meaning |
|---|---|
| `-o, --output json\|text` | output format (automatic: text in a terminal, json when piped) |
| `--dry-run` | show what would happen, without changing anything |
| `--write` | allow changes in raw commands (`db query`, `cache run`) |
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
  `--write` (`db query`, `cache run`).
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
- Every command has at least one real example in `--help`.
- Shell completion completes host, conn, group, and tag names from the inventory.
- `komando guide` (for agents) and `docs/features/` (for people, one file per feature) are always
  updated in the same commit as the feature.
- Renaming a command or flag: the old name keeps working as an alias
  for one minor release, with a warning on stderr, then it is removed.

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
| `host --jump` and `conn --via` | ✅ `--via` for everything; `--jump` becomes an alias ([network.md](network.md)) |
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
   app-db` gives a local port for TablePlus/`psql`, and `komando shell`
   for interactive SSH, and `komando db shell app-db` opens komando's own SQL
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

## Fix backlog

Result of an audit of 149 commands at commit `93f7268`. P0 = safety, P1 =
consistency issues that often hit users, P2 = tidying up. Old names stay
accepted as aliases for one release. The naming rules for commands and flags
are guarded by `TestConventions` (`internal/cli/conventions_test.go`).

| # | Prio | Problem | Status |
|---|---|---|---|
| 1 | P0 | Snippets could run on a protected host without `--yes` unless marked `--mutating` | ✅ Treated as a change; `--read-only` for safe ones |
| 2 | P0 | `secret set NAME VALUE` (goes into shell history and `ps`) | ✅ Refused (`SECRET_IN_ARGS`) |
| 3 | P0 | Selectors only picked hosts | ✅ Universal selectors, `kind:`, `meta.skipped`, `NO_MATCHING_TARGETS`, "did you mean" |
| 4 | P1 | `logs -f` = file | ✅ `--file` with no short letter; `-f, --follow` follows |
| 5 | P1 | `rm`, `del`, `remove`, `delete` | ✅ `rm` in every command, the rest are aliases |
| 6 | P1 | `-n` had three meanings | ✅ `-n, --limit`; `fs cat --line-numbers`; `job logs --max-bytes` |
| 7 | P1 | `--host` vs `--target` | ✅ `--target` (accepts selectors) |
| 8 | P1 | `--param` vs `--var` | ✅ `--var` |
| 9 | P1 | `--force` vs `--overwrite` | ✅ `--overwrite` |
| 10 | P1 | `-r` vs `-R` | ✅ `-r` |
| 11 | P1 | `storage get/put` | ✅ `download/upload` (done in another session) |
| 12 | P1 | `-g` = group and grep | ✅ `-g` only for group |
| 13 | P1 | Inconsistent sudo | ✅ Sudo rule in section 3; `pkg` and `user` get `--no-sudo` |
| 14 | P1 | No `list`/`test` for everything | ✅ `komando list`, `komando test` |
| 15 | P2 | `cache keys` without an `ls` alias | ✅ (another session) |
| 16 | P2 | `HOST` vs `TARGET` in usage | ✅ `TARGET` |
| 17 | P2 | People at a terminal only got an error | ✅ `[y/N]` prompt, and type the name for dangerous ones |
| 18 | P2 | Name `all`, `Web1` vs `web1` | ✅ Refused |
| 19 | P2 | `komando import` does not exist yet | ✅ `komando import SOURCE` (v0.3) |
| 20 | P0 | `host add --overwrite` silently removed protected | ✅ Needs `--yes` |
| 21 | P0 | `host rm` / `edit --protected=false` on a protected target without `--yes` (a way around) | ✅ Needs `--yes` |
| 23 | P0 | Aliases without protected (`user@address`, a second name, a second conn to the same server) bypassed protected | ✅ Protected follows the address |
| 24 | P1 | One "y" answer at the terminal applied to other checks in the same command | ✅ Each answer is for one question only; `rm` on many targets is asked once |
| 25 | P1 | `tunnel start --host-key-policy off --yes` failed in a background process | ✅ |
| 22 | P0 | `config set audit off`, `host_key_policy off`, `--host-key-policy off`, `policy allow` without confirmation; `audit tru` turned off the audit | ✅ Needs `--yes`; strict on/off values |

Anti-slop audit of 225 commands, 2026-11-07 (at `5847edb`):

| # | Prio | Problem | Status |
|---|---|---|---|
| 26 | P1 | `komando` alone printed ~90 lines of help (against section 10) | ✅ First steps; `--help` for everything |
| 27 | P1 | A command typo printed cobra's multi-line "Did you mean this?" inside the JSON message | ✅ One line with the suggestion; hint names the command meant |
| 28 | P1 | A flag typo (`--tiemout`) had no suggestion | ✅ "did you mean --timeout?" |
| 29 | P1 | 247 usage errors shared one hint ("run with --help or `komando schema`") | ✅ The command's own example and `--help` |
| 30 | P1 | 71 of 197 commands had no example in `--help` | ✅ All have one; `TestConventions` and `TestExamplesParse` guard it |
| 31 | P1 | Text output of `host add/edit`, `conn add` and the like was a sorted field dump with `action: added` and UTC timestamps | ✅ Headline first (`added web2`), name first, local times |
| 32 | P2 | `server(s)`, `problem(s)` ... in about 20 messages; "2 of 2 failed" | ✅ `countOf`, `failedOf` |
| 33 | P2 | `test` on one target said `PARTIAL_FAILURE`, `exec` said the real code | ✅ The target's own code |
| 34 | P2 | `list` PROTECTED column showed `false` on every row | ✅ `yes` or `-` |
| 35 | P2 | `export -o text` showed `secrets_needed: [hidden]` for an empty list | ✅ Not masked |
| 36 | P2 | Every sub-command's `--help` repeats 11 global flags | ✅ Shows `--dry-run`, `-o`, `--timeout`, `--yes`; the rest in `komando --help` |
| 37 | P2 | 55 `Short` lines are longer than 80 characters and wrap in `komando --help` | ✅ Top level ≤ 64, others ≤ 80 (`TestConventions`); the full sentence moved to Long |
| 38 | P2 | `config set parallel 5` prints only `5` | ✅ `parallel: 10 → 5`, or `parallel: already 5` |
| 39 | P2 | `policy list -o text` prints the regular expressions as YAML | ✅ A table of what each rule stops; the patterns with `-o json` |
| 40 | P2 | Some hints are questions ("is sshd running and the port correct?") instead of a next step | ✅ Each says what to check or run |
| 41 | P2 | A group command with no sub-command (`komando db`) piped prints help text, not a JSON envelope | ✅ Piped: a `USAGE` envelope (exit 2) naming the sub-commands; `komando` alone piped points to `guide` and `schema`. In a terminal: help as before |

Next:
- Single-target commands refuse a selector that picks many, with the
  same message everywhere (done, through `singleHost`/`singleConn`).
- `db query` against many databases at once (`@prod` containing several
  databases) is not supported yet; it is now refused with a clear message.
