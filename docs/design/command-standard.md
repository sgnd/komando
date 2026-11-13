# The komando command standard

The rules every command follows: grammar, names, arguments, flags, help
text, confirmations, errors and output. It is for a person learning
komando and for a contributor adding a command. The wider rules are in
[principles.md](principles.md); the words of every message are in
[message-style.md](message-style.md).

Each rule has an ID (`S-…`) that code and tests cite, and a tag that says
how it is checked:

- **[schema]**: `internal/cli/standard_test.go` checks it from the command
  tree or the schema. A new command that breaks it fails `go test`.
- **[code]**: a test checks it from the Go code or from a recorded run
  (golden files, error catalog, PTY test).
- **[review]**: a person checks it in review.

Rules that cannot change because of the contract:

- **JSON field names are never renamed or removed.** New fields may be added.
  `komando schema` output is part of this: a change to a `flags[].type`,
  `default`, `kind`, `path` or `usage` value is listed in the release note
  (S-9.8), even when no field name changes.
- **Error codes and exit codes stay** within output contract 1. Fixes to
  them are recorded for contract 2. Every new exit-code path on an existing
  command is listed in the release note with a TestAgentGolden row.
- **One command, one ID** (S-1.6). The success envelope, the error
  envelope, the audit log and every name-keyed table use the same string.
- **No legacy.** A rename is clean: the old name stops working, and every
  caller (help, examples, guide, skill, docs, tests) changes in the same
  change. Only plain synonyms stay (S-1.7).
- **A short letter has one meaning** within its scope (S-5.14).
- **No `--json`, `--no-input`, `--quiet` or TUI.** Output is `-o`.
- **`--yes`, `--allow-dangerous` and `--reveal` mean a person said yes.**
  No new flag may do what they do, and no change may let an agent skip a
  stop it gets today (S-7.1).

---

## 1. Grammar

**S-1.1** A command is `komando <noun> <verb> [ITEM] [TARGET] [args] [flags]`.
[schema: every leaf path has 2 or 3 words, except the top-level set in S-1.4]

**S-1.2** The noun's own item comes first, then TARGET:
`key deploy NAME TARGET`, `recipe run NAME TARGET`, `group add GROUP TARGET...`.
Commands without an item start with TARGET: `svc restart TARGET UNIT...`.
[review]

**S-1.3** One need, one command. Two commands may not do the same job.
A second spelling is a hidden alias, never a second documented command.
[schema: no two visible leaves share the same `Short`]

**S-1.4** Top-level commands are a closed list. Anything new goes under a
noun. [schema: the set of top-level names equals this table plus the S-2.1
nouns]

| Kind | Top-level commands |
|---|---|
| Nouns | every noun in S-2.1 |
| Shortcuts | `list`, `test`, `exec`, `shell`, `logs`, `cp`, `upload`, `download`, `sync`, `facts` (alias `info`), `reboot`, `status`, `login`, `logout`, `import`, `export`, `rename` |
| About komando | `audit`, `doctor`, `schema`, `guide`, `update`, `version`, `seal`, `completion`, `help`, `ssh-gate` |
| Help topics (only as `komando help TOPIC`) | `environment`, `exit-codes`, `output`, `safety` |

**S-1.4a** Frozen forever: `ssh-gate` and its flags `--name` and
`--read-only`. Their exact spelling is written into servers'
`authorized_keys` (`command="/usr/local/bin/komando ssh-gate --name phone"`).
No rename, no alias swap, no shorthand. [schema: allow-list pins them]

**S-1.5** A subcommand name may never equal a value a person can pass in the
same position. The cloud names `aws`, `gcp` and `azure` are reserved: no new
server, conn or VPN may take them (as with `all`). `login aws` is the
cloud login. Guide topics may never be
named `install` or `uninstall`. [schema: no subcommand name equals a guide
topic; code: validName refuses the reserved words]

**S-1.6** Every command carries an ID: its dotted path by primary names
(`fs.list`, `secret.show`, `host.rename`, `pkg.security`). A rename
changes the ID with the name, in the same change.
`commandName` returns it. The success envelope, the error envelope, the
audit log, `audit --command`, `commandKinds`, the gate tables
(`gateOnServers`, `gateReadForm`), `personalCmds`, `localReads`,
`leavesHome` and the masking checks are all keyed by it. A wrapper
command (S-1.8) carries the ID of the command it runs.
[code: every key in every name-keyed table resolves to a command ID; the
error and success envelope of a command carry the same ID]

**S-1.7** Synonyms. A few plain synonyms are hidden cobra `Aliases` and
print nothing: `ls` for `list`, `rm` words (`remove`, `delete`, `del`),
plural nouns, `server` and `database`, and the ones the tables below name.
Help, examples and docs use only the primary name. [code]

**S-1.8** A synonym that needs its own argument shape, or lives under
another parent, is a thin hidden wrapper command with its own `Args`,
carrying the ID of the command it runs (S-1.6). [review]

## 2. Nouns

**S-2.1** Official nouns. The documented name is in the first column.
Every noun has its plural as a hidden alias. The human word that help text
uses for a noun (S-2.3) always resolves as that noun.
[schema: alias list contains the plural and the help word]

| Noun | What it is | Aliases |
|---|---|---|
| `host` | a server (help text says "server") | hosts, server, servers |
| `conn` | a connection to a database, cache, queue, storage, cluster or registry | conns |
| `vpn` | a VPN komando connects for you | vpns |
| `group` | a named set of servers and conns | groups |
| `secret` | a value in komando's vault | secrets |
| `key` | an SSH key komando knows | keys |
| `recipe` | a saved command | recipes |
| `policy` | your own block rules | policies |
| `job` | a long command running on a server | jobs |
| `tunnel` | a port forward komando keeps running | tunnels, pf |
| `config` | komando settings | |
| `fs` | files on servers | files |
| `svc` | system services (systemd, Windows) | service, services |
| `pkg` | packages | package, packages |
| `user` | Linux accounts | users |
| `cron` | scheduled commands | crons |
| `docker` | containers on servers | container, containers, ctr |
| `net` | network checks | network |
| `cert` | TLS certificates | certs |
| `db` | databases | dbs, database, databases, sql |
| `cache`, `queue`, `storage`, `cluster`, `registry` | conn families | caches, queues, clusters, registries, plus product aliases (redis, kafka, s3, k8s) |

**S-2.2** A noun is a category in human words. Product names are aliases.
Accepted exceptions: the abbreviations `fs`, `svc`, `pkg`, `net`, `conn`
(standard in kubectl and gh), each with its human word as an alias; and
`cluster helm` (engine-specific). [review]

**S-2.3** Words in help text. "server" for a host, "conn" for a non-SSH
target (first mention: "conn (database, cache, queue, storage, cluster or
registry)"), the family word when the family is known ("database").
"service" means only a `svc` unit or a Kubernetes/Swarm Service. "resource"
is not used. [schema: no Short or Long outside `svc` and `cluster` contains
"service" meaning a conn; no Short contains "resource"]

## 3. Verbs

**S-3.1** A verb has one meaning. The table is the full list; a new verb
needs a row here first. [schema: every leaf verb is in this table or in the
tool-word list S-3.3]

### Inventory verbs (things in komando's own list)

| Verb | Meaning | Aliases | Follows |
|---|---|---|---|
| `list` | list items | ls | gh, gcloud, az, helm |
| `show` | everything about one item | (get on secret, config) | gh repo view, flyctl status |
| `add` | put an existing thing into komando, or into a group | | gh, git remote add |
| `edit` | change some fields of an item | | gh repo edit |
| `rename` | rename an item and every reference to it | mv | git branch -m |
| `rm` | take an item out of komando (the real thing is not touched) | remove, delete, del | git rm, docker rm |
| `test` | can komando reach it and log in | ping | ansible ping |
| `cp` | copy to a new name or place | copy | cp |
| `check` | compare against a rule, change nothing | | terraform validate |

### Verbs inside a target

| Verb | Meaning | Aliases | Follows |
|---|---|---|---|
| `list` | what is in it | ls | kubectl get, aws s3 ls |
| `describe` | everything about one object | | kubectl describe |
| `get` | the raw value of one item | | kubectl get, redis GET |
| `info` | a summary of the target: version, role, size | | redis INFO, docker info |
| `status` | state of something that runs (unit, job, rollout, release, VPN session) | | systemctl status |
| `logs`, `history`, `events` | what happened | | kubectl logs/events, helm history |
| `create` | make a new thing on the target | | kubectl create, gh |
| `set` | write one value | | redis SET, gh secret set |
| `rm` | delete a thing on the target (needs `--allow-dangerous`) | remove, delete, del | kubectl delete |
| `start`, `stop`, `restart`, `reload`, `enable`, `disable` | change the run state of an existing thing | | systemctl, docker |
| `kill` | signal something running now | stop (on job) | kill, docker kill |
| `wait` | wait until it ends | | kubectl wait |
| `purge` | empty it but keep it | | rabbitmqctl purge_queue |
| `prune` | delete old things by a rule | | docker prune |

### Running, files, sessions, rights

| Verb | Meaning | Follows |
|---|---|---|
| `exec` | a shell command on servers (aliases run, x) | docker exec, kubectl exec |
| `run` | the area's own raw command (`cache run`, `cluster run`) or a saved recipe | redis-cli, kubectl |
| `query` | SQL or MongoDB | psql -c |
| `shell` | an interactive session, person only (aliases ssh, connect) | |
| `upload`, `download` | move files (put, get on storage) | aws s3 cp, gh release download |
| `sync`, `dump`, `restore` | copy trees, back up and load | rsync, pg_dump |
| `up`, `down` | a VPN session | wg-quick, tailscale |
| `login`, `logout` | a kept login | gh auth, docker login |
| `install`, `uninstall` | put files in, take them out | helm, apt |
| `update` | refresh an index (`pkg update`); komando itself at top level | apt update |
| `upgrade` | install newer packages (`--security`: only security fixes, one server at a time) | apt upgrade, dnf upgrade --security |
| `grant`, `revoke`, `deploy`, `gen`, `trust`, `lock`, `unlock`, `passwd` | rights and keys | GRANT, ssh-keygen, passwd |

**S-3.2** Pairs that must stay pairs: add/rm (inventory), create/rm (on a
target), start/stop, up/down, login/logout, grant/revoke, lock/unlock,
install/uninstall, enable/disable. [schema: for each noun with one half, the
other half exists or is listed as an exception]

**S-3.3** Tool words. A verb used only in one area, named after that area's
own tool, is allowed when this list names it:
`docker ps/images/pull/compose/raw/inspect`,
`registry inspect/copy` (crane, skopeo), `cache keys` (Redis KEYS),
`user add`, `db user add` (useradd; hidden alias `create`),
`db grant/revoke` (SQL), `pkg installed/upgradable/security`,
`queue peek/send/lag/groups`, `db activity/locks/sizes/explain/kill`,
`fs cat/stat/chmod/mkdir/write/replace/mv`, `svc daemon-reload`,
`cluster scale/apply/rollback/forward/values`, `net dns/http/ports/check`,
`key gen/deploy`, `host trust/ssh-command`, `ssh-gate line`, `conn kinds`,
`audit verify`, `config approval-code`, `secret keychain/passphrase`.
[schema: allow-list]

**S-3.4** In a family noun (`db`, `cache`, `queue`, `storage`, `cluster`,
`registry`) verbs act on what is inside the conn. Editing, renaming,
testing and removing the conn itself is `conn edit|show|rename|test|rm`.
One recorded exception: `<family> add` is visible and means `conn add`
limited to that family, with that family's questions ([principles.md](principles.md#11-help-and-ease-of-use)). A family
`rm` given only a conn name explains itself (S-10.3).
[schema: the only conn-level verb under a family noun is add]

**S-3.5** A read command never becomes a write through a flag, except the
documented switches in S-5.9 (`--write`). [schema: no `kind: read` command
has a flag whose usage says "installs", "deletes" or "changes"]

**S-3.6** `update` at the top level takes only a version. A word that
matches a server or conn name is a USAGE error with the hint
`komando pkg upgrade NAME`. [code]

## 4. Arguments

**S-4.1** Argument words are UPPERCASE. `[X]` is optional, `X...` repeats,
`A|B` is a choice. Only a literal stays lowercase (`--`). [schema: Use parses
with this grammar]

**S-4.2** Each word has one meaning in every command: [schema: allow-list of
words; the completion and picker map has one entry per word]

| Word | Means | Picker / completion |
|---|---|---|
| `TARGET` | a selector that may pick several, of the kinds the command serves; the prompt label says which: `TARGET (servers):`, `TARGET (clusters):` | filtered by the command's kinds |
| `SERVER` | exactly one server | servers |
| `CONN` | one conn of the command's family | that family |
| `NAME` | one item of the command's own noun (or a new name in `add`; a cron entry's name in `cron`) | that noun |
| `GROUP` | an inventory group | groups |
| `USER` | an account (Linux or database) | none |
| `JOB`, `TUNNEL`, `RULE` (policy), `SETTING` (config) | that item | jobs, tunnels, none |
| `KEY` | a cache key only | none |
| `OBJECT` | a storage object | none |
| `CONSUMER` | a queue consumer group | none |
| `IMAGE` | `REPO[:TAG\|@DIGEST]` | none |
| `TYPE/NAME` | a cluster object; `POD\|TYPE/NAME` where a bare pod works | none |
| `FILE` | a file on this computer | files |
| `PATH` | a path on a server | none |
| `ADDRESS[:PORT]`, `DOMAIN`, `URL` | network places | none |
| `-- COMMAND...` | a shell or program command | none |
| `-- ARGS...` | arguments for a fixed program | none |

**S-4.3** A required flag is shown in the usage line with an UPPERCASE value
(`db restore CONN --from FILE`); optional flags never are. A choice of flags
is in parentheses: `tunnel start TARGET (-L SPEC | -R SPEC | -D SPEC)`.
[schema: required flag ⇔ present in Use]

**S-4.4** Passthrough commands: `exec`, `job start`, `docker exec`,
`docker compose`, `docker raw`, `cluster exec`, `cluster shell`,
`cluster run`, `cache run` (every command whose Use has `-- COMMAND...` or
`-- ARGS...`). komando flags are read anywhere before `--`
(`exec @web -P 20 --read-only -- df -h`). Any word after the fixed positionals (TARGET, CONTAINER,
`POD|TYPE/NAME`, CONN) must come after `--`. Without `--`, such a word is a
USAGE error (exit 2) with the hint
``put -- before the command: `komando exec web1 -- apt-get install -y nginx` ``.
So `-y` in `apt-get install -y nginx` can never be read as `--yes`, and a
trailing `--dry-run`, `-P 1` or `--fail-fast` is never read by komando
while the words around it go to the server. `kubectl exec` has
the same rule. [code: one shared PreRunE helper using `ArgsLenAtDash`;
TestStandardPassthrough walks the tree and checks every command with
`COMMAND...`/`ARGS...` in Use has it, and runs both failing forms]

**S-4.5** One quoted string (`cron set`, `recipe add`, `policy check`) is
written `COMMAND` without `--`, and Long says "one quoted string". [review]

**S-4.6** A missing argument is asked for only at a terminal. The prompt
label is the Use word plus its kind. Agents get USAGE (exit 2). [code]

## 5. Flags

### 5.1 Dictionary

**S-5.1** A flag name has one meaning and one type in every command, except
the allow-listed rows marked *exception*. [schema: group flags by name; each
group has one type; meanings checked by usage-text template where one exists]

| Flag | Short | Type | Meaning | Default and units |
|---|---|---|---|---|
| `--limit` | `-n` (not in cluster, not on storage rm) | int | the most items, rows or log lines to show (last ones for logs). Never a safety cap. Says in its usage text whether it counts per target or in total | each command keeps its current default; a `--limit` added where there was none defaults to 0 = no limit. 0 = no limit wherever the text says so |
| `--head`, `--tail` | | int | first or last N lines of one file or log (`fs cat`, `storage cat`); *exception*: on `job status`/`job wait`, `--tail` = also show the last N lines of output (0 = none) | 0 = all on fs/storage cat; job status 20, job wait 30 |
| `--max-<noun>` | | bytes or int | a safety cap: the run is refused above it (`--max-remove`, `--max-bytes`, `--max-output`) | stated per flag |
| `--timeout` | | duration | how long this command may run per target (global). *exception*: `job wait --timeout` is local, total across servers, default 10m, ends with WAIT_TIMEOUT | setting, 5m |
| `--wait` | | duration | wait for the result up to this long; the global `--timeout` still applies and whichever ends first stops the run. *exception*: on `cluster deploy/restart/rollback/scale/status` it is a bool (as in helm), bounded by `--timeout` | 0 = do not wait |
| `--idle` | | duration | stop after this long with nothing new | stated per flag |
| `--interval`, `--expires`, `--ttl`, `--older-than`, `--warn` | | duration | a span | per flag; "0 = never" or "> 0" in the usage text |
| `--since`, `--until` | | when | a point in time | `30m`, `7d`, `today`, `yesterday`, `2026-11-07 14:30`, RFC3339 |
| `--from` | | string | a local input file, the pair of `--to` (`db restore`, `fs write`, `queue send`) | `-` = stdin |
| `--to` | | string | a local output file | `-` = stdout |
| `--file` | `-f` (not on log streamers) | string | a manifest or input file a tool reads (`cluster apply`, `docker compose`, `db query`); *exception*: `logs --file PATH` is a log file on the server | `-` = stdin where the tool allows it |
| `--content` | | string | inline file content (`fs write`) | |
| `--config` | | tool word | *exception*: `queue create --config KEY=VALUE` (kafka-topics), `vpn add --config FILE` (OpenVPN, WireGuard) | |
| `--key` | | string | *exception*: `queue send --key` is the message key (Kafka); elsewhere an SSH key file | |
| `--env`, `--label`, `--option`, `--var`, `--header`, `--config` (queue) | `-e` for --env | stringArray | `KEY=VALUE`, repeatable, never split on commas. A value whose text after a comma looks like `KEY=` is a USAGE error: "repeat --option for each KEY=VALUE" | |
| `--group`, `--tag`, `--add-*`, `--rm-*`, `--kind`, `--unset` | `-g`, `-t` | stringSlice | a list of names, comma-separated | |
| `--all` | `-a` on read commands only | bool | also what is normally left out (read), or every item instead of one named item (change: no shorthand) | false |
| `--all-namespaces` | `-A` | bool | every namespace (cluster) | false |
| `--namespace` | `-n` (cluster only) | string | Kubernetes namespace. An all-digit value given as `-n` is a USAGE error: "`--limit N`, or `--namespace=N` for a namespace named N" | the conn's |
| `--sudo` | `-s` | bool | run it with sudo on the server | off |
| `--sudo-user` | | string | run it as this user with `sudo -u` | |
| `--no-sudo` | | bool | do not use sudo (system commands that default to sudo) | off |
| `--overwrite` | | bool | replace what is there | false |
| `--backup` | | bool | keep the previous version as PATH.bak | false |
| `--recursive` | `-r` | bool | include everything under a folder | false |
| `--follow` | `-f` (log streamers) | bool | stream new lines until Ctrl-C or `--timeout` | false |
| `--write` | | bool | let a read-first command (SQL, Redis, kubectl text) change things | false |
| `--read-only` | | bool | declare shell text as read only | false |
| `--dry-run` | | bool (global) | show the plan, change nothing; never blocked | false |
| `--refresh` | | bool | update the package index first (dnf, zypper) | false |
| `--*-ref` | | string | where a secret is: `secret:NAME`, `env:VAR`, `file:PATH` or a manager ref | |
| `--user` | | string | the account on the target the command acts as or on | |
| `--container` | `-c` | string | a container name | |
| `--dir` | `-C` | string | the working folder | |
| `--revision` | | int | a release or rollout revision | 0 = previous |
| `--progress` | | bool | with `-o json`, progress as one JSON object per line on stderr (`upload`, `download`, `cp`, `sync`, `storage upload/download`); text mode keeps its own progress line | false |

**S-5.2** Durations use one komando type (`Type() == "duration"`): Go units
and `Nd` days. A bare integer is accepted only as `0`; every other span
needs a unit, so `--older-than 30` is a USAGE error, never 30 seconds.
No span flag is a plain string. [schema: every flag named in the span rows
has type duration; code: `30` refused, `0` accepted]

**S-5.3** Byte sizes use one type (`Type() == "bytes"`): an integer, or
KB/MB/GB/KiB/MiB/GiB, where KB = KiB = 1024 bytes (as `dbx.ParseBytes`
reads them today). [schema: every `--max-bytes`/`--max-output` has type
bytes; code: `10GB` = 10×1024³]

**S-5.4** `--since`/`--until` use one parser (`parseWhen`) and one usage text.
[schema: identical usage text; code: no other parser]

**S-5.5** Negatives: only `--no-X` where X is on by default; never both
`--X` and `--no-X` on one command (except `--sudo`/`--no-sudo` on
commands that default to sudo, where `--sudo` is absent). [schema]

**S-5.6** A flag value never looks like a positional argument: a name used
as a value flag anywhere is never a bool elsewhere. [schema: covered by S-5.1]

**S-5.7** Defaults shown are the real ones. A default taken from a setting
keeps its `default` value and adds `default_from` (additive) in the schema;
durations print short (`1h`, `10m`, `0`); an unset optional number shows
no default, never `-1`. [schema: no default "-1"; no default "1h0m0s"-style]

**S-5.8** Every list command has `--limit` (S-5.1 defaults). A run that
stops at the limit sets the additive `meta.truncated: true` and, in text
mode, prints one stderr line `showing N of more; use --limit 0 for all`.
[schema: every leaf whose verb is list/ls (or a list tool word) has --limit;
code: truncation sets the field]

**S-5.9** Read-first or change-first. Text in a language komando parses
(SQL, Redis, kubectl text through `run`) is read only unless `--write`.
Shell text is a change unless `--read-only`. No third switch. `docker raw`
and `docker compose` take docker's own verbs, which include `exec` and
`run`; they have no read form and are always gated as a change.
[schema: no flag named `--apply`; every `kind: depends` command except
`docker raw`, `docker compose` and `cluster shell` has exactly one of
--write / --read-only]

**S-5.10** Multi-target runs continue after a failure (`--fail-fast` stops).
One-at-a-time rollouts (`pkg upgrade --security`) stop on a regression
(`--keep-going` continues). [review]

**S-5.11** Each flag has one usage text template per name. Shared texts
(`--sudo`, `--no-sudo`, `--*-ref`, `--since`, `--until`, `--protected`,
`--namespace`) come from one Go constant. [schema: one usage text per name
for these names]

**S-5.12** A command shows only flags that do something on it. [review;
schema for log commands: `--priority` only on journal readers]

**S-5.13** On `edit` commands, the list flags are `--add-X`/`--rm-X`;
`--group`/`--tag` are hidden there. [schema]

**S-5.18** (removed 2026-11-13: no legacy) Hidden flag aliases are gone;
a flag has one name.

### 5.2 Reserved shorthands

**S-5.14** A short letter means the same long flag wherever it appears,
inside the scope given here. A new shorthand needs a row here and a
reference CLI that uses it the same way. [schema: walk the
tree, compare every shorthand with this table]

| Letter | Long flag | Scope | From |
|---|---|---|---|
| `-o` | `--output` | global | kubectl |
| `-P` | `--parallel` | global | xargs -P |
| `-y` | `--yes` | global; never after `--` (S-4.4) | apt, gcloud |
| `-h` | `--help` | global | |
| `-v` | `--version` | root only | |
| `-a` | `--all` | read commands only (docker ps, fs ls, user list, db activity, cache info, cluster helm values, guide); `docker prune -a` kept (docker's own) | ls, docker ps |
| `-A` | `--all-namespaces` | cluster | kubectl |
| `-c` | `--container` | any --container; `--cmd` only on exec and job start | kubectl |
| `-C` | `--dir` | any --dir; `--comment` only on key gen | git, make |
| `-e` | `--env` | any --env | docker |
| `-f` | `--follow` on log streamers; `--file` elsewhere | | tail, kubectl apply |
| `-g` | `--group` | add and import | |
| `-l` | `--selector` | cluster | kubectl |
| `-n` | `--namespace` in cluster (digits refused); `--limit` elsewhere; none on `storage rm` | | kubectl, head |
| `-p` | `--parents` on writers; `--priority` on journal readers | | mkdir, journalctl |
| `-r` | `--recursive` | everywhere | cp |
| `-s` | `--sudo` | everywhere | |
| `-t` | `--tag` | add (hidden on edit) | |
| `-u` | `--unit` | logs | journalctl |
| `-b`, `-D`, `-L`, `-R` | bits; dynamic, local, remote | key gen; tunnel start | ssh-keygen, ssh |

`storage rm` has no `-n`: its cap is `--max-remove`, never `--limit`.
[schema: allow-list]

**S-5.15** Never a shorthand for: `--allow-dangerous`, `--reveal`,
`--write`, `--dry-run`, `--port`, `--user`, `--label`, or a bool `--all`
on a change command. [schema]

**S-5.16** An unknown flag or shorthand gets a did-you-mean,
including common foreign shorthands (`-n` outside its scope, `-it`, `-L`,
`-w`, `-p` on fs mkdir). [code]

**S-5.17** An unknown command word gets help in this order:
(1) a curated table of foreign words, each mapped to a full command for
`error.hint`: `server` (alias), `delete`/`remove` → `komando host rm NAME`
(or the noun in the next word), `get` → `komando list`,
`ps` → `komando docker ps TARGET`, `kubectl` → `komando cluster run TARGET -- ...`,
`psql`/`mysql` → `komando db query CONN`, `apt`/`yum` → `komando pkg`,
`systemctl` → `komando svc`; (2) edit distance 1 for words of 4 letters or
fewer, 2 otherwise, at most 2 suggestions; (3) the hint names a command only
when there is exactly one suggestion. [code: TestAgentGolden rows for
`ps`, `get`, `delete web1`, `kubectl`, `psql`]

## 6. Help text

**S-6.1 Short (leaf)**: an imperative verb phrase in sentence case. No full
stop, no flags, no semicolons, no "e.g." or "etc.", at most one parenthesis
for scope. At most 64 characters at top level, 72 elsewhere. [schema]
Guideline: read commands usually start with Show, List or Check. [review]

**S-6.2 Short (group)**: the area in human words and 3 or 4 main jobs as
plain verbs, never a partial list of command names:
`Services on servers: check, start, stop, read logs`. [schema: a group Short
names no sibling command unless it names all of them]

**S-6.3** A Short never says "Same as". The alias goes in Long's first
line: `Same as komando logs TARGET --unit UNIT.` [schema]

**S-6.4** Person-only commands end their Short with `(person only)`,
generated from the same table that produces NEEDS_PERSON. [schema]

**S-6.5 Long**, in this order: (1) what it does and what it returns (the
main data fields); (2) a generated `Safety:` line (S-7.7); (3) notes on
kinds, formats and units. Wrapped at 76 columns. Every command with
`kind` change or depends has a Long. [schema]

**S-6.6 Examples**: a leaf has at least 2 (the simplest call, then a
selector or the most useful flag); a group has 3 to 5 that walk look,
dry run, change. [schema]

**S-6.7** A change command has at least one `--dry-run` example line
(generated from its first change example where possible). A line with
`--yes`, `--allow-dangerous` or `--reveal` is never the first or the only
example, comes right after a `--dry-run` line of the same command, and ends
with `# after a person's yes`. Words after `--` are not flags. [schema]

**S-6.8** Examples use one table of sample names: servers `web1`, `web2`,
`db1`, `@web`; databases `prod-db`, `staging-db`; cache `prod-redis`; queue
`prod-kafka` (topic `orders`); storage `backups`; registries `ghcr`,
`harbor`; clusters `prod-k8s`, `swarm1`; VPN `office`; users `alice`, `app`.
English only. A conn is never named after its own family word. Comments use
`  # ` and say why. [schema: names from the table; no non-English words list]

**S-6.9** Every example parses: the command exists, every flag exists.
[schema, already TestExamplesParse]

**S-6.10** Every backticked `komando …` in Short, Long, hints, Next: lines
and error catalogs names a real command, and its UPPERCASE words are that
command's Use words. [code]

**S-6.11** Top-level help groups: Start, Servers, Data, Platform,
Inventory, Access, Overview, Setup. Start lists commands, not nouns:
`host add`, `conn add`, `import ssh-config`, `list`, `test TARGET`,
`guide install`. Inventory: host, conn, group, import, export, rename.
Help topics are listed only under `komando help`. [review]

## 7. Confirmations

**S-7.1** One rule table, `riskOf(command, args, flags) → tier`, decides
the tier. The prompted path, the gates, the schema and the docs all read it.
No change to the table may let a command and flag combination that stops
an agent (POLICY_BLOCKED, PROTECTED_*, SAFETY_SETTING, CONFIRM_REQUIRED)
run without that stop. [code: every `kind` change/depends command has a
row; TestAgentGolden has a row per gated command and flag combination]

**S-7.2** The tiers:

| Tier | What | Agent needs | Person at a terminal sees |
|---|---|---|---|
| T0 read | looks only | nothing | nothing |
| T1 change | reversible, or only komando's own list | nothing | typed in full: runs. Prompted: `Run it? [y/N, d = --dry-run first]` |
| T2 protected | any T1 or T3 on a protected server or conn | `--yes`, exit 6 PROTECTED_HOST / PROTECTED_TARGET | `web1 (protected): <what changes>. Continue? [y/N]` |
| T3 dangerous | cannot be undone, or an outage: deleting data or files, purge, restore, reboot, scale to 0, stopping sshd, user rm, sync --delete, deleting a secret or key file, a policy or classifier hit | `--allow-dangerous`, exit 6 POLICY_BLOCKED | `This deletes <what> on <where> for good. Type <answer> to continue:` |
| T3s safety | weakens komando's own checks: audit off, removing a deny rule, downgrade, keychain or passphrase off, open bind, sending a secret, unprotecting a server, conn or VPN, clearing a VPN's `--mfa` | `--yes`, exit 6 SAFETY_SETTING / OPEN_BIND / SECRET_DESTINATION | `This turns off a komando safety check: <what>. Continue? [y/N]` |
| T4 person only | approval-code setup, typing a secret, `--reveal`, accepting an old copy, two-factor and VPN login, replacing a pinned host key | no flag; NEEDS_PERSON and friends, hint names the command a person runs | the command itself |

A bulk action has its own confirm: `group rm GROUP`
on a group of more than 3 members still needs `--yes` from an agent
(CONFIRM_REQUIRED).

**S-7.3** The typed answer is the name of what goes away or stops: one
item with a name of 60 characters or less → that name; several items or a
long name → the count, labelled (`Type 37 (objects under daily/ in backups)`);
the whole target (reboot, db restore, sync --delete, exec hits) → the target
name. Never the bare word "yes". [code: PTY test per T3 command]

**S-7.4** One question per command. A prompted command that reaches a T3
gate asks `Run it?` once and the typed name once; T3 on a protected target
asks one typed question with "(protected)" and the answer covers both.
[code: PTY test]

**S-7.5** `--dry-run` works on every change command, is never blocked, and
lists every approval the real run needs in `meta.would_need`
(`["--allow-dangerous","--yes"]`), next to the unchanged
`meta.would_be_blocked`. [code]

**S-7.6** A prompt never adds a flag. A terminal answer counts only when the
terminal can prompt. Flags count for one command and are written to the
audit. [code]

**S-7.7** The schema carries `confirm: {tier, flag, when}` per command,
generated from S-7.1, and Long's `Safety:` line is generated from the same
row. Shorts carry no approval notes. [schema]

**S-7.8** `kind` in the schema matches the tier: a command that can stop
with PROTECTED_* is never `kind: read`. A kind change is decided together
with its ssh-gate entry (full keys allowed or not), and both go in the
release note. [schema + rule table]

**S-7.9** "Blocked by …" is used only for a custom deny rule or a policy or
classifier hit, never for a command's own built-in tier. [code]

## 8. Errors and hints

**S-8.1** Every error code is a string literal in `errcodes.go`. No code is
built with `ToUpper` or `+`. [code: TestErrorCodeCatalog scans for both]

**S-8.2** New codes are `<SUBJECT>_<OUTCOME>`. SUBJECT is the command's own
family or item word. OUTCOME and its exit code come from this list:
[code: catalog test with an allow-list of today's exceptions]

| OUTCOME | Exit |
|---|---|
| NOT_FOUND, MISSING (a tool) | 3 |
| EXISTS, IN_USE, CONFLICT, BUSY | 8 |
| INVALID, UNSUPPORTED | 2 |
| AUTH, UNREACHABLE, TLS | 4 |
| DENIED, FAILED (server side), ERROR (server's own words) | 5 |
| REQUIRED (an approval) | 6 |
| TIMEOUT | 7 |
| a local failure | 1 |

**S-8.3** One code has one meaning. `<THING>_NOT_FOUND` names exactly what
is missing. Where a code is shared today, `error.thing` says which
(`ssh_key`, `cache_key`, `swarm_service`, `repository`, `k8s_object`).
[code]

**S-8.4** `error.message` says what happened and the state of the world:
lower-case start, no full stop, no `tool:` prefix, the human kind word.
Not found is always `no <kind> named "<name>"[ in <where>]`. [code: catalog test]

**S-8.5** `error.hint` says only the next step, as one sentence with the
exact command in backticks, filled in: `run it again: `komando test web1``.
A flag-only fix is still a whole command line. At most one "or". It is never
a question. [code: every catalog hint has a backticked command, allow-list
for outside fixes]

**S-8.6** Fixed phrases: "run it again" for a retry. One helper builds every
approval hint, in two variants. For a detected agent: "check with
--dry-run, ask the user; once they agree, run it again with --yes" (or
--allow-dangerous). Otherwise: "check with --dry-run, then run it again
with --yes: `komando …`". [code: one hint per approval code and variant]

**S-8.7** Placeholders in hints are the Use words of the command they name.
`fillHint` fills every inventory word it knows (TARGET, SERVER, CONN, NAME).
No `<x>`, no `…`. [code]

**S-8.8** A suggestion ("did you mean") goes in the additive
`error.suggestion` and, as a whole command line, in `error.hint`
(`komando cache keys prod-redis`), because agents are taught to read the
hint. People see it after the message. The guide and skill mention
`error.suggestion`. [code]

**S-8.9** A person who answers no gets exit 6 and `Cancelled. Nothing was
changed.`; Ctrl-C gets CANCELLED, exit 1, `Stopped. Nothing was run.`
[code]

## 9. Output

**S-9.1** JSON keys are snake_case. Existing keys stay as they are, even
when they break the rules below. [code: tag lint]

**S-9.2** New JSON keys only: a moment is `<event>_at` (UTC RFC3339); a
duration is `<what>_ms` or `<what>_seconds`; a size is `<what>_bytes`; a
count is `<thing>_count`; an exit status is `exit_code`; a list is plural
and an array of objects (`{name, reason}`); warnings are `warnings []string`.
`results[].host` is the target's name of any kind. [code: tag lint with
today's tags as allow-list]

**S-9.3** Next steps: one source, the form-hint `next` list. A person sees
`Next: a · b · c` on stderr, at most three, filled in. Agents keep
`data.next` (and `data.next_steps` where it exists today); no third field.
Nothing "next" goes to stdout. [code]

**S-9.4** Every add, edit, rename and rm has a Next list: add → `test`,
`show`; edit → `show`, `test`; rename → `show NEW`; rm → `list`; a test that
passed → the first use command of the kind. [code]

**S-9.5** An empty result says so on stdout: `no <things> yet: `komando … add``
when the list is empty, `no <things> match <filter>` otherwise. [code: each
list command has an empty-line test]

**S-9.6** Text tables: booleans `yes` or `-`; times local with the zone
(`2026-11-07 14:30 WIB`); ages `3h` under AGE or SINCE; headers are words
with spaces (`USED BY`); the target column is NAME. Text output is not part
of the contract, but changes to it are listed in the release note because
agents read `-o text`. [code: data_table helpers are the only path]

**S-9.7** Every change command has its own `Text()`. The generic renderer
is a fallback, tracked in a shrinking list. [code]

**S-9.8** `komando schema` is read by agents (AGENTS rule 2).
`komando schema` with a synonym (`komando schema host ls`) shows the
command it runs. The fields agents read for approvals and limits
(`error.suggestion`, `error.thing`, `meta.would_need`, `meta.truncated`,
schema `confirm`, schema `default_from`) are part of the output contract.
[code]

## 10. Journeys

**S-10.1** Every inventory kind has these steps, with these verbs. A
missing step is a hidden alias to the command that does it, or is listed
here as "none". [schema: for each kind, each verb resolves]

| Kind | add | test | show | list | edit | rename | rm | back up |
|---|---|---|---|---|---|---|---|---|
| host | add | test | show | list | edit | rename | rm | export |
| conn | add | test | show | list | edit | rename | rm | export |
| vpn | add | test | show | list | edit | rename | rm | export |
| key | gen, add | none | show | list | edit | rename | rm | none yet |
| secret | set (alias add) | check (person) | show (alias get) | list | set | rename | rm | none yet |
| group | add | test @GROUP | show | list | add/rm members | rename | rm (no TARGET) | export |
| recipe | add | none | show | list | add --overwrite | none | rm | export |
| policy rule | deny (alias add) | check | none | list | none | none | rm | export |
| job | start | none | status (alias show) | list | none | none | kill (alias stop), rm | none |
| tunnel | start | none | show | list | none | none | stop | none |

**S-10.2** Flags match across kinds: `vpn add/edit` take the same
`--label`, `--protected`, `--unset` as host and conn; `rm` and `edit` take
`NAME|TARGET...` alike. `--unset` may not name `mfa` or `protected`;
`--protected=false` and clearing `--mfa` are T3s (S-7.2); a multi-target
`vpn rm` follows the `host rm` tier. [schema; code: parity test with host]

**S-10.3** A family `rm` given only a conn name, at a terminal, says what it
deletes and how to take the conn out of komando instead, before any
question. [code]
