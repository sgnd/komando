# The komando command standard

The rules every command follows: grammar, names, arguments, flags, help
text, confirmations, errors and output. It is for a person learning
komando and for a contributor adding a command. The wider rules are in
[principles.md](principles.md); the words of every message are in
[message-style.md](message-style.md).

This is the standard of the v2.7 command tree (release v0.18.0). A line
that starts `TODO(cut):` is a point the owner has not decided or a build
that is not finished; it names what it waits on and goes before the cut
merges.

Each rule has an ID (`S-…`) that code and tests cite, and a tag that says
how it is checked:

- **[schema]**: `internal/cli/standard_test.go` checks it from the command
  tree or the schema. A new command that breaks it fails `go test`.
- **[code]**: a test checks it from the Go code or from a recorded run
  (golden files, error catalog, PTY test).
- **[review]**: a person checks it in review.

Rules that cannot change because of the contract:

- **JSON field names are never renamed or removed.** New fields may be
  added. `komando schema` output is part of this: a change to a
  `flags[].type`, `default`, `kind`, `path` or `usage` value is listed in
  the release note (S-9.8), even when no field name changes.
- **The field that names the entry a command ran on is the entry's type
  word** (S-9.9).
- **Error codes and exit codes stay** within an output contract
  (`meta.contract`). A removed or renamed code raises the contract. Every
  new exit-code path on an existing command is listed in the release note
  with a TestAgentGolden row.
  TODO(cut): the new `meta.contract` value waits on the release pull
  request.
- **One command, one ID** (S-1.6). The success envelope, the error
  envelope, the audit log and every table keyed by command use the same
  string.
- **No legacy.** A rename is clean: the old name stops working, and every
  caller (help, examples, skill, docs, tests, apps) changes in the same
  change. Only plain synonyms stay (S-1.7).
- **A short letter has one meaning** within its scope (S-5.14).
- **No `--json`, `--no-input` or `--quiet`.** Output is `-o`. A person's
  missing-argument questions may use keyboard menus built from the
  command table; an agent, a script and JSON keep the plain path (S-4.6).
  TODO(cut): the wording of the menus rule waits on the interactive-mode
  design note (C162).
- **`--yes`, `--allow-dangerous` and `--reveal` mean a person said yes.**
  No new flag may do what they do, and no change may let an agent skip a
  stop it gets today (S-7.1).

One more line for every review:

- **No plan, account or service check in any command.** A command never
  asks whether someone paid and never asks Komando Cloud whether something
  is allowed (the paid boundary, [principles.md](principles.md#15-technical-rules)).
  Paid things live in komando-apps and komando-cloud, never in this tree.
  [review]

---

## 1. Grammar

**S-1.1** A command has one of four shapes. [schema: every leaf path
matches one of them]

| Form | Shape | Example |
|---|---|---|
| A thing komando connects to | `komando TYPE PROVIDER VERB NAME [args] [flags]` | `komando host ssh exec web1 -- uptime` |
| Inside it | `komando TYPE PROVIDER AREA VERB NAME [ITEM] [flags]` | `komando queue kafka message list prod-kafka orders` |
| komando's own thing | `komando NOUN [KIND] VERB [NAME] [flags]` | `komando credential password add admin-web --user admin` |
| A built-in or an action across types | `komando VERB [TARGET] [flags]` | `komando copy ./site web1:/srv` |

The words in order: **type** (`host`), **provider** (`ssh`), **area**
(`tunnel`, `topic`, `object`, `image`), **verb**. A connection option is a
typed flag of its provider. A URL is still accepted as a short way to give
the same options.

**S-1.2** The item comes first, then the target, then the rest. NAME is the
entry's name in komando's list. Where a verb takes many entries it takes a
TARGET selector (`@group`, `tag:x`, `label:k=v`, `all`). [review]

**S-1.3** One need, one command. Two commands may not do the same job. A
second spelling is a hidden synonym (S-1.7), never a second documented
command. [schema: no two visible leaves share the same `Short`]

**S-1.4** Top-level commands are a closed list of 26 names, plus cobra's
own `completion`. Anything new goes under one of them. [schema: the set of
top-level names equals this table plus `completion`]

| Group | Top-level commands |
|---|---|
| Built-ins | `list`, `test`, `config`, `update`, `version`, `schema` |
| Types | `host`, `database`, `cache`, `queue`, `storage`, `cluster`, `registry`, `vpn`, `cloud` |
| komando's own | `credential`, `group`, `policy`, `snippet` |
| Across types | `copy`, `import`, `export`, `status` |
| About komando | `agent`, `audit`, `doctor` |

`list` and `test` at the top act on every kind of entry. Inside a provider
they act on that provider's entries.

**S-1.4a** (removed 2026-11-24 with the command it froze: no legacy.)

**S-1.5** A name may never equal a value a person can pass in the same
position. An entry may not be named after a type word, a provider word or
`all`. [schema: no subcommand name equals a word the table lists at that
level; code: validName refuses the reserved words]
TODO(cut): the full reserved-word list waits on the table builder (PR B).

**S-1.6** Every command carries an ID: its dotted path by primary names
(`host.ssh.exec`, `credential.key.create`, `queue.kafka.message.list`). A
rename changes the ID with the name, in the same change. `commandName`
returns it. The success envelope, the error envelope, the audit log,
`audit list --command` and the masking checks are all keyed by it, and
every ID resolves to a tier row (S-7.1).
`internal/cli/testdata/command_ids.txt` is generated from
the table, one line per leaf. [code: every key in every table resolves to
a command ID; the error and success envelope of a command carry the same
ID]

**S-1.7** Synonyms. A few plain synonyms are hidden cobra `Aliases` and
print nothing: `ls` for `list`. Help, examples and docs use only the
primary name. `remove` and `delete` are two verbs (S-3.1), so neither is
a synonym of the other. [code]
TODO(cut): whether `rm` stays as a synonym of `remove`, and the plural
aliases of the type words, wait on the alias column of the table (PR B).

**S-1.8** A synonym that needs its own argument shape is a thin hidden
wrapper command with its own `Args`, carrying the ID of the command it
runs (S-1.6). [review]

**S-1.9** At most four words come before NAME (`host ssh tunnel start`,
`queue kafka message list`, `registry oci image copy`). Depth is allowed;
structure is the point. [schema]

**S-1.10** A removed command answers "unknown command". It names no new
path and gives no hint. [code: TestAgentGolden row per removed top-level
word]

**S-1.11** Help is only `--help`, at each level (`komando --help`,
`komando host --help`, `komando host ssh --help`). There is no `help`
command and no help topic as a command. Topics are docs articles. `schema`
lists every path with its type, provider, area and verb, so a picker can
be built from it. [schema]

## 2. Types and nouns

**S-2.1** The types, with the providers the table holds. A type is a
category in human words; a provider is a product or protocol name in
lowercase. [schema: the table is the only source of the tree]

| Type | Providers |
|---|---|
| `host` | `ssh`, `winrm`, `telnet`*, `serial`* |
| `database` | `postgres`, `mysql`, `mariadb`*, `sqlserver`, `oracle`, `sqlite`, `mongodb`, `clickhouse`, `snowflake`, `bigquery` |
| `cache` | `redis`, `valkey`*, `memcached` |
| `queue` | `kafka`, `rabbitmq`, `nats`, `sqs`, `pubsub` |
| `storage` | `s3`, `gcs`, `azblob`, `sftp`, `ftp`, `smb`, `webdav` |
| `cluster` | `kubernetes`, `nomad`*, `swarm` |
| `registry` | `oci` |
| `vpn` | `wireguard`, `openvpn`, `globalprotect`, `fortinet`, `anyconnect`, `pulse`, `f5`, `l2tp`, `ipsec`, `ikev2`, `tailscale`, `system`, `socks`, `proxy` |
| `cloud` | `aws`*, `gcp`*, `azure`*, `alibaba`*, `tencent`*, `digitalocean`* |

`*` ships in a later minor release, one at a time, not in the cut.

**S-2.2** No abbreviation is a type or a noun, and no product name is a
type: `kubernetes` is a provider, `cluster` is the type; `s3` is a
provider, `storage` is the type. [review]

**S-2.3** Words in help text. "server" for a `host` entry. "entry" for one
thing in komando's list. The type's own word for a type ("database").
"service" means only a Kubernetes or Swarm Service. "conn" and "resource"
are not used. [schema: no Short or Long contains "conn" meant as a noun or
"resource"]
TODO(cut): the list of plural and human-word synonyms for the type words
waits on the alias column (PR B).

**S-2.4** komando's own nouns:

| Noun | Kinds or verbs | What it is |
|---|---|---|
| `credential` | `password`, `token`, `key`, `certificate`, `store PROVIDER`, plus `list` and `run` | what komando logs in with, sealed, never shown |
| `group` | `create`, `edit`, `list`, `show`, `rename`, `remove` | a named set of entries and snippets |
| `policy` | `check`, `create`, `list`, `show`, `remove` | your own block rules |
| `snippet` | `create`, `edit`, `exec`, `list`, `show`, `rename`, `remove` | a saved command or plan |
| `config` | `get`, `set`, `show`, `approval-code`, `vault keychain`, `vault passphrase` | komando settings |
| `agent` | `skill install`, `skill uninstall`, `mcp start`, `mcp stop` | how AI agents use komando |
| `audit` | `list`, `check`, `export`, `recording list`, `recording show`, `recording export`, `recording remove` | the signed log and shell recordings |

Credential store providers: `vault`, `aws-sm`, `gcp-sm`, `azure-kv`,
`onepassword`, `bitwarden`, `keepass`, `env`, `file`. [schema]

TODO(cut): `agent mcp` and the `audit` verbs `export` and `recording ...`
are built after the cut (one minor each); they wait on their own rows.
TODO(cut): the verb of `audit recording remove` is `delete` in the tree;
the rule of S-3.1 says `remove` for komando's own file. It waits on O-14.

**S-2.5** A mixed group may hold entries of many types and
providers, and snippets. A verb under a provider acts once per provider:
`komando host ssh exec @prod`, then `komando host winrm exec @prod`.
Members of another provider are skipped and named in `meta.skipped`.
`list`, `test`, `copy` and `status` take a mixed selector as it is. [code]
TODO(cut): the field and the exit code for skipped members wait on O-30.

## 3. Verbs

**S-3.1** A verb has one meaning. The table is the full list; a new verb
needs a row here first. [schema: every leaf verb is in this table or is a
named exception of S-3.3]

| Verb | One meaning | Used in |
|---|---|---|
| `add` | give komando a thing that exists outside it | every provider; credential kinds |
| `create` | komando or the target makes a new thing | `credential key`, `group`, `policy`, `snippet`; `queue` topic and message; `storage` object |
| `edit` | change saved details | every provider; credential kinds; `group`, `snippet` |
| `list` | the contents of the level you are at | everywhere |
| `show` | everything about one thing | everywhere; `config show` |
| `rename` | rename and fix every reference | every provider; credential kinds; `group`, `snippet` |
| `remove` | take out of komando's list; the real thing is untouched | every provider; credential kinds; `group`, `policy`, `snippet` |
| `delete` | destroy inside the target | `queue` topic and message, `storage` object, `registry` image |
| `test` | can komando reach it and log in; the person step runs here | every provider; top `test` |
| `check` | compare against a rule, change nothing | `policy check`, `audit check` |
| `exec` | run on a target | `host ssh`, `host winrm`, `cluster kubernetes`, `snippet` |
| `run` | run on this computer | `credential run` |
| `raw` | the target's own command language | `cache`, `cluster` |
| `query` | SQL or a MongoDB query | `database` |
| `shell` | an interactive session, person only | `host`, `database`, `cluster kubernetes` |
| `backup`, `restore` | save a whole database to a file, load it back | `database` |
| `read`, `move`, `link` | print an object, move or rename it, a time-limited link | `storage object` |
| `copy` | copy bytes or an image | top `copy`; `registry oci image copy` |
| `prune` | delete old things by a rule | `registry oci image` |
| `info` | a summary of the target | `queue` only (E5) |
| `start`, `stop` | begin or end something that keeps running | `vpn`, tunnels, `agent mcp` |
| `status` | state of something that runs | top `status`, `vpn` |
| `install`, `uninstall` | put files on a place, take them off | `credential key`, `agent skill` |
| `trust` | pin a server's host key | `host ssh` |
| `discover` | find what an account holds and add it to the list | `cloud` |
| `get`, `set` | one setting | `config` (E3) |
| `export`, `import` | komando's own file out and in | top; `audit export` |
| `update`, `version`, `schema`, `doctor` | komando itself | top |

**S-3.2** Pairs that must stay pairs: add/remove (entries), create/remove
(komando's own things), create/delete (inside a target), start/stop,
install/uninstall, backup/restore. `registry oci image` has `delete`
without `create` (E4). [schema: for each noun with one half, the other
half exists or is listed here]

**S-3.3** Named exceptions. [schema: allow-list]

| ID | Exception | Why it may stay |
|---|---|---|
| E1 | the noun leaves `config approval-code`, `config vault keychain`, `config vault passphrase` | the owner accepted these places |
| E2 | `copy` at the top (files) and `registry oci image copy` (images) | different nouns, one meaning |
| E3 | `get` and `set` only in `config` | a setting has one value |
| E4 | `registry oci image` has `delete`, `prune`, `copy` and no `create` | images come from builds |
| E5 | `info` on `queue` providers | a queue has no raw command, so S-3.4 does not apply |

TODO(cut): E1 waits on O-15 (verbs instead of noun leaves). `storage sftp
object move --mode` (chmod) waits on O-13.

**S-3.4** Every provider has these verbs: `add`, `edit`, `list`, `remove`,
`rename`, `show`, `test`. A type keeps another verb or an area only when
its own raw command cannot do the job. [schema]

| Type | Raw command | What stays besides the inventory verbs |
|---|---|---|
| `host` | `exec`, `shell` | ssh: `trust`, `tunnel` |
| `database` | `query`, `shell` | `backup`, `restore` |
| `cache` | `raw` | nothing |
| `cluster` | `raw` | kubernetes: `exec`, `shell`, `tunnel` |
| `queue`, `storage`, `registry`, `vpn`, `cloud` | none | their areas, whole |

**S-3.5** A read command never becomes a write through a flag, except the
documented switches in S-5.9 (`--write`). [schema: no `kind: read` command
has a flag whose usage says "installs", "deletes" or "changes"]

**S-3.6** `update` at the top level takes only a version. Any other word
is a USAGE error. [code]

**S-3.7** `group remove` removes the group only. Members go with
`group edit --remove`. [review]

## 4. Arguments

**S-4.1** Argument words are UPPERCASE. `[X]` is optional, `X...` repeats,
`A|B` is a choice. Only a literal stays lowercase (`--`). [schema: Use parses
with this grammar]

**S-4.2** Each word has one meaning in every command. [schema: allow-list of
words; the completion and picker map has one entry per word]

| Word | Means | Picker / completion |
|---|---|---|
| `TARGET` | a selector that may pick several entries of the command's type; the prompt label says which: `TARGET (servers):` | filtered by the command's type |
| `NAME` | one entry of the command's own type and provider (or a new name in `add`); one item of komando's own noun | that type or noun |
| `KIND` | a credential kind: `password`, `token`, `key`, `certificate` | the four kinds |
| `GROUP` | a group | groups |
| `USER` | an account a credential logs in as | none |
| `ITEM` | the thing inside a target (a topic, an object, an image, a consumer) | none |
| `FILE` | a file on this computer | files |
| `PATH` | a path on a server | none |
| `ADDRESS[:PORT]`, `DOMAIN`, `URL` | network places | none |
| `ID` | a session ID of `exec` (S-10.4) | none |
| `-- COMMAND...` | a shell or program command | none |
| `-- ARGS...` | words for the target's own command language | none |

TODO(cut): the words per area (`TOPIC`, `OBJECT`, `IMAGE`, `CONSUMER`
instead of `ITEM`) wait on the `Args` of each leaf in the table (PR B).

**S-4.3** A required flag is shown in the usage line with an UPPERCASE value
(`database postgres restore NAME --from FILE`); optional flags never are. A
choice of flags is in parentheses:
`host ssh tunnel start NAME (-L SPEC | -R SPEC | -D SPEC)`. [schema:
required flag ⇔ present in Use]

**S-4.4** Passthrough commands: every command whose Use has
`-- COMMAND...` or `-- ARGS...`: `host ssh exec`, `host winrm exec`,
`cluster kubernetes exec`, `cluster PROVIDER raw`, `cache PROVIDER raw`,
`credential run`. komando flags are read anywhere before `--`
(`komando host ssh exec @web -P 20 --read-only -- df -h`). Any word after
the fixed positionals (TARGET, NAME) must come after `--`. Without `--`,
such a word is a USAGE error (exit 2) with the hint
``put -- before the command: `komando host ssh exec web1 -- apt-get install -y nginx` ``.
So `-y` in `apt-get install -y nginx` can never be read as `--yes`, and a
trailing `--dry-run`, `-P 1` or `--fail-fast` is never read by komando
while the words around it go to the server. `exec --attach ID` has no
command and no `--`. [code: one shared PreRunE helper using
`ArgsLenAtDash`; TestStandardPassthrough walks the tree and checks every
command with `COMMAND...`/`ARGS...` in Use has it, and runs both failing
forms]

**S-4.5** One quoted string (`policy check`, `policy create`) is written
`COMMAND` without `--`, and Long says "one quoted string". [review]

**S-4.6** A missing argument is asked for only at a terminal. The question
for each argument comes from the leaf's `Args` and `Options` in the table,
one line at a time, and the whole line is shown before it runs. Agents,
scripts, CI, `TERM=dumb` and JSON get USAGE (exit 2). [code]

## 5. Flags

### 5.1 Dictionary

**S-5.1** A flag name has one meaning and one type in every command, except
the allow-listed rows marked *exception*. [schema: group flags by name; each
group has one type; meanings checked by usage-text template where one exists]

| Flag | Short | Type | Meaning | Default and units |
|---|---|---|---|---|
| `--limit` | `-n` | int | the most items, rows or log lines to show. Never a safety cap. Says in its usage text whether it counts per target or in total | each command keeps its current default; 0 = no limit wherever the text says so |
| `--head`, `--tail` | | int | first or last N lines of one object (`storage object read`) | 0 = all |
| `--max-<noun>` | | bytes or int | a safety cap: the run is refused above it (`--max-bytes`, `--max-output`) | stated per flag |
| `--timeout` | | duration | how long this command may run per target (global) | setting, 5m |
| `--wait` | | duration | wait for the result up to this long; the global `--timeout` still applies and whichever ends first stops the run | 0 = do not wait |
| `--idle` | | duration | stop after this long with nothing new | stated per flag |
| `--interval`, `--expires`, `--ttl`, `--older-than`, `--warn` | | duration | a span | per flag; "0 = never" or "> 0" in the usage text |
| `--since`, `--until` | | when | a point in time | `30m`, `7d`, `today`, `yesterday`, `2026-11-07 14:30`, RFC3339 |
| `--from` | | string | a local input file, the pair of `--to` (`database P restore`, `queue P message create`) | `-` = stdin |
| `--to` | | string | a local output file (`database P backup`) | `-` = stdout |
| `--file` | `-f` | string | a manifest or input file a tool reads (`database P query`) | `-` = stdin where the tool allows it |
| `--config` | | tool word | *exception*: `queue P topic create --config KEY=VALUE`, `vpn P add --config FILE` | |
| `--key` | | string | *exception*: `queue P message create --key` is the message key (Kafka) | |
| `--env`, `--label`, `--option`, `--var`, `--header` | `-e` for --env | stringArray | `KEY=VALUE`, repeatable, never split on commas. A value whose text after a comma looks like `KEY=` is a USAGE error: "repeat --option for each KEY=VALUE" | |
| `--group`, `--tag`, `--add`, `--remove`, `--kind`, `--unset` | `-g`, `-t` | stringSlice | a list of names, comma-separated | |
| `--all` | `-a` on read commands only | bool | also what is normally left out (read), or every item instead of one named item (change: no shorthand) | false |
| `--sudo` | `-s` | bool | run it with sudo on the server | off |
| `--sudo-user` | | string | run it as this user with `sudo -u` | |
| `--overwrite` | | bool | replace what is there | false |
| `--recursive` | `-r` | bool | include everything under a folder (`copy`) | false |
| `--follow` | `-f` (streamers) | bool | stream new lines until Ctrl-C or `--timeout` | false |
| `--write` | | bool | let a read-first command (SQL, Redis, kubectl text) change things | false |
| `--read-only` | | bool | declare shell text as read only | false |
| `--dry-run` | | bool (global) | show the plan, change nothing; never blocked (but S-7.5's one exception) | false |
| `--credential` | | string | the name of the credential an entry logs in with. A name, never a reference string | |
| `--sudo-credential` | | string | the credential that holds the sudo password | |
| `--psk-credential` | | string | the credential that holds a preshared key; generated at 256 bits, never typed | |
| `--store`, `--item` | | string | on `credential KIND add`: the named store and the item in it that holds the value | |
| `--ask` | | bool | on `credential password add`: a person types the password at every connect; it is never stored | false |
| `--user` | | string | the account a credential logs in as (`credential password add`, `credential key add`). An entry has no `--user` of its own | |
| `--protected` | | bool | the entry's changes need a person's yes (S-7.2) | false |
| `--container` | `-c` | string | a container name (`cluster kubernetes exec`) | |
| `--dir` | `-C` | string | the working folder | |
| `--attach` | | ID | `exec`: come back to the session with this ID, read its output and its exit code (S-10.4) | |
| `--stop`, `--signal` | | bool, word | with `exec --attach ID`: signal the run; `--signal` names the signal (default `TERM`) | |
| `--remove` | | bool | with `exec --attach ID`: remove that session's log on the server | |
| `--end` | | bool | on `test`: end the kept login of NAME, or of every entry when no NAME is given (S-10.5) | false |
| `--sync`, `--delete`, `--exclude`, `--emptied` | | bool, string | on `copy`: compare and copy only what changed; remove what the source does not have (S-7.2); skip paths; allow an emptied folder | false |
| `--progress` | | bool | with `-o json`, progress as one JSON object per line on stderr (`copy`); text mode keeps its own progress line | false |

TODO(cut): the cluster flags (`--namespace`, `--all-namespaces`,
`--selector`) and `--revision`, the `--wait` of an `exec` that outlasts a
tool timeout, the `--from N` offset of `exec --attach` (it collides with
`--from FILE` above), the `--run-on` of `database P backup` and the
spelling of the list flags on `edit` (`--add-X`, `--remove-X`) wait on the
`Options` of each leaf in the table (PR B, C, C324).

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
`--X` and `--no-X` on one command. [schema]

**S-5.6** A flag value never looks like a positional argument: a name used
as a value flag anywhere is never a bool elsewhere. [schema: covered by S-5.1]

**S-5.7** Defaults shown are the real ones. A default taken from a setting
keeps its `default` value and adds `default_from` (additive) in the schema;
durations print short (`1h`, `10m`, `0`); an unset optional number shows
no default, never `-1`. [schema: no default "-1"; no default "1h0m0s"-style]

**S-5.8** Every list command has `--limit` (S-5.1 defaults). A run that
stops at the limit sets the additive `meta.truncated: true` and, in text
mode, prints one stderr line `Note: showing the first N; --limit 0 shows all`
(or the command's own cut note in its output).
[schema: every leaf whose verb is `list` has --limit; code: truncation sets
the field]

**S-5.9** Read-first or change-first. Text in a language komando parses
(SQL, Redis, kubectl text through `raw`) is read only unless `--write`.
Shell text is a change unless `--read-only`. No third switch.
[schema: no flag named `--apply`; every `kind: depends` command has exactly
one of --write / --read-only]

**S-5.10** Multi-target runs continue after a failure (`--fail-fast` stops).
[review]

**S-5.11** Each flag has one usage text template per name. Shared texts
(`--sudo`, `--credential`, `--since`, `--until`, `--protected`) come from
one Go constant. [schema: one usage text per name for these names]

**S-5.12** A command shows only flags that do something on it. [review]

**S-5.13** On `edit` commands, a list is changed with `--add` and
`--remove`; `--group`/`--tag` are hidden there. [schema]

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
| `-a` | `--all` | read commands only | ls |
| `-c` | `--container` | any --container; `--cmd` only on `exec` | kubectl |
| `-C` | `--dir` | any --dir; `--comment` only on `credential key create` | git, make |
| `-e` | `--env` | any --env | docker |
| `-f` | `--follow` on streamers; `--file` elsewhere | | tail, kubectl apply |
| `-g` | `--group` | `add` and `import` | |
| `-n` | `--limit` | everywhere a list has it | head |
| `-r` | `--recursive` | everywhere | cp |
| `-s` | `--sudo` | everywhere | |
| `-t` | `--tag` | `add` (hidden on `edit`) | |
| `-b`, `-D`, `-L`, `-R` | bits; dynamic, local, remote | `credential key create`; `host ssh tunnel start`, `cluster kubernetes tunnel start` | ssh-keygen, ssh |

TODO(cut): the shorthands of the cluster options (`-A`, `-l`, and `-n` for a
namespace) wait on the cluster leaf options (PR C).

**S-5.15** Never a shorthand for: `--allow-dangerous`, `--reveal`,
`--write`, `--dry-run`, `--port`, `--user`, `--label`, or a bool `--all`
on a change command. [schema]

**S-5.16** An unknown flag or shorthand gets a did-you-mean,
including common foreign shorthands (`-it`, `-w`). [code]

**S-5.17** An unknown command word gets help in this order:
(1) a curated table of words from other tools, each mapped to a full
command for `error.hint`: `ps` → `komando host ssh exec TARGET --read-only -- docker ps`,
`kubectl` → `komando cluster kubernetes raw NAME -- ...`,
`psql` → `komando database postgres query NAME`,
`apt`, `yum` and `systemctl` → `komando host ssh exec TARGET -- ...`;
(2) edit distance 1 for words of 4 letters or fewer, 2 otherwise, at most
2 suggestions; (3) the hint names a command only when there is exactly one
suggestion. The table holds no word of a removed komando command (S-1.10).
[code: TestAgentGolden rows for `ps`, `kubectl`, `psql`]
TODO(cut): the final contents of the table wait on the built tree (PR B).

## 6. Help text

**S-6.1 Short (leaf)**: an imperative verb phrase in sentence case. No full
stop, no flags, no semicolons, no "e.g." or "etc.", at most one parenthesis
for scope. At most 64 characters at top level, 72 elsewhere. [schema]
Guideline: read commands usually start with Show, List or Check. [review]

**S-6.2 Short (group)**: the area in human words and 3 or 4 main jobs as
plain verbs, never a partial list of command names:
`Servers over SSH: run commands, open a shell, forward ports`. [schema: a
group Short names no sibling command unless it names all of them]

**S-6.3** A Short never says "Same as". The alias goes in Long's first
line. [schema]

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
`harbor`; clusters `prod-k8s`, `swarm1`; VPN `office`; users `alice`,
`app`; credentials `admin-web`, `api-prod`; credential store `my-vault`;
group `prod`. English only. An entry is never named after its type or
provider word. Comments use `  # ` and say why. [schema: names from the
table; no non-English words list]

**S-6.9** Every example parses: the command exists, every flag exists.
[schema, already TestExamplesParse]

**S-6.10** Every backticked `komando …` in Short, Long, hints, Next: lines
and error catalogs names a real command, and its UPPERCASE words are that
command's Use words. A script lists every `komando ` path in the hint
strings and checks each against the table. [code]

**S-6.11** Top-level help groups are the five of S-1.5: Built-ins, Types,
komando's own, Across types, About komando. [review]
TODO(cut): whether a "Start" block of first commands stays waits on the
help builder and its golden (PR B).

## 7. Confirmations

**S-7.1** One rule table, `riskOf(command, args, flags) → tier`, decides
the tier. It is keyed by (type, verb), and by (type, area, verb) inside a
target, never by the full path. A provider adds a row only when it
differs (`database sqlite restore`). The prompted path, the gates, the
schema and the docs all read it. No change to the table may let a command
and flag combination that stops an agent (POLICY_BLOCKED, PROTECTED_*,
SAFETY_SETTING, CONFIRM_REQUIRED) run without that stop. [code: every
leaf has a tier row and every row names a command that exists
(`TestLeafNotWeaker`); TestAgentGolden has a row per gated command and
flag combination]

**S-7.2** The tiers:

| Tier | What | Agent needs | Person at a terminal sees |
|---|---|---|---|
| T0 read | looks only | nothing | nothing |
| T1 change | reversible, or only komando's own list | nothing | typed in full: runs. Prompted: `Run it? [y/N, d = --dry-run first]` |
| T2 protected | any T1 or T3 on a protected entry | `--yes`, exit 6 PROTECTED_TARGET | `web1 (protected): <what changes>. Continue? [y/N]` |
| T3 dangerous | cannot be undone, or an outage: `database P restore`, `queue P topic delete`, `queue P message delete --all`, `storage P object delete`, `registry oci image delete` and `prune`, `credential KIND remove`, `credential key remove --delete-file`, `credential key uninstall`, `copy --sync --delete`, and any text a policy rule rates dangerous in `exec`, `query`, `raw` or `snippet exec` | `--allow-dangerous`, exit 6 POLICY_BLOCKED | `This deletes <what> on <where> for good. Type <answer> to continue:` |
| T3s safety | weakens komando's own checks: audit off, `policy remove`, `update` to an older version, `config vault keychain --off`, open bind on a tunnel, sending a secret, `TYPE edit --protected=false`, clearing a VPN's `--mfa` | `--yes`, exit 6 SAFETY_SETTING / OPEN_BIND / SECRET_DESTINATION | `This turns off a komando safety check: <what>. Continue? [y/N]` |
| T4 person only | `config approval-code`, typing a secret, `--reveal`, accepting an old copy, every `shell`, the person step of `test` (two-factor, cloud login), replacing a pinned host key | no flag; NEEDS_PERSON and friends, hint names the command a person runs | the command itself |

A bulk action has its own confirm: `group remove` on a group of more than 3
members still needs `--yes` from an agent (CONFIRM_REQUIRED).

**S-7.3** The typed answer is the name of what goes away or stops: one
item with a name of 60 characters or less → that name; several items or a
long name → the count, labelled (`Type 37 (objects under daily/ in backups)`);
the whole target (`database P restore`, `copy --sync --delete`, an `exec`
hit) → the target name. Never the bare word "yes". A text sent through
`cluster P raw`, `cache P raw` or `database P query` asks a person only
for `--allow-dangerous`: the typed name of the old structured commands
is a recorded loss. [code: PTY test per T3 command]

**S-7.4** One question per command. A prompted command that reaches a T3
gate asks `Run it?` once and the typed name once; T3 on a protected target
asks one typed question with "(protected)" and the answer covers both.
[code: PTY test]

**S-7.5** `--dry-run` works on every change command, is never blocked (but
for an AI agent's command in another data folder, `KOMANDO_HOME`), and
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
with PROTECTED_* is never `kind: read`. A kind change goes in the release
note. [schema + rule table]

**S-7.9** "Blocked by …" is used only for a custom deny rule or a policy or
classifier hit, never for a command's own built-in tier. [code]

**S-7.10** A command for a person at a terminal (every `shell`,
`config vault passphrase`, the person step of `test` ...) never runs for an
AI agent. No variable and no terminal lets an agent's process start one.
[code]

**S-7.11** Stops kept in commands. Each stop lives in command code, not in
a table, stays with its command and has a pinning test that passes on the
old tree and on the new one. [code]

| Function | What it stops | v2.7 home |
|---|---|---|
| `guardProtection`, `guardConns` | a change to a protected entry without the person | every typed `add`, `edit`, `remove` |
| `protectedUsers` | a credential used by a protected entry is protected | `credential`, following `--credential NAME` |
| `protectedTwinHost`, `protectedTwinConn` | a twin with the same address dodging protection | the typed entries; compares across providers of one type |
| `guardKubePlugin`, `guardCloudLogin` | the kubeconfig login program, checked on every cluster command | the cluster type, every verb |
| `localWriteProtected`, `protectedFilesOf` | an agent writing komando's home | `copy` and every local write |
| `protectedTargets` | removing a protected target | the typed `remove` verbs |
| `RefGuard` | `env:` of unlock variables, `file:` of komando's home | `credential store PROVIDER add`, `edit` and every resolve |
| `refuseEncodedSecret` | a secret passed in an encoded form | `exec` text and `credential run` |

TODO(cut): the pinning test of each function waits on the move pull
requests (M3c pins, C350).

**S-7.12** Nothing replaces a command with `exec`, `query` or `raw` unless
a rule rates the same danger there, or the loss is written in the release
note and the docs. A removed read command is checked: either
`exec --read-only` still allows its text, or the loss is written. [code:
the cut plan's check script lists every removed command with its carrier]

**S-7.13** A recorded loss is one line in the release note and in the
docs, with its workaround. These are recorded: the never-trust list of host
CAs (a stolen signed key cannot be cut off without replacing the CA; the
workaround is to remove the CA and sign every key again, and it is a
security gap), the validate, back-up and undo of file
edits, one-server-at-a-time reboot with a boot-ID check, the typed name of
a person on a cluster delete or a scale to zero through `raw`, and
the certificate expiry check until paid monitoring exists. [review]

## 8. Errors and hints

**S-8.1** Every error code is a string literal in `errcodes.go`. No code is
built with `ToUpper` or `+`. [code: TestErrorCodeCatalog scans for both]

**S-8.2** New codes are `<SUBJECT>_<OUTCOME>`. SUBJECT is the command's own
type or item word. OUTCOME and its exit code come from this list:
[code: catalog test with an allow-list of today's exceptions]

| OUTCOME | Exit |
|---|---|
| NOT_FOUND, MISSING (a tool) | 3 |
| EXISTS, IN_USE, CONFLICT, BUSY, CHANGED (changed while komando worked) | 8 |
| INVALID, UNSUPPORTED | 2 |
| AUTH, UNREACHABLE, TLS | 4 |
| DENIED, FAILED (server side), ERROR (server's own words) | 5 |
| REQUIRED (an approval) | 6 |
| TIMEOUT | 7 |
| a local failure | 1 |

**S-8.3** One code has one meaning, and one meaning has one code: two
causes share a code only when the next step is the same, and one cause
gives the same code to an agent and to a script. `<THING>_NOT_FOUND` names
exactly what is missing; an unknown entry name is `TARGET_NOT_FOUND` for
every command. Every code has one exit code. [code: TestOneCodeEach,
TestErrorCodeCatalog]

**S-8.4** `error.message` says what happened and the state of the world:
lower-case start, no full stop, no `tool:` prefix, the human kind word.
Not found is always `no <kind> named "<name>"[ in <where>]`. [code: catalog test]

**S-8.5** `error.hint` says only the next step, as one sentence with the
exact command in backticks, filled in: `run it again: `komando host ssh test web1``.
A flag-only fix is still a whole command line. At most one "or". It is never
a question. [code: every catalog hint has a backticked command, allow-list
for outside fixes]

**S-8.6** Fixed phrases: "run it again" for a retry. One helper builds every
approval hint, in two variants. For a detected agent: "check with
--dry-run, ask the user; once they agree, run it again with --yes" (or
--allow-dangerous). Otherwise: "check with --dry-run, then run it again
with --yes: `komando …`". [code: one hint per approval code and variant]

**S-8.7** Placeholders in hints are the Use words of the command they name.
`fillHint` fills every inventory word it knows (TARGET, NAME). No `<x>`,
no `…`. [code]

**S-8.8** A suggestion ("did you mean") goes in the additive
`error.suggestion` and, as a whole command line, in `error.hint`
(`komando host ssh show web1`), because agents are taught to read the
hint. People see it after the message. The skill and AGENTS.md mention
`error.suggestion`. [code]

**S-8.9** A person who answers no gets exit 6 and `Cancelled. Nothing was
changed.`; Ctrl-C gets CANCELLED, exit 1, `Stopped. Nothing was run.`
[code]

**S-8.10** When a kept login has ended or was never made, the agent's
command fails and `error.hint` names `komando test NAME`. An agent never
types a code. [code: TestAgentGolden row]

**S-8.11** A store that cannot be read says so in plain words and names
the next command. A store with a leftover `secret:` value is refused with
`STORE_REFERENCE_UNSUPPORTED` (exit 2); the message names the record type,
the entry and the field, never the value. An agent or CI never migrates a
store: it gets NEEDS_PERSON. [code]

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

**S-9.4** Every add, edit, rename and remove has a Next list: add → `test`,
`show`; edit → `show`, `test`; rename → `show NEW`; remove → `list`; a test
that passed → the first use command of the type. [code]

**S-9.5** An empty result says so on stdout: `no <things> yet: `komando … add``
when the list is empty, `no <things> match <filter>` otherwise. [code: each
list command has an empty-line test]

**S-9.6** Text tables: booleans `yes` or `-`; times local with the zone
(`2026-11-07 14:30 WIB`); ages `3h` under AGE or SINCE; headers are words
with spaces (`USED BY`); the target column is NAME. Text output is not part
of the contract, but changes to it are listed in the release note
because agents read `-o text`. [code: data_table helpers are the only path]

**S-9.7** Every change command has its own `Text()`. The generic renderer
is a fallback, tracked in a shrinking list. [code]

**S-9.8** `komando schema` is read by agents (the agent rules, rule 2).
`komando schema` with a synonym shows the command it runs. The fields
agents read for approvals and limits (`error.suggestion`,
`meta.would_need`, `meta.truncated`, schema `confirm`, schema
`default_from`, schema `credential_stores`) are part of the output
contract. [code]

**S-9.9** The JSON field that names the entry a command ran on is its
type's own word, from one closed list: `agent`, `audit`, `cache`, `cloud`,
`cluster`, `config`, `credential`, `database`, `group`, `host`, `policy`,
`queue`, `registry`, `snippet`, `storage`, `vpn`. No new output field takes
a name outside the list. `test` names the field by the entry's type. A
record in an export file carries a `type` field; the export and import
results count per type in an object keyed by the type word
(`"database": 3`). [code: a test walks the output structs and checks that
the field naming the entry equals the type word of the leaf that writes
it]
TODO(cut): the field of a tunnel's service (its type is known only when it
runs) waits on O-18.

## 10. Journeys

**S-10.1** Every kind of thing has these steps, with these verbs. A
missing step is listed here as "none". [schema: for each kind, each verb
resolves]

| Kind | add | test | show | list | edit | rename | remove | back up |
|---|---|---|---|---|---|---|---|---|
| entry (every type and provider) | add | test | show | list | edit | rename | remove | export |
| credential password, token, certificate | add | none | show | list | edit | rename | remove | none yet |
| credential key | create, add | none | show | list | edit | rename | remove | none yet |
| credential store PROVIDER | add | test | show | list | edit | rename | remove | none yet |
| group | create | test @GROUP | show | list | edit --add, --remove | rename | remove | export |
| snippet | create | none | show | list | edit | rename | remove | export |
| policy rule | create | check | show | list | none | none | remove | export |
| exec session | exec | none | exec --attach ID | status | none | none | exec --attach ID --stop, --remove | none |
| tunnel | start | none | list | list | none | none | stop | none |
| kept login | test | test | status | status | none | none | test --end | none |

**S-10.2** Flags match across entries: every provider's `add` and `edit`
take the same `--label`, `--protected`, `--unset`, `--credential`; `remove`
and `edit` take `NAME|TARGET...` alike. `--unset` may not name `mfa` or
`protected`; `--protected=false` and clearing `--mfa` are T3s (S-7.2); a
multi-target `remove` follows the `host ssh remove` tier. [schema; code:
parity test with host]

**S-10.3** Credentials. An entry points at a credential only with
`--credential NAME` on `add` and `edit`; changing the credential changes
every entry that uses it. A reference to a credential is written
`credential:NAME` everywhere: URLs, flags and
`credential run --env KEY=credential:NAME`. A reference string of an
outside store is never typed on an entry; it lives in a
`credential store PROVIDER` entry, and a credential points at an item in a
named store with `--store` and `--item`. A key used by two users is two
credentials. [code; review]

**S-10.4** A long run. Every `exec` runs in a session on the server and
prints its session ID first. `exec --attach ID` comes back to it, streams
the output and returns the exit code; `--stop [--signal TERM]` and
`--remove` end it and remove its log. The ID is made by komando, 128 bits
random, checked against `^[a-z0-9]{26}$` before any path use. The log
folder is `~/.komando/sessions/` of the login user (mode 0700, files 0600,
never `/tmp`); a log is removed after a finished `--attach` read or after
7 days. Output may hold secrets and is masked only on this computer. The
first call's approval covers a re-attach; `--attach` only reads. [code:
test of start, lose, attach, read the rest and the exit code]
TODO(cut): `host winrm exec` ships only when its Windows session meets the
same promises (0700 folder, 0600 log, random ID, retention, `--stop`,
`--remove`); it waits on C359. The wait limit and the exit code for a run
that outlasts an agent's tool timeout wait on C324.

**S-10.5** The person step. A kept login has no command of its own. When a
server asks for a two-factor code or a cloud account needs a login, a
person runs `komando test NAME` once; the kept login lasts 8 hours (the
`login_for` setting caps it, with a test) and agents reuse it. A person
ends it early with `komando test NAME --end`, or all of them with
`komando test --end`. `status` only shows. An agent never types a code
(S-8.10). [code]

**S-10.6** Agents. `komando agent skill install` writes the skill and the
guard hooks for every supported agent; `komando agent skill uninstall`
removes them and needs `--yes` from an agent. The rules text for agents
lives in the skill file (`skills/komando/SKILL.md`) and in the repo's
`AGENTS.md`; no command prints them. A release checks that both still
match the CLI. [review; code: the skill copy in `internal/cli` equals the
repository copy]
