# komando design principles

These are the rules for every command, flag, message and output. New
features must follow them. A command that breaks them is a bug.

In short: **one way to do each thing, words people understand, safe when
in doubt, and every error says what to do next.**

The detailed rules live in three more pages, each the one place for its
topic:

- [command-standard.md](command-standard.md): grammar, names, arguments,
  flags, help text, confirmations, errors and output, rule by rule;
- [message-style.md](message-style.md): the words of every message;
- [code-layout.md](code-layout.md): where code goes and the rules tests keep.

## 1. What komando is

komando is one client for all devops work: servers, databases, caches,
message queues, object storage, clusters, registries, VPNs, secrets and
files. One inventory, one way of working, one safety layer. It is for two
users, equally:

- **a person** at a terminal, who types commands; komando asks only for
  what a command is missing, one line at a time;
- **an AI agent or a script**, which gives every argument and flag and gets
  JSON back; it is never asked anything.

Every feature works both ways. Teams (shared inventory, roles, who is
acting) are served by the komando app, not by the open-source CLI.

### Goals

1. **Universal client.** One inventory (`host` + `conn`) for every kind of
   target. A new kind is registered in `internal/driver`; it needs no new
   model and no new flags.
2. **The features people use every day.** Each area can look, search,
   read, change, back up and restore. Rarely used features are left out.
3. **Many kinds of target**, each one meeting the criteria in section 14.
4. **Useful in the first five minutes, easy to move to.** Every command
   has the same shape. Existing configuration comes in with one
   `komando import`. No lock-in: state can be exported as plain JSON.

### Core model

Every feature fits these four ideas. If it does not, it is not ready.

```
target   = host (SSH or WinRM, can run commands)  |  conn (everything else, has a kind)
kind     = the product: postgres, redis, s3, k8s, ftp, oci, ...
family   = kinds with the same verbs  ->  one top-level command
risk     = read | write | destructive  ->  the same guard for all
```

| Command | Family |
|---|---|
| `exec`, `fs`, `cp`, `svc`, `docker`, ... | host (Linux; Windows over SSH or WinRM) |
| `db` | sql and document databases |
| `cache` | key-value |
| `queue` | message queues |
| `storage` | object and file storage |
| `cluster` | orchestrators (Kubernetes, Docker Swarm) |
| `registry` | container registries |
| `secret` | the local vault and external secret stores |
| `vpn` | the path to a target |

## 2. Commands

```
komando <noun> <verb> [ITEM] [TARGET] [args] [flags]
komando db query prod-db "select 1"
komando storage upload backups ./dump.sql.gz
```

- **There is one interface.** `komando` alone prints the commands by group.
  There is no menu, no TUI and no full-screen app.
- **The noun is a work area in plain words** (`host`, `conn`, `db`,
  `cache`, `queue`, `storage`, `cluster`, `registry`, `secret`, `vpn`).
  Product names are only aliases (`s3`, `redis`, `k8s`, `kafka`).
- **A verb has one meaning everywhere.** `list` lists, `show` shows one
  item, `rename` renames, `rm` removes. Words an area's own tool uses
  stay (`scale`, `apply`, `peek`, `purge`), from a fixed list.
- **A few shortcuts live at the top level** (`exec`, `logs`, `cp`, `list`,
  `test`, `upload`, `download`), with the same shape as the long form.
- **Words for a server go after `--`** on every command that passes them
  on (`exec web1 -- uptime`), so komando never reads them as its own flags.
- **One cluster command.** Verbs every engine has sit under `cluster` and
  work on any cluster; a feature only one engine has says so on the other
  (`cluster helm` is for Kubernetes). `docker` is for one server.
- **No legacy.** A rename is clean: the old name stops working, and help,
  examples, the guide, the skill and these docs change in the same change.
  A few plain synonyms (`ls` for `list`) are accepted; docs show only the
  primary name.

The full verb list, the argument words, the flag dictionary and the short
letters are in [command-standard.md](command-standard.md) (S-1 to S-5).

## 3. Targets and selectors

Selectors pick everything: servers and conns alike.

| Selector | Picks |
|---|---|
| `NAME` | one host or conn (names are unique across both) |
| `web-*`, `db-?` | names by pattern |
| `@GROUP` | every member of the group |
| `tag:T`, `label:K=V` | everything with that tag or label |
| `kind:postgres`, `kind:host`, `kind:db` | everything of that kind, or of that command family |
| `os:windows`, `os:linux` | servers by system |
| `all` | everything |
| `a,b,!c` | a combination; `!` leaves one out |
| `user@addr:port` | a server not in the inventory (hosts only) |

1. **Commands that look** (`list`, `test`, `show`, `audit`) use everything
   picked.
2. **Commands that act** use the members they can serve (`exec` → hosts,
   `db` → databases). The rest are listed in `meta.skipped` with the
   reason, never dropped quietly.
3. If none can be served: `NO_MATCHING_TARGETS` (exit 3) with a hint that
   names the right command.
4. A selector that matches nothing is an error, never a success with zero
   results. A typo gets "did you mean".
5. Results are always sorted by name.
6. **Safety checks run for the whole batch before anything runs.** One
   protected target that needs a yes stops the whole batch, and every such
   target is named.
7. `db query` runs against one database; a selector that picks several is
   refused.

## 4. Flags

- **A flag has one meaning and one type in every command** (the
  dictionary is in [command-standard.md](command-standard.md#5-flags)).
- `-o`, `--dry-run`, `--yes`, `--allow-dangerous`, `--reveal`,
  `--timeout`, `--parallel` and `--via` mean the same on every command.
- **Read or write, by default.** Text in a language komando reads (SQL,
  Redis, kubectl) is read-only unless `--write`. Shell text counts as a
  change unless `--read-only`. A command with a clear verb (`storage
  upload`, `svc restart`) needs neither.
- **sudo.** System commands (`svc`, `pkg`, `user`, `recipe`) use sudo when
  needed; `--no-sudo` turns it off. Other commands use it only with
  `--sudo`.

## 5. Output

- **One JSON envelope** on stdout when piped; neat text in a terminal.
  Progress, prompts and warnings always go to stderr.
- Colour only in a terminal, never with `NO_COLOR`.
- Lists are sorted by name, as one list; a KIND or TYPE column tells kinds
  apart. Lists without names keep their own order: jobs and tunnels by
  start time, crontab lines as in the file, `audit` by time.
- Many targets: `data.results[]` per target, `data.summary` (`ok`,
  `failed`), skipped targets in `meta.skipped[]`. Top-level `ok` is false
  if any one failed; the exit code is the worst one.
- Large results are cut, with `truncated: true` and a hint (`--limit`,
  `WHERE`, a prefix). Output is never unlimited.
- Times in JSON are UTC RFC3339; text for people shows local time with
  the zone.
- Binary values are `{"base64": "..."}`, big numbers are strings, and
  `null` and an empty string stay different.
- Text for people fits in 80 columns; long columns are cut with `…` and
  shown in full with `-o json`.

### Output contract

The output shape is **contract version 1** (`meta.contract` in every
answer, `contract` in `komando schema`). Within one version, the envelope
(`ok`, `command`, `data`, `error`, `meta`), field names, error codes and
exit codes are never renamed or removed: only added. A breaking change raises the contract
number and is written in the CHANGELOG.

## 6. Errors

Every error has a stable UPPER_CASE `code`, a `message` (what happened, in
plain words) and a `hint` (the exact command to run next). A typo gets
"did you mean". Errors from a server are passed on as they are, with the
server's own code in `data`. If a command cannot be undone, or a dry run is
not possible, it says so. The details are in
[command-standard.md](command-standard.md#8-errors-and-hints) and
[message-style.md](message-style.md).

## 7. Confirmation and safety

- **One risk table (`internal/cli/risk.go`) decides how much approval a
  change needs**: none for a
  read, `--yes` for a protected target or a safety setting,
  `--allow-dangerous` for what cannot be undone, and some steps only a
  person can take (the tiers are in
  [command-standard.md](command-standard.md#7-confirmations); every
  command's row is in [safety.md](../features/safety.md#what-needs-a-yes)).
- **Agents and scripts**: a change that needs approval fails without the
  flag (exit 6), with a hint. `--dry-run` is never blocked and lists the
  approvals the real run would need. A known AI agent's `--yes`,
  `--allow-dangerous` and `--reveal` open a window on the person's screen;
  the person approves, not the agent.
- **People at a terminal**: komando asks instead. A protected target gets
  `[y/N]`; something that cannot be undone asks the person to type its
  name. The answer is read from the terminal, not from piped
  stdin, so an agent cannot give it. A yes counts only when a person can
  be asked, and only for that one run.
- **Logins ask the person, as ssh does.** What an SSH or VPN login asks
  that komando cannot answer from the vault (a password, a one-time code)
  goes to the person, with the server's name, hidden. Agents and scripts
  get `NO_AUTH` or `AUTH_FAILED` and a hint that sends a person to run the
  command. For a server with a two-factor login, a person runs
  `komando login HOST` once and the agent's commands use that login for a
  few hours.
- **A value only the person knows is typed by the person.** An agent that
  runs `secret set NAME` without a value gets `NEEDS_PERSON`.
- `--allow-dangerous` and `--yes` apply to one command only and are
  recorded in the audit.
- **No way around it.** Removing, replacing or turning off protection on a
  protected target needs `--yes`. Turning off the audit log or the host
  key check, or removing a deny rule, needs `--yes` (`SAFETY_SETTING`).
- **Fail closed**: if the audit cannot be written, the change is refused.
- **Ctrl-C during a command** stops its work: a transaction is rolled
  back, temporary files are removed, and it ends with `CANCELLED`, exit 1.
- **Ctrl-C at a question** stops it, puts the terminal back as it was and
  counts as no: `cancelled`, exit 6. At a hidden prompt it is `CANCELLED`,
  exit 1. Ctrl-D is an empty answer, which is no.
- **A paste of more than one line at a hidden prompt** is refused and
  nothing is stored or sent.
- `HOSTKEY_MISMATCH` is never fixed automatically.

## 8. Secrets

- Secrets never appear in command arguments, URLs, the audit or output,
  except `secret get --reveal` asked for by a person.
- A secret is entered at a hidden prompt, with `--from-env VAR`, or on
  stdin. **A value as an argument is refused**: it lands in shell history
  and in `ps`.
- AI agents see passwords, keys and tokens as `[hidden]`, and personal
  data on protected targets as `[hidden: email]` and the like.
- A ref that cannot be read (empty `env:X`, missing file, a file others
  can read) is an error that names the ref, never its value.

## 9. Inventory and names

- Names: letters, digits, `-`, `_`, `.`; 1–63 characters; starting with a
  letter or digit. Unique across hosts and conns, ignoring case.
- Words that mean something as a selector (`all`) cannot be names.
- A rename updates everything that refers to the item (groups, `--via`,
  recipes). A remove is refused while the item is in use
  (`HOST_IN_USE`, `SECRET_IN_USE`, `KEY_IN_USE`, ...), and the users are
  listed.
- State is written atomically under a file lock, so two komando processes
  never overwrite each other. A change of the state format makes a backup
  first.

## 10. Moving in

```
komando import SOURCE [FILE] [--dry-run] [--group G]
komando export [--to FILE]
```

- Importing again is safe: the same items are skipped, different ones are
  reported. Existing items are replaced only with `--overwrite`.
- Fields komando does not take are reported, never dropped quietly.
- Names that clash between sources get a suggested new name.
- Secrets from any source go into the vault and are used as `secret:NAME`.

## 11. Help and ease of use

- **People use commands, not a menu.** `komando` alone, for a person at a
  terminal, prints the commands by group with START first (and, with
  nothing added yet, how to add the first server). For agents and scripts
  it prints the first steps; piped, one `USAGE` envelope. Help topics:
  `komando help safety|environment|exit-codes|output`.
- **A typed command asks a person for what is missing**, and nobody else.
  It asks only when stdin, stdout and stderr are terminals, no AI agent
  runs komando, `CI` is not set, `TERM` is not `dumb` and the output is
  text. It asks for missing arguments in order, then required flags, one
  line each, labelled with the real name (`CONN (database):`, `--old:`).
  `?` shows help; a default shows in brackets; a wrong answer is explained
  and asked again. Lists come from the inventory: a number picks, text
  narrows, a selector or a new name is taken as typed. One item that is
  not protected is used and said; a protected item is never picked
  automatically.
- After the questions komando shows the full `$ komando ...` line. A read
  runs at once; a change asks `Run it? [y/N, d = --dry-run first]`. The
  questions never add `--yes`, `--allow-dangerous`, `--reveal` or
  `--write`. A command typed in full runs as it always did.
- `host add`, `conn add`, `vpn add` and each area's add, typed alone, ask
  that kind's own questions, never a password (that is asked hidden).
- After a command a person ran ends well: `Next time: <line>` when komando
  asked for something, and up to three `Next:` lines. `show` ends with
  that item's commands. All on stderr, only at a person's terminal.
- Agents and scripts get exactly what they got before: the same exit code,
  error and hint. A test (`TestAgentGolden`) holds this.
- Every command has at least one real example in `--help`, and every
  example must parse.
- Shell completion completes host, conn, group and tag names.
- `komando guide` (for agents) and `docs/features/` (for people, one page
  per feature) change in the same commit as the feature.

## 12. One need, one command

Before adding a command or flag, check whether something already does it.
If so, extend that one.

- One idea has one name in every area (the path is always `--via`).
- A per-area version of a general command exists only as an alias that
  calls the general one, never as a second implementation.
- Doing one item or many at once may be two commands, sharing the same
  code.

Examples in place: `test` (`host test` and `conn test` call it), `list`,
`logs` (`svc logs` and `docker logs` call it), `recipe`, `upload` /
`download`, `exec --script`, `import` / `export`, `status --short`.

## 13. Everything the native tool can do

komando is as strong as the original tool through three paths, the same
in every area:

1. **Commands komando understands** (`db schema`, `cache get`,
   `storage ls`): structured output, safe. For most daily work.
2. **A raw path in the native language**, still classified, read-only by
   default and audited: `exec`, `db query`, `cache run`,
   `cluster run -- <kubectl args>`.
3. **Your own tool, through komando's path**: `komando tunnel start prod-db`
   gives a local port for any client; `komando shell` opens SSH;
   `komando db shell prod-db` opens komando's own SQL shell with the
   password from the vault.

Paths 2 and 3 are not overlaps: they exist on purpose, with the same
safeguards.

## 14. Adding a family

A new family is added only when all of these hold:

1. It fits the `conn` + kind + verb model, with no new ideas.
2. It can be read-only by default, with an honest risk classification.
3. It can be built in pure Go.
4. People use it every day.
5. Someone will maintain it: tests and docs.

A family is done when:

- it is registered as a kind in `internal/driver` (URL scheme, port, example);
- `conn add` and `test` work, including `--via HOST`;
- passwords come only through refs and are refused in a URL;
- it is read-only by default, enforced by the server where possible
  (read-only transaction, read-only token, Kubernetes `--dry-run=server`);
- risk is classified before anything is sent, and the rules show in
  `komando policy`;
- `--dry-run` is real, or the command says plainly it cannot be;
- protected needs `--yes`, destructive needs `--allow-dangerous`;
- it writes one audit line per command, with no secrets;
- it has JSON output and readable text;
- it has a section in `komando guide`, a page in `docs/features/`, and an
  importer when there is a common source.

## 15. Technical rules

- **Pure Go, no cgo, one binary for everyone.** No lite or full builds and
  no size limit, but pick light dependencies and no plugin system.
- **Everything built in.** No feature needs Docker or another installed
  program (no kubectl, psql, pg_dump, openvpn, cloud CLIs). komando talks
  to each API itself.
- **Our own code where no suitable open library exists, and fully open
  source**: no closed or prebuilt parts. Never copy GPL code.
- **No pool and no daemon.** One connection per command. Tunnels, VPN
  sessions, kept logins and jobs are the only background processes
  (`komando status` lists them).
- **The paid boundary.** The CLI never syncs between devices. Sync and the
  AI assistant are only in the paid apps, and these rules keep paid-plan
  logic out of komando:
  1. komando, the open-source CLI, never contains plan, tier, seat,
     billing, account, allowance or licence checks, and never asks Komando
     Cloud whether something is allowed. Every command works with no
     account and no network beyond the targets a person names.
  2. Anything a paid service needs from the CLI comes in only as a
     **neutral, open capability**: read or write an open format, check a
     signature against a key list, or talk to a local process over a local
     socket. It must work for anyone who brings their own keys and lists,
     with Komando Cloud switched off.
  3. **"Allowed because paid" lives only in Komando Cloud** (a separate,
     closed repo) **and in the apps**. The apps may show what is paid; they
     never lock anything that works on the device.
  4. The komando binary never links the sync library or a Komando Cloud
     client, and calls no komando-owned host except the release site, when
     a person runs `komando update`. The sync library is a public Go module
     in its own folder, `sync/` with its own `go.mod`
     (`github.com/sgnd/komando/sync`), never under `internal/`, and
     `cmd/komando` never imports it. (The alternative, if the owner prefers
     it, is a separate `sgnd/komando-sync` repo.)

  Code that would break rule 1 is a design error, not a feature: change the
  design so the check happens on the service. `internal/boundary` checks
  rule 4 in `go test`.

## 16. Not goals

- Replacing full tools (`psql`, `kubectl`, `terraform`, `helm`) in
  everything they do. komando handles the common daily work safely; the
  rest runs through `exec` or the original tool.
- Infrastructure as code, cloud provisioning, GitOps.
- GUI, TUI, menus, dashboards or full-screen apps.
- Monitoring or alerting that runs all the time.

## Anti-slop checklist

Check every new command and every review against this list (it follows
[clig.dev](https://clig.dev)).

**Words**
- [ ] Counts are words: "1 server", "3 servers", "1 of 3 failed", "both
  failed". Never `server(s)` or "2 of 2 failed".
- [ ] A change says what happened first: `added web2`, `changed web2`,
  `web2: nothing to change`, `would add web2 (dry run)`.
- [ ] No emoji, banners, boxes or ASCII art. `✓`/`✗`/`!` in `doctor` and
  `●` per server are the only symbols.
- [ ] Booleans for people are `yes` or `-`, not `true`/`false`.
- [ ] Times for people are local with the zone; JSON keeps UTC RFC3339.

**Errors**
- [ ] One line of message, no stack trace, no raw library text with
  newlines.
- [ ] A typo in a command, flag, name or selector gets "did you mean".
- [ ] The hint is the exact next command, or the command's own example.
- [ ] One target that fails gives its own error code, not
  `PARTIAL_FAILURE`.

**Help**
- [ ] `komando` alone: commands by group for a person; the first steps
  otherwise, a dozen lines at most.
- [ ] Every command has a real example, and every example parses.
- [ ] `Short` is an imperative verb phrase, no full stop, no flags: 64
  characters at most at the top level, 72 elsewhere (the full rules are
  S-6 of the command standard).
- [ ] A sub-command's `--help` lists only the global flags that matter
  there.

**Streams and scripts**
- [ ] Data on stdout; progress, prompts, warnings and text-mode errors on
  stderr.
- [ ] Piped output is one JSON envelope, never mixed with text.
- [ ] Nothing asks a question when stdin or stdout is not a terminal.
- [ ] The exit code is honest: non-zero whenever `ok` is false.

## Edge cases

Use this list for every feature and every review.

**Targets and network**
- `--via` host down, slow, or with a changed host key (`HOSTKEY_MISMATCH`, never skipped)
- IPv6 (`[2001:db8::1]:22`), DNS failure, wrong port, a silent firewall (a timeout, never a hang)
- Bastion chains with more than one hop; a company proxy
- TLS with a self-signed certificate: an explicit option per conn, never turned off quietly
- 500 targets at once: `--parallel`, output stays sorted, one failure does not stop the rest

**Credentials**
- Ref missing, env empty, file unreadable, vault locked without a terminal
- Expired token (AWS session, kube exec plugin): a clear error that says how to renew
- Password in the URL at `conn add` or `import`: refused, hint `secret set`

**Safety**
- Dangerous commands in disguise: comments, mixed case, odd spacing, several statements, Redis `rename-command`
- Unknown commands count as a write
- One protected target in a batch stops the whole batch before it starts
- `--yes` given when not needed: runs, gives no extra right
- Dry run not possible (MySQL DDL, `VACUUM`): said, not run
- Audit cannot be written: the change is refused

**Data and output**
- Very large results, binary values, non-UTF-8 text, `NULL`, numbers over 2^53, time zones
- Narrow terminal; output piped to `less` or `head` (a closed pipe is not an error)
- Partial failure over many targets: an honest exit code and summary

**Files and transfer**
- The destination exists: not replaced without `--overwrite`
- An interrupted download: write to a temporary file, then rename
- A trailing slash (`dir` vs `dir/`): its meaning is in `--help`, the same for `cp` and `storage`
- `~` in local and remote paths, spaces and unicode in names, symlinks, very large files (progress on stderr)

**Processes**
- Over about 2 minutes: `job`; the connection drops while a job runs; orphan jobs are cleaned up
- Ctrl-C: roll back, clean up, `CANCELLED`; at a question, a no with echo back on
- Two komando processes on the same state

**Per area**
- **db**: long locks (`lock_timeout`), read-only replicas, connection limits, restore into the wrong database (protected and type the name)
- **cache**: `KEYS` on a big cache (use `SCAN`), Redis cluster (`MOVED`), sentinel, database numbers
- **storage**: versioned buckets (delete markers), "folders" that are prefixes, multipart upload, links that live at most 7 days
- **cluster**: default namespace, kubeconfig context, exec auth plugins, `apply` always with a diff and `--dry-run=server` first
- **registry**: Docker Hub rate limits, tag vs digest (deleting a digest deletes its other tags too)

**Moving in and versions**
- `~/.ssh/config` with `Include`, `Match` and wildcards; kubeconfig with many contexts
- Importing again, clashing names, fields komando does not take
- Output contract: new fields are allowed, old fields stay until a major version
