# Code layout

This page is the one place for the rules a contributor (a person or an AI
agent) follows when adding code: what goes where, how packages and files
are named, and the rules every change keeps. Tests check most of them; the
"Checked by" column says which. The product rules behind them are in
[principles.md](principles.md).

## The rules in short

| Rule | Checked by |
|---|---|
| **Built in only.** A feature works with the komando binary alone: no Docker, no other program to install on this computer. Programs the operating system already has, and programs on the server, are fine ([principles.md](principles.md#15-technical-rules)). | review |
| **Own version** where no suitable open library exists: komando writes the client itself, as its own Go package. | review |
| **Open source only.** Libraries are MIT, BSD, ISC or Apache (MPL only unchanged, as a library). No GPL or LGPL code, not even copied or translated. No prebuilt blobs. | review |
| **Pure Go.** `CGO_ENABLED=0`; a library that needs cgo does not qualify. | `make dist` |
| **One need, one command.** Two commands may not do the same job. | `TestStandard*` |
| **Every command says whether it reads or changes things** (`commandKinds` in `internal/cli/kinds.go`). | `TestEveryCommandHasKind` |
| **Command IDs change only on purpose**, together with the command name (`internal/cli/testdata/command_ids.txt`). | `TestCommandIDsStable` |
| **The JSON answers keep their shape.** Fields are added, never renamed or removed. | `TestOutputShapes`, `TestAgentGolden` |
| **Functions up to 100 lines, files up to 800.** Split instead of growing. | `internal/codesize` |
| **Coverage does not drop** below `test/coverage-floor.txt`. | `make cover` |
| **Every command runs once end to end** (`test/e2e/checks/coverage.sh`). | `make e2e` |
| **Messages follow [message-style.md](message-style.md).** | `message_style_test.go` |
| **Packages and files are named as below.** | `internal/layout` |

## Packages

`cmd/komando` only starts the program. `internal/cli` turns commands and
flags into calls: it reads the flags, runs the safety checks, calls the
work and prints the answer. Code that talks to something outside komando
(a protocol, a service, a file format) lives in its own package under
`internal/`, so it can be tested without the command line.

**Package names** are one short lower-case word, no underscores. A package
gets an `x` at the end only when the plain word would clash with:

- a standard library package (`net` → `netx`);
- a package komando imports (`ssh` → `sshx`, `proxy` → `proxyx`);
- another komando package (`store` → `storex`);
- a word the code uses as a variable name everywhere (`db`, `cache`,
  `queue`, `browser` → `dbx`, `cachex`, `queuex`, `browserx`).

The packages keep the names they have: a rename costs every open branch a
conflict and gains nothing. A new package follows the rule.

**One engine per sub-package** under its family: `queuex/nats`,
`queuex/sqs`. A fake server or helper that only tests use goes in a
`...test` sub-package (`proxyx/proxytest`).

**When a noun gets its own package:** when it has logic that needs neither
cobra nor komando's global state (the inventory, the guards, the audit
log), and the logic is more than a file or two. The command itself (flags,
guard, audit, output) stays in `internal/cli`. Moving a whole area out of
`internal/cli` happens one area at a time.

Every package is listed here; `internal/layout` fails when one is missing
or a listed one is gone.

| Package | What it is |
|---|---|
| `cmd/komando` | `main`: starts `internal/cli` |
| `internal/browserx` | a sign-in page in a browser window (VPN SAML logins) |
| `internal/cachex` | Redis-compatible caches and memcached, with the risk of each command |
| `internal/cli` | every command: flags, safety checks, audit and output |
| `internal/cloud` | komando's own clients for cloud and secret-manager APIs |
| `internal/codesize` | test only: the 100-line and 800-line limits |
| `internal/dbx` | SQL and MongoDB against a conn, dump and restore |
| `internal/driver` | the kinds of conns and the risk levels the safety checks use |
| `internal/engine` | one komando call: who makes it and its approvals |
| `internal/flock` | a file lock between komando processes |
| `internal/ipsec` | komando's own IKEv1 and IKEv2 clients |
| `internal/kube` | the Kubernetes API over HTTPS, without client-go |
| `internal/l2tp` | komando's own L2TP client |
| `internal/layout` | test only: the package and file names on this page |
| `internal/netx` | the networks komando reaches targets through (VPNs, proxies) |
| `internal/openvpn` | komando's own OpenVPN client |
| `internal/out` | the JSON envelope and the text output of every command |
| `internal/policy` | finds destructive shell commands |
| `internal/ppp` | a small PPP peer for L2TP |
| `internal/proxyx` | HTTPS clients through the company proxy |
| `internal/proxyx/proxytest` | a test proxy for the tests |
| `internal/queuex` | message queues, with Kafka built in |
| `internal/queuex/nats` | NATS JetStream |
| `internal/queuex/pubsub` | Google Cloud Pub/Sub |
| `internal/queuex/rabbitmq` | RabbitMQ |
| `internal/queuex/sqs` | Amazon SQS |
| `internal/registry` | container registries over the OCI Distribution API |
| `internal/sealdb` | the local store file (SQLite of sealed rows) |
| `internal/sealrow` | seals one record of the local store |
| `internal/sshx` | SSH: dialing through jump hosts, host keys, running commands |
| `internal/sslvpn` | komando's own SSL VPN clients (AnyConnect, Fortinet, GlobalProtect, F5, Pulse) |
| `internal/store` | komando's state: inventory, conns, keys, jobs, tunnels, settings |
| `internal/storex` | object storage, FTP, SFTP, WebDAV and SMB behind one interface |
| `internal/vault` | the encrypted secrets |
| `internal/winrm` | komando's own WinRM client for Windows servers |

## Files in internal/cli

A file is named for the command it serves. The noun is the first word of
the command (`komando db dump` → `db`), as listed in
`internal/cli/testdata/command_ids.txt`, with any hyphen left out
(`ssh-gate` → `sshgate`).

| Name | Holds | Examples |
|---|---|---|
| `<noun>.go` | the command and what most of its verbs share | `host.go`, `db.go`, `cluster.go` |
| `<noun>_<verb>.go` | one verb, when it is big enough for its own file | `job_start.go`, `fs_replace.go`, `key_revoke.go` |
| `<noun>_<topic>.go` | one part of the noun | `db_dump_tls.go`, `conn_tls.go`, `cluster_swarm.go` |

- Join words with `_`; never glue them (`db_dump.go`, not `dbdump.go`).
- Never shorten a noun or invent a prefix (`cluster_kctl.go`, not
  `kctl.go`; `user.go`, not `ops_user.go`).
- A topic may have parts of its own: `cluster_kctl_change.go` is part of
  `cluster_kctl.go`, the layer that does the Kubernetes verbs.
- `errcodes.go` is generated (`KOMANDO_UPDATE_ERRCODES=1 go test
  ./internal/cli -run TestErrorCodeCatalog`); do not edit it by hand.

### Shared areas

Code that many commands use is named for its area instead of a noun:
`<area>.go` or `<area>_<topic>.go`. A new area needs a row here first, with
a reason; `internal/layout` reads this table.

| Area | What it holds |
|---|---|
| `approval` | the person's approval: the window, the code, the hints |
| `args` | the argument words of a command, and the words after `--` |
| `ask` | asking a person for a password or a login answer |
| `cmdid` | the stable command IDs |
| `common` | small helpers nearly every command uses (state, timeouts, fan-out, audit) |
| `confirm` | yes/no and typed confirmations |
| `errcodes` | the error catalog (`errcodes.go` is generated) |
| `flag` | the shared flag types, old flag names and help for a mistyped flag |
| `form` | the questions a typed command asks for what is missing |
| `guard` | the safety checks before a change: protected targets, safety settings, agent hooks, deletes |
| `inv` | looking up and checking names and values in the inventory |
| `kinds` | what each command does, in one word (reads or changes) |
| `localtool` | finding a program on this computer |
| `modules` | the module commands (`svc`, `logs`, `pkg`, `net`, `user`, `cron`) and the runner they share |
| `oldname` | old spellings, kept as hidden names |
| `personal` | hiding personal data from AI agents |
| `pick` | the lists a question picks from |
| `platform` | process helpers that differ per operating system |
| `prompter` | the question engine behind `form` |
| `readonly` | holding `--read-only` to its promise |
| `risk` | the one table of what each command and flag needs before it runs |
| `root` | the command tree, the global flags and the start of every command |
| `select` | selectors: `@group`, `tag:x`, `kind:x` |
| `sensitive` | hiding secrets from AI agents |
| `stdin` | reading piped input |
| `suggest` | "did you mean" for a word komando does not know |
| `synonyms` | permanent second names of commands |
| `term` | the terminal's size and mode |
| `text` | the shared `-o text` output: tables, widths, empty lists, change lines |
| `ttyin` | reading from the terminal, hidden input included |
| `via` | `--via` paths: the VPN and SSH hops in front of a target |
| `windows` | Windows servers over WinRM (a target, not a platform suffix: `windows_fs.go` builds everywhere) |

## Tests

- A test of one file sits next to it: `db_dump.go` → `db_dump_test.go`.
- A test that checks one rule across many files is named for the rule:
  `standard_test.go`, `message_style_test.go`, `agent_golden_test.go`.
- Expected output and other test data go in `testdata/`. Golden files are
  rewritten only for a change you meant, after reading the diff.
- `TestMain` and the helpers many tests use (`testState`, ...) are in
  `cli_test.go`.

## Platform files

A file that builds only on some systems says so in its name, with one of
these endings, and the `//go:build` line agrees with the name:

| Ending | Builds on | `//go:build` line |
|---|---|---|
| `_windows.go`, `_darwin.go`, `_linux.go` (any Go system name) | that system (Go reads the name) | none needed; if there is one, it names the same system |
| `_unix.go` | every system but Windows | `//go:build !windows` (or `unix`) |
| `_other.go` | the systems the files beside it do not cover | `//go:build !darwin`, `!windows`, ...: the systems of those files |

- A program file whose `//go:build` line names a system has one of these
  endings. A test may carry a build line without one, to skip a system.
- Do not end a name with a system or processor word by accident
  (`_arm.go`, `_js.go`, `_wasm.go`): Go would build that file only there.

## Adding a command, step by step

1. Put it in `<noun>.go` or `<noun>_<verb>.go`. A new top-level noun is
   rare: the command standard keeps a closed list.
2. Give it an ID and a kind (`commandKinds`), an example, and a row in the
   risk table (`risk.go`) if it can stop for an approval.
3. Keep the cobra builder short: it reads the flags and calls one function
   that does the work.
4. Add a unit test next to the file, and an end-to-end check in
   `test/e2e/checks/` inside the area whose containers it needs.
5. Run `make lint` and `go test ./internal/...`.
