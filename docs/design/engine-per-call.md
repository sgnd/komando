# One call, one value: the engine without shared state

The CLI runs one command per process. The Mac and iPhone apps will embed
the engine and run several commands in one process, at the same time: a
person's command and an AI agent's command, side by side. That only works
when nothing one command does reaches the other. This page says what a
call carries, how the code gets it, and what is still shared.

## The problem (gap F01)

Before this change, `internal/cli` kept the state of "the command running
now" in package variables:

| What | Where | Uses |
|---|---|---|
| The printer (`out.P`) | `internal/out` | 365 in cli, 138 in its tests |
| The global flags (`g`: `--dry-run`, `--yes`, `-o` ...) | `root.go` | 257 |
| The current call (`cur()`, `isAgent()`, `interactive()` ...) | `approval.go`, `common.go` | 106 |
| What a command found out (`askedAbout`, `blockAudited`, `nextNow` and 9 more) | 12 files | 60 |
| Environment reads (`os.Getenv`, `os.LookupEnv`, `os.Environ`) | 30 files | 50 |
| `os.Args` (the command line in the audit log and the approval window) | 5 files | 11 |
| `os.Stdout`, `os.Stderr`, `os.Stdin` as writers and readers | 40 files | 109 |
| Hooks the lower packages call (`vault.OnResolve`, `sshx.HostKeyPinned` ...) | 7 `init` functions | 10 |

Two commands at once would share all of it: one would print into the
other's output, see the other's `--yes`, and read the other's agent
variables.

## The design

### engine.Call: what the caller hands in

`internal/engine` has `Call`: the environment (`LookupEnv`, `Environ`),
`Stdin`, `Stdout`, `Stderr`, whether a person can answer at a terminal
(`Terminal`), and the approval window (`Ask`; nil opens komando's own).
The CLI makes one from its process (`processCall`). An app makes one per
command. `Call.Caller()` says who calls (person, script or agent), read
from that environment only.

### cli.RunCall: the entry point

```go
func RunCall(ctx context.Context, c engine.Call, args []string) int
```

`RunCall` runs one command as `c` and returns the exit code. The
envelope or the text goes to `c.Stdout`, notes and warnings to
`c.Stderr`. `Execute` (what `main` calls) does the process's own work
once (core dumps off, the Windows console, Ctrl-C) and then calls
`RunCall` with the process's call. The JSON output is the same as before,
byte for byte.

### call: what a command runs with

Inside `internal/cli`, `call` holds everything one command needs:

- `io` (the `engine.Call`), `args` (the command line), `stdin`, `terminal`
- `caller` and `sess` (`engine.Session`: the approvals)
- `out`: its own `out.Printer`, whose `W` and `Err` are the call's stdout
  and stderr
- `flags`: the global flags; the command tree binds them (`newRoot(cl)`)
- what the command finds out as it runs (`askedAbout`, `blockAudited`,
  `nextNow`, `promptConfirmed` and the others)

`out.P`, `g`, `cur()`, `active`, `startCall` and the package variables
above are gone. There is no "current call" in a package variable.

### How the code gets the call

- A function that runs a command gets it from the command:
  `cl := callOf(cmd)`. `newRoot(cl)` puts the call in the root command's
  context, and the root's `PersistentPreRunE` puts it in the running
  command's context, so every command of the tree finds it.
- Every other function takes it as its first parameter: `func
  resolveTargets(cl *call, st *store.State, ...)`. 471 functions do;
  229 command functions take it from their command.
- The few answers everybody asks for are methods: `cl.isAgent()`,
  `cl.interactive()`, `cl.yesOK()`, `cl.dangerOK()`, `cl.revealOK()`,
  `cl.personAllows()`, `cl.policyStop()`.
- The environment is read through the call only: `cl.getenv`,
  `cl.lookupEnv`, `cl.environ`. Nothing in `internal/cli` calls
  `os.Getenv`, `os.LookupEnv` or `os.Environ` except `processCall`.
- Types whose methods need the call keep it in a field set where they are
  made (`kctlRun`, `sqlShell`, `fill`, the sync sides, `connMgr`, the
  progress writers). Results whose text says "would ..." under
  `--dry-run` are `out.PrinterTexter`s: `TextFor(p)` reads `p.DryRun`
  from the printer that prints them. `rmResult` keeps `dryRun` in a field
  because its JSON changes too.
- Test seams that are package variables (`askOnScreen`, `promptable`,
  `offerBackup`, `openBucket` ...) take the call as their first
  parameter. Production never writes them.
- A command tree that is only read (the guided forms, ssh-gate's check,
  the risk table) is built for a call of its own: `newRoot(treeCall())`.

### One answer covers one command

`call.begin` runs when a command starts (the root's `PersistentPreRunE`):
the caller is read again from the call's environment and the session
starts empty. A call that runs two commands (a test) asks again for the
second, as two processes did.

## What is still shared, and why

The packages under the cli keep some state of their own. A call cannot
reach it yet. Each item below is safe for two calls at once, or says what
is not.

1. **Hooks of sshx, vault and netx.** `sshx.HostKeyPinned` and
   `netx.StartSession` get the context of the connection, which carries
   the call: they answer for that call. `vault.OnResolve`,
   `vault.RefGuard`, `vault.AgentCall`, `sshx.HostSecretEnv`,
   `sshx.PersonAtTerminal`, `sshx.Asker` and `netx.LockBusy` get no call.
   `call_hooks.go` sets them once and answers over every call running in the
   process (a call counts from the end of its setup, `call.enter`, to the
   end of its command, `call.leave`): a value read for one call is hidden
   in all of them; one agent among them makes a guard answer as for an
   agent; a person is asked at the terminal only while theirs is the only
   call. That is safe, not exact. Next step: these packages take a
   `context.Context` that carries the call (`vault.Resolve` takes none
   yet; `sshx` would carry it on the `Client`).
2. **`store.DryRun` and `store.AllowOldCopy`.** The store reads them on
   every write. `storeDryRun` writes them only when they change, so calls
   without `--dry-run` never touch them. A dry run at the same time as
   another call still makes the other call's store writes previews. This
   must change before the apps run calls side by side: `store.Update`
   needs a dry-run parameter (48 callers) and `vault` reads it twice.
3. **The process's terminal.** Raw mode, the PTY questions and Ctrl-C
   use the process's terminal. Only a call with `Terminal: true` asks
   questions; an app's calls never do. `out.StderrWidth`, `out.StdoutWidth`
   and `out.UnicodeOK` (it reads `TERM` and `LANG`) describe the process's
   terminal. sshx writes the "first connection" note to `os.Stderr`.
4. **The data folder.** `store.Home()` and the vault read `KOMANDO_HOME`,
   `env:` references and the unlock variables from the process's
   environment. An app's calls share one data folder, so this is right
   for them; a call's own `KOMANDO_HOME` must match the process's.
5. **Set once per process.** `Version` (an `init`), `vtOK` (the Windows
   console, in `Execute`), the signal handler (in `Execute`; an app passes
   its own context to `RunCall`), and `store.Close` (in `Execute`; an app
   closes the store when it quits).
6. **Background processes.** `login-holder` sets `sshx.Asker` and
   `vpn serve` sets `netx.SessionSecret`. Each runs as a process of its
   own and never in an app.

## Tests

- `TestPersonAndAgentCallsAtOnce` runs a person's call and an agent's call
  through `RunCall` at the same time, eight rounds: each prints only its
  own output (text for the person, one JSON envelope for the agent), and
  each reads only its own environment, never the process's.
- `TestPersonAndAgentApprovalsApart` runs both at once with approvals:
  the person's yes to a safety change and to a dangerous action is not
  the agent's, and the agent's window, which the person denies, never
  counts for the person's call.
- `TestCallsApartAtOnce` (two agents) and `engine.TestSessionsApart` stay.
- All run under `go test -race`.
- The tests share one call, `tcl` (`testcall_test.go`), as they shared the
  package variables: they run one at a time.
