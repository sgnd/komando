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
- the caller (`cl.caller()`) and `sess` (`engine.Session`: the approvals)
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
  `cl.environ` is what a program the call starts gets: it leaves out
  `KOMANDO_VAULT_PASS` and the other unlock values
  (`vault.StripUnlock`). It is never nil: an `exec.Cmd` whose `Env` is
  nil inherits the process's whole environment, so a call with no
  environment starts programs with none (a dump tool then gets no `PATH`
  or `HOME`; an app hands in what its programs need).
  `vault.TakeUnlockEnv` cleans only the process's environment, and an
  app hands each call one of its own. A komando process that needs the
  vault gets `vault.SelfEnv` or the values on its stdin.
- Output goes to the call's writers only: `cl.out.W` and `cl.out.Err`.
  Nothing in `internal/cli` writes to `os.Stdout` or `os.Stderr`. Whether
  a person reads it is asked of the call's own writer
  (`isTerminal(cl.out.W)`, `isTerminal(cl.out.Err)`): `-o auto`, the
  progress lines, the retry notes and the questions. The width lines
  wrap at is the call's too (`out.WidthOf`): `cl.width()` asks the
  call's stderr, `textWidth(cl)` its stdout; a writer that is no
  terminal (a pipe, an app's writer) wraps nothing. For the komando
  program those writers are the process's stdout and stderr, so it
  behaves as before, byte for byte. The notices of a built-in SSL VPN's
  browser sign-in go to the call's stderr (`netx.SSLVPNLogin` takes it). Followed lines from several pods or clusters
  (`cluster logs --follow`, `cluster run`) take turns on the call's
  stdout (`call.liveMu`).
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

By then the call is already running, and other calls' hooks read it
from their own goroutines (below). So what a hook reads changes only
under a lock: the caller is an atomic value (`cl.caller()`,
`cl.setCaller`), the session is made once and reset in place under its
own lock (`engine.Session.Reset`), and the printer's vault values are
set with `out.Printer.SetSecrets`, which drops the old ones and loads
the new ones on first use.

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
   process (a call counts from the first step of its command to the end:
   `execute` calls `call.enter` before anything can open the store or the
   vault, and `call.leave` when it returns). This order matters: the store
   is opened once per process, and `vault.AgentCall` decides there whether
   an agent's `KOMANDO_KEYCHAIN=off` keeps the old-copy check. An agent's
   `--reveal` opens the store (is the approval code on?) before the
   command runs, so a call counted any later would open it as no
   agent's. What the hooks read of a call is safe to read while it runs
   (see "One answer covers one command"); `TestHooksReadRunningCallsSafely`
   checks it under `-race`. One gap is left: a host key pinned by a
   connection whose context carries no call (none in a command today)
   is written to the audit log of the first running call, which reads
   that call's flags as it runs. A value read for one call is hidden
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
3. **The process's terminal.** Raw mode (the fd of `os.Stdin`), the PTY
   questions and Ctrl-C use the process's terminal. Only a call with
   `Terminal: true` asks questions; an app's calls never do. The
   questions are drawn on the call's stderr. The width lines wrap at is
   the call's own (above); `out.UnicodeOK` (it reads `TERM` and `LANG`)
   still describes the process's terminal. sshx writes the "first
   connection" note to `os.Stderr`. Programs komando starts for itself
   (the approval window, the browser, a credential helper, background
   komando processes) get the process's environment.
4. **The data folder.** `store.Home()` and the vault read `KOMANDO_HOME`,
   `env:` references and the unlock variables from the process's
   environment. An app's calls share one data folder, so this is right
   for them; a call's own `KOMANDO_HOME` must match the process's.
5. **Set once per process.** `Version` (an `init`), `vtOK` (the Windows
   console, in `Execute`), the signal handler, and `store.Close` (in
   `Execute`; an app closes the store when it quits). `Execute` sets
   `call.signals`, and `execute` arms Ctrl-C only after the guided
   questions, as before: a Ctrl-C at a question, or at the preview it
   offers, stops only that. An app passes its own context to `RunCall`;
   one already done after the questions stops the command with "Stopped.
   Nothing was run."
6. **Paths through jump hosts.** sshx shares one login to the same jump
   hosts among the servers behind them (`openJumps`, a cache of the
   process), so calls at once share it too. The cache key names the VPN,
   each jump host and the host-key check (`chainKey`): a path dialed with
   `--host-key-policy off` is never handed to a call that checks keys.
7. **Background processes.** `login-holder` sets `sshx.Asker` and
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
- `TestAgentCallCountsBeforeTheStoreOpens` runs an agent's `list --reveal`
  through `RunCall` with only that call running and the real
  `vault.AgentCall`: the approval window and every read of the store's
  change count see an agent, and an old copy of the store stops with
  `STORE_OLD_COPY`.
- `TestHooksReadRunningCallsSafely` calls the hooks from one goroutine
  over and over while agents' calls run their commands through
  `RunCall`: under `-race`, nothing a hook reads is written without a
  lock.
- `TestCallEnvironForChildren`: a call with no environment starts a
  program with an empty one, not the process's, and a call's own
  environment loses its unlock values.
- `TestWidthIsTheCalls`: an app's writers wrap nothing; stderr notes
  ask the call's stderr, a text result its stdout.
- `TestCallsApartAtOnce` (two agents), `engine.TestSessionsApart` and
  `engine.TestSessionReset` stay.
- All run under `go test -race`.
- The tests share one call, `tcl` (`testcall_test.go`), as they shared the
  package variables: they run one at a time. A test that sets an agent's
  variable uses `setCallerEnv`, which reads `tcl`'s caller again after
  the variable is restored, so the next test does not start as an agent.
