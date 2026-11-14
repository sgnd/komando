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
  or `HOME`; an app hands in what its programs need). Two programs a
  command starts do not get it yet (item 2 of "What is still shared").
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
second, as two processes did. Before that, `newRoot` starts the global
flags from their defaults and resets the printer (`out.Printer.Reset`):
what the last command set on it (`DryRun`, `Pretty`, `Mask`, `Personal`,
`NoRedact`) is not the next one's, and `execute` chooses the output
format again from `json`. `Reset` keeps the values `AddValue` hid: the
values the command before read are dropped by `call.enter`
(`out.Printer.ForgetAdded`) before the call counts as running. From then
on another call's `vault.OnResolve` adds to it, and nothing drops that
value while the command runs.

By then the call is already running, and other calls' hooks read it
from their own goroutines (below). So what a hook reads changes only
under a lock: the caller is an atomic value (`cl.caller()`,
`cl.setCaller`), the session is made once and reset in place under its
own lock (`engine.Session.Reset`), and the printer's vault values are
set with `out.Printer.SetSecrets`, which drops the old ones and loads
the new ones on first use.

### The store: a preview and a look at an old copy

Two things the store did for "the command running now" are the call's
too.

**A dry run is a parameter.** Every change says how it goes:
`store.Update(w, fn)` and `store.UpdateRuntime(w, fn)` take a
`store.Write`, `store.Save()` or `store.Preview()`. `store.Write` is a
struct, not a bool, so a bare `true` or `false` does not compile. `Save`
and `Preview` are functions, not variables, so no code can set one to the
other (`store.Save = store.Preview` does not compile). The zero
`store.Write{}` names neither: a change with it stops (`Write.Check`).
With `Preview()`, `fn` runs on a copy that is never saved, as `--dry-run`
did before. The vault's
writes take it too (`vault.Set`, `Delete`, `DeleteMany`, `Copy`,
`Rename`, `RenameMany`, `ChangeKey`): a preview of one stops with
`store.ErrDryRun`, as before. In the cli every caller passes
`cl.storeWrite()`, which is `Preview()` under the call's `--dry-run`. A
parameter, and not a value in a `context.Context`, because there are
few callers (about 60) and all of them hold the call: a change that
does not say how it goes does not compile, where a missing context
value would quietly save a dry run's change. netx keeps a VPN
session's runtime record up to date (its last use, a dead session
gone). It does not hold the call, so it asks a hook with the context of
the connection, as `sshx.HostKeyPinned` does: `netx.WriteFor(ctx)` is
the call's `storeWrite()`, and for a context that carries no call it is
`store.Preview()`: nothing is written, and no other call's `--dry-run`
is read. So a dry run that uses a
VPN session writes nothing to `runtime.json`. It still stops an idle
session's process, as before; the next command finds it gone and drops
it from the record. `netx.ReapIdle` runs only outside a dry run and
saves.

**A look at an old copy belongs to the call.** doctor and a dry run may
open an old copy of the store to look at it (they change nothing; doctor
must say what is wrong). The call keeps that leave in `cl.oldCopy`: a
dry run sets it when its command starts, doctor while it looks
(`lookAtOldCopy(cl)`). The store opens the sealed store deep down
(`store.DB`), from reads that carry no call: `store.Load`, the vault,
the host keys of sshx, the audit log. So it asks a hook,
`store.OldCopyOK`, and the cli answers yes only while every running call
may look (`oldCopyAllowed`). One call's leave never opens the old copy
for a call beside it. The other way round, a dry run beside a plain call
on an old copy stops with `STORE_OLD_COPY` too: safe, not exact, and
only on a restored folder. Exact needs `store.DB` to take the call (a
`context.Context`) through every read, the same next step as the hooks
below.

The store keeps its open handles per home (`cachedDB`), in two sets.
`dbOpen` holds the ones every caller may use: a checked store, and one
opened unchecked because the keychain was slow or could not be read
(read only, opened and checked again once the keychain is asked again:
after a slow keychain's minute, or `recheckAfter`). `lookOpen` holds an
old copy opened to be looked at; only a caller that may look gets it. Any
other caller gets the store opened and checked again, and
`STORE_OLD_COPY`, with a handle of its own; it never closes the
look-only one.

A handle that is no longer handed out (its file was replaced, its key
changed, its check ran out, a person accepted the copy) may still be in
use by another call. It is never closed at once: `drop` stops its writes
(`sealdb.DB.StopWrites`, with `STORE_CONFLICT`), so nothing goes through
it into a file put aside, and it waits in `retired`. Each open sweeps
`retired` (`sweepRetired`): a handle retired at least `retireGrace` (10
seconds) ago with no step running is closed (`sealdb.DB.CloseIdle`). A
call that still holds it then gets `STORE_CONFLICT` ("run it again"),
never a raw `sql: database is closed`. So a process that runs for hours
(an app, `tunnel serve`, `vpn serve`) beside a keychain that stays slow
keeps one or two handles open, not one more per minute. `store.Close`
closes the rest when the process ends.

A look never changes the old copy: its handle has `sealdb.NoWrites`
set, and a write stops with `STORE_OLD_COPY` ("nothing was changed").
Each write would raise the old copy's change count, until it passed for
the newest. So a dry run on an old copy writes no audit record there,
and says so. `CopyState` and `AcceptOldCopy` (doctor, and a person's
`doctor --accept-old-copy`) look with an explicit parameter
(`openOldCopy`), not through the hook. Neither writes to the store:
accepting sets the keychain's count. After that, `AcceptOldCopy` stops
handing out the look-only handle (`forgetOldCopy`), so the next open
checks the store again, finds the newest copy and can write (the audit
record of the accept).

**A look never makes a store.** When `store.db` is missing, a read that
may look sees no store (or `STATE_CORRUPT`, when the folder shows it
had one). Only `createDB` makes a store (`sealdb.Create`; `sealdb.Open`
never makes a file, and tells SQLite not to). It always checks first,
under the store's lock, whoever asks (`missingGuardedStore`,
`missingStore`): a dry run's audit record never starts an empty store
over a missing one, which would drop every pinned host key, rule and
secret and set the keychain's count down. `store.db` removed between
`Peek` and `Open` goes back to those checks too; it never comes back as
an empty store that passes for "an older copy (change 1)".

The check makes a store when the keychain answers that it keeps no count
for this folder, or when there is no keychain on the computer at all (the
vault's `genGet` says so with `store.NoKeychain`: turned off, or no
keychain tool). When the keychain cannot say (slow, locked, broken), it
depends on who asks and on the folder:

- A person or a script (`store.AgentCaller`, which the vault sets from
  `vault.AgentCall`) in a folder with no trace of a store gets one. Its
  key stays out of the keychain (`KeySource` is asked for a key file), and
  `store.Notice` prints one note on the running calls' stderr: the key
  file alone guards it. This is a first run on a computer whose keychain
  does not work (a Linux server with `secret-tool` but no session, a Mac
  over SSH with its keychain locked, `sudo -E`, Mac CI). The store this
  process made is the newest copy, so it is not compared; its next opens
  are (below).
- An AI agent's call never gets one: `KEYCHAIN_SLOW` or `STORE_OLD_COPY`.
  Nil `store.AgentCaller` counts as an agent, and so does the vault's
  hook when `vault.AgentCall` is unset (`AgentCall == nil ||
  AgentCall()`).
- A folder with a trace of a store gets none, whoever asks. The traces
  (`storeTrace`) are `store.made`, `store.key`, `store.key.new`,
  `store.db-journal`, `runtime.pids` and a sealed `runtime.json`.
  `store.made` is the one every store leaves: a store whose key is in the
  keychain has no `store.key`, and with `store.db` gone its folder would
  hold only lock files. `createDB` writes it before it moves the new
  `store.db` into place (a crash in between leaves a store that is
  noticed when lost, not one that looks like none) and removes it only
  with a store it did not keep. `openDB` writes it for a store made
  before komando wrote it. `AcceptOldCopy` removes it when a person starts
  an empty store on purpose. A refused attempt never writes it. The lock
  files are not traces: komando makes `.store.lock` before it makes a
  store, so a refused attempt leaves one behind, in this run or an
  earlier one. The audit log is inside `store.db`.

The hint of such a stop first says to put `store.db` back from a backup;
a fresh start (a person's terminal, or `KOMANDO_KEYCHAIN=off`) is offered
only for a folder with no trace. A read beside such a keychain sees no
store, as reads go on beside a slow keychain.

**A key file store fails closed too.** A store whose key is in `store.key`
or a passphrase is compared when the keychain keeps a count for its
folder: then it is a backup from before `secret keychain`. When the
keychain cannot say whether it keeps one (`checkGeneration`: anything but
"no count" or `NoKeychain`), the store is opened read only
(`KEYCHAIN_FAILED`, or `KEYCHAIN_SLOW` when slow), or as a look for a
caller that may look. A write would raise its change count until it
passed for the newest copy. A person on a computer with no working
keychain sets `KOMANDO_KEYCHAIN=off`; an agent's `off` is ignored for the
count (`vault.countOff`). An agent's `KOMANDO_KEYCHAIN` path is ignored
for the key and the count alike (`vault.keychainFile`): pointed at a new,
empty keychain file, it would find no count and let an empty store start
over a guarded one, and a path used for one and not the other would split
a store's key from its count. An agent cannot redirect the keychain; a
store whose key is in a person's keychain file is not opened by an
agent's call (the key error says why).

How long a slow keychain is left alone is kept per home
(`slowUntil`), and a late answer marks the home that was asked, never
the one in use by then. So one test's slow stand-in keychain never
makes the next test's home slow. The probe that stops waiting
(`probeCount`) reads everything its goroutine uses before it starts it:
the home, and the read itself from `GenerationKeep.Ask` (the vault's
`genAsk` reads who asks, which keychain and tool, and the item's name).
The goroutine may run on for a few seconds after the probe gave up, and
reads no hook or setting a test puts back meanwhile.

**Known limits, not from this change.** These were there before, and
stay for a change of their own:

- `sealdb`'s `Close` closes the database without taking `d.mu`. At the
  end of a process a step still running on another goroutine may meet a
  closed database.
- A write after `store.db` was renamed over (a restore while a command
  runs) can stop with SQLite's raw `SQLITE_READONLY_DBMOVED`, not a
  komando error that says what happened.
- On Linux, `secret-tool` talks to the Secret Service at the agent's
  `DBUS_SESSION_BUS_ADDRESS`: an agent can point it at a bus of its own,
  which answers what the agent wants (no count, say).
- Keychain items made through `/usr/bin/security` carry no `-T` list, so
  any process of the same user can read the key or reset the change count
  through `security` too.

## What is still shared, and why

The packages under the cli keep some state of their own. A call cannot
reach it yet. Each item below is safe for two calls at once, or says what
is not.

1. **Hooks of sshx, vault and netx.** `sshx.MayPin`, `sshx.HostKeyPinned`,
   `sshx.ChainOwner`, `netx.StartSession` and `netx.WriteFor` get the
   context of the connection, which carries the call: they answer for
   that call. Every command's context carries its call (`newRoot` and
   `execute` put it there; each dial, tunnel, job, VPN session and the
   ssh gate's commands use the command's context). A context that
   carries no call is a bug, and these hooks never answer for another
   running call instead: `sshx.MayPin` refuses to pin a new server's key
   (the dial fails with an error that says so, and nothing goes into any
   call's output or audit log), `netx.StartSession` refuses to start a
   VPN, `netx.WriteFor` writes nothing, and `sshx.ChainOwner` gives a
   path that nobody shares. `vault.OnResolve`,
   `vault.RefGuard`, `vault.AgentCall`, `store.Notice`, `sshx.HostSecretEnv`,
   `sshx.PersonAtTerminal`, `sshx.Asker` and `netx.LockBusy` get no call.
   `call_hooks.go` sets them once and answers over every call running in the
   process (a call counts from the first step of its command to the end:
   `execute` calls `call.enter` before anything can open the store or the
   vault, and `call.leave` when it returns). This order matters: the store
   is opened once per process, and `vault.AgentCall` decides there whether
   an agent's `KOMANDO_KEYCHAIN` (`off`, or a keychain file) keeps the
   old-copy check, and whether a first store may start beside a keychain
   that cannot be read (`store.AgentCaller`). An agent's
   `--reveal` opens the store (is the approval code on?) before the
   command runs, so a call counted any later would open it as no
   agent's. What the hooks read of a call is safe to read while it runs
   (see "One answer covers one command"); `TestHooksReadRunningCallsSafely`
   checks it under `-race`, and `TestHostKeyPinNeedsItsCall`,
   `TestResolvedValueStaysHiddenFromEnter` and `TestChainOwnerIsTheCommand`
   check the three paths that once answered for the wrong call. A value
   read for one call is hidden
   in all of them; one agent among them makes a guard answer as for an
   agent; a person is asked at the terminal only while theirs is the only
   call. That is safe, not exact. `store.OldCopyOK` answers the same
   way ("The store", above). Next step: these packages take a
   `context.Context` that carries the call (`vault.Resolve` takes none
   yet; `sshx` would carry it on the `Client`).
2. **The process's terminal.** Raw mode (the fd of `os.Stdin`), the PTY
   questions and Ctrl-C use the process's terminal. Only a call with
   `Terminal: true` asks questions; an app's calls never do. The
   questions are drawn on the call's stderr. The width lines wrap at is
   the call's own (above); `out.UnicodeOK` (it reads `TERM` and `LANG`)
   still describes the process's terminal. sshx writes the "first
   connection" note to `os.Stderr`. Programs komando starts for itself
   (the approval window, the browser, a credential helper, background
   komando processes) get the process's environment. So do two programs
   a command starts: a kubeconfig's exec credential plugin
   (`internal/kube/kube.go`, `cmd.Env = os.Environ()`) and `openconnect`
   for a VPN (`internal/cli/vpn_session.go`, whose `Env` is nil, so it
   inherits the process's). Both should take the call's `cl.environ`.
   A call with `Terminal: true` must hand in a `Stderr` that is safe for
   writes from several goroutines: `netx.LockBusy` writes its notice
   ("another komando command is connecting vpn ...") to every running
   call's stderr from the goroutine of the call that waits.
3. **The data folder.** `store.Home()` and the vault read `KOMANDO_HOME`,
   `env:` references and the unlock variables from the process's
   environment. An app's calls share one data folder, so this is right
   for them; a call's own `KOMANDO_HOME` must match the process's.
4. **Set once per process.** `Version` (an `init`), `vtOK` (the Windows
   console, in `Execute`), the signal handler, and `store.Close` (in
   `Execute`; an app closes the store when it quits). `Execute` sets
   `call.signals`, and `execute` arms Ctrl-C only after the guided
   questions, as before: a Ctrl-C at a question, or at the preview it
   offers, stops only that. An app passes its own context to `RunCall`;
   one already done after the questions stops the command with "Stopped.
   Nothing was run."
5. **Paths through jump hosts.** sshx shares one login to the same jump
   hosts among the servers behind them (`openJumps`, a cache of the
   process), within one command. The cache key (`chainKey`) names the
   command that opened the path (`sshx.ChainOwner`, a number `call.enter`
   gives each command), the VPN, each jump host and the host-key check.
   So a path a person's command opened (after the person answered a
   login question, say) never serves an AI agent's command, or another
   command of the same person with other approvals, and a path dialed
   with `--host-key-policy off` is never handed to a command that checks
   keys. `TestChainServesOneOwner` checks it under `-race`.
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
- `TestAgentCallCountsBeforeTheStoreOpens` runs an agent's `list --reveal`
  through `RunCall` with only that call running and the real
  `vault.AgentCall`: the approval window and every read of the store's
  change count see an agent, and an old copy of the store stops with
  `STORE_OLD_COPY`.
- `TestHooksReadRunningCallsSafely` calls the hooks from one goroutine
  over and over while a person's calls and agents' calls run `version`,
  `list` and `secret list` (which open the store) through `RunCall`:
  under `-race`, nothing a hook reads is written without a lock. It
  fails if the hooks never ran while both kinds of call were running.
- `TestDryRunBesideARealChange`: a person's `host add --ask-password`
  has started and waits for its password while a dry run's `host add`
  runs from start to end; then the person's call saves its server and
  its password, and the dry run's server is not saved. Six more pairs
  run at once in no set order.
- `TestOldCopyLookStaysInItsCall`: on an old copy, a dry run alone may
  look and a plain call after it may not; a plain call beside a dry run
  that has opened the old copy and still runs stops with
  `STORE_OLD_COPY`; six more pairs run at once, and no plain call ever
  gets the old copy.
- `TestDryRunNeverMakesMissingStore` (cli) and
  `TestLookNeverMakesMissingStore` (store): with `store.db` gone and the
  keychain remembering its count, a dry run (its preview, its audit
  record) makes no store and leaves the count as it was; the next plain
  call stops with `STORE_OLD_COPY`. `TestMissingStoreKeychainCannotAnswer`:
  a slow, locked or broken keychain never lets an unknown caller make a
  store; one that says "no count", or none at all, does.
- `TestFirstStoreKeychainCannotBeRead` (store) and the vault's
  `TestNewStoreKeychainCannotAnswer`: beside a locked or hanging keychain,
  a person's first store is made in a key file with one note, and the
  next run only reads; an agent's call is refused, and so is a person's in
  a folder with `store.key`, `runtime.pids` or a sealed `runtime.json`
  left. A lock file or a plain `runtime.json` is no trace, and an agent's
  refused attempt leaves none: a person's first store is made after it.
  `TestKeychainStoreGoneKeychainCannotAnswer` (store and vault): a store
  whose key is in the keychain, `store.db` removed, and a keychain that is
  locked, slow or hangs: nobody's call (a person's, a script's, an
  agent's, or one with no hook) starts an empty store, as `store.made`
  is left. `TestStoreMadeWrittenOnOpen`: a store made before `store.made`
  gets it when opened.
- `TestKeyfileStoreKeychainCannotAnswer`: a key file store beside a locked
  or slow keychain is read, takes no write (a look neither), and is caught
  as an old copy once the keychain answers.
  `TestAgentKeychainPathKeepsCount` (vault): an agent's keychain file
  path does not hide the count. `TestAgentKeychainPathNotUsed`: a
  person's store in a keychain file keeps its key and count there, and an
  agent's call with the same path neither opens it nor writes anything;
  an agent's new store keeps both its key and its count in the default
  keychain, none in its path.
- `TestRetiredHandles` and `TestRetiredHandlesBounded`: a handle whose
  file was replaced takes no write (`STORE_CONFLICT`) but still reads; a
  busy one is kept, an idle one is closed once its grace is over, and a
  store opened again thirty times leaves at most one retired handle open.
  `TestStoreGoneBetweenPeekAndOpen`: `store.db` removed after `Peek`
  makes no store and gets the missing-store answer. sealdb's
  `TestOpenNeverCreates` and `TestStopWritesAndCloseIdle` check the
  lower half.
- `TestOldCopyHandleStaysOpenAndTakesNoWrites`: a plain call on an old
  copy never closes the handle a look uses, and no write reaches the old
  copy; after `AcceptOldCopy` the store takes writes again.
- `TestVpnDryRunKeepsRuntime`: a dry run that uses a running VPN session
  leaves its last use in `runtime.json` as it was; a plain run updates it.
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
  It is for every variable the caller is read from (the agent
  variables, `KOMANDO_ACTOR`, `USER`, `USERNAME`). `executeArgs` ends
  each command with `endCommand`: the global flags and the printer's
  settings are off again, so a test that calls komando's code with `tcl`
  and runs no command does not see an earlier test's `--dry-run`. A test
  that runs `newRoot(tcl)` itself registers `t.Cleanup(endCommand)`; one
  that only parses a line builds `newRoot(treeCall())`, whose flags are
  not `tcl`'s. A result's `TextFor` in a test that runs no command takes
  `realRun()`, a printer of its own. `go test -shuffle=on` finds a test that depends on the order.
