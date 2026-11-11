# Phase 0 review, part 2: engine session, sealed host keys, sealed audit log

Reviewed at d492ec0 (`feat/phase0-sealed-store`), read-only. This covers
what the first review (`docs/design/phase0-review.md`, findings H1-H4,
M1-M5) left out, and adds the stability checklist for the major release.
Docker e2e was not run.

"Confirmed" means a throwaway test in a temp copy showed it, or the code
leaves no doubt (said each time). "Unconfirmed" means read, not tested.

Sessions changing the branch in parallel, and what they touch here:

- **sealdb integrity (H1, H2, M2)**: fixes the root cause of S1 and A1, and
  M2 is the "cut-off end" that `audit verify` admits it cannot see.
- **file backend removal**: removes the plain branch of `eachAudit`
  (auditlog_sealed.go:39) and of `writeAudit`; makes S2 more important
  (a missing store.db must fail, not read as "no pins").
- **deprecated flags / OpenVPN os-mode removal**: no finding here depends on
  them; see the checklist (C5).

## Summary

| ID | Area | Severity | Status |
|----|------|----------|--------|
| S1 | A deleted pin row lets a new host key in on first use | High | Confirmed by reading (follows from H2) |
| S2 | A missing store.db reads as "no pins": any key is pinned | High | Confirmed by reading (follows from H3) |
| S3 | A pin line that does not parse counts as "no pin": new key accepted | Medium | Confirmed by test |
| S4 | `seal` drops @revoked lines: a revoked key is trusted again | Medium | Confirmed by reading |
| S5 | No time limit on the store inside the host key check | Low | Unconfirmed |
| A1 | An audit write that fails is silently ignored | Medium | Confirmed by reading |
| A2 | One bad audit record hides the whole log from `komando audit` | Medium | Confirmed by reading |
| A3 | `komando audit` opens every record, also for the last 50 | Low | Confirmed by reading |
| E1 | `sess` is a process global swapped by `newRoot()` | Low now, blocker for the apps | Confirmed by reading |
| E2 | The engine `Caller` is not what decides "agent" | Low | Confirmed by reading |
| E3 | "cancelled: nothing was changed" can be untrue | Low | Unconfirmed |

No way was found for an agent's approval to cover a second command in the
CLI today, or for a person's "no" to be turned into a yes.

## 1. Engine session (internal/engine, cli/approval.go, common.go, root.go)

What holds: `resetApproval()` runs in `newRoot()` and again in
`PersistentPreRunE` (root.go:355, :367), so answers never outlive one
command in a process. `personAllowsFor` (approval.go:88) holds the session
lock for the whole check and window, so parallel fan-out goroutines
(common.go:227) see one window and one answer. A "no" in the window sets
`asked=true, allowed=false`, and every later check in the command returns
that no, also one naming a new `what` (`!w.Allowed` short-circuits). A
second window for a new `what` resets `allowed` to false first, so an
earlier yes can only be lost, never widened. `SaidNo` only ever adds.

### E1. `sess` is a process global replaced by `newRoot()` (Low now; must change before the apps)

- Where: approval.go:51-53; root.go:355, :367; form_cmd.go:578 and
  sshgate.go:360 also call `newRoot()` inside a running process.
- Scenario: a guided form (form_cmd.go:578) builds a new root and runs a
  command in the same process. That replaces `sess`: answers the person
  gave earlier are lost (safe: they are asked again), and the outer
  `Execute` then reads `sess.PersonSaidNo()` (root.go:103) from the new
  session, so a "no" given in the inner command loses its "cancelled"
  wording. The pointer itself is written with no lock; any goroutine still
  running from the previous command would race on it.
  For the Mac/iPhone apps, which run many calls in one process, one global
  session means one agent's "Allow once" covers a person's call that runs
  at the same moment, and the other way round.
- Fix: pass `*engine.Session` down with the command (context value or a
  field on a per-call struct) and drop the global before any in-process
  multi-call use. Add a `-race` test that runs two calls at once with
  different answers.

### E2. The `Caller` in engine is not what decides (Low)

- Where: approval.go:45-47 (`isAgent` reads `os.LookupEnv` directly);
  `engine.CallerFrom` is used only for the actor name (common.go:651).
- Scenario: when the apps start building `Caller` values for their calls,
  every check still reads the process environment, so an agent call in an
  app that was started from a person's terminal is treated as a person.
- Fix: make `isAgent`/`agentName` read the call's `Caller`, set once per
  call from the environment in the CLI.

### E3. "cancelled: nothing was changed" can be untrue (Low, unconfirmed)

- Where: root.go:103-106, common.go:515 and :553.
- Scenario: a command writes something, then asks a person a second
  question (a protected target, a safety setting) and they say no. The
  error says "nothing was changed" though the first write stayed.
- Fix: say "cancelled" only; or keep "nothing was changed" only when no
  write step committed in this call (a flag the store sets on commit).

## 2. Sealed host keys (sshx/hostkeys_sealed.go, client.go:601)

What holds: the check is made twice, read then write, and the write step
checks again before pinning (no race between two first connections).
Two pin records for one address stop with `ErrTampered` (hostkeys_sealed.go:79).
A store that cannot be opened (locked keychain, wrong key) fails the
connection: it never falls back to "unknown". A key that differs from a
pin always returns `hostKeyChanged` (client.go:612-617).

### S1. A deleted pin row lets a new host key in on first use (High)

- Where: client.go:613-633 with sealdb H2 (rows can be removed unnoticed).
- Scenario: an agent deletes the `records` row of type pin for a server
  with plain sqlite. The next connection finds no pin, and with the
  default policy pins whatever key is offered: a man-in-the-middle is
  accepted with only the "pinned on first use" note.
- Fix: the H2 fix (a sealed index of ids bound to the change count) closes
  it. Until then, also keep in the host record (sealed with it) that a pin
  existed, and refuse first-use pinning for a host that had one.
- Affected by: the sealdb integrity session (H2). Add a test there:
  delete a pin row, connect, expect a stop.

### S2. A missing store.db reads as "no pins" (High)

- Where: hostkeys_sealed.go:33-34 (`ErrNoStore` → empty pins).
- Scenario: as H3, an agent moves store.db away. `view` sees no store,
  the callback reaches `update`, `store.DB(true)` creates a fresh store,
  and the new key is pinned there.
- Fix: once the home is known to be sealed (the H3 keychain item), a
  missing store is an error here, never "no pins".
- Affected by: file backend removal and the H3 fix.

### S3. A pin line that does not parse counts as no pin (Medium, confirmed by test)

- Where: hostkeys_sealed.go:107-111 (`continue` on a line that does not
  parse, so it is not added to `Want`).
- Test: a `sealedTx` with one pin `ssh-futuretype AAAAbad` for
  `h.example`; `Check` with any ed25519 key returned
  `knownhosts: key is unknown` with `len(Want)==0`. The callback then
  takes the first-use path and appends the offered key.
- Differs from knownhosts: it fails the whole file on a line it cannot
  parse, so it never accepts here. A pin can stop parsing after a
  downgrade to a komando built with an older x/crypto, or from a bad
  carried line.
- Fix: a pin record with any line that does not parse is a stop
  (`HOSTKEY_UNREADABLE`, hint: `komando host trust` by a person), not
  "unknown". `Pins` already counts raw lines; use that count.

### S4. `seal` drops @revoked lines, so a revoked key is trusted again (Medium)

- Where: cli/seal.go:183-205 (`marker != ""` → skipped) and the warning at
  :268 ("trusted again on their next connection").
- Scenario: a person marked a stolen host key `@revoked`. After `seal`,
  that line is gone; the next connection to that server with the revoked
  key pins it on first use. Hashed and wildcard names are the same: a
  first use after `seal` is a man-in-the-middle chance.
- Fix: carry @revoked keys as a "never" list in the pin record and refuse
  them in `Check`; for hashed/wildcard lines, set those hosts to
  `strict` until a person runs `host trust`, or refuse `seal` without a
  flag that says the person accepts it. The warning should say "pinned
  again without asking", not "trusted again".

### S5. No time limit on the store inside the host key check (Low, unconfirmed)

- Where: hostkeys_sealed.go:39, :47 (`context.Background()`).
- Scenario: another komando process holds the write lock (a long `seal`,
  a stuck process). The SSH handshake waits inside the callback for as
  long as the store's busy wait allows; a `-P 50` fan-out then waits per
  server. It fails closed (good), but the error may read as a network
  timeout.
- Fix: pass the dial context in, and on a busy store return a clear
  `STORE_BUSY` error with a hint.

## 3. Sealed audit log (cli/auditlog_sealed.go, inv_meta.go)

What holds: each record is sealed with its number; a gap, a moved record or
a wrong time column stops reading at that number (sealdb.go:695-705). Paging
by `seq > after` in short read steps is correct: records are only appended,
and a gap at a page edge is caught because `want` starts at `after+1`.
`FirstBroken = last+1` (auditlog_sealed.go:98) is right also when the break
is the first record of a page. The note honestly says a cut-off end is not
seen (that is M2).

### A1. An audit write that fails is silently ignored (Medium)

- Where: common.go:635 (`_ = appendAudit(rec)`); root.go:344 skips the
  "can the log be written" check on sealed homes.
- Scenario: the keychain locks, or the store is busy or was changed by H1,
  after a command ran. The change is made, nothing is written to the log,
  and nobody is told. On a plain home the pre-check catches most of this.
- Fix: on failure print a warning to stderr and add it to `meta.warnings`
  in JSON; on a sealed home, open the store for writing in the pre-check
  (as the plain branch opens the file), so a locked store stops the
  command before it acts.

### A2. One bad audit record hides the whole log from `komando audit` (Medium)

- Where: inv_meta.go:136-150 (any error from `eachAudit` returns; the
  records already read are thrown away). The plain branch skips a bad line
  instead.
- Scenario: one record sealed with an old key (H1), or one damaged page,
  and `komando audit` shows only an error. The person loses the log at the
  moment they need it most.
- Fix: print the records before the break and a warning naming the first
  broken number (`audit verify` for details). Exit code stays non-zero.

### A3. `komando audit` opens every record (Low)

- Where: inv_meta.go:136, auditlog_sealed.go:64-85.
- Scenario: a log of a few hundred thousand records: every `komando audit`
  (default last 50) decrypts all of them, in hundreds of read steps.
- Fix: when there are no filters, read the newest `limit` records with
  `seq > max-limit`; keep the full scan for `verify` and for filters.

## 4. Stability checklist for the major release

Each item: what has never been tested end to end, the smallest test that
would cover it, who can run it, and what to look for. "Person" means the
owner on their own Mac or a borrowed machine; nothing here needs a
developer at the keyboard except where said.

| # | Never tested end to end | Smallest test before release | Who | Look for |
|---|---|---|---|---|
| C1 | Full Docker e2e suite (never finished: Docker has 2 GB here) | Raise Docker Desktop memory to 6-8 GB and run `make e2e` once; or run it on a Linux CI runner (GitHub `ubuntu-latest` has 16 GB) | Docker lab on a bigger machine, or CI | Pass count against the last good run (901/0 on v0.8.0); any test that hangs; leftover containers |
| C2 | Real macOS keychain (only stand-ins in tests) | On a Mac: new home, `komando host add`, `secret set`, `komando list`; then lock the keychain (`security lock-keychain`) and run `komando list`; then unlock and run again | Person (owner's Mac) | First run asks once and is remembered; locked keychain gives a clear error, not `STORE_OLD_COPY`; after unlock everything works; H4: `security find-generic-password -s <service> -w` from a plain shell should ask, not print |
| C3 | Change count against an old copy, with the real keychain | Copy `store.db` away, run one changing command, copy the old file back, run `komando list` | Person | `STORE_OLD_COPY` with a hint; nothing written |
| C4 | Windows on a real machine (compile-checked only) | On a Windows 10/11 PC or VM: unzip the release, `komando --version`, add one host, `komando test`, an agent command with `--yes` (approval window), `secret set`/`get`, `job start` and close the terminal, `komando update` | Person with a Windows PC, plus a `windows-latest` CI job running `go test ./...` | Window appears and Deny really denies; Credential Manager item exists; job survives; update replaces the exe; no Unix path errors |
| C5 | Login for root OpenVPN after the FIFO login is removed | After the os-mode removal lands: connect to one real OpenVPN server with username/password and one with a TOTP code | Person with VPN access (the Telkomsel lab) | Connects; the password never appears in `ps`, files or logs; `vpn down` cleans up |
| C6 | `komando seal` on a real large folder | Copy the owner's real `~/.komando` to a test folder (`KOMANDO_HOME` set by the person, not an agent), run `komando seal`, then `komando list`, `audit verify`, connect to 3 hosts, then `seal --undo` and back | Person | Time taken; every host, secret, pin and audit record carried (counts in the result match); skipped known_hosts lines listed (S4); pins work without a "pinned on first use" note; undo restores |
| C7 | Rekey under load (H1) | Two terminals: one runs a loop of `komando list`, the other changes `secret passphrase` | Person, or a Go test once H1 is fixed | No `store was changed outside komando` afterwards; `audit verify` OK |
| C8 | Host key change on a real server | Regenerate a lab server's host key, connect | Docker lab (one container) or person | `HOSTKEY_MISMATCH`, never a silent pin; also with the pin row deleted (S1) once H2 is fixed |
| C9 | Upgrade from v0.8 home to this release | Install v0.8, make a home with hosts, pins, secrets and audit; install the new build; run `komando list`, connect, `audit` | Person or CI script | Clear message telling the person to run `seal` (or that it ran); no data lost; old binary refuses or warns on the sealed home |
| C10 | Linux keyring (`secret-tool`) and key-file mode on a headless server | On a Linux VM with and without a desktop session: new home, a few commands, reboot, again | CI (Linux runner, key-file mode) + person (desktop) | Headless picks the key file with a 0600 check; keyring locked case is a clear error |
| C11 | `go test -race ./...` and staticcheck on the final branch | Run both after all parallel sessions merge | CI | Zero races; staticcheck clean |

Release gate suggestion: C1, C2, C3, C6, C9 and C11 must pass; C4 must pass
or Windows ships marked "preview"; H1, H2, H3, S1, S2 fixed or the release
notes say plainly what an agent on the same account can still do.
