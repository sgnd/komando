# Phase 0 review: feat/phase0-sealed-store against origin/main

Reviewed at d492ec0 (33 commits ahead of origin/main, 15 behind). Read-only:
no code was changed. `go test ./...` passes, and so do `go vet ./...` and
`GOOS=windows go vet ./...`. staticcheck is not installed and was not run.
Docker e2e was not run.

"Confirmed" means a throwaway test in a temp copy of the repo showed the
problem, or reading the code leaves no doubt (this is said each time).
"Unconfirmed" means it was found by reading the code and was not tested.
Line numbers are approximate where marked with ~.

Not covered: internal/engine/session.go, internal/sshx/hostkeys_sealed.go,
internal/cli/auditlog_sealed.go, and Windows ACLs. Nothing ran on a real
Windows machine.

## High

### H1. A process holding the old key writes audit rows the new key cannot open (confirmed by test)

- Where: internal/sealdb/rekey.go:16, sealdb.go:289 (`run`), `AppendAudit` (~651).
- Scenario: process B opened the store earlier and kept its key in the
  per-process DB cache. Process A changes the key (`secret passphrase`, or
  keychain to passphrase) and commits. B then writes an audit line, which
  almost every command does, sealed with the old key. From then on `Audit`
  fails with "store was changed outside komando". Every later `Rekey` fails
  too, because it opens every audit row, so the key can never be changed
  again. Record writes are safe only because `Put`/`Delete` open the sealed
  generation record; `AppendAudit` and `SetMeta` do not.
- Test: two `Open` handles on one file, `Rekey` on A, `AppendAudit` on B,
  reopen with the new key: `Audit(0,100)` returns the tampered error.
- Fix: in every write step, right after `BEGIN IMMEDIATE`, check that the
  key opens the keycheck row (or compare a key id in meta). On a mismatch,
  fail and drop the cached handle so the next open uses the new key.

### H2. An old record row can be written back without the change count noticing (confirmed by test)

- Where: internal/sealdb/sealdb.go:496 (`open`, AAD built from the row's
  readable `version` column), :606 (`write1`), generation.go.
- Scenario: an agent copies the raw `records` row for a host while it says
  `protected=false` (or holds an old pinned host key, policy or deny rule).
  After a person changes it, the agent writes the old row back with plain
  sqlite. `Get` opens it with no error and the generation does not change
  (3 before, 3 after in the test). Deleting a row the same way also goes
  unnoticed.
- Effect: an agent can undo "protected", `host_key_policy`, deny rules, or
  roll back a pinned host key.
- Fix: bind each record to the store's state. For example, keep a sealed
  index of (id, version) updated in the same transaction as the generation
  and checked on every read, or put the generation into each record's AAD
  with a sealed per-id version list.

### H3. Moving one file turns a sealed home back into a plain one (confirmed by reading)

- Where: internal/store/backend.go:39 (`Sealed()` only checks that
  store.db exists), internal/store/sealing.go:143 (`missingStore` only
  checks that state.json is the "moved" note).
- Scenario: an agent runs `mv ~/.komando/store.db x` and writes its own
  plain state.json with any hosts, policy and pins. komando runs in plain
  mode and never asks the keychain for the change count.
- Fix: once a home is sealed, record that outside the folder an agent can
  write (a "sealed" item in the keychain next to the change count). Refuse
  plain mode, and refuse to create a fresh store, while it exists. Only
  `seal --undo` by a person removes it.
- Note: the session removing the file backend may remove plain mode
  entirely, which closes most of this. A missing store.db must then fail
  loudly instead of starting an empty store.

### H4. Any process of the same user can read the keychain items and lower the change count (unconfirmed; a local hook blocked the test)

- Where: internal/vault/keychain.go:148 (`add-generic-password` through
  /usr/bin/security with no `-T`), :191.
- Scenario: the item trusts /usr/bin/security, so an agent shell can run
  `security find-generic-password -s <service> -w` and get the store key
  without a prompt, or `add-generic-password -U` to lower the change count
  and then put back an old store.db. On Windows, `CredRead` from any
  process of the same user does the same; on Linux, `secret-tool` on an
  unlocked collection does.
- Effect: an agent can read every secret and beat the old-copy check.
- Fix: on macOS create the items so that reading them asks the person (at
  least `-T ""`; better, the Security framework from a signed binary with
  access control). For Windows and Linux, say plainly in the docs and in
  `doctor` that the keychain does not separate programs of the same user.
- Should be checked by hand on a Mac before release.

## Medium

### M1. Another program can press "Allow once" (unconfirmed; Windows not tested)

- Where: internal/cli/approvalwin_windows.go (~110-125, `wndProc` acts on
  any `WM_COMMAND` with id 1); the macOS osascript dialog at
  internal/cli/approval.go:298 has a similar risk.
- Scenario: the agent starts a command with `--allow-dangerous`, then runs
  PowerShell `FindWindow` + `PostMessage(hwnd, WM_COMMAND, 1, 0)`. Windows
  does not block this between processes at the same level, so the command
  is approved with no person. On macOS, an agent whose terminal has
  Accessibility permission can click the button through System Events.
- Fix: on Windows, accept only a click whose `lParam` is the real Allow
  button and that came from real input. Better on every platform: show a
  short random code in the window that must be typed back into it.

### M2. Audit entries at the end can be removed unnoticed (confirmed by reading)

- Where: internal/sealdb/sealdb.go:676-706 (the read only checks that seq
  numbers have no gaps); audit writes do not raise the change count
  (generation.go:37).
- Scenario: `DELETE FROM audit WHERE seq>N; UPDATE sqlite_sequence SET
  seq=N WHERE name='audit'`. The log still looks complete and the agent's
  own actions are gone from `komando audit`.
- Fix: chain the entries (each entry's AAD includes the previous entry's
  tag) and keep the head, or the count, in a sealed record covered by the
  change count.

### M3. A keychain store can be locked out by its own change-count check (unconfirmed)

- Where: internal/vault/sealed_keys.go ~305-316 (`sealedKeyToKeychain`),
  internal/store/backend.go ~223-227 (new store).
- Scenario A: `secret keychain` commits `key_mode=keychain`, then
  `StartGeneration` fails (keychain locked, 5 s timeout, crash). Every
  command then stops with `STORE_OLD_COPY` on a store that is not old, and
  store.key is left on disk.
- Scenario B: on a new store the error from `GenerationKeeper.Set(n)` is
  ignored (`_ =`) and the check runs right after, so a failed write makes
  the new store refuse to open.
- Fix: write the change count before `key_mode=keychain` commits and fail
  the command if it cannot be written. Do not ignore the `Set` error.

### M4. `seal --undo` takes no locks and deletes the journal (unconfirmed)

- Where: internal/cli/seal_archive.go:207-277 (`unseal`),
  internal/store/move.go:47 (`RemoveStore`).
- Scenario: undo holds none of the locks `seal` takes. Another komando
  process can commit to store.db after undo has read it; that change stays
  only in the `.undone` copy. `RemoveStore` also deletes
  `store.db-journal` on its own: if another process is mid-write, its
  rollback journal is gone, and a hot journal from an earlier crash is
  thrown away instead of replayed.
- Fix: take the same locks as seal (`BeginSeal`/`EndSeal`) for the whole
  undo; open and close the DB once (which replays a hot journal) before
  renaming; move the journal with the store, never delete it alone.

### M5. Passphrase to key file gets stuck after a crash, and can lose the new key (unconfirmed)

- Where: internal/vault/sealed_keys.go:155-176.
- Scenario: store.key is created with `O_EXCL` before `Rekey`. A crash
  before commit leaves store.key next to a store still sealed with the
  passphrase, and every retry fails with "file exists". The other way: if
  COMMIT succeeded but an error is reported afterwards
  (sealdb.go:322-330), the error path deletes the only copy of the new key
  and the store cannot be opened.
- Fix: write `store.key.new`, rename it to store.key only after commit, and
  on start try a leftover `.new` against the store. Never delete the new
  key without checking that the old key still opens the store.

## Low

- L1. internal/store/generation.go:70: when the keychain is slow
  (`ErrKeychainSlow`) the old-copy check is skipped. An agent that keeps
  the keychain busy can skip it. Fail closed for writes. (Unconfirmed.)
- L2. internal/store/generation.go:96-106: raising the count is read then
  write, not atomic. Two processes can leave the keychain below the store;
  it is raised again later, so detection survives. Commits also never
  compare against the keychain, so a long-running process does not notice
  an old copy put back under it. (Unconfirmed.)
- L3. internal/cli/seal_archive.go:187: the old plain files are replaced by
  rename, so their blocks stay on disk until reused. Say so in the docs and
  suggest a disk-encryption check in `doctor`.
- L4. internal/cli/term_windows.go `waitInput`: `FlushConsoleInputBuffer`
  after an empty peek can drop a key pressed in between. Read and discard
  only the records that were peeked. (Unconfirmed.)
- L5. internal/netx/proc_windows.go `Terminate` uses `TerminateProcess`, so
  VPN and job helpers get no chance to clean up routes or socket files on
  Windows. Clean up from the caller after exit, or give the helper a stop
  event. (Confirmed by reading; documented in the comment.)
- L6. internal/vault/credman_windows.go:48: the error says "(advapi32
  CredReadW)". Plain words: "the Windows Credential Manager is not
  available on this computer".
- L7. internal/cli/platform_windows.go:53 sends `os.Interrupt` to mean
  "window size changed". Use a value that cannot be read as Ctrl+C.

## Checked and fine

- Unix behaviour after the Windows work: flock still blocks on the same file
  and is released at the same point; umask, SIGWINCH, `Setsid`, raw mode,
  EINTR handling, process checks and the self-update rename are unchanged.
  The zip path only runs for data that starts with `PK\x03\x04`.
- internal/codesize passes (100 lines per function, 800 per file). The
  largest new file is internal/sealdb/sealdb.go at 709 lines.
- Comments in the new Windows files are short and specific.

## Effect of the parallel changes

- Removing the file backend: removes most of H3 (no plain mode to fall back
  to), as long as a missing store.db then fails instead of creating an empty
  store. It also removes the plain branches of `seal`, but not M4, which is
  about the sealed store being moved aside. The other findings stay.
- Removing deprecated flags: none of these findings depend on them.

## Suggested order

H1 and M4 can lose data in normal use; fix them first. Then H3 and H2 (an
agent can undo protection), M3 (lock-out), M5. H4 and M1 need platform
work and could be written down as known limits for this release if they
cannot be fixed now.
