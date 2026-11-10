# Phase 0, step S6: the sealed store for fresh installs

Status: plan, 2026-11-10. Part of [sync-security.md](sync-security.md)
section 16. Nothing here changes an existing home: that is S9.

## What S6 does

A fresh home (no `state.json`, `vault.json`, `known_hosts`, `audit.jsonl`
or key files) keeps everything in one sealed SQLite file, `store.db`:
servers, conns, VPNs, keys, recipes, settings and deny rules, vault
entries, host key pins, the keys komando made, and the audit log. Runtime
data stays in `runtime.json` until S7. An existing home keeps its files,
byte for byte.

## Decisions

- **Backend choice.** `store.Sealed()` looks only at the home folder:
  `store.db` there means sealed; old files there mean files; an empty home
  means sealed. Both at once: sealed wins and `doctor` warns. A read on a
  fresh home makes no file and no key; the first write makes both, under
  `.store.lock`.
- **The store key.** The vault's three key modes give a 32-byte master
  key: the keychain item, a key file named `store.key` (never `vault.key`),
  or scrypt of the passphrase with a stored salt. `sealrow.NewKey` derives
  the row key from it with its own HKDF label. The vault hands the key to
  the store through a function the vault sets, which avoids an import
  cycle. A sealed check record makes a wrong key say so.
- **Passphrase homes** now need the passphrase for every command, reads
  included. Background processes already get it on stdin; the login
  holder's own `PASS` line moves to that helper first.
- **Records.** One sealed record per server, conn, VPN, key, recipe and
  secret, one for settings, one per pinned address, one per key komando
  made (its private and public parts), and the audit table. `store.Update`
  becomes one write step: read everything, run the change, check names,
  write only the records that changed, by ID.
- **References keep names** in S6, so both backends behave the same and
  the unchanged e2e suite can prove it. Moving them to IDs is mechanical
  afterwards: every record already has a stable ID.
- **Host key checks** in the sealed store must answer exactly as the
  known_hosts file does (host name and IP, ports, IPv6). A test runs the
  same cases against both.
- **`host ssh-command`** gives a person a temporary private known_hosts
  copy; a key sealed in the store stops with a hint to use `komando shell`.
- **Audit** rows are sealed and numbered; `audit verify` reports the first
  broken number; `audit --follow` reads new rows in short steps.
- **Agents see** one new error code in S6, `STORE_NEWER`. `STORE_OLD_COPY`
  and `STORE_MOVED` come with S8 and S9. Output keeps its shape, except a
  sealed key's `path` (`sealed:<id>`) and the meaning of `first_broken`.

## Commits, in order

0. Background processes all read the passphrase with `ReadPassStdin`.
   Found already true: `tunnel serve` and `vpn serve` read it before their
   first store read, and the login holder keeps its `PASS` line (its stdin
   also carries two-factor questions), which hands the passphrase to the
   same `ReadPassStdin`. No change needed.
1. `store`: backend choice, lazy `DB()`, the key seam; `sealdb` meta and
   key check.
2. `vault`: the store key in all three modes.
3. `store`: Load and Update on the sealed store, with a sweep for store,
   vault and pin calls made inside an Update (they now stop with
   `ErrNested`).
4. `vault`: entries sealed, and a key change that reseals everything.
5. `sshx`: sealed pins, with the side-by-side check test.
6. Keys komando made, sealed; `ssh-command` copies and refusal.
7. Audit sealed: write, list, verify, follow.
8. What people and agents see: `config show`, `doctor`, the guard, error
   codes, docs, CHANGELOG.
9. Turn it on for fresh homes, and run the whole e2e suite twice, on a
   sealed home and on a files home, plus a passphrase pass and a check
   that a fresh home holds no readable names.

Each commit is tested on its own; the switch stays off until commit 9.

## Risks to watch

- Store calls nested inside an Update worked or hung before; now they stop.
  Commit 3 needs the sweep.
- Many parallel connections pinning keys and writing audit rows share one
  write lock: measure a run against 50 servers.
- A check that disagrees with known_hosts would accept a changed key: the
  side-by-side test is required.
- `audit --follow` must not hold a read step between polls.
