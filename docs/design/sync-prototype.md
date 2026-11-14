# Sync crypto prototype (phase 1)

Date: 2026-11-14. Code: [`sync/`](../../sync), branch `proto/sync-crypto`.
Status: **prototype**. The code is its own public Go module,
`github.com/sgnd/komando/sync` (package `komandosync`). The komando CLI
never imports it, so the CLI binary does not contain it. It has no network
and no command. The CLI never syncs.

The question from the paid plan (`komando-notes/paid/phases.md`, phase 1):
**"Does the design in spec.md section 6 work as written?"** Spec section 6
says that sections 6 to 9 of `sync-security.md` (called **SS** here) stand
as written. So this prototype builds SS 6 to 9 and spec 5.2 to 5.4, runs
them end to end against a server that lies, and lists every place where
the text could not be built as written.

## The answer

**Go. Nothing is open; the format can be frozen.** Everything up to
finding 55 is decided by the owner (2026-11-14), written into SS 6.2,
7.2, 8.1 and 9, built here and tested. A review of those decisions found
five faults in the code and five places where SS or this document was
behind (findings 57 to 66). The code faults are fixed, each with a test
that fails without its fix. What follows directly from a decided rule is
written into SS. The last three points were settled on 2026-11-14 (SS
21 is empty):

- **Finding 61, two newcomers take one free name at once:** decided by
  the owner: both are shown as "waiting: name taken" and neither is found
  by name until a person picks one. Built and tested.
- **Finding 57, the list of applied name changes:** decided by the owner:
  it is pruned at every snapshot every current device named. Built and
  tested. Format change: a snapshot names the snapshot it builds on
  (`Base`).
- **Finding 56, Go 1.26:** run. Under Go 1.26.0 `go vet` passes, `go test
  -race` passes, and the vectors check out in Swift.

The core holds. Two and three devices sync end to end. The server never
holds a plaintext or a key. Every attack of a lying server is caught: it
drops, reorders, replays, rolls back, forks and swaps, and each ends in a
named error, never in silently changed data. Removed devices cannot read
later writes, and only their writes that a remaining device confirmed
count; past the recorded last write, only what applies by itself. Every
recovery-key step waits 24 hours while another device is listed, and a
live device can cancel it. History no longer grows without end: a signed
snapshot that every device confirmed lets the older writes go, and a new
device starts from it. Everything is in Go's standard library, from Go
1.26 on: X-Wing is in `crypto/hpke`, so there is no gap there.

What the freeze re-test built, one test or more each (`freeze_test.go`
unless named):

- **Finding 35, which writes of a removed device count:** past the floor
  only what applies by itself is kept; its approvals and waiting changes
  are dropped on every device and shown; a summary counts only while its
  signer is listed; a summary log whose list entry goes down is refused
  (`TestHeldSummaryCannotBringInAnApproval`,
  `TestRemovedSignerSummaryDoesNotCount`, `TestBackdatedSummaryIsRefused`,
  and `TestKeptAgainIsShown` for finding 36).
- **Finding 32, never take back:** a device that applied a stricter value
  from past the cut writes it again as its own write; an approval past
  the cut is dropped and shown (`TestRemovalNeverTakesBackAStricterValue`,
  `TestApprovalPastTheCutIsDropped`).
- **Finding 33, sealing again:** the per-write "sealed again" write is
  gone from the format; old writes are sealed under the newest key only
  in a snapshot; the alert on old-key writes stays
  (`TestWriteUnderASupersededKey`).
- **Finding 9, snapshots:** made, judged, refused when they differ,
  confirmed, pruned, and a new device starts from one (`TestSnapshots`).
- **Finding 16, the stricter-values table:** `protected` on, `approval`
  required, "never use AI here" on, and a new deny rule apply by
  themselves; everything else waits (`TestStricterValuesTable`).
- **Finding 17, the old holder of a name:** approving the newcomer deletes
  the old holder in the same signed yes, shown as "replaces prod-db
  (deleted)" (`TestApprovingANewcomerDeletesTheOldHolder`).
- **Finding 19, lowest Go version:** `go.mod` names Go 1.26.0
  (`TestLowestGoVersion`).
- **Finding 31:** text only (SS 6.2); nothing to build.

Each of these tests fails on the code without its rule (checked by
undoing each rule in a copy: 15 undone rules, 15 failing tests). The
rules of findings 40 and 43 had no test then; finding 60 adds three.

### How it got here

A review on 2026-11-14 found that the first version of this prototype, and
the text it was built from, let the waits and the "a person agreed" rule
(SS 8.1) be skipped (findings 22 to 30). The owner then decided the four
design choices that were left open (2026-11-14), and SS now has them:

- **Finding 22, kit steps:** anything the recovery key signs waits 24
  hours while another device is listed, and any listed authority key can
  cancel it. A recovery step on a listed device needs that device's own
  sync key. The kit alone gets only the takeover.
- **Finding 25, writes under a replaced key:** refresh the list before
  sealing a secret and ask when it cannot; accept such writes with an
  alert; the writer seals them again once it catches up (later replaced
  by finding 33: only a snapshot seals again).
- **Finding 26, which writes of a removed device count:** those up to the
  newest write a remaining device covered in a signed summary from before
  the removal. A stricter value is never taken back. Anything dropped is
  shown to a person (later narrowed by findings 32 and 35).
- **Finding 18, pairing code:** 27 characters, the last one a check.

The prototype now follows all four, each with a test. It also follows
"time only delays, never refuses" (SS 6.2) for the 7-day rule: a device
that sees a young device act on an older one too early holds the list
instead of refusing it (finding 2).

All ten points of the first must-change list are now in SS, and the code
follows them:

1. Replacing a recovery kit starts a new account key (finding 1).
2. The device list has "pending", "apply" and "cancel" entries. The apply
   carries the new key. Only a listed authority key cancels, never a kit.
   A device whose clock says "too early" holds the list and keeps syncing
   up to the hold (findings 2, 3, 24, 27 and 28).
3. SS says what the 24-hour wait protects and what it does not (findings
   4 and 5).
4. A takeover's apply names the final last writes. A removal makes every
   device merge again without the dropped writes (findings 6 and 7), and
   which writes count is set by signed summaries (finding 26).
5. Records are not re-encrypted at a removal; snapshots are still to be
   designed (findings 8 and 9).
6. A new authority key needs the device's own request, signed by its sync
   key and by the new key (finding 23).
7. Kit steps wait 24 hours (finding 22).
8. A record's type is fixed in its ID when it is made. A device record is
   written only by its own device (finding 29).
9. Writes sealed under a replaced key (finding 25).
10. The pairing reply uses a fresh key per answer and names the request it
    answers; each device answers a code once (finding 30).

Findings 31 to 38 came after that, from building the updated SS and from
a third review. They are decided as well and built (above).

## What was built

| Part | File | What it does |
|---|---|---|
| Device keys | `keys.go` | `Signer` (P-256, the Secure Enclave's shape: it signs a message and returns DER) for the sync key and the authority key; `Unwrapper` (X-Wing) for the unwrap key. `SoftSigner` is the software stand-in; its `Presence` hook stands in for Face ID |
| Signatures | `keys.go` | ECDSA P-256 in one fixed form: r and s as 32 bytes each, s in the lower half. The Secure Enclave returns DER with either s; it is turned into this form, and any other form is refused. Every signed message starts with a purpose label |
| Record sealing | `seal.go` | AES-256-GCM under a key used once, with a key commitment tag; Padmé padding |
| Key transport | `keys.go`, `keyring.go` | HPKE with X-Wing (`crypto/hpke.MLKEM768X25519`, KEM ID 0x647a), HKDF-SHA256, AES-256-GCM. The `info` value binds account, generation and receiver |
| Device list | `list.go`, `listcheck.go` | The signed hash chain, checked from entry 1 by every device. Account ID = hash of entry 1 |
| Writes and summaries | `write.go`, `sync.go` | Each write is sealed, signed by the sync key, numbered and chained to the device's previous write, and names the newest list entry. Each sync ends with a signed summary |
| Merging | `merge.go` | Field by field, newest hybrid clock wins; deletion is final; the stricter-values table; changes that wait apply only with a signed yes, which also deletes the old holder of a name it takes; two agreed records of one type that hold one name are both shown as "waiting: name taken" and are not found by name until a person picks one (`NameClashes`, `Find`, `KeepName`) |
| Pairing | `pair.go` | QR or 27 characters (26 for the one-time 128-bit secret, 1 check), 10 minutes, one try |
| Recovery kit | `kit.go`, `shamir.go`, `recover.go`, `admin.go` | 256-bit key as 56 letters with a check, typed back before sync starts, up to 3 kits, 2-of-3 paper (own Shamir over GF(256)), recovery on a new device, recovery step on a listed device, kit replacement and an authority key signed in with the kit: each waits 24 hours while another device is listed |
| Removed devices | `removal.go` | Which writes of a removed device count: floor, cut from summaries of listed devices, only what applies by itself between them; merging again without the rest; stricter values written again; a list of dropped writes for the person |
| Snapshots | `snapshot.go`, `state.go` | A signed, sealed copy of the merged state at a set of writes, naming the snapshot it builds on; judged by every device on that base, confirmed when every current device names it in a summary, then the older writes go and the list of applied name changes is pruned; a new device starts from it |
| Hostile server | `server.go` | Stores blobs and logs. Read hooks let a test drop, reorder, replay, roll back, fork per device and swap anything. Write hooks let it drop a store or a delete while saying it was done |

### The constructions chosen

**Record key and commitment.** SS 7.2 says "HKDF-SHA256(vault key, 32
random bytes, record context) gives a fresh key and a commitment tag". The
prototype makes that exact:

```
okm    = HKDF-SHA256(secret = vault key, salt = 32 random bytes,
                     info = label || SHA-256(bound header), length 64)
key    = okm[0:32]    AES-256-GCM key, used for this one write
commit = okm[32:64]   stored in the clear, checked before opening
nonce  = 12 zero bytes (safe: the key is never used twice)
```

Why: AES-GCM alone is not key-committing (one ciphertext can open under
two keys). Deriving the key and the tag together and checking the tag
first is the "CommitKey" fix of Albertini, Duong, Gueron, Kölbl, Luykx and
Schmieg (USENIX Security 2022). Fooling it needs an HMAC-SHA256 collision.
The header goes into `info`, so the tag also commits to the record's place.
It costs one HKDF call and 32 bytes, and needs nothing outside the
standard library.

**Kit keys.** The kit is 256 bits and nothing else. Its P-256 signing key
is HKDF output tried as a scalar (counter on the rare miss). Its X-Wing
sealing key is `DeriveKeyPair(HKDF(kit, label))`. Both public halves sit in
the list.

**Account sealing key.** Derived from the account key with
`DeriveKeyPair`, so no separate sealed copy is needed (SS 7.1 says it is
stored sealed under the account key; deriving it is the same and simpler).
It is only used by teams, which this prototype does not build.

**Letters.** Crockford's base32 (no I, L, O, U; O reads as 0, I and L as
1). A kit is key plus a 3-byte check: 56 characters in 14 groups of four.
A typo is caught by the check (tested at every position). A paper part is its
number, a 2-byte kit ID, its 32-byte share and a 2-byte check: 60
characters in 15 groups. The kit ID keeps parts of an old kit out: any two
parts of one kit give it back, and the result is checked against the ID.
The person types two groups back before sync starts.

**Pairing.** The new device seals its keys and name under a key derived
from the secret. The AEAD tag is the check code. The reply comes back
under a key from the secret, 32 fresh random bytes sent with it, and the
hash of the request it answers.

The code is the secret in 26 Crockford base32 characters and one check
character:

```
check = (1·v0 + 3·v1 + 5·v2 + ... + 51·v25) mod 32
```

where `vi` is the value of character i. Each weight is odd, so it has an
inverse mod 32, and changing any one character, the check included,
always changes the sum. So every one-character typo is caught on the
existing device before it reads anything from the server or uses the try
(`TestPairingTypoCaughtBeforeTheTry`). Most swaps of two neighbours are
caught too; the rest show as a check-code mismatch, which does not use
the try either.

**Which writes of a removed device count.** Each removed device has a
floor and a cut. The floor is the last write the removal records (or the
newest write of it that a confirmed snapshot holds, if later). The cut is
the newest write of it that a device **still listed** covered in a signed
summary naming a list entry from before the removal. Up to the floor,
every write stays. Between floor and cut, only what applies by itself
stays: a note, a description, a stricter value, a new deny rule; the
removed device's approvals and waiting changes are dropped on every
device and listed in `DroppedWrites`. Past the cut, everything is dropped
and listed. This rule reads only the list and the change, so every device
does the same. A device that had applied a stricter value from past the
cut writes it again as its own write (`Report.Rewritten`), but only when
that write was still the one in force on it (finding 54). A deny rule is
written again under one ID bound to the dropped write, so every device
writes the same rule (finding 52).

A cut that a listed device's summary set stays when the server later
hides that summary. Once that device is removed too, the cut is found
again without it, so every device agrees whatever it saw before; a device
that applied more merges again. Each summary names the hash of its
signer's summary before it. A device refuses a summary log whose list
entry goes down as the summary number goes up, also against the summary
of that signer it holds (`ErrRollback`), and two summaries with one
number or a broken chain (`ErrFork`). An old summary counts toward a cut
only when its chain up to the one the device holds is served (findings
47 and 48). A summary
signed after the removal that covers more than the cut means the server
holds back the summary that shows it: `ErrMissingWrites`.

**Snapshots.** A snapshot names the list entry, the key generation in
force there, the writes it holds (one head per device, as a summary) and
the hash of the state's one byte form. The state is sealed with the
record seal, bound to that header, under the vault key of that
generation: the newest the signer had, so it is the one place old records
are sealed again under the newest key. The signer's sync key signs header
and sealed body.

```
state  = records by ID (type, agreed, deleted, fields by name with value
         and clock; a deleted record keeps only its name), waiting changes
         by write, approvals whose change is not among the writes yet
header = format, suite, account, signer, number, list entry and its hash,
         key generation, heads, SHA-256 label hash of state
body   = record seal of state, place = header
```

While a removal of a device waits, and for a snapshot naming a list
entry from before a device's removal, a snapshot holds nothing of that
device past the write the removal records (finding 45). Another device
takes a snapshot only when it keeps to that and its own merged state at
those writes has the same hash; otherwise it refuses it
(`Report.Refused` and an alert) and keeps the writes. Each summary names the newest snapshot its
signer accepted and the one it builds on. When every current device names
one snapshot, each device builds on it: its state becomes the base, the
writes it holds leave the device's log, and the service may drop them
(`SnapshotToPrune`, `MemServer.PruneWrites`). A new device takes the
snapshot every other current device names (or else the one they all
build on), checks its state against the signed hash, and reads only the
writes after it. It does so only when each of those summaries names a
list entry at or after the newest one about a removal, and the snapshot
keeps to the caps above; otherwise it reads from write 1 (finding 46).

**Deny rule IDs.** A new deny rule applies by itself, its edit or delete
waits. "New" needs an identity no other write can claim: a deny rule's ID
is `recordID("deny", first 12 bytes of H(label, writer, write number))`,
so only the write that makes it can create it. A second "create" of that
ID from any other write is refused like a wrong type. The one other
"create" allowed is a deny rule written again from past a removed
device's cut: its write names the dropped write (`Change.Target`), and
its ID is `recordID("deny", first 12 bytes of H(label, dropped write,
fields))`, so every device that writes it again writes the same rule
(finding 52).

**Approvals.** The authority key signs the change it agrees to and the
sorted IDs of the old holders of the name it takes. Applying the yes
applies the change and deletes those holders in the same step.

**Hashes.** Every labelled hash puts each part's length in front of it, so
two lists of parts never hash the same way.

**Record IDs.** 12 random bytes and a 4-byte tag of the record type. A
write that names another type for an ID is refused by every device.

## What the tests show

`cd sync && go test -race ./...`: 132 tests and subtests pass, 0
fail (94 top-level tests); statement coverage 87.9%. The same run passes
under Go 1.27.3 (the default toolchain here) and under Go 1.26.0
(`GOTOOLCHAIN=go1.26.0`, finding 56), and earlier runs passed under Go
1.27.4. All table-driven where there is a table.

| Hostile server does this | The device reports |
|---|---|
| Drops a write in the middle | `ErrMissingWrites` |
| Drops the newest write (hides a record) | `ErrMissingWrites` |
| Hides a deletion marker | `ErrMissingWrites` |
| Reorders writes | `ErrMissingWrites` |
| Moves a write into another device's log | `ErrBadWrite` |
| Serves a second, different write with the same number (a stolen sync key) | `ErrFork` |
| Forges a write with its own key | `ErrBadSignature` |
| Flips one bit of a sealed body | `ErrBadSignature` |
| Rolls the whole server back | `ErrRollback` |
| Rolls the list back (undoes a removal) | `ErrRollback` |
| Hides a removal from one device (fork) | `ErrListBehind` |
| Shows another account's list | `ErrAccountMismatch` |
| Adds a list entry signed by a key not on the list | `ErrNotAuthorized` |
| Changes a list entry, keeps its signatures | `ErrNotAuthorized` |
| Replays or reorders list entries | `ErrChainBroken` |
| Passes off one device's summary as another's, or raises its number | `ErrBadSignature` |
| Hands over another device's sealed key | `ErrNoKey` |
| Hands over a key it made itself | `ErrKeyMismatch` |
| Replays writes inside one answer | ignored and counted (`Report.Duplicates`); state unchanged |
| Holds back every write and summary of one device | not visible alone (as SS 9 says); caught by comparing summaries side by side (`ErrMissingWrites`), and sync stays stopped until fixed |
| Swaps the pairing request or makes up the reply | `ErrCheckCode` |
| Enrols a new device into an account it made up | `ErrAccountMismatch` |
| Hides a waiting takeover until it is applied | the live device holds the list for its own 24 hours and shows it (finding 4) |
| Answers one pairing code from two devices (a forked list, a delete it ignores) | two replies under different keys; the same device answers once (`ErrPairingUsed`) |
| Serves a device that missed a wait the apply at once | `Report.Hold` and an alert; sync goes on up to the hold (finding 27) |
| Shows a device a young device's direct removal of an older one | `Report.Hold` until 7 days after the young device was listed, on this device's clock; never a refusal (finding 2) |
| Hides a remaining device's summary from before a removal | `ErrMissingWrites`, from that device's summary after the removal |
| Keeps a device on the list from before a removal | its writes are accepted with an alert (`Report.OldKey`); they are sealed under the newest key in the next snapshot |
| Holds a device back so its summary covers a removed device's late approval | the approval and the change it agrees to are dropped on every device and shown (`DroppedWrites`) |
| Serves a snapshot that differs from the merged state | refused (`Report.Refused`, an alert); the writes are kept |
| Does not answer when a device reads the list before sealing a secret | `ErrListUnchecked`, unless the person says "save anyway" |

| A listed or captured key tries this | The devices report |
|---|---|
| A device without Touch ID relabels a server as a note | change dropped (`Report.Rejected`) on every device, old and new |
| Another device deletes or renames a device's name record | change dropped |
| A device added today swaps an older device's authority key | `ErrNotAuthorized` (no request from that device) or `ErrYoungDevice` |
| The kit alone signs in a new authority key | `ErrNotAuthorized` |
| The kit alone, on a device that is not listed, uses the recovery step | `ErrNotAuthorized` |
| The kit and a listed device replace the kits, remove a device or sign in a key at once while another device is listed | `ErrNotAuthorized`; only as a 24-hour pending change |
| The kit cancels a lost-kit replacement | `ErrNotAuthorized` |
| A write sealed under another key generation than its list entry has | `ErrBadWrite` |
| A stolen sync key backdates a summary to before a removal | `ErrRollback` (the summary log, or the summary this device holds, names a later list entry), even when the server hides the newer summary |
| A stolen sync key signs a summary with the number of an old one | `ErrFork` (two summaries with one number, or one that does not follow the one before it); with the rest of the chain hidden, it does not count toward a cut |
| A stolen sync key of a removed device signs a summary that covers a removed device's writes | ignored: only summaries of listed devices count |
| A device makes a second "create" of an existing deny rule's ID | change dropped (`Report.Rejected`) |
| An approval whose list of old holders was changed | approval dropped (`Report.Rejected`) |
| A one-character typo in the pairing code | `ErrPairingTypo`, before the server is asked and before the try is used |

After every failed check the device's data is unchanged. A whole account
life (three devices, secrets, approvals, a removal) leaves no plaintext,
no name and no key in anything the server holds (`TestServerNeverSeesPlaintextOrKeys`).

Also tested: changes that wait (address, secret, command, rename, looser
rule, new record, delete) apply only after an authority key's yes; notes,
descriptions and stricter rules apply at once; approvals signed by a sync
key, by a device without Touch ID or by an authority key not yet signed in
are dropped; the kit must be typed back before sync starts; a Mac without
Touch ID cannot turn sync on, add or remove devices; a removed device
cannot open the new key or new writes; of its writes that a remaining
device confirmed before the removal, those that apply by themselves are
kept, the rest dropped and shown to the person, and a stricter value it
set is written again by a device that applied it; a device
that joins after two key changes still reads generation-1 records; the
7-day rule with its cancellable "remove later" and "sign in later"; Face
ID changes; every kit step waiting 24 hours, applied after the wait or
cancelled by a device with an authority key, which then asks for new
kits; all recovery paths; the 2-of-3 paper kit, also with a part of
another kit; merging the same writes in either order gives the same
state.

**Vectors.** `testdata/vectors.json` (record sealing, Padmé, key IDs, kit
letters and derived keys, paper parts, HPKE X-Wing, the fixed signature
form, a list entry's bytes and hash, the pairing code, a snapshot (its header
with `Base`), a deny rule's ID, an approval's signed bytes, and the frozen layouts: a summary
with `Prev`, `Snap` and `Base`, a write's header, signed bytes and hash,
a change body with `Target`, a deny rule written again and its ID, and a
snapshot state with a deleted record, a waiting change, approvals and an
applied change that set a name) is computed by the
prototype and only pins regressions. Two outside checks stand behind it:

- `testdata/crosscheck.swift` recomputes every value in it with Apple
  CryptoKit, a separate implementation: HKDF and AES-256-GCM for record
  sealing, X-Wing keys from their seeds, HPKE with exactly this suite
  (X-Wing, HKDF-SHA256, AES-256-GCM), P-256 keys and signatures, Shamir
  over GF(256) and the letters, and the snapshot's state hash, seal and
  hash, a deny rule's ID and the bytes an approval signs. It builds each
  layout from its fields, never from given bytes: the summary, the write
  (header, seal, signed bytes, hash), the change body, the deny rule
  written again, the snapshot header (with `Base` after `KeyGen`) and
  the snapshot state, sorting and filtering as the
  format says. It prints 42 checks, all ok (macOS 27, Swift 6.4.2); the snapshot
  header check replaced the one that only compared the header's end.
- `external_test.go` checks the building blocks against published
  vectors: RFC 5869 cases 1 and 3 for HKDF, and the draft-ietf-hpke-pq
  vector for X-Wing (`DeriveKeyPair`, decapsulation, the HKDF-SHA256 key
  schedule; that vector uses ChaCha20-Poly1305, since no published vector
  has X-Wing with AES-256-GCM). GF(256) is checked against FIPS-197 in
  `crypto_test.go`.

## Findings: where the text is wrong, ambiguous or unbuildable

Each finding says what SS says, what goes wrong, what the prototype does,
and what to change. **Wrong** means the text as written is insecure or
cannot work. **Gap** means two careful builders would make incompatible
choices. **Clarify** means one sentence is enough.

### 1. Wrong: replacing a kit does not end the old kit

SS 6.4: "Replacing the kit needs the current recovery key." SS 7.1 seals
the account key to the kit. Nothing says a kit replacement starts a new
account key. But the old kit's sealed copy of the current account key
stays on the server (a hostile server keeps it even if asked to delete
it). So a replaced, lost or stolen kit still opens everything written
until the next device removal. The prototype makes every kit replacement
(and every lost-kit replacement) start the next key generation, and tests
that the current key is never sealed to a replaced kit. **Change SS 6.4:
replacing kits makes a new account key, like removing a device.**

### 2. Wrong: waits on each device's own clock make devices disagree

SS 6.2: "A device added less than 7 days ago cannot remove older devices",
with each device counting "from the moment it first received the entry
itself". A device that was offline sees "D was added" and "D removed B" at
the same moment. On its clock D is 0 days old, so it refuses an entry
every online device accepted. It stops syncing on a valid chain (the
first version did this). A rule judged on local clocks can only *delay*,
never *refuse*, or devices split.

The prototype: entries before a device joined are vouched for by the
device that paired it, so a new device does not trip on old history.
**Change: make every timed rule a waiting change (finding 3). A device
whose clock says "too early" holds the list at that entry and shows why;
it never refuses on time alone. Drop "cannot" for the 7-day rule: a young
device's removal of an older one is a waiting change any older device can
cancel.**

**Now in SS 6.2 and built.** A young device asks with `RemoveLater` or
`SignInAuthorityLater`. A direct entry that a device's own clock finds too
early holds the list until 7 days after it first saw the young device
listed (`TestOfflineDeviceHoldsAValidRemoval`). See finding 31 for what
the hold cannot do.

### 3. Gap: "waits" and "any device can cancel" need list entries SS does not have

SS uses waits in three places (24-hour kit add, 7-day lost kit, 7-day
rule) and says "any device can cancel". A linear signed chain cannot undo
an entry. The list needs three more actions, which the prototype adds:

- **pending**: holds the change, signed as that change would be, but no
  new key;
- **apply**: by the device that asked, after the wait on its own clock;
  it carries the new key, made then (finding 28);
- **cancel**: by any listed authority key. Never by a kit: a stolen kit
  would block the lost-kit replacement that ends it (finding 24).

Order in the chain decides: a cancel before the apply wins. Each device
holds an apply until its own clock has counted the full wait from when it
first saw the pending entry. Time only delays; the outcome is the same on
every device. **Add these actions to the SS 6.2 list format.**

### 4. Wrong as a promise: the 24-hour wait does not hold against a server that has the kit

SS 4 and 6.4: the wait "stops a captured recovery key from quietly adding
a device". Two limits:

- **It does not protect reading.** The kit opens its sealed copy of the
  account key at once. A thief with the kit and the server's blobs reads
  everything before any wait starts (tested: the recovering device reads
  at once).
- **A server that also has the kit can hide the pending entry** from the
  live devices until it is applied. They then see both at once. The
  prototype holds the list for 24 hours on their clock and shows the
  alert (`TestHiddenRecoveryWaitIsHeld`), but there is no entry left to
  cancel with: after the hold it applies. Detected, not prevented.

**Change SS 4: say the wait guards against a kit thief while the service
is honest, and that a kit opens the data at once.** A stronger form needs
every live device to sign that it saw the pending entry, which a lost
device can never do. Also: after a takeover is cancelled, the kit is in
someone's hands. The cancelling device should be made to replace the kits
(with a new key, finding 1); SS does not say so.

### 5. Unbuildable: "if another listed device has synced recently"

SS 6.4 waits only "when another listed device has synced recently". The
recovering device cannot check that: summaries carry no time anyone must
believe (SS 6.2), and the server's word is what the wait distrusts. The
prototype always waits when any other device is listed. **Change: always
wait, or say the service's last-sync time decides (acceptable, since
finding 4 already limits the wait to an honest service).**

### 6. Gap: writes made during the 24-hour wait

The takeover removes every other device "at its write number". The
devices keep writing during the 24 hours. If the numbers are fixed when
the wait starts, those writes are lost. The prototype lets the apply
entry name the final last writes. **Add this to SS 6.4.**

### 7. Gap: a removal can drop writes other devices already applied

SS 6.2: "Removing a device records that device's last accepted write.
Anything it signs after that is dropped by everyone." The remover only
knows what it has seen. Another device may already have applied newer
writes of the removed device. As written, devices end with different data
forever. The prototype keeps every applied change and merges again
without the dropped ones. Merging is order-free once a record's type is
fixed in its ID (finding 29; `TestMergeIsOrderFree`), so this is exact.
**Add: "a device that applied writes past the recorded last write merges
again without them."** But see finding 26: which writes count must not be
left to the remover alone. Both are now in SS 6.2 and built.

### 8. Wrong to build: "records are re-encrypted right away"

SS 7.1. It gains little: the removed device already read every record it
was sent, and new writes use the new key. It costs a rewrite of every
record by the remover, which then becomes the signer of all of them. And
it removes nothing: the old ciphertexts stay on the server inside each
device's hash-chained log, which every device needs to check the chains.
The prototype does not re-encrypt. Old generations stay readable through a
key history sealed under each new key (SS's "old keys kept, sealed under
the new ones"). **Drop the sentence, or tie it to finding 9.**

### 9. Gap: nothing ever gets smaller

Every device checks every write of every device from write 1. Deletion
markers are "dropped" (SS 9), but a marker inside a hash-chained log
cannot be dropped without breaking the chain. A new device downloads the
whole history. Today: 1,000 records are 2,000 writes and about 1 MB, and a
new device takes 0.19 s to check them on an M2. That grows without end.
**Design a signed snapshot: a summary plus the sealed state at that
point, signed by a device, after which older writes can go.** It is also
the place where re-encryption (finding 8) and marker dropping can happen.

**Decided and built** (SS 9): signed by one device's sync key; every
other device accepts it only when it matches its own merged state at the
writes it names; older writes go once every current device has signed a
summary naming it; a new device starts from the newest one. "Snapshots"
above has the form. With 1,000 records a new device now joins in about
10 ms instead of about 0.3 s, and the server holds 0.23 MB instead of
1 MB (sizes below). Test: `TestSnapshots`.

### 10. Gap: the list fixes "the hash of the sealed record", which changes

SS 6.2 and 8.2: the device's name and SSH key sit in a sealed record whose
hash is fixed in the list entry. Any re-encryption changes the sealed
bytes. The prototype fixes a salted hash of the plaintext instead (the
salt stops the server from confirming a guessed name like "Budi's
iPhone"). The salt is exactly 16 bytes and each part is hashed with its
length, so no device can move bytes from the salt into the name. **Say "a
salted hash of the record's content", with that layout.**

### 11. Gap: "signed by A's authority key, and by B"

SS 6.2. B cannot sign the entry itself without an extra round trip: it
does not know the account or the entry when it asks to join. The
prototype has B sign its own keys (proof of possession), and the entry
carries that signature. Those signatures are not tied to an account, so
B must trust the account only from a reply sealed under the pairing
secret, and that reply must never reuse a key (finding 30). **Say so in
SS 6.2, or add the round trip.**

### 12. Gap: the kit's public sealing key is not on the list

SS 7.1 seals each new account key "for the recovery kit", but a device
does not hold the kit. It needs the kit's public sealing key. SS 6.2 lists
only the kit's signature. The prototype puts both public keys (signing and
X-Wing sealing, derived from the kit) in the entry. **Add them to SS 6.2,
and fix the derivation (above) in the format.**

### 13. Gap: binding the record type and ID versus "names encrypted"

SS 7.2 ties every record to "record ID, record type, version counter".
Bound data must be in the clear to be checked, which tells the server the
type of each record and which record each write edits. The prototype puts
type and ID inside the sealed body (covered by the signature and the
AEAD), and binds the clear header (format, suite, account, vault, writer,
write number, previous hash, list entry, key generation, clock). A
per-record version counter adds nothing over the clock and the write
number, so it is left out. **Say which fields are in the clear.**

### 14. Gap: two devices adding a list entry at once

A linear chain needs the service to append only on top of the head it
expects (`AppendAt`). The loser rebuilds and signs again: a second Face ID
prompt. A lying service can accept both and show each side its own; the
writes and summaries then name a list entry the other side does not have,
and both stop (`ErrFork`). **Add compare-and-append to the service API.**

### 15. Clarify: deletion rules

SS 8.1 says "anything not on the 'applies by itself' list waits", and
also lists "deleting a protected record" under waits, as if other deletes
did not wait. The prototype makes every delete wait, except notes. SS 9
says "deleting wins over a simultaneous edit". With a hybrid clock there
is no "simultaneous". The prototype makes a delete final: later edits to
that record ID do nothing; undoing a delete makes a new record.

### 16. Clarify: "stricter applies at once" must not depend on order

If "stricter" is judged against the current value, two devices that
receive the same writes in a different order disagree. The prototype
judges it from the new value alone (`protected=true`, `approval=required`
apply at once; their opposites wait). **List, per field, which values are
stricter.**

**Decided and built** (SS 8.1): a fixed table. `protected` on, `approval`
required, "never use AI here" on (`never_ai`), and a new deny rule (its
own record type) apply by themselves; anything not in the table waits,
also a value of a table field other than its stricter one. Test:
`TestStricterValuesTable`. See finding 39 for what "new" means for a
deny rule.

### 17. Clarify: a name held by another record

SS 8.1: the newcomer "waits and is shown as replaces prod-db". The
prototype shows it. SS does not say what happens to the old holder once
the newcomer is approved. **Say whether approving it deletes, renames or
keeps the old record.**

**Decided and built** (SS 8.1): approving the newcomer deletes the old
holder in the same signed yes. The screen says "replaces prod-db
(deleted)" (`Waiting.ReplacesLine`). The yes signs the old holders' IDs
with the change, so nobody can swap which record it deletes. Test:
`TestApprovingANewcomerDeletesTheOldHolder`.

### 18. Clarify: pairing details

- "One try" is not defined. The prototype: the request is gone once the
  existing device opens it with the right code, each device answers a
  code once whatever the server does, and the new device accepts one
  reply. A typo is reported as a check-code mismatch and does not burn
  the try.
- 26 characters of base32 hold 130 bits: the 128-bit secret and 2 spare
  bits, so there is almost no typo check. A 27th character would give one.
  **Decided and built: 27 characters, the last a check (above).**
- "10 minutes" can only be counted on device clocks. The new device counts
  from when it made the secret. The existing device compares the creation
  time sealed in the request with its own clock.

### 19. No gap: X-Wing is in the standard library

`crypto/hpke.MLKEM768X25519()` is X-Wing from `draft-ietf-hpke-pq`, KEM ID
0x647a (checked by a test). `DeriveKeyPair` works for it, so kit keys need
no extra code. `golang.org/x/crypto` is not needed at all. The format
should name the lowest Go version with `crypto/hpke` (1.26, to be checked
against the release notes); this was built with Go 1.27.4.

**Decided and built** (SS 7.2): Go 1.26 is the lowest. `sync/go.mod` says
`go 1.26.0`, and the module still builds and passes on the installed Go
1.27.4. The installed toolchain has no release notes or API lists, so the
check is `go vet`'s `stdversion` analyzer, which knows when each standard
library name was added and refuses any newer than the module's Go
version: it passes at 1.26.0, and at 1.25.0 it flags `crypto/hpke`
("requires go1.26 or later"). So nothing newer than Go 1.26 is used, and
nothing older is enough. A build and test run with Go 1.26.0 itself
passed later (finding 56). Test: `TestLowestGoVersion`.

### 20. Clarify: a device that comes back

After a takeover, SS 6.4 says live devices "come back by QR". A removed
device ID is never listed again (otherwise "anything it signs after that is
dropped" is ambiguous), so a returning device makes new keys and joins as
a new device. **Say so.**

### 21. Confirmed as SS says: holding back is detected, not prevented

A server that holds back everything one device wrote, its summaries
included, cannot be seen by another device alone. Comparing signed
summaries side by side catches it, and sync then stays stopped until the
server delivers. This matches SS 4 and 9.

## Review findings of 2026-11-14

A crypto review, a hostile-server review and a spec review attacked the
first version. Each finding below was reproduced on that version. Code
errors are fixed, each with a test that fails without the fix (checked by
undoing each fix in a copy). Problems in the text are recorded here with a
recommended resolution.

### 22. Wrong: the kit can act at once, with no wait

SS 6.1 lets the recovery key sign in a new authority key. SS 6.4 lets a
kit step on a listed device remove devices and replace the kits at once.
Neither waits. In the first version a thief with only the kit could split
a takeover into steps that each apply at once: remove one device, sign in
its own key as another device's authority key, add its own device with
that key, remove the last device. The owner's devices were out within one
minute, and the thief held the only kits. A quieter form added the thief's
device and pushed an address change that other devices applied at once.

The prototype now refuses both paths for a kit alone. A new authority key
needs the device's own request (finding 23). A recovery step needs the
signature of the listed device's sync key, and that device cannot remove
itself. The kit alone, on a new device, gets only the 24-hour takeover.

What is left is SS's own design: the kit together with a listed device
without Touch ID can still remove every authority device and replace the
kits at once. That is the stolen-Mac-plus-kit case.

**Change SS 6.1 and 6.4: anything the kit signs that removes a device
with an authority key while another authority device is listed, replaces
the kits, or signs in an authority key is a pending change. It waits 24
hours, and any listed authority key can cancel it. A newly signed-in
authority key signs no list entries until its own wait is over. Every
device shows an alert for a new authority key, above all the device it
names. Say in SS 4 what a captured kit can do at once: read everything.**

**Decided and built.** `ReplaceKits`, `RecoveryStep` and
`SignInAuthorityWithKit` apply at once only when the device is the only
one listed. Otherwise they write a pending entry signed by the kit; the
asking device applies it after 24 hours with `ApplyPending`, using its
sync key when it has no authority key (a Mac without Touch ID, or a
device whose Face ID changed). A direct entry of this kind is refused
while another device is listed. The device that cancels a kit step sets
`KitsAtRisk` and alerts "replace the kits now". Tests:
`TestRecoveryStepOnListedDevice`, `TestKitStepCancelled`,
`TestReplaceKits`, `TestAuthoritySignInWithKitWaits`.

### 23. Wrong: another device's authority key could be swapped without it (fixed in code)

SS 6.1: "another device signs the new key in." Nothing says the device
whose key changes must ask. In the first version any authority device,
even one added that day, could put any key in as an older device's
authority key. That also reset the older device's age, so the young
device could then remove it at once, and the 7-day rule and every cancel
were bypassed.

The prototype now: the device asks with an `AuthRequest`, signed by its
sync key and by the new key. The request names the key it replaces, so it
cannot be replayed. The device that signs it in obeys the 7-day rule. How
old a device is to others is counted from when it was first listed; a new
authority key only limits what that device itself may do for 7 days.
Every device shows an alert. **Add this to SS 6.1 and 6.2.**

### 24. Wrong: a kit could cancel the lost-kit replacement (fixed in code)

The first version let a current kit sign a cancel. A thief with the kit
then cancelled every lost-kit replacement, and every new key generation
stayed sealed to the thief's kit. SS 6.4 says "any device can cancel".
The prototype now accepts a cancel only from a listed authority key.
**Say "any listed device with an authority key; never a kit".**

### 25. Gap: writes sealed under an old key after a removal

A removal starts a new key generation. A device that has not seen the
removal yet still seals under the old key, and the removed device can
open those writes with its old key. A server can keep a device on the old
list for as long as it hides newer entries. So the promise of SS 6.2 and
7.1 holds only for devices that have synced since the removal.

The prototype now refuses a write whose key generation differs from the
one in force at the list entry it names. That stops a client that keeps
the old key on purpose, but not a device held on an old entry.

**Change SS 7.1: say that writes under a superseded generation are
readable by the removed device. Recommended: before sealing a write that
holds a secret, a device refreshes the list and warns when it cannot.
Accept writes under a superseded generation with an alert, and have the
writer seal them again under the newest generation once it catches up.**

**Decided and built.** A secret record is sealed only after the list is
read again; when the list cannot be read, `ConfirmUnchecked` asks the
person, and without a yes the write stops with `ErrListUnchecked`. A list
that reads but fails a check is never saved past. A write under a
replaced generation is accepted; a device that already held a signed
state and knew the newer key counts it in `Report.OldKey` and alerts. On
catching up, the writer writes a copy of each such write under the newest
generation: a "sealed again" write that names the write it copies and
changes nothing in the merged data; a copy that differs is dropped. Tests:
`TestSecretWriteRefreshesTheList`, `TestWriteUnderASupersededKey`. What
"such writes" means is finding 33, which replaced the "sealed again"
write with the snapshot.

### 26. Wrong: a removal can undo stricter rules and approvals

Finding 7 has every device drop the removed device's writes after the
last write the remover saw. The remover may be behind. In the review, B
set `protected=true` on a server (that applies at once), and A applied it.
C, which had not synced, removed B at an older write. A then dropped B's
write, and the server was no longer protected: a looser rule nobody
approved. Approvals B signed are dropped the same way, and a remover can
name write 0 and erase everything the device ever wrote.

**Change SS 6.2. Recommended: accept the removed device's writes up to
the newest write that any remaining device covered in a signed summary
naming a list entry before the removal. Never take back a stricter value
that applied by itself. Show anything dropped to a person to confirm.**

**Decided and built** as "Which writes of a removed device count" above.
When merging again, an approval the removed device signed is kept, and of
a record change only its stricter values are. `DroppedWrites` lists the
dropped writes until the person calls `ConfirmDropped`, and every sync
alerts while any are left. Tests: `TestRemovalKeepsWritesASummaryCovered`
(the review's case: the write stays on every device),
`TestRemovalNeverTakesBackAStricterValue`, and
`TestRevokedDeviceCannotReadOrWrite` (a write nobody confirmed is
dropped). See finding 32.

### 27. Gap: a hold stopped sync for the whole wait (fixed in code)

The first version held the list before an apply entry, but other devices
had moved on: their summaries and writes named newer entries. So a device
that missed a wait failed every sync for the whole wait with an error that
blamed the server (`ErrListBehind`), and showed no alert. The prototype
now keeps syncing everything that names entries up to the hold, keeps the
rest for later (`Report.Held`), and returns the hold with its alert.
**Say in SS 6.2: a held device keeps syncing up to the hold and shows it;
it is not an attack.**

### 28. Gap: a waiting change fixed its key too early (fixed in code)

The first version put the new key generation in the pending entry. Any
other key change during the wait (a removal, a recovery step) left the
pending change unable to apply, and its alert stayed for good. Anyone who
could start a generation could block a lost-kit replacement. The pending
entry now holds only the intent (devices, kits); the apply entry carries
the new key, made when it applies. A removal whose device another entry
already removed applies as done, with no new key. **Use this form in
finding 3's list entries.**

### 29. Wrong: a record's type came from the first write seen (fixed in code)

Each write names its record's type inside the sealed body. The first
version took the type from whichever write a device opened first, and a
new device opens logs in device-ID order. A Mac without Touch ID could
write "this server is a note, address 203.0.113.9". Old devices held it
as waiting; a newly paired device applied it at once. The SS 8.1 rule was
skipped, and devices kept different data for good. Any device could also
delete or rename another device's name record.

The prototype now fixes the type in the record ID (a 4-byte tag of the
type), refuses a write whose type does not fit, and lets only a device
write its own device record, never delete it. Merging is then order-free
(`TestMergeIsOrderFree`). **Add to SS 7.2 and 8.1: a record's type is
fixed when it is made and bound to its ID.**

### 30. Wrong to build: the pairing reply reused a key (fixed in code)

The reply was sealed under a key from the secret alone, with a zero
nonce. That is safe only if one device answers once. "One try" rested on
the server deleting the request. A server that ignores the delete and
shows a second device a forked list gets the code answered twice: two
replies under one key and nonce, with plaintext the server mostly knows.
It can then forge a reply naming an account it made up. The new device's
join signatures are not tied to an account (finding 11), so they can be
replayed into that fake list.

The prototype now seals the reply under a key from the secret, 32 fresh
random bytes and the hash of the request, and each device answers a code
once. **Say so in SS 6.3.**

## Findings against the updated SS (2026-11-14)

The prototype was brought in line with SS as updated for the owner's
decisions. Three places could not be built exactly as written. They are
recorded here; SS is not changed.

### 31. Gap: a young device that skips the wait blocks every device for 7 days

SS 6.2: a device listed less than 7 days ago that removes an older device
does so as a waiting change, and "time only delays, never refuses". A
modified client can skip the pending entry and append the removal
directly. List entries carry no time anyone must believe, so the other
devices cannot refuse it without splitting (finding 2). They hold the
list at it (built). But a held list cannot take a new entry, so during
those 7 days no older device can cancel anything or remove the young
device first, and after the hold the removal applies. A pending entry
would have given them 7 days to cancel. This is the same limit as finding
4: the wait guards against a person using an honest app, not against a
modified client, and the hold makes it visible, not stopped.
**Recommended: say so in SS 6.2, as SS 4 already does for the kit wait.**

**Decided** (SS 6.2): SS now says plainly that a modified client on a
young device can skip the waiting change, and other devices can only hold
it for 7 days. Text only; the hold was already built
(`TestYoungDeviceCannotRemoveOlder`).

### 32. Gap: "never take back" can leave devices different

The cut is set by signed summaries, so every device that sees the same
summaries keeps the same writes. But SS 6.2 also says that merging again
"never takes back a stricter value that applied by itself, and never
drops an approval the removed device signed". Only a device that had
applied such a write past the cut keeps it: one whose own summary never
reached the server. Devices that never applied it do not get it. For a
stricter value the difference is only ever toward stricter. For an
approval it is not: the device that kept it shows the approved address,
the others still show the change as waiting. The prototype does what SS
says (`TestRemovalNeverTakesBackAStricterValue`). **Recommended: the
device that keeps a stricter value writes it again as its own write, so
every device gets it; an approval past the cut is dropped like any other
write and shown to the person, who can approve again.**

**Decided and built** (SS 6.2), as recommended. Tests:
`TestRemovalNeverTakesBackAStricterValue` (every device ends protected),
`TestApprovalPastTheCutIsDropped` (the device that had applied the yes
merges again without it and shows it; a fresh yes applies).

### 33. Clarify: which writes the writer seals again

SS 7.1: "once the writer catches up with the newest entry, it seals those
writes again". A device cannot know when the server received the key
change it hid, so it cannot tell its writes made before the removal from
those made after. The prototype seals again its own record writes that
are under a replaced generation and name the list entry it held just
before the key change reached it, or a later one: the writes made while
its view was frozen (finding 37). A server
that hid more than one entry can leave older writes out. Sealing again
also takes nothing back: the old sealed copy stays on the server, where
the removed device can open it. It only puts the newest copy under the
newest key. In the same way, "an alert on every device that sees it"
would alert a new device on all of history, so the prototype alerts only
on a device that already held a signed state and already knew the newer
key. **Recommended: say which writes, as above, and say that sealing
again is not a way to take a write back. Or drop it and leave re-sealing
to the snapshot (finding 9).**

**Decided and built** (SS 7.1): sealing again happens only in a snapshot.
The per-write "sealed again" kind is gone from the format (a body of that
kind is refused), and so is `Report.Resealed`. The alert on writes under
an old key stays; when the list moved outside a sync, it counts from the
generation at the entry the device held before that move (finding 37).
Test: `TestWriteUnderASupersededKey`.

### Other review points

- **Paper kit parts** now carry a kit ID (above). Before, three parts with
  one from an old kit gave a wrong key and looked like a lost kit.
- **Hashes** of several parts now put each part's length in front. Before,
  a device could move bytes from the salt of another device's name record
  into its name and keep the pinned hash.
- **Vectors** now have outside checks (above). Before, every vector came
  from the prototype's own code.
- **Hostile server** now has write hooks, so tests can model a server that
  ignores a delete or keeps a fork.

## Findings of the third review (2026-11-14)

A third review attacked the prototype as updated for the owner's
decisions. Three faults were in the code and are fixed, each with a test
that fails without the fix. One is a design problem in SS 6.2 and is
recorded here with a recommendation; SS is not changed. Tests are in
`review3_test.go`.

### 34. Wrong: a step signed by a replaced kit still applied (fixed in code)

A thief with a kit, alone or with a stolen Mac without Touch ID, starts
two kit steps: two takeovers, or two recovery steps that remove the
iPhone. The iPhone cancels one. That sets "replace the kits now", and the
person replaces the kits. The second step was still waiting, and after its
24 hours it applied: the iPhone was removed and the thief's new kits
replaced the person's. The kit's signature was checked only when the
pending entry was added, never again when it applied. SS 6.4 says
replacing the kits ends the old kit.

The pending change now records the signing key of the kit that signed it.
When the kits are replaced (a kit change, a recovery step or a takeover),
every waiting step a replaced kit signed ends: it is done, never applies,
and is no longer shown as an alert. An apply entry for it is refused by
every device (`ErrChainBroken`). `ApplyPending` and `Recovery.Finish`
report `ErrKitReplaced`. Tests: `TestReplacedKitEndsItsTakeover`,
`TestReplacedKitEndsItsRecoveryStep`. **Say in SS 6.4: replacing the kits
also ends every waiting step the old kit signed.**

### 35. Wrong: a held or backdated summary raises the cut of a removed device

SS 6.2 (finding 26) keeps a removed device's writes up to the newest write
that any remaining device covered in a signed summary naming a list entry
from before the removal. A summary's list entry is chosen by whoever holds
the signer's sync key, and a device the server holds back honestly names
an old entry. Two cases, both reproduced:

- **Hostile server.** A removes iPad X. The server keeps the Mac mini M on
  the list from before the removal. X, which has an authority key, changes
  prod-db's address and approves it itself. M applies both and signs a
  summary naming the old entry. Every device then raises X's cut and
  applies the change. The only alert is "sealed under a key from before a
  removal".
- **Honest server, stolen sync key.** The thief holds the stolen Mac's sync
  key and the removed iPad. A removes both. A summary signed with the
  Mac's sync key, naming the entry from before the removals and covering
  the iPad's new writes, is still counted, because a removed signer still
  counts. One sync key, the key with no Face ID prompt, brings in a
  removed authority device's approvals.

This breaks SS 4 ("a removed device must not be able to write anything
after removal") and, through the approvals, SS 8.1.

**Recommended:**

- A summary cannot raise the cut by itself for anything that needs a
  person. Past the last write the removal records, keep only writes that
  apply by themselves (plain record changes that need no yes, and
  stricter values). Drop the removed device's approvals and waiting
  changes past that point on every device, and show them to the person
  for a fresh yes. This rule depends only on the list, so every device
  does the same.
- Count only summaries whose signer is still listed.
- Refuse a summary log whose list entry goes down as its number goes up.
- Say in SS 4 and 6.2 that a server holding a remaining device back can
  extend which writes of a removed device count, as SS 7.1 already says
  for the old key, and show every write kept past the recorded last write
  as "kept from a removed device after it was removed".

The stronger choice, counting a summary only when its signer's next
summary names the removal and covers no more writes, stops the cut from
growing while a device is held, but needs that device to sync again.

**Decided and built** (SS 4 and 6.2), the recommended rule, not the
stronger choice. The prototype does not add the "kept from a removed
device after it was removed" line: SS keeps only "anything dropped is
shown". Tests: `TestHeldSummaryCannotBringInAnApproval` (case 1),
`TestRemovedSignerSummaryDoesNotCount` (case 2),
`TestBackdatedSummaryIsRefused`.

### 36. Wrong: a dropped write the person confirmed came back silently (fixed in code, approvals open)

A removes X. X's late change and its approval are dropped, the alert says
"2 changes from removed devices were not kept", and the person confirms.
Later a summary raises X's cut (case 35). The writes then applied, and
`DroppedWrites` stopped listing them, with no word to the person.

Now a raised cut moves such writes from "not kept" to "kept again".
`KeptAgain` lists them until the person calls `ConfirmDropped`, and every
sync alerts: "N changes from removed devices that were shown as not kept
are now kept; check them and confirm". The writes still apply on every
device, so devices stay the same; holding them back on one device only
would split them (a later summary of another device covers them).
Test: `TestKeptAgainIsShown`. Approvals among them still apply; keeping
them out needs the rule recommended in finding 35.

**Settled by finding 35.** Approvals and waiting changes among writes kept
again stay dropped; only what applies by itself comes back.
`TestKeptAgainIsShown` now checks that a removed device's address change
and its own yes stay out while its note comes back.

### 37. Gap: a list refresh outside Sync lost alerts and resealing (fixed in code)

Sync took "what is new" from the list entry it held when it started. Many
other calls already move the list forward: a secret write refreshes it
(SS 7.1), and so do removals, pairings and waiting changes. After such a
move, Sync showed no "A new device was added" (SS 6.3) or new authority
key alert (SS 6.1), and did not seal again the writes made while behind
(SS 7.1).

The device now remembers the list entry it held before the first move it
has not handled yet, and Sync alerts from it. Its own new entries do not
count. (Resealing went with finding 33.) Test:
`TestListRefreshOutsideSyncStillAlerts`.

### 38. SS 21 was out of date

SS 21 still said the prototype drops everything after the recorded last
write. It then listed findings 31 to 36 with their recommendations. After
the owner's decisions it said nothing is open, and that the format can be
frozen once this re-test passes. The re-test passed, but its review found
findings 45 to 56. The owner decided them the same day and SS now states
them; SS 21 then kept only the Go 1.26 check and finding 61 open. Both
were settled on 2026-11-14 (findings 56 and 61), and SS 21 now lists
nothing open.

## Findings of the freeze re-test (2026-11-14)

Building the decisions above raised no new fault in SS. Six places
needed one more sentence so that two builders make the same choice. Each
is built as recommended here. Decided and built: the owner decided all
six on 2026-11-14, and SS 6.2, 7.2, 8.1 and 9 state them.

### 39. Clarify: what makes a deny rule "new" (decided and built)

SS 8.1: "a new deny rule applies by itself; an edit or delete of one
waits." A write that says "create" for an existing deny rule's ID is an
edit in disguise: with the newest clock it would replace the rule's
pattern, and a writer picks its own clock, so no order of "creates" can
be trusted. **Recommended: bind a deny rule's ID to the write that makes
it (above, "Deny rule IDs"); any other "create" of that ID is refused.**

### 40. Clarify: a cut can go down (decided and built)

"A summary counts toward the cut only while its signer is still on the
list" means a cut can go down when that signer is removed later. Every
device then finds the same, lower cut; one that applied more merges
again, shows what it dropped, and writes again any stricter value. While
the signer is listed, a cut it set stays, even if the server hides its
summary later. **Recommended: say both in SS 6.2.**

### 41. Clarify: what a snapshot keeps of a deleted record (decided and built)

Deletion markers go with a snapshot (SS 9), but deletion is final and a
deletion marker holds a name (SS 8.1). The prototype keeps, for a deleted
record, its type and its name field, and drops the rest. **Recommended:
say so in SS 9.**

### 42. Clarify: which snapshot a summary names (decided and built)

To accept a newer snapshot while building on an older one, each summary
names two: the newest one its signer accepted, and the one it builds on.
A new device takes the one every other current device names as newest,
or else the one they all build on, so it never needs writes the service
already dropped. **Recommended: say so in SS 9.**

### 43. Clarify: a floor below a confirmed snapshot (decided and built)

A removal records the last write it accepted. A confirmed snapshot holds
writes every current device agreed on before. If a removal names an
older write than the snapshot holds, the snapshot wins: those writes stay
as they are. An honest remover has confirmed the snapshot, so its
recorded write is never older. **Recommended: say so in SS 6.2.**

### 44. Clarify: a device takes back its own acceptance (decided and built)

A device that accepted a snapshot judges it again at every sync until it
builds on it. A removal that changes what the writes give (finding 35)
makes it differ, and the device stops naming it. **Recommended: say so in
SS 9.**

## Findings of the review of the freeze re-test (2026-11-14)

A review attacked the re-tested code and checked it against SS. It found
ten faults in the code and three gaps in SS. Each code fault is fixed
with a test in `review4_test.go` that fails without the fix (checked by
undoing each fix in a copy). Decided and built: the owner decided
findings 45 to 55 on 2026-11-14, and SS 6.2, 7.2, 8.1 and 9 state them.
Finding 56 (the Go 1.26 run) stayed open until the run passed (below).

### 45. Wrong: a snapshot raised a removed device's floor past a waiting removal (fixed in code)

A young iPhone asks to remove the stolen iPad X; the removal waits 7
days. During the wait X moves prod-db and approves it itself. An honest
device makes a snapshot, every device names it and builds on it. When
the removal applies, the floor rose to the snapshot, so X's yes was kept
for good and never shown. **Fixed: while a removal of a device waits, and
for a snapshot naming a list entry from before that device's removal, a
snapshot holds nothing of it past the write the removal records.** An
honest device's snapshot stops there; one that holds more is never
taken, without an alert (it may be honest and early). Test:
`TestSnapshotStopsAtAWaitingRemoval`. **Recommended for SS 9 and 6.2.**

### 46. Wrong: a new device started from a snapshot the others took back (fixed in code)

The server showed a new Mac only summaries from before the removal,
naming a snapshot that held X's yes. The Mac built on it, and its floor
rose to it, so it kept 203.0.113.9 for good while the others showed
10.0.0.5, with no alert. **Fixed: a new device starts from a snapshot only
when every other member's newest summary names a list entry at or after
the newest entry that removes a device, asks for a removal, or applies
or cancels one, and only when the snapshot passes the caps of finding
45. Otherwise it reads from write 1** (and stops with `ErrMissingWrites`
if those writes are gone). The cap check alone stops the attack; the
list-entry check is a second wall for a cut that goes down later. Test:
`TestNewDeviceSkipsASnapshotFromBeforeARemoval`. **Recommended for SS 9.**

### 47. Wrong: hiding the newer summary bypassed the backdated-summary refusal (fixed in code)

The check compared only neighbours in the served log. A held M's summary
k, which names the removal. The thief signed k+1 naming the entry before
it, and the server hid k. **Fixed: each summary is also checked against
the newest summary of its signer this device holds. A later one that
names an earlier list entry is `ErrRollback`; one with the same number
that differs is `ErrFork`.** Test:
`TestBackdatedSummaryRefusedWhenTheNewerIsHidden`.

### 48. Wrong: a summary with the number of an old one raised the cut (fixed in code, format change)

Summaries were not chained, so a thief with M's sync key could sign a
second summary with the number of M's honest summary from before the
removal, naming the same entry and covering X's late note. **Fixed: a
summary names the hash of its signer's summary before it (`Prev`, 32
bytes; summary 1 names zero), so each signer's summaries form one chain.
Two different summaries with one number, or one that does not follow the
one before it, are `ErrFork`. A summary older than the one this device
holds counts toward a cut only when every summary from it up to that one
is served.** Test: `TestSummaryBesideAnOldOneIsRefused` (beside the old
one, in its place, and with the chain after it hidden). **Recommended
for SS 9's description of a summary.**

### 49. Wrong: SnapshotToPrune offered a snapshot not every device named (fixed in code)

After building on s1, a device accepted a newer s2 and offered s2 for
pruning, though no other device had named it. **Fixed: the device keeps
the snapshot it builds on and offers only that one.** Test:
`TestSnapshotToPruneIsTheConfirmedOne`.

### 50. Wrong: approving a newcomer could delete a device's own record (fixed in code)

A server named "iPhone" listed the iPhone's device record as the old
holder of its name. The yes deleted that record, which no write may
delete, and the device's name was gone for good. A modified client could
also list any record in Replaces. **Fixed: names are held per type, and
only by types whose new record waits (finding 53). A yes deletes only
old holders of the newcomer's own type, read from the type tag in each
ID, never a device record or a note.** The line stays "replaces prod-db
(deleted)": the old holder is always of the same type. Test:
`TestApprovalNeverDeletesADeviceRecord`.

### 51. Gap: editing implied a yes that deletes (built as recommended)

On a device with Face ID, editing collects the person's yes (SS 8.1).
Creating a second server named prod-db therefore deleted the first in the
same edit; the person never saw "replaces prod-db (deleted)".
**Decided by the owner 2026-11-14: a yes that deletes something is never
implied. A change with a replaces line waits on every device, also the
one that made it, until the person says yes on that screen.** Built so.
Test: `TestAutoApproveNeverImpliesADeletingYes`.

### 52. Wrong: a deny rule from past the cut was written again once per device (fixed in code, format change)

Each device that had applied the removed device's deny rule wrote it
again under a new ID, so N devices made N copies. **Fixed: a deny rule
written again has an ID bound to the dropped write and to the rule's
fields, and its write names the dropped write (`Change.Target`, until now
used only by approvals). Every device that writes it again writes the
same record with the same fields. Its fields take a zero clock, so a
later copy never undoes an edit made with a yes in between. A device that
already holds it, or its deletion, does not write it.** If a later
summary raises the cut, the original rule comes back beside the copy:
two equal rules, never N. Test: `TestRewrittenDenyRuleIsOneRule`.
**Recommended for SS 6.2 and 8.1.**

### 53. Gap: a record that applies by itself could take a held name (built as recommended)

SS 8.1 says a held name cannot be taken. A note, and a new deny rule,
apply at once, with no name check. **Decided by the owner 2026-11-14:
names are unique per record type, and only for types whose new record
waits for a person (servers, secrets, rules, and the like). Notes, device
records and deny rules hold no name and take none.** Built so (with
finding 50).

### 54. Wrong: writing a stricter value again undid a newer yes (fixed in code)

X turned `protected` on. B pulled it, then turned it off with a person's
yes. A removed X with no summary covering X's write. B compared only with
the state after merging again, saw "off", and wrote "on" again, undoing
the newer yes. **Fixed: a stricter value is written again only when the
merged data before merging again still held it with the dropped write's
clock, so the removed device's write was the one in force; a deny rule
only when it was still there.** Test:
`TestStricterValueReplacedByAYesIsNotWrittenAgain`. **Recommended for SS
6.2.**

### 55. Gap: SS 21 said nothing was open while SS lacked findings 39 to 44

SS 21 said "Nothing open; the format can be frozen". Findings 39 to 44
(deny rule IDs, a cut that goes down, what a snapshot keeps of a deleted
record, the two snapshots in each summary, a floor below a confirmed
snapshot, taking back an acceptance) are built but not in SS, and the
summary and snapshot layouts depend on them. A second builder could not
follow SS alone. **Decided by the owner 2026-11-14 and done: write 39 to 54 into SS
6.2, 8.1 and 9, including the summary's layout (`Prev`, `Snap`, `Base`),
before the format is frozen. Until then SS 21 lists them as open.**

### 56. Gap: Go 1.26 was not tried (done: it passes)

SS 7.2 said the re-test builds with Go 1.26. Only `go.mod` names
`go 1.26.0`, and `go vet` of Go 1.27 checks the standard library calls
against it. That check does not catch a change in how `crypto/hpke`
behaves between 1.26 and 1.27. No Go 1.26 toolchain is on this machine,
and fetching one is a download. **Recommended, owner to confirm: allow
fetching Go 1.26.x (`GOTOOLCHAIN=go1.26.0 go test ./...` in `sync/`) and
run the tests and the vectors under it before freezing. Until then this
check is open.** The owner approved the download on 2026-11-14. A try was
blocked before it fetched anything: the module cache holds only an empty
lock file for go1.26.0. So the run has not happened. The recorded runs
used Go 1.27.3 (the default toolchain in this worktree) and Go 1.27.4
(cached).

**Done 2026-11-14, with the owner's approval of the download:** in
`sync/`, `GOTOOLCHAIN=go1.26.0 go version` gives go1.26.0 darwin/arm64;
`go vet ./...` passes; `go test -race -count=1 ./...` passes;
`swift testdata/crosscheck.swift testdata/vectors.json` gives every check
ok. After findings 57 and 61 were built, the same runs pass again under
Go 1.26.0 and Go 1.27.3 (132 tests and subtests, 42 Swift checks).
Recorded in SS 7.2, 18 and 21.

## Findings of the review of the owner's freeze decisions (2026-11-14)

A review attacked the code built from the decisions above and checked it
against SS. Each code fault is fixed with a test in `review5_test.go`
that fails on the code before its fix. What follows directly from a
decided rule is written into SS and marked "follows from". The two points
that needed a new rule (findings 57's growing list and 61) were decided
by the owner on 2026-11-14 and are built.

### 57. Wrong: two yeses for one newcomer left devices with different data (fixed in code, format change)

A, B and C agree on S1 "prod-db". A makes S2 "prod-db" and C makes S3
"prod-db". A has seen S3 when it approves S2, so its yes replaces S1 and
S3; B has not, so its yes replaces only S1. A later yes overwrote the
earlier one's list, and a yes for a change that had already applied
deleted nothing. Which records were deleted then depended on arrival
order: A had S3 deleted, B had it waiting, C either. Snapshots were then
refused for good. A modified client could do the same on purpose.
**Fixed: a change replaces the union of the holders every valid yes
names; a yes that arrives after the change applied deletes the holders it
adds. Only a change that sets a name replaces anything. A snapshot's
state keeps each applied change that set a name, with that union, so a
device that starts from a snapshot gives the same result (format: the
state gains one list). A waiting change whose record is deleted is no
longer listed.** Tests: `TestTwoApprovalsOfOneNewcomerAgree`,
`TestLateApprovalAddsAHolderInAnyOrder` (six orders, two through a
snapshot). Written into SS 8.1 and 9 as following from the decided rule
and from order-free merging.

The list of applied name changes then grew by one entry per approved new
name or rename and was never pruned. **Decided by the owner 2026-11-14:
prune it at every snapshot every current device has named, keeping the
result identical on all devices.** Built so:

- A device empties the list when it builds on a snapshot every current
  device named, and a new device does when it starts from one. So a
  snapshot's state holds only the name changes since the snapshot its
  signer builds on. Only types that hold names are listed (not notes,
  device records or deny rules).
- A yes that arrives later for a pruned change deletes nothing more. If
  the holders it names still hold the name, finding 61's rule shows them
  as "waiting: name taken" on every device, so nothing disappears and
  nothing is used by an ambiguous name.
- States built on two different snapshots can differ in the pruned list,
  so a snapshot now names the snapshot it builds on (`Snapshot.Base`,
  in its signed header after `KeyGen`: a format change). A device judges
  it on that base: when it does not build on that base yet, it builds
  the state the same way, from its own base through each named base,
  pruned at each, and checks each base's state hash on the way. A base it
  cannot reach (not on the server, or older than its own) leaves the
  snapshot waiting, never refused with an alert; its signer makes a newer
  one. A device never goes back from a snapshot to the one it builds on.

Tests: `TestSnapshotPrunesAppliedNameChanges` (the second snapshot holds
one entry, not three; all devices and a new one hold the same data),
`TestSnapshotOnANewerBaseIsJudgedOnIt` (a device that does not build on
the first snapshot yet takes an honest second one built on it). Each
fails under its mutation: no pruning at the base, no pruning while
judging, judging without the base, and going back to the base.

### 58. Wrong: a stricter value was written over a newer yes read in the same sync (fixed in code)

Finding 54 was only half fixed. B judged "still in force" before reading
the sync's writes. When A's newer yes (`protected` off) arrived in the
same sync as the removal, B still wrote `protected` on again, with a
newer clock, and every device ended with "on". **Fixed: each value to
write again carries the dropped write's clock, and it is judged again
after the sync's writes are merged: a field with a newer clock is not
written.** Test: `TestStricterValueNotWrittenOverAYesInTheSameSync`.

### 59. Wrong: a deny rule deleted with a yes came back as a copy (fixed in code)

X made deny rule R; B and C applied it, with no summary covering it. C
deleted R with its own yes, and A removed X. B read both in one sync and
wrote R's copy, so every device had a live rule a person had deleted.
**Fixed: after the merge, a deny rule is not written again when its
original is deleted.** Test:
`TestDeletedDenyRuleNotWrittenAgainInTheSameSync`.

### 60. Gap: the rules of findings 40 and 43 had no test, and one did not work (fixed in code)

Three mutations left every test green: a floor that ignores the
confirmed snapshot, a cut that stays after its signer is removed, and a
cut dropped while its signer is listed. The new tests caught a real
fault: once A removed M, whose summary had set X's cut, A's own summary
from before that (which covered X up to the old cut) was taken as proof
of a hidden summary, and A could not sync again (`ErrMissingWrites`).
**Fixed: a summary signed while a device that could have set the cut was
still listed, and that device has since been removed, is read up to the
lowered cut.** Tests: `TestCutGoesDownWhenItsSignerIsRemoved`,
`TestCutStaysWhileItsSignerIsListed`,
`TestFloorNeverGoesBelowAConfirmedSnapshot`. Each fails under its
mutation (checked). Written into SS 6.2 as following from finding 40.

### 61. Gap: two newcomers can take one free name at once (decided and built)

A and B are offline and each make a server named prod-db. Neither sees
another holder, so each yes replaces nothing, and after syncing both are
live with one name. SS 8.1 says two records never hold one name, and
commands pick targets by name. The recommendation was that the record
whose creating write sorts first keeps the name. **Decided by the owner
2026-11-14 otherwise: both are marked "name taken" and wait until the
person picks one; nothing disappears silently.** Built so:

- A clash is two or more agreed, live records of one name-holding type
  with one name. It is read from the merged records alone, so every
  device that holds the same writes shows the same clash, in any order
  (`NameClashes`, shown as "waiting: name taken: prod-db (2 server
  records)").
- No record in a clash is found by name (`Find` answers
  `ErrNameTaken`). Each stays readable by its ID, since a link by ID is
  not ambiguous, and nothing is deleted.
- The person's pick is an ordinary change under SS 8.1. "Keep this one"
  (`KeepName`) writes the kept record's name again, so the change waits
  with "replaces prod-db (deleted)" for the others, and the person's yes
  on that screen deletes them. That yes is never implied by editing
  (finding 51). Renaming or deleting one waits like any rename or delete.
- Two people who each keep a different one, on two devices at once, both
  approve a deleting yes; both records are then deleted, as each screen
  said. That is the rule of finding 57, not a new one.

Tests: `TestTwoNewcomersWithOneNameWaitForAPick` (three devices, both
servers waiting on all of them, the pick deletes the other everywhere),
`TestNameTakenEndsWithARename` (a rename keeps both; notes with one name
never clash). Each fails when the clash check or the refusal in `Find` is
undone. The existing name rules still pass.

### 62. Gap: the vectors did not pin the frozen layouts (fixed)

No vector covered a summary, a write's header and signed bytes, a change
body with `Target`, a deny rule written again, or a snapshot state with a
deleted record, and `crosscheck.swift` only hashed bytes it was given.
**Fixed: five new vectors, and `crosscheck.swift` builds each from its
fields (42 checks, all ok).** `go test -run TestVectors -update` now
keeps the random parts that still check out.

### 63. Gap: this document was behind SS (fixed)

The answer, the intros of findings 39 to 56, and findings 38, 51, 53, 55
and 56 still said "owner to confirm" for points the owner had decided.
Updated.

### 64. Gap: SS 15 did not say the service must keep summaries (written into SS 15)

The cut rules need a remaining device's summary from before each removal,
and finding 48 counts an older summary only when its chain up to the
newest is served. SS 15 described storage as "sealed records by opaque
ID". **Written into SS 15 as following from findings 9, 41 and 48:
append-only logs per device; writes and deletion markers go only up to a
snapshot every current device named; summaries are never deleted.**

### 65. Gap: SS named the wrong Go version (written into SS 7.2 and 18)

SS 7.2 said the prototype used Go 1.27.4 and that the re-test builds with
Go 1.26; SS 18 said the format freezes once the re-test passes. The
default toolchain here is Go 1.27.3, and no Go 1.26 run happened. Fixed
in SS 7.2 and 18, and in finding 56 and the timings below.

### 66. Gap: the test counts were out of date (fixed)

Updated from a fresh run (above).

## Limits of this prototype

- No teams, member lists or team vaults (SS 12), no approvals on the
  phone (SS 14), no wake-ups, no AI.
- The Secure Enclave is not exercised; `Signer` has its shape. The real
  Face ID prompt, and its "no passcode fallback", need Apple hardware.
- The in-memory server has no "since" query: a device reads and hashes
  every stored write each sync. A real service returns only what is new.
- Device state (the "Keychain" values) lives in memory; restore from a
  backup and the 90-day rule (SS 9) are not built.
- The email code the server asks for before a recovery and the email that
  announces a kit step (SS 6.4) are server work, not built.
- A device reads every summary of every remaining device to find a
  removed device's cut. A summary counts toward a cut only when every
  summary from it up to the one the device holds is served (finding 48),
  so a real service must keep the chain of summaries from before each
  removal up to now. SS 15 now says the service never deletes summaries
  (finding 64). Snapshots drop writes, not summaries.
- A snapshot's state keeps the applied changes that set a name since the
  snapshot it builds on (finding 57); the list is pruned at every
  snapshot every current device named.
- A snapshot is one sealed blob of the whole state. A real service would
  split it into parts so that a device fetches it in pieces.
- Pruning is a test hook (`MemServer.PruneWrites`). A device judges a
  snapshot by merging again from its base, which is fine for thousands of
  records and would want a running hash for many more.
- One device that never syncs keeps every write on the server: by design,
  older writes go only once every current device named the snapshot.
- The device's clock check against the server before pushing (SS 9) is
  not built; far-future writes are held as SS says.

## Sizes and timings

Apple M2, Go 1.27 (1.27.3 or 1.27.4: the run did not record which; not
run again after findings 57 and 61), `go test -bench . -benchtime=2s` (the two joins:
`-benchtime=1x`, best of three runs, on a busier machine than before).

| Operation | Time |
|---|---|
| Seal a 1 KiB record (HKDF, AES-256-GCM, Padmé) | 2.2 µs |
| Open a 1 KiB record | 1.7 µs |
| Sign, P-256 fixed form (software) | 23 µs |
| Verify, P-256 | 55 µs |
| Seal a key to a device, HPKE X-Wing | 114 µs |
| Open it | 83 µs |
| New device joins and checks 1,000 records (2,000 writes) from write 1 | 191 ms (258 ms in the re-test run) |
| New device joins from a confirmed snapshot of the same 1,000 records | 9 ms |
| A device holding 1,000 records pulls one change | 2.6 ms |

| Thing | Size |
|---|---|
| List entry 1 (first device, account key 1) | 2,955 bytes |
| Entry adding the first kit | 1,532 bytes |
| Entry adding a device | 1,715 bytes |
| A write (a 3-field server record) | 579 bytes (288 sealed) |
| A summary naming 2 devices (and two snapshots, and the summary before it) | 376 bytes |
| A snapshot of 1,000 server records | 226 KB |
| 1,000 records on the server after pruning to that snapshot | about 0.23 MB |
| Account key sealed to a device (X-Wing HPKE) | 1,168 bytes |
| 1,000 records on the server, everything included | about 1 MB |

X-Wing keys (1,216 bytes each) make list entries large. They grow with
the number of devices, not with data.

## Running it

```
cd sync
go test -race ./...
go test . -run XXX -bench .
go test . -run TestSizes -v
go test . -run TestVectors -update   # only for a change you meant
swift testdata/crosscheck.swift testdata/vectors.json
```
