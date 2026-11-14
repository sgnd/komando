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

**Go for the core of the design. No-go for freezing the format until the
must-change list below is in SS and re-tested here.**

The core holds. Two and three devices sync end to end. The server never
holds a plaintext or a key. Every attack of a lying server is caught: it
drops, reorders, replays, rolls back, forks and swaps, and each ends in a
named error, never in silently changed data. Removed devices cannot read
later writes, and their later writes are dropped. A kit on a new device
takes the account over only after the 24-hour wait, and a live device can
cancel it. Everything is in Go's standard library: X-Wing is in
`crypto/hpke`, so there is no gap there.

A review on 2026-11-14 found that the first version of this prototype, and
the text it was built from, let the waits and the "a person agreed" rule
(SS 8.1) be skipped. A device added today, or the kit alone, could swap an
older device's authority key at once. The kit alone could remove devices
and take the kit slot at once. A device without Touch ID could relabel a
server as a note on newly joined devices. The prototype now closes each of
these (findings 22 to 30), and a test shows each attack fails. Three of
them are design choices SS must make; the prototype only shows one way
(findings 22, 25 and 26).

Must change before the format is frozen:

1. Replacing a recovery kit must start a new account key (finding 1).
2. The device list needs "pending", "apply" and "cancel" entries. The
   apply carries the new key. Only a listed authority key cancels, never
   a kit. A device whose clock says "too early" holds the list and keeps
   syncing up to the hold (findings 2, 3, 24, 27 and 28).
3. Say plainly what the 24-hour wait protects and what it does not
   (findings 4 and 5).
4. A takeover's apply names the final last writes; a removal makes every
   device merge again without the dropped writes (findings 6 and 7), but
   never undoes a stricter rule or an approval that way (finding 26).
5. Drop "records are re-encrypted right away", and design snapshots
   instead (findings 8 and 9).
6. A new authority key needs the device's own request, signed by its sync
   key and by the new key. The 7-day rule applies to the device that signs
   it in, and "older" is counted from when a device was first listed
   (finding 23).
7. Anything the kit signs that removes an authority device, replaces the
   kits or signs in an authority key waits 24 hours, cancellable by a
   listed authority key. A recovery step needs a listed device's own
   signature (finding 22).
8. A record's type is fixed in its ID when it is made. A device record is
   written only by its own device (finding 29).
9. Say what happens to writes sealed under an old key generation after a
   removal (finding 25).
10. The pairing reply uses a fresh key per answer and names the request it
    answers; each device answers a code once (finding 30).

## What was built

| Part | File | What it does |
|---|---|---|
| Device keys | `keys.go` | `Signer` (P-256, the Secure Enclave's shape: it signs a message and returns DER) for the sync key and the authority key; `Unwrapper` (X-Wing) for the unwrap key. `SoftSigner` is the software stand-in; its `Presence` hook stands in for Face ID |
| Signatures | `keys.go` | ECDSA P-256 in one fixed form: r and s as 32 bytes each, s in the lower half. The Secure Enclave returns DER with either s; it is turned into this form, and any other form is refused. Every signed message starts with a purpose label |
| Record sealing | `seal.go` | AES-256-GCM under a key used once, with a key commitment tag; Padmé padding |
| Key transport | `keys.go`, `keyring.go` | HPKE with X-Wing (`crypto/hpke.MLKEM768X25519`, KEM ID 0x647a), HKDF-SHA256, AES-256-GCM. The `info` value binds account, generation and receiver |
| Device list | `list.go`, `listcheck.go` | The signed hash chain, checked from entry 1 by every device. Account ID = hash of entry 1 |
| Writes and summaries | `write.go`, `sync.go` | Each write is sealed, signed by the sync key, numbered and chained to the device's previous write, and names the newest list entry. Each sync ends with a signed summary |
| Merging | `merge.go` | Field by field, newest hybrid clock wins; deletion is final; changes that wait apply only with a signed yes |
| Pairing | `pair.go` | QR or 26 characters, one-time 128-bit secret, 10 minutes, one try |
| Recovery kit | `kit.go`, `shamir.go`, `recover.go` | 256-bit key as 56 letters with a check, typed back before sync starts, up to 3 kits, 2-of-3 paper (own Shamir over GF(256)), recovery on a new device with the 24-hour wait, recovery step on a listed device |
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

**Hashes.** Every labelled hash puts each part's length in front of it, so
two lists of parts never hash the same way.

**Record IDs.** 12 random bytes and a 4-byte tag of the record type. A
write that names another type for an ID is refused by every device.

## What the tests show

`cd sync && go test -race ./...`: 90 tests and subtests pass, 0
fail (55 top-level tests); statement coverage 86.5%. All table-driven where
there is a table.

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

| A listed or captured key tries this | The devices report |
|---|---|
| A device without Touch ID relabels a server as a note | change dropped (`Report.Rejected`) on every device, old and new |
| Another device deletes or renames a device's name record | change dropped |
| A device added today swaps an older device's authority key | `ErrNotAuthorized` (no request from that device) or `ErrYoungDevice` |
| The kit alone signs in a new authority key | `ErrNotAuthorized` |
| The kit alone, on a device that is not listed, uses the recovery step | `ErrNotAuthorized` |
| The kit cancels a lost-kit replacement | `ErrNotAuthorized` |
| A write sealed under another key generation than its list entry has | `ErrBadWrite` |

After every failed check the device's data is unchanged. A whole account
life (three devices, secrets, approvals, a removal) leaves no plaintext,
no name and no key in anything the server holds (`TestServerNeverSeesPlaintextOrKeys`).

Also tested: changes that wait (address, secret, command, rename, looser
rule, new record, delete) apply only after an authority key's yes; notes,
descriptions and stricter rules apply at once; approvals signed by a sync
key, by a device without Touch ID or by an authority key not yet signed in
are dropped; the kit must be typed back before sync starts; a Mac without
Touch ID cannot turn sync on, add or remove devices; a removed device
cannot open the new key or new writes; its later writes are dropped; a
device that joins after two key changes still reads generation-1 records;
the 7-day rule with its cancellable "remove later"; Face ID changes; all
recovery paths; the 2-of-3 paper kit, also with a part of another kit;
merging the same writes in either order gives the same state.

**Vectors.** `testdata/vectors.json` (record sealing, Padmé, key IDs, kit
letters and derived keys, paper parts, HPKE X-Wing, the fixed signature
form, a list entry's bytes and hash, the pairing code) is computed by the
prototype and only pins regressions. Two outside checks stand behind it:

- `testdata/crosscheck.swift` recomputes every value in it with Apple
  CryptoKit, a separate implementation: HKDF and AES-256-GCM for record
  sealing, X-Wing keys from their seeds, HPKE with exactly this suite
  (X-Wing, HKDF-SHA256, AES-256-GCM), P-256 keys and signatures, Shamir
  over GF(256) and the letters. All 24 checks pass (macOS 27, Swift 6.4).
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
every online device accepted. It stops syncing on a valid chain
(`TestOfflineDeviceRefusesAValidRemoval` pins this). A rule judged on
local clocks can only *delay*, never *refuse*, or devices split.

The prototype: entries before a device joined are vouched for by the
device that paired it, so a new device does not trip on old history. For
the rest the rule is enforced as written (a refusal) to show the problem.
**Change: make every timed rule a waiting change (finding 3). A device
whose clock says "too early" holds the list at that entry and shows why;
it never refuses on time alone. Drop "cannot" for the 7-day rule: a young
device's removal of an older one is a waiting change any older device can
cancel.**

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
`TestRemovalDropsWritesAlreadyApplied` shows the devices end equal. **Add:
"a device that applied writes past the recorded last write merges again
without them."** But see finding 26: which writes count must not be left
to the remover alone.

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

### 17. Clarify: a name held by another record

SS 8.1: the newcomer "waits and is shown as replaces prod-db". The
prototype shows it. SS does not say what happens to the old holder once
the newcomer is approved. **Say whether approving it deletes, renames or
keeps the old record.**

### 18. Clarify: pairing details

- "One try" is not defined. The prototype: the request is gone once the
  existing device opens it with the right code, each device answers a
  code once whatever the server does, and the new device accepts one
  reply. A typo is reported as a check-code mismatch and does not burn
  the try.
- 26 characters of base32 hold 130 bits: the 128-bit secret and 2 spare
  bits, so there is almost no typo check. A 27th character would give one.
- "10 minutes" can only be counted on device clocks. The new device counts
  from when it made the secret. The existing device compares the creation
  time sealed in the request with its own clock.

### 19. No gap: X-Wing is in the standard library

`crypto/hpke.MLKEM768X25519()` is X-Wing from `draft-ietf-hpke-pq`, KEM ID
0x647a (checked by a test). `DeriveKeyPair` works for it, so kit keys need
no extra code. `golang.org/x/crypto` is not needed at all. The format
should name the lowest Go version with `crypto/hpke` (1.26, to be checked
against the release notes); this was built with Go 1.27.4.

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
The prototype still does what finding 7 says.

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

## Limits of this prototype

- No teams, member lists or team vaults (SS 12), no approvals on the
  phone (SS 14), no wake-ups, no AI.
- The Secure Enclave is not exercised; `Signer` has its shape. The real
  Face ID prompt, and its "no passcode fallback", need Apple hardware.
- The in-memory server has no "since" query: a device reads and hashes
  every stored write each sync. A real service returns only what is new.
- Device state (the "Keychain" values) lives in memory; restore from a
  backup and the 90-day rule (SS 9) are not built.
- The device's clock check against the server before pushing (SS 9) is
  not built; far-future writes are held as SS says.

## Sizes and timings

Apple M2, Go 1.27.4, `go test -bench . -benchtime=2s`.

| Operation | Time |
|---|---|
| Seal a 1 KiB record (HKDF, AES-256-GCM, Padmé) | 2.2 µs |
| Open a 1 KiB record | 1.7 µs |
| Sign, P-256 fixed form (software) | 23 µs |
| Verify, P-256 | 55 µs |
| Seal a key to a device, HPKE X-Wing | 114 µs |
| Open it | 83 µs |
| New device joins and checks 1,000 records (2,000 writes) from write 1 | 191 ms |
| A device holding 1,000 records pulls one change | 2.6 ms |

| Thing | Size |
|---|---|
| List entry 1 (first device, account key 1) | 2,955 bytes |
| Entry adding the first kit | 1,532 bytes |
| Entry adding a device | 1,715 bytes |
| A write (a 3-field server record) | 579 bytes (288 sealed) |
| A summary naming 2 devices | 280 bytes |
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
