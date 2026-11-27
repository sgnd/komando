# The sealed file (passphrase v1, recipient v2)

One file format for two jobs: `komando export --sealed` moves everything,
passwords included, to another computer, and `komando export --for-phone`
moves it to the iPhone app. The content is the same; the header says how
the file opens: with a passphrase, or with the private key the phone made
for this one export. The iPhone app reads the same bytes. This page is the
contract between the two; `internal/sealfile` is the Go side.

## Who makes one, who opens one

- Only a person at a terminal makes a sealed file, as with `credential password show
  --reveal`. An AI agent or a script gets `NEEDS_PERSON` (exit 6), which no
  flag lifts. A dry run says what would be sealed and never asks anything.
- The passphrase is typed at the terminal, twice, hidden (15 or more
  characters). It never comes from the command line or the environment.
- The audit log records `export.sealed` with the counts, never the content.
- `komando import komando FILE` opens a passphrase file: a person types the
  passphrase once, hidden. A file for the phone does not open in the CLI
  (`SEALED_FILE_UNSUPPORTED`).

## Commands

```
komando export --sealed --to FILE [TARGET] [--with-keys]
komando export --for-phone --to FILE [TARGET] [--with-keys]
komando import komando FILE [--overwrite]
```

`--for-phone` asks for the key file the phone shared (the 1216-byte X-Wing
public key, raw or as base64 or hex; the key as text works too, but is
longer than many terminals take on one line) and for the key check the
phone shows: the hex SHA-256 of the key, 64 characters, typed with any
spaces, dashes or case. A 32-byte X25519 key from an iPhone app made
before the post-quantum switch is refused with `PHONE_KEY_INVALID` and a
message to update the app.
A key that does not match the key check is refused (`PHONE_KEY_INVALID`),
so a key file swapped on the way is caught. Fetching the key over the
local network is not built yet.

## Layout

All lengths are little endian.

| Bytes | What |
|---|---|
| 8 | magic `KMDSEAL1` |
| 4 | `header_len` |
| `header_len` | the header, JSON, in the clear |
| passphrase mode: 12 | nonce |
| the rest | the ciphertext with its 16-byte tag |

**aad** is the first `12 + header_len` bytes of the file: the magic, the
length and the header. A change to any of them breaks the seal.

### Header

```json
{"v":1,"mode":"passphrase","kdf":{"name":"scrypt","n":131072,"r":8,"p":1,"salt":"KyTHrsNLyOX1qnsGgN/SesKYjWkv3E+EgXXV3mTfm6U="},"kem":null,"compression":"deflate","created_at":"2026-11-14T09:30:00Z","made_by":"komando test"}
```

```json
{"v":2,"mode":"recipient","kdf":null,"kem":{"suite":"MLKEM768X25519-SHA256-AES256GCM","enc":"FJ6UWxXQ...(1120 bytes, base64)...YGg==","key_id":"d18291b1e61a31c9e46a2a5eb0d6d5089dbb6f1baf2d694026a6e987719f5b9d"},"compression":"deflate","created_at":"2026-11-14T09:30:00Z","made_by":"komando test"}
```

| Field | Value |
|---|---|
| `v` | 1 in passphrase mode, 2 in recipient mode |
| `mode` | `passphrase` or `recipient` |
| `kdf` | passphrase mode only, else `null` |
| `kem` | recipient mode only, else `null` |
| `compression` | `deflate`: raw DEFLATE (RFC 1951, no zlib or gzip wrapper) |
| `created_at` | RFC 3339, UTC |
| `made_by` | `komando` and the version that made it |

base64 is standard base64 with padding (RFC 4648 section 4). A reader
refuses an unknown `v`, `mode`, `compression`, KDF name or suite, and a
header with both or neither of `kdf` and `kem`. A recipient header with
`v` 1 is the X25519-only file of komando 0.14.0: it is refused as
outdated (make the file again), never opened; there is no reader for it.

The header must be exactly the JSON komando writes (Go's `json.Marshal`
of the fields in the order above): no spaces, no other key order or case,
no duplicate or unknown key, nothing after the closing brace. A reader
compares the header with that form and refuses anything else as damaged
(`SEALED_FILE_INVALID`), so two readers never see different fields. Nothing in the header is
trusted before the file opens; the counts are inside, not in the header.

### Passphrase mode

`key = scrypt(passphrase, salt, N=131072, r=8, p=1, 32 bytes)`, the same
cost as komando's store, with a fresh 32-byte salt and a fresh 12-byte
nonce for each file. The body is the nonce, then
`AES-256-GCM(key, nonce, deflate(content), aad)`. A reader takes `n` from
2^14 to 2^20 (a power of two), `r` 1 to 32 and `p` 1 to 4, so a file
cannot ask for gigabytes of memory.

A wrong passphrase and a file changed after sealing look the same to
AES-GCM: both are `WRONG_PASSPHRASE`, and the message says so.

### Recipient mode

HPKE base mode (RFC 9180, with the X-Wing KEM of draft-ietf-hpke-pq) to
the phone's one-time X-Wing public key. The suite is the one komando's
sync uses:

| Part | Value | HPKE ID |
|---|---|---|
| KEM | MLKEM768-X25519 (X-Wing): ML-KEM-768 and X25519, post-quantum | `0x647a` |
| KDF | HKDF-SHA256 | `0x0001` |
| AEAD | AES-256-GCM | `0x0002` |

`info = "komando sealed file v2"`. HPKE's single-shot seal: the
encapsulated key (1120 bytes: the ML-KEM-768 ciphertext, then the X25519
ephemeral public key) goes in `kem.enc`, and the body is the HPKE
ciphertext of `deflate(content)` with the aad above (sequence number 0, so
the nonce is the base nonce), its 16-byte tag at the end. There is no
separate nonce or content key. `kem.key_id` is the hex SHA-256 of the 1216
bytes of the phone's public key (the ML-KEM-768 encapsulation key, 1184
bytes, then the X25519 public key, 32).

HPKE base mode does not say who sealed the file: anyone with the phone's
public key can make a file that opens. The check phrase is what ties the
file to this computer: the person compares the six words the CLI printed
with the six the phone shows, and a mismatch is refused.

The phone's private key is the 32-byte X-Wing seed. SHAKE256(seed) gives
64 bytes for ML-KEM-768's key generation (d, z), then the 32-byte X25519
private key. In Go: `hpke.MLKEM768X25519().NewPrivateKey(seed)`; in
CryptoKit (iOS 26, macOS 26) the X-Wing key's seed representation is the
same 32 bytes.

In CryptoKit, as a sketch (check the names against the SDK):

```swift
let suite = HPKE.Ciphersuite.XWingMLKEM768X25519_SHA256_AES_GCM_256
var r = try HPKE.Recipient(privateKey: key, ciphersuite: suite,
                           info: Data("komando sealed file v2".utf8), encapsulatedKey: enc)
let deflated = try r.open(body, authenticating: file.prefix(12 + headerLen))
let content = try (deflated as NSData).decompressed(using: .zlib) as Data  // Apple's zlib is raw DEFLATE
```

The phone keeps its private key only in memory or the keychain until the
import ends, then deletes it.

## Content

The `komando export` document (`komando-export/1`: `hosts`, `conns`,
`vpns`, `recipes`, `secrets_needed`, `keys_needed`, and for a whole export
`deny_rules` and `settings`), plus:

```
"secrets":             {"NAME": "value", ...}   every secret the records use that is in the vault
"keys":                {"NAME": "OpenSSH private key text", ...}   only with --with-keys
"key_passphrase_refs": {"NAME": "credential:NAME"}  a key in keys that has a passphrase
```

`secrets_needed` still lists every secret the records name; a name in it
that is not in `secrets` was not in the vault. Not inside: pinned host
keys (each is checked again on first use), the audit log, exec sessions,
tunnels, sessions, logins, the approval-code key, cloud tokens. A security key
(FIDO2) stays on its device.

## Check phrase

After sealing, the CLI prints six words; the phone shows the same six for
the file it got, and the person compares them. A mismatch is refused. The
words open nothing.

The words are the first 66 bits of the SHA-256 of the whole file, read 11
bits at a time from the most significant bit of the first byte, each an
index into the BIP-39 English word list (2048 words, verbatim; the file of
one word per line, each ending in a line feed, has SHA-256
`2f5eed53a4727b4bf8880d8f3f199efc90e58503646d9ff8eff3a2ed3b24dbda`). Both
sides pin that hash in a test.

## Import rules

`import komando FILE` on a sealed file applies the same limits as any
export file (a proxy command is dropped, a password reference is kept only
for a secret that is not here yet, read-only recipes come in as changes),
then:

- a secret of the file whose name is not here goes into the vault;
- the same value here is left as it is, and the records may use it;
- another value here is kept, and the file's records do not get it, unless
  `--overwrite` and the person says yes at the terminal;
- a key of the file whose name is not here is kept in komando's sealed
  store, like one `credential key create` made; a key with a name that is here is left
  out.

## Errors

| Code | When |
|---|---|
| `NEEDS_PERSON` | an AI agent or a script makes or opens a sealed file |
| `WRONG_PASSPHRASE` | the passphrase does not open the file, or the file was changed |
| `SEALED_FILE_INVALID` | the file is cut short or its header is not JSON |
| `SEALED_FILE_UNSUPPORTED` | a newer version, an unknown method, or a file for the phone (of either version) |
| `PHONE_KEY_INVALID` | the phone's key cannot be read, or does not match its key check |
| `WEAK_PASSPHRASE`, `PASSPHRASE_MISMATCH` | the passphrase typed when sealing |

## Test vectors

`internal/sealfile/testdata/vectors.json` pins every byte of one file of
each mode. The recipient vector gives the fixed inputs (the X-Wing seed,
the 64 bytes of encapsulation randomness: 32 for ML-KEM-768's `m`, then
the 32-byte X25519 ephemeral private key; created_at and made_by), the
steps on the way (public key, key_id, enc, shared secret, AEAD key, base
nonce, header, deflated content) and the whole file in hex. The passphrase
vector fixes the salt and the nonce the same way. `refused` lists files
that must not open, each with the error it gets: the X25519 recipient file
of komando 0.14.0 (outdated), a changed tag, ciphertext, created_at or
enc, a cut enc or header, another key's key_id, header v3 and the old
suite in a v2 header.

`TestKnownAnswers` seals each vector again with a second implementation
written from the specs (`reference_test.go`: X-Wing, the RFC 9180 key
schedule and AES-256-GCM, not crypto/hpke) and compares every byte, opens
it with the package, and checks every refused file.
`TestReferenceDraftVector` checks that second implementation against the
draft-ietf-hpke-pq vector in `testdata/xwing_draft_vector.json`. An opener
on another platform (the iPhone app) opens each file and refuses each
refused one; CryptoKit cannot take fixed encapsulation randomness, so it
checks the opening side only.

A format change writes new vectors
(`KOMANDO_UPDATE_SEALVECTORS=1 go test ./internal/sealfile/`), and the
iPhone app's copy changes with them.
