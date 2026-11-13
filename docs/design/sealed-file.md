# The sealed file (format v1)

One file format for two jobs: `komando export --sealed` moves everything,
passwords included, to another computer, and `komando export --for-phone`
moves it to the iPhone app. The content is the same; the header says how
the file opens: with a passphrase, or with the private key the phone made
for this one export. The iPhone app reads the same bytes. This page is the
contract between the two; `internal/sealfile` is the Go side.

## Who makes one, who opens one

- Only a person at a terminal makes a sealed file, as with `secret show
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

`--for-phone` asks for the key file the phone shared (or the key as text:
32 bytes as base64 or hex) and for the key check the phone shows: the hex
SHA-256 of the key, 64 characters, typed with any spaces, dashes or case.
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
{"v":1,"mode":"passphrase","kdf":{"name":"scrypt","n":131072,"r":8,"p":1,"salt":"KyTHrsNLyOX1qnsGgN/SesKYjWkv3E+EgXXV3mTfm6U="},"kem":null,"compression":"deflate","created_at":"2026-11-14T09:30:00Z","made_by":"komando 0.14.0"}
```

```json
{"v":1,"mode":"recipient","kdf":null,"kem":{"suite":"X25519-SHA256-AES256GCM","enc":"CLueRj8K1F4YQSiGVbun5RBjOvyC3MewbSx4VXiFDVg=","key_id":"ebe7c40501d20c8ef3ba7fdbce25d3e44c6b01e67ab6eeb22e072ff1cdb28ddb"},"compression":"deflate","created_at":"2026-11-14T09:30:00Z","made_by":"komando 0.14.0"}
```

| Field | Value |
|---|---|
| `v` | 1 |
| `mode` | `passphrase` or `recipient` |
| `kdf` | passphrase mode only, else `null` |
| `kem` | recipient mode only, else `null` |
| `compression` | `deflate`: raw DEFLATE (RFC 1951, no zlib or gzip wrapper) |
| `created_at` | RFC 3339, UTC |
| `made_by` | `komando` and the version that made it |

base64 is standard base64 with padding (RFC 4648 section 4). A reader
refuses an unknown `v`, `mode`, `compression`, KDF name or suite, and a
header with both or neither of `kdf` and `kem`. Nothing in the header is
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

HPKE base mode (RFC 9180) to the phone's one-time X25519 public key, suite
DHKEM(X25519, HKDF-SHA256), HKDF-SHA256, AES-256-GCM, with
`info = "komando sealed file v1"`. HPKE's single-shot seal: the
encapsulated key goes in `kem.enc` and the body is the HPKE ciphertext of
`deflate(content)` with the aad above (sequence number 0). There is no
separate nonce or content key. `kem.key_id` is the hex SHA-256 of the 32
bytes of the phone's public key; `suite` is there so v2 can add X-Wing.

In CryptoKit (iOS 17, macOS 14):

```swift
let suite = HPKE.Ciphersuite(kem: .Curve25519_HKDF_SHA256, kdf: .HKDF_SHA256, aead: .AES_GCM_256)
var r = try HPKE.Recipient(privateKey: key, ciphersuite: suite,
                           info: Data("komando sealed file v1".utf8), encapsulatedKey: enc)
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
"key_passphrase_refs": {"NAME": "secret:NAME"}  a key in keys that has a passphrase
```

`secrets_needed` still lists every secret the records name; a name in it
that is not in `secrets` was not in the vault. Not inside: pinned host
keys (each is checked again on first use), the audit log, jobs, tunnels,
sessions, logins, the approval-code key, cloud tokens. A security key
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
  store, like one `key gen` made; a key with a name that is here is left
  out.

## Errors

| Code | When |
|---|---|
| `NEEDS_PERSON` | an AI agent or a script makes or opens a sealed file |
| `WRONG_PASSPHRASE` | the passphrase does not open the file, or the file was changed |
| `SEALED_FILE_INVALID` | the file is cut short or its header is not JSON |
| `SEALED_FILE_UNSUPPORTED` | a newer version, an unknown method, or a file for the phone |
| `PHONE_KEY_INVALID` | the phone's key cannot be read, or does not match its key check |
| `WEAK_PASSPHRASE`, `PASSPHRASE_MISMATCH` | the passphrase typed when sealing |

## Test vectors

`internal/sealfile/testdata/vectors.json` holds one file of each mode with
everything needed to open it: the recipient's private key, the passphrase,
the expected content, the length of the aad and the check phrase.
`TestKnownAnswers` opens them; CryptoKit opens the recipient file with the
code above. A format change writes new ones
(`KOMANDO_UPDATE_SEALVECTORS=1 go test ./internal/sealfile/`), and the
iPhone app's copy changes with them.
