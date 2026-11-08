# Checking a release's build provenance in `komando update`

Status: **proposed, 2026-11-09**. Nothing is built yet; this note asks for
a decision on a new dependency.

## The problem

`komando update` downloads the release archive for this computer and checks
it against `checksums.txt`. Both files come from the same release. Someone
who can change the release's files (a stolen token with `contents: write`, a
mistake in the release workflow) can replace both, and the check passes.

Every release already carries signed build provenance (SLSA level 2):
[`release.yml`](../../.github/workflows/release.yml) runs
`actions/attest-build-provenance`, which signs an in-toto statement naming
each archive's SHA-256 with a short-lived Sigstore certificate issued to the
workflow, and records it in Sigstore's public transparency log. A person can
check a download with `gh attestation verify FILE --repo sgnd/komando`
(SECURITY.md). `komando update` does not check it.

## What a check would prove, and what it would not

Checked properly, the provenance says: this archive's SHA-256 was signed by
the workflow `.github/workflows/release.yml` of `sgnd/komando`, running on
GitHub's runners for the tag `vX.Y.Z`, and the signature is in the public
log. That stops a replaced archive (or a replaced `checksums.txt`): the
attacker has no way to get such a certificate for their file.

It does **not** prove the tag is a reviewed commit. Anyone who can push a
`v*` tag starts the release workflow, and the workflow signs whatever that
tag points at. So the check is only worth as much as the rule for tags:

- Add a tag ruleset for `v*` (only the owner creates them; nobody updates
  or deletes them). Today the repo has only the "Protect main" branch
  ruleset. This needs no code and should come first.
- Optionally, check that the provenance's source commit is on `main` (one
  more GitHub API call).

## The steps of a check

For the tag `vX.Y.Z` and `D`, the SHA-256 that `checksums.txt` gives for
this computer's archive (the download must still match it, as today, so the
check can run before the archive is downloaded):

1. Fetch the attestations: `GET https://api.github.com/repos/sgnd/komando/attestations/sha256:D`
   (no token needed for a public repo; 60 requests an hour per address).
   Each one holds a Sigstore bundle (`application/vnd.dev.sigstore.bundle.v0.3+json`).
2. Get Sigstore's trusted root (the Fulcio CA certificates, the transparency
   log and certificate-transparency log keys). It is published through TUF,
   which also handles key rotation.
3. Check the bundle: the signing certificate chains to Fulcio and was valid
   at the time the log recorded; its certificate-transparency proof (SCT) is
   good; the log entry is in the log (inclusion proof against a signed
   checkpoint) and matches the bundle; the DSSE signature over the in-toto
   statement is good under the certificate's key.
4. Check the statement: its subject lists the archive's name with digest
   `sha256:D`, and its predicate type is SLSA provenance v1.
5. Check who signed: the certificate's OIDC issuer is
   `https://token.actions.githubusercontent.com`, and its identity is
   `https://github.com/sgnd/komando/.github/workflows/release.yml@refs/tags/vX.Y.Z`
   (the tag `komando update` asked for), on a GitHub-hosted runner.

Only then is the archive downloaded, checked against `D`, unpacked and
tried, as today. Any failure stops
the update with a new error (`PROVENANCE_INVALID`), and the hint names
`gh attestation verify` so a person can look themselves. There is no flag to
skip it; a person who must can still use `install.sh` or download by hand.

## Options

**A. Use [sigstore-go](https://github.com/sigstore/sigstore-go)** (the
library behind `gh attestation verify`'s checks). It does steps 2 and 3
with TUF, keeps up with Sigstore's changes (new log versions, key
rotation), and is kept by the Sigstore project. About 100 lines of komando
code for steps 1, 4 and 5, plus tests with a recorded real bundle.

Measured on 2026-11-09 with sigstore-go v1.4.0, linked into komando at
`origin/main` 6c58369 (`go build -trimpath -ldflags="-s -w"`, darwin/arm64):

| | komando today | with sigstore-go |
|---|---|---|
| binary | 61.5 MB | 69.4 MB (+7.9 MB, +13%) |
| modules in `go list -m all` | 672 | 848 (+176) |

CONTRIBUTING.md asks for no new dependency, or a small, well-kept one.
sigstore-go is well kept, but not small. It also brings code komando does
not need (gRPC, OpenTelemetry) that `make security` then has to watch.

**B. Write a small verifier with the standard library.** Embed the trusted
root and check exactly the one bundle shape GitHub makes today. Roughly
500–700 lines of certificate, Merkle-tree and signature code, written
by komando and reviewed by nobody else. It breaks the day the format
changes: Sigstore is moving its public log to Rekor v2, with a new entry
format, and its keys rotate. A komando whose verifier no longer
understands the new bundles cannot update itself to the version that
would. Not recommended.

**C. Run `gh attestation verify` when `gh` is installed.** No new code to
speak of, but not in-process, it depends on the person's `gh` and its
login, and a check that runs only when a program happens to be there does
not protect anyone. Not recommended.

**D. Sign `checksums.txt` with a key of komando's own.** The release
workflow signs it with an Ed25519 key kept in a GitHub environment secret
that needs the owner's approval to use; komando carries the public key and
checks the signature with `crypto/ed25519` (about 40 lines, no new
dependency). It protects against replaced files as well as A does, as long
as the environment stays protected. The cost is a key to keep: losing it
means a release that old komandos refuse, and rotating it needs one
release signed by both keys. It is not SLSA; the provenance stays for
`gh attestation verify`.

## Recommendation

1. Now: add the `v*` tag ruleset. Without it, neither A nor D proves more
   than "built by our workflow from some tag".
2. Then choose between **A** (standard, more checks, +7.9 MB and 176
   modules) and **D** (tiny, but a key to keep). A is the better long-term
   answer if the size is acceptable; D is the better answer if the
   dependency rule wins.
3. Either way: the check runs before `checkWritable` asks anything, so a
   bad release fails before the person is asked to approve it, and it runs
   in `--dry-run` too (it changes nothing).
