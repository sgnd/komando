# komando v0.4.0 (draft release notes)

Draft for the next release after v0.3.1, taken from `## [Unreleased]` in
`CHANGELOG.md` and the commits on `release-readiness/2026-11`. Proposed as
v0.4.0, not v0.3.2, because two exit codes change (see "Changed"), and
`internal/out/out.go` treats exit codes as part of the public contract.

Not tagged or published. Before tagging, rename `## [Unreleased]` in
CHANGELOG.md to `## [0.4.0] - DATE`, add a `### Highlights` list as the other
versions have, and update the link footer (see CONTRIBUTING.md, "Releases").

## Highlights

- Security fixes for AI agents: downloads, `upload`/`sync`, `fs cat`/`fs
  replace`, `exec --read-only` and the danger check now hide or block more
  (merged in PR #45 after v0.3.1 was tagged).
- The vault no longer replaces a missing `vault.key` while stored secrets
  need it, and `secret set` checks that `KOMANDO_VAULT_PASS` opens the
  existing secrets.
- Exit codes: `NO_AUTH` now exits 4 and `SECRET_UNRESOLVED` exits 3
  everywhere. Scripts and agents that branch on the old codes need updating.
- Release archives now include `THIRD_PARTY_LICENSES`.

## Security

- Downloads by an AI agent (`download`, `sync`, `storage download`, also to
  stdout) save text files the way `fs cat` shows them, with secret values as
  `[hidden]`.
- `upload` and `sync` refuse a file that still holds `[hidden]` or
  `[secret:NAME]`, as `fs write` does.
- `fs cat` and `fs replace` hide Redis passwords (`requirepass`,
  `masterauth`, ACL rules).
- `exec --read-only` checks the SQL in `psql -c`, `mysql -e` and
  `--stdin-file`, and the commands sent to `redis-cli`, `valkey-cli` and
  `keydb-cli`. It also catches `sort -o`, `uniq IN OUT`, `split`,
  `openssl -out`, `date -s`, `hostname NAME`, `dmesg -C` and `less +CMD`.
- The danger check stops `bash --rcfile FILE -c ...`, `ufw --force reset`,
  `iptables -P INPUT DROP`, writes onto `/etc/passwd`, `/etc/shadow` or
  `/etc/sudoers` with `cp`, `mv`, `tee`, `truncate` or `dd`,
  `echo '...' | sh` and `base64 -d | sh`.
- `secret set` checks that `KOMANDO_VAULT_PASS` opens the secrets already
  stored. A missing `vault.key` is no longer replaced by a new one while
  secrets need it: komando asks you to restore it.

## Changed (breaking for scripts that read exit codes)

- `NO_AUTH` (a server with no key, identity or password, and no ssh-agent
  key) exits 4, like `AUTH_FAILED`. It was 2.
- `SECRET_UNRESOLVED` (a password reference that cannot be read) exits 3
  everywhere. It was 2 for servers and 1 for conns and registry CAs.
- The agent guide's error table now says `PARTIAL_FAILURE` exits with the
  worst code among the failed servers, which is what komando already did.

## Added

- Release archives include `THIRD_PARTY_LICENSES`, with the license texts
  and NOTICE files of the Go modules and the Go standard library built into
  komando. `make licenses` writes it on its own.
- `install.sh` installs a chosen version with `KOMANDO_VERSION=vX.Y.Z`.
- The README has Update, Uninstall and "Something wrong?" sections, says how
  to move the vault key into the system keychain (`komando secret keychain`),
  and gives the Go version needed for `go install` (1.27 or newer).
- The docs explain how to turn on the AI agent seatbelts for agents komando
  does not recognize by name: set `KOMANDO_AGENT=1` (or `AI_AGENT=1`) in the
  agent's environment.
- The README says that on a protected server `exec` needs `--read-only` for
  commands that only read.

## Fixed

- `install.sh` no longer installs into `~/.local/bin` when
  `KOMANDO_INSTALL_DIR` is set but cannot be written. It creates the folder,
  or stops with a message.

## For maintainers

- CI also vets and builds for macOS, and every CI job has a timeout.
- `release.yml` passes the tag to `make dist` through `$GITHUB_REF_NAME`
  instead of an expression in the `run:` line.
- `make dist` now runs a pinned `go-licenses` (v2.0.1), so the release build
  needs the Go module proxy.
- The e2e scripts pass `shellcheck -S warning`, print komando's output when a
  check cannot parse it, and check the SFTP/FTPS upload result directly.
  The cause of the occasional FTPS e2e failure is not fixed yet.
- The roadmap in `docs/design/vision.md` calls its steps milestones M2 to M7,
  not release numbers.

## Known issues

- `golang.org/x/crypto` v0.58.0 has advisory GO-2026-5932 at the module
  level. govulncheck reports that komando does not call the affected code. No
  fixed x/crypto release existed when this draft was written.

## Install or update

```bash
curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh
```

Check a download: `gh attestation verify FILE --repo sgnd/komando`
