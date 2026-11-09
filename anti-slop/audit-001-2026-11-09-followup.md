# antislop audit 001: follow-up (2026-11-09)

All 23 items of [audit-001-2026-11-09.md](audit-001-2026-11-09.md) were approved and fixed on branch `fix/antislop-audit`. 67 files changed. Nothing is committed yet.

## What changed, per item

| # | Fix |
|---|---|
| 1 | README.md:15 and SECURITY.md:26: secrets are hidden from an agent komando recognises (Claude Code, Codex, Cursor, Gemini CLI, or any agent with `KOMANDO_AGENT=1`). |
| 2 | security-standards.md: the hooks sentence now names that condition. LLM02 and LLM06 are 🟡 with the gap named. |
| 3 | security-standards.md: row 8.3 is 🟡, and row 9.1 says "by default" and names `--legacy-crypto` and `--allow-pap`. `.github/workflows/cla.yml` now has top-level `permissions: {}`, with the write permissions on the `cla` job, so the Token-Permissions ✅ is true. |
| 4 | `errcodes_test.go`: the scanner now finds codes without an underscore, codes set through a variable, and codes passed through wrapper functions. The catalog grew from 233 to 249 codes. New ones: CERT_PROBLEMS, NXDOMAIN, SECRET_DESTINATION, K8S_CONFLICT, K8S_ERROR, K8S_INVALID, KUBECONFIG, REGISTRY_AUTH, REGISTRY_UNSUPPORTED, SKIPPED. |
| 5 | FAILED (`cluster run`/`exec`), TIMEOUT and CANCELLED have their own hints now. `internal/out` gives any error without a hint a general one for its exit code, in JSON and in text, so `error.hint` is never empty. New test: `TestErrorJSONAlwaysHasHint`. output.md:51 says exactly that. |
| 6 | The catalog takes each code's example and hint from the same call site. All 249 entries were read through, and entries that did not fit were fixed (DEPLOY_FAILED now describes `key deploy`). About 60 hints that used to be empty are now filled. |
| 7 | guide.md: WRITE_FAILED exits 1 for a file on this computer and 5 for a file on a server. CONFIRM_REQUIRED was added to the exit-6 row. |
| 8 | CHANGELOG.md:30: "more hints now name a whole command you can run". |
| 9 | root.go package comment, scoped honestly: a terminal gets text, a person at a terminal can be asked, and `update` run as root is not audited. |
| 10 | network.md: `--port 15432`; no `--bind` (a different listen address goes in the `-L`/`-D` spec and needs `--yes`); `VPN_IN_USE`. |
| 11 | resources-and-db.md: `--arg VALUE`, the audit log stores only how many `--arg` values there were, and the link points to `docs/features/databases.md`. |
| 12 | built-in.md: `cluster exec`, `cluster shell`, and copying through `cluster run TARGET -- cp`. |
| 13 | vision.md: the import table matches `importSources`. aws uses `aws_profile` and copies no key; termius and tableplus are removed; rclone, filezilla and csv are corrected or added. |
| 14 | gap/README.md: PARTIAL is `39 (+1 NOT PLANNED)` and the total is 256. "Biggest P2 themes" now separates what is open from what is done, each checked in the code. |
| 15 | netx.go package doc: which VPN kinds run inside komando, the openconnect family, and the deprecated OpenVPN `--os-mode`. |
| 16 | No em dashes left in README, guide.md, commands.md, servers.md or features/README.md. An empty table cell now says "none". |
| 17 | About 300 em dashes replaced across 14 design docs. `git grep -c '—'` finds 0 in the whole repo. |
| 18 | "80%" removed from vision.md and ux.md. |
| 19 | README intro bullets without bold lead-ins. |
| 20 | No mechanical bold in "Safety, in one minute". |
| 21 | registry.md: one `secret set lan-ca` line. |
| 22 | Every dash-banner comment removed or replaced with a plain line: about 45 in internal/cli, openvpn and kube, plus 24 found later in internal/ipsec. None are left. |
| 23 | storage.go lists every storage kind, and the change-history asides in sslvpn.go and sshx/client.go are deleted. |

## Tests

- **gofmt, go vet and staticcheck v0.8.2** (`make lint`): clean.
- **`go test -race -count=1 ./...`**: all 23 packages ok.
- **`make e2e`**: passed 933, failed 0.

## Delivery Gate (text only; komando has no UI)

- **R-02 PASS:** `git grep -c '—'` gives 0 for every file in the repo (the `anti-slop/` reports excluded).
- **R-17/R-36/R-38 PASS:** every claim from the audit now matches the code. The checks for each item are in the table above.
- **R-24/R-26 PASS:** the commands, flags, codes and links named in the audit now exist. The docs example test (`go test ./internal/cli/ -run 'Doc|Help|Example'`) passes.
- **R-31 PASS:** no decorative comment banners are left in non-test Go files.
- **Not applicable:** the visual rules (contrast, mobile, keyboard, themes).

## Rollback

Everything is unstaged on `fix/antislop-audit`. `git checkout release/0.8.0 && git branch -D fix/antislop-audit` discards it, after a `git stash` or `git restore .` to drop the working-tree changes.

## Left open

- **Codes with only a general hint:** K8S_ERROR, SWARM_ERROR, NO_PASSPHRASE and VPN_CLIENT_MISSING have catalog hints, but some of their call sites give no hint of their own, so those calls get the general hint.
- **WRITE_FAILED in the catalog:** it is listed as exit 1, the exit most of its call sites use. A write on a server exits 5, and `guide.md` says so.
