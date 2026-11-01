# Contributing to komando

Thanks for helping! 🇮🇩 Kontribusi dalam Bahasa Indonesia juga sangat diterima —
issue dan pull request boleh ditulis dalam Bahasa Indonesia atau English.

## Get started in 3 commands

```bash
make build    # compile ./bin/komando
make test     # fast unit tests (no servers needed)
make e2e      # real SSH tests in Docker (bastion + private target)
```

`make help` lists everything.

## Easiest first contribution: add a recipe

Recipes are ready-made diagnostics (`komando ops list`). They live in one list
in [`internal/cli/ops.go`](internal/cli/ops.go). Add an entry like:

```go
{Name: "swap-usage", Category: "system", Desc: "Processes using swap",
 Cmd: `for f in /proc/*/status; do awk '/^(Name|VmSwap)/{printf $2" "}END{print ""}' $f; done | sort -k2 -n -r | head -n {{limit}}`,
 Params: map[string]string{"limit": "10"}},
```

- `{{name}}` is replaced by a safely quoted parameter (`--param name=value`).
- Set `Sudo: true` if root is usually needed, `Mutating: true` if it changes anything.
- Keep it portable (Debian/Ubuntu and RHEL-family at least).

## Adding or changing a command

Each area has its own file in `internal/cli/` (`host.go`, `exec.go`, `fs.go`,
`job.go`, `tunnel.go`, `modules.go`, …). Follow these rules — they are what
makes komando usable by AI agents:

1. **Print results only via `out.P.Print`.** It writes one JSON envelope when
   piped (agents) and readable text in a terminal (humans). Give a result type
   a `Text() string` method if the generic text view is not clear enough.
2. **Never prompt.** Missing input is an error with a `hint`.
3. **Typed errors**: `out.Errf(exitCode, "UPPER_SNAKE_CODE", "hint: what to do next", "message")`.
   Reuse existing codes and exit codes (see `internal/out/out.go`).
4. **Multi-host commands** return `data.results[]` + `data.summary` (use
   `fanout`, `probe` or `runFleet` in `common.go` / `exec.go`).
5. **Safety**: anything that changes a server must call `guard(...)` with
   `mutating=true`, respect `--dry-run`, and call `audit(...)`.
6. **Quote everything** sent to a remote shell with `sshx.Q`.
7. Add a unit test for pure logic and, when it touches SSH, a check in
   `test/e2e/run.sh`.

## Style

- `gofmt` and `go vet` must pass (`make lint`).
- Keep dependencies minimal; komando is a single static binary.
- Keep it simple. Prefer a small, obvious solution over a clever one.
- Write for beginners. New features go in [`docs/usage.md`](docs/usage.md);
  only the most important ones also get a line in `README.md` and `README.id.md`.

## Releasing (maintainers)

1. Move the `Unreleased` notes in [`CHANGELOG.md`](CHANGELOG.md) under a new version.
2. `git tag v0.2.0 && git push origin v0.2.0`
3. GitHub Actions builds the binaries and publishes the release.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Please do not open a public issue.
