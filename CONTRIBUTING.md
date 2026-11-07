# Contributing

Thanks for helping! Please write issues, pull requests and docs in English.

komando is open source under the [AGPL-3.0](LICENSE), and is also sold under a
[commercial license](COMMERCIAL-LICENSE.md) that pays for its work. Before your
first pull request is merged, please sign the
[Contributor License Agreement](CLA.md): a bot asks you on the pull request, and
you sign once by writing a comment. You keep the copyright of what you wrote.

komando is one command line for DevOps work, for people and their AI agents. It stays simple on purpose: one static binary, no windows or menus, safe by default.

## Report a bug or suggest a feature

Use the [Bug report](https://github.com/sgnd/komando/issues/new?template=bug-report.yml) or [Suggest a feature](https://github.com/sgnd/komando/issues/new?template=suggest-a-feature.yml) form. For a security problem, see [SECURITY.md](SECURITY.md) instead.

## Before you add something

A change fits when all of these are true:

- It is DevOps work on a server, database, cache, storage, cluster, registry or VPN.
- It works as a command, for a person and for an AI agent. No prompts, no windows.
- It is safe by default: it only reads unless the user says otherwise.
- It needs no new dependency, or the dependency is small and well kept.

Bigger features start as a design note in [`docs/design/`](docs/design/) (for example [resources and `komando db`](docs/design/resources-and-db.md)). Open an issue first if you are not sure.

## Get started in 3 commands

You need [Go](https://go.dev/dl/) (the version in [`go.mod`](go.mod) or newer),
`make` and `git`. The end-to-end tests also need
[Docker](https://docs.docker.com/get-docker/).

```bash
make build    # compile ./bin/komando
make test     # fast unit tests (no servers needed)
make e2e      # real SSH tests in Docker (bastion + private target)
```

`make help` lists everything.

## Easiest first contribution: add a recipe

Recipes are ready-made checks (`komando recipe list`). They live in one list in [`internal/cli/ops.go`](internal/cli/ops.go). Add an entry like:

```go
{Name: "swap-usage", Category: "system", Desc: "Processes using swap",
 Cmd: `for f in /proc/*/status; do awk '/^(Name|VmSwap)/{printf $2" "}END{print ""}' $f; done | sort -k2 -n -r | head -n {{limit}}`,
 Params: map[string]string{"limit": "10"}},
```

- `{{name}}` is replaced by a safely quoted value (`--var name=value`).
- Set `Sudo: true` if root is usually needed, `Mutating: true` if it changes anything.
- Keep it portable (Debian/Ubuntu and RHEL-family at least).

## Add or change a command

Each area has its own file in `internal/cli/` (`host.go`, `exec.go`, `fs.go`, `db.go`, `cluster.go`, ...). Follow these rules. They are what makes komando usable by AI agents:

1. **Print results only via `out.P.Print`.** It writes one JSON envelope when piped (agents) and readable text in a terminal (humans). Give a result type a `Text() string` method if the generic text view is not clear enough.
2. **Never prompt.** Missing input is an error with a `hint`.
3. **Typed errors**: `out.Errf(exitCode, "UPPER_SNAKE_CODE", "hint: what to do next", "message")`. Reuse existing codes and exit codes (see `internal/out/out.go`).
4. **Multi-host commands** return `data.results[]` + `data.summary` (use `fanout`, `probe` or `runFleet` in `common.go` / `exec.go`).
5. **Safety**: anything that changes a server must call `guard(...)` with `mutating=true`, respect `--dry-run`, and call `audit(...)`.
6. **Quote everything** sent to a remote shell with `sshx.Q`.
7. Add a unit test for pure logic and, when it touches SSH, a check in `test/e2e/run.sh`.
8. **Say what it does**: add the command to `commandKinds` in [`internal/cli/kinds.go`](internal/cli/kinds.go) (`reads`, `changes` or `dependsOn("why")`). A test fails on a command without one.
9. **Keep pieces small**: a function up to 100 lines, a file up to 800. Split instead of growing ([`internal/codesize`](internal/codesize/codesize_test.go) checks it).
10. **Never break the JSON**: fields may be added, never renamed or removed. `TestOutputShapes` keeps the shape of the answers; after adding a field, run `go test ./internal/cli -run TestOutputShapes -update-shapes`.

The reasons behind 8–10, and what comes next, are in [docs/design/maintenance.md](docs/design/maintenance.md).

Update the docs in the same pull request:

- the feature's page in [`docs/features/`](docs/features/README.md);
- `internal/cli/guide.md` (what `komando guide` prints) if an AI agent should use it differently;
- `internal/cli/skill.md`, then copy it to `skills/komando/SKILL.md` (a test checks that they match).

A test also reads every `komando ...` example in the docs (`README.md`, `AGENTS.md`, `CONTRIBUTING.md`, `SECURITY.md`, `docs/features/`, the guide and the skill) and fails when a command, subcommand or flag does not exist.

## Send a pull request

1. Make the change, with tests.
2. Run the checks:

   ```bash
   make lint     # gofmt, go vet, staticcheck
   make cover    # unit tests, and coverage may not drop below test/coverage-floor.txt
   make security # known vulnerabilities (govulncheck)
   make e2e      # needs Docker; run it when the change talks to a server or service
   ```

   VPN changes also have `make e2e-openvpn`, `make e2e-ipsec` and `make e2e-vpnclients` (GitHub runs them every night and on VPN pull requests).

3. Add a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) if users will notice the change.
4. Open the pull request. [GitHub](.github/workflows/ci.yml) runs lint, unit tests, the security check and the end-to-end tests again.

## Release a version

Every version is a GitHub release, and `install.sh` only downloads releases. `main` can be ahead of them.

1. In [`CHANGELOG.md`](CHANGELOG.md), rename `## [Unreleased]` to `## [X.Y.Z]` and start a new empty `## [Unreleased]` above it. In the link footer at the end of the file, add a `[X.Y.Z]` compare link from the previous tag and change `[Unreleased]` to compare from `vX.Y.Z`.
2. Commit, then push the tag:

   ```bash
   git tag vX.Y.Z && git push origin main vX.Y.Z
   ```

3. [Release](.github/workflows/release.yml) runs every test again, checks that `CHANGELOG.md` has a section for the version, builds the binaries for Linux and macOS (amd64 and arm64), signs their build provenance and publishes the release. If a test fails, nothing is published: fix it, delete the tag (`git push origin :vX.Y.Z`) and tag again.

## Writing

- `gofmt`, `go vet` and `staticcheck` must pass (`make lint`).
- Keep it simple. Prefer a small, obvious solution over a clever one.
- Write for beginners: simple words, short sentences, a real example first. Many readers have never used a terminal.
- New features get their own page in [`docs/features/`](docs/features/README.md); only the most important ones also get a line in `README.md`. Explain a new word in the [glossary](docs/features/glossary.md).

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
