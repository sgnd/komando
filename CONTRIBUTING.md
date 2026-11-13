# Contributing

Thank you for helping. Please write issues, pull requests and docs in English.

komando is open source under the [AGPL-3.0](LICENSE), and is also sold under a
[commercial license](COMMERCIAL-LICENSE.md) that pays for its work. Before your
first pull request is merged, please sign the
[Contributor License Agreement](CLA.md): a bot asks you on the pull request, and
you sign once by writing a comment. You keep the copyright of what you wrote.

komando is one command line for DevOps work, for people and their AI agents. It stays simple on purpose: one static binary, no menus or windows, safe by default. People and agents type the same commands; at a person's terminal komando only asks for what a command is missing.

## Report a bug or suggest a feature

Use the [Bug report](https://github.com/sgnd/komando/issues/new?template=bug-report.yml) or [Suggest a feature](https://github.com/sgnd/komando/issues/new?template=suggest-a-feature.yml) form. For a security problem, see [SECURITY.md](SECURITY.md) instead.

## Before you add something

A change fits when all of these are true:

- It is DevOps work on a server, database, cache, queue, storage, cluster, registry or VPN.
- It works as a command, for a person and for an AI agent. No windows, and no prompt an agent or a script can meet.
- It is safe by default: it only reads unless the user says otherwise.
- It needs no new dependency, or the dependency is small and well kept.

For a bigger feature, open an issue first so the design can be agreed before the code. Every feature follows [docs/design/principles.md](docs/design/principles.md) and the [command standard](docs/design/command-standard.md).

## Build and test

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

Recipes are ready-made checks (`komando recipe list`). They live in one list in [`internal/cli/recipe.go`](internal/cli/recipe.go). Add an entry like:

```go
{Name: "swap-usage", Category: "system", Desc: "Processes using swap",
 Cmd: `for f in /proc/*/status; do awk '/^(Name|VmSwap)/{printf $2" "}END{print ""}' $f; done | sort -k2 -n -r | head -n {{limit}}`,
 Params: map[string]string{"limit": "10"}},
```

- `{{name}}` is replaced by a safely quoted value (`--var name=value`).
- Set `Sudo: true` if root is usually needed, `Mutating: true` if it changes anything.
- Keep it portable (Debian/Ubuntu and RHEL-family at least).

## Add or change a command

Each command has its own files in `internal/cli/`, named for its noun (`host.go`, `db_dump.go`, `cluster_swarm.go`, ...). Where code goes and how packages and files are named is in [docs/design/code-layout.md](docs/design/code-layout.md), with every contributor rule in one list. Follow these rules. They are what makes komando usable by AI agents:

1. **Print results only via `out.P.Print`.** It writes one JSON envelope when piped (agents) and readable text in a terminal (humans). Give a result type a `Text() string` method if the generic text view is not clear enough.
2. **Never prompt an agent or a script.** Missing input is an error with a `hint`. A person at a terminal is asked only for what a flag or argument can also give, through the prompter (`promptable` in `internal/cli/prompter.go` decides who may be asked). A question never adds `--yes`, `--allow-dangerous`, `--reveal` or `--write`.
3. **Typed errors**: `out.Errf(exitCode, "UPPER_SNAKE_CODE", "hint: what to do next", "message")`, with every code listed in `internal/cli/errcodes.go`. Reuse existing codes and exit codes. The words follow [docs/design/message-style.md](docs/design/message-style.md).
4. **Multi-host commands** return `data.results[]` + `data.summary` (use `fanout`, `probe` or `runFleet` in `common.go` / `exec.go`).
5. **Safety**: anything that changes a server must call `guard(...)` with `mutating=true`, respect `--dry-run`, and call `audit(...)`.
6. **Quote everything** sent to a remote shell with `sshx.Q`.
7. Add a unit test for pure logic and, when it touches SSH, a check in `test/e2e/checks/`, listed in the right area of `test/e2e/run.sh` (`make e2e AREA=NAME` runs that area alone).
8. **Say what it does**: add the command to `commandKinds` in [`internal/cli/kinds.go`](internal/cli/kinds.go) (`reads`, `changes` or `dependsOn("why")`). A test fails on a command without one.
9. **Keep pieces small**: a function up to 100 lines, a file up to 800. Split instead of growing ([`internal/codesize`](internal/codesize/codesize_test.go) checks it).
10. **Never break the JSON**: fields may be added, never renamed or removed. `TestOutputShapes` keeps the shape of the answers; after adding a field, run `go test ./internal/cli -run TestOutputShapes -update-shapes`.

A new command needs a form hint, so a person who leaves an argument out is asked for it well: add one in `internal/cli/form_hints_*.go` (which arguments come from a list, which flags to ask first, its `Next:` lines). `TestFormEveryCommandHasAHint` fails until you do, and `TestFormEveryCommandHasAnArea` fails when its first word is in no area of `formAreas` ([`internal/cli/form_cmd.go`](internal/cli/form_cmd.go)). A new kind of server or conn also needs an add form (`TestFormEveryKindHasAnAddForm`). What agents and scripts get must not change by accident: `TestAgentGolden` compares every command against a recording (`KOMANDO_GOLDEN_UPDATE=1` records it again, only on purpose).

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

   VPN changes also have `make e2e-openvpn`, `make e2e-ipsec` and `make e2e-vpnclients` (GitHub runs them every night and on VPN pull requests). Changes to the Windows commands have `make e2e-windows`, which runs komando's PowerShell in a PowerShell container.

   Some packages also have tests against a live service that you start yourself. They are skipped by default; each one's `t.Skip` line names the variable to set.

3. Add a line under `## [Unreleased]` in [`CHANGELOG.md`](CHANGELOG.md) if users will notice the change.
4. Open the pull request. [GitHub](.github/workflows/ci.yml) runs lint, unit tests, the security check and the end-to-end tests again.

## Release a version

Every version is a GitHub release, and `install.sh` only downloads releases. `main` can be ahead of them.

`main` takes changes only through a pull request whose `Lint and unit tests`, `Security` and `End-to-end tests` checks pass (the "Protect main" ruleset), and that includes the release commit. A `git push origin main` is refused.

1. On a new branch from `main`, update [`CHANGELOG.md`](CHANGELOG.md): rename `## [Unreleased]` to `## [X.Y.Z] - YYYY-MM-DD`, give it a `### Highlights` list, and start a new empty `## [Unreleased]` above it. In the link footer at the end of the file, add a `[X.Y.Z]` compare link from the previous tag and change `[Unreleased]` to compare from `vX.Y.Z`. Change the version in the example output in [`docs/features/output.md`](docs/features/output.md) too.
2. Commit it as `Release X.Y.Z` and open a pull request. When its checks pass, merge it with **Create a merge commit**.
3. Tag the merged `main`, and only then push the tag:

   ```bash
   git switch main && git pull
   git tag vX.Y.Z && git push origin vX.Y.Z
   ```

   Do not push the tag before the pull request is merged: the tag starts the release at once, from a commit that is not on `main` yet.
4. [Release](.github/workflows/release.yml) runs every test again, checks that `CHANGELOG.md` has a section for the version, builds the binaries for Linux, macOS and Windows (amd64 and arm64), signs `checksums.txt` with the [release signing key](#the-release-signing-key), signs their build provenance and publishes the release. If a test fails, nothing is published:
   - a test that fails now and then (the FTPS end-to-end test has): run the failed jobs again with `gh run rerun RUN_ID --failed`;
   - a real failure: fix it in a pull request, delete the tag (`git push origin :vX.Y.Z`), and tag the new `main` again.

### The release signing key

`komando update` installs a release only when its `checksums.txt` is signed with a key whose public half is built into komando (`Keys` in [`internal/releasesig`](internal/releasesig/releasesig.go)). The private half is the secret `RELEASE_SIGNING_KEY` of the GitHub environment `release`, which only `v*` tags may use. The release workflow signs with it and writes `checksums.txt.sig`; it stops before publishing when the secret is missing or its public key is not in `Keys`.

Set it up once, in a terminal in this repository (Go and `gh` installed, `gh auth login` done):

1. Make the key. The private key goes into the file you name, never on the screen:

   ```bash
   go run ./scripts/releasesig new ~/komando-release.key
   ```

   It prints the public key (44 characters ending in `=`). Put that line into `Keys` with a pull request.
2. Make the environment `release`, usable only by `v*` tags:

   ```bash
   gh api -X PUT repos/sgnd/komando/environments/release -F 'deployment_branch_policy[protected_branches]=false' -F 'deployment_branch_policy[custom_branch_policies]=true'
   gh api -X POST repos/sgnd/komando/environments/release/deployment-branch-policies -f name='v*' -f type=tag
   ```
3. Store the private key as the environment's secret:

   ```bash
   gh secret set RELEASE_SIGNING_KEY --env release --repo sgnd/komando < ~/komando-release.key
   ```
4. Keep a copy of `~/komando-release.key` somewhere safe that is not this computer's disk (a password manager), then delete the file. GitHub never shows the secret again. Without the key, komandos already installed refuse every later release, and people must reinstall with the install line.
5. Protect the release tags, so only you can make, move or delete a `v*` tag (the signature says "made by our workflow from a `v*` tag", so it is worth only as much as the rule for tags):

   ```bash
   gh api -X POST repos/sgnd/komando/rulesets --input - <<'JSON'
   {"name": "Protect release tags", "target": "tag", "enforcement": "active",
    "conditions": {"ref_name": {"include": ["refs/tags/v*"], "exclude": []}},
    "rules": [{"type": "creation"}, {"type": "update"}, {"type": "deletion"}],
    "bypass_actors": [{"actor_id": 5, "actor_type": "RepositoryRole", "bypass_mode": "always"}]}
   JSON
   ```

   Role 5 is the repository admin: you can still push and delete tags (step 4 of [Release a version](#release-a-version)); nobody else can.

To change the key (it leaked, or you lost it): make a new one, add its public key to `Keys` beside the old one, and release that komando signed with the old key. Then put both private keys in the secret, one per line (each adds a signature), so komandos that know either key update. Once most people run a komando with the new key, remove the old one from `Keys` and from the secret. A leaked key that must stop working at once: remove it from `Keys` and the secret right away; komandos that know only that key must reinstall with the install line.

## Writing

- `gofmt`, `go vet` and `staticcheck` must pass (`make lint`).
- Keep it simple. Prefer a small, obvious solution over a clever one.
- Write docs for beginners, as [the feature guide](docs/features/README.md#writing-these-pages) says: simple words, short sentences, the command first.
- New features get their own page in [`docs/features/`](docs/features/README.md); only the most important ones also get a line in `README.md`. Explain a new word in the [glossary](docs/features/glossary.md).

This project follows the [Code of Conduct](CODE_OF_CONDUCT.md).
