# Keeping komando maintainable

komando grew to about 68,000 lines of Go (plus 20,000 lines of tests) in
its first week. Most of it is written with AI agents. That is fast, but
nobody holds the whole program in their head, so the code itself must make
mistakes hard: small pieces, rules that tests check, and outputs that
cannot change by accident. This page says what is in place, why, and what
comes next.

## Where things stood (2026-11-07)

- `internal/cli` held 40,000 lines: 59% of the program, about 225
  commands in one Go package. Some functions were 200–270 lines long,
  seven files over 1,000 lines.
- The packages under it (`policy`, `driver`, `openvpn`, `cloud`, ...)
  are small and well tested (75–92%).
- The safety checks (`guard`, `guardConns`, `guardProtection`,
  `guardSafety`, `guardDocker`, `guardBody`) are called by hand in each
  command. Nothing said which commands change things, so a new command
  that forgot its check would not be noticed.
- Weakly tested: `storex` 7%, `ipsec` 20%, `netx` 27%, `dbx` 34%,
  `cachex` 38%, `cli` 55%.
- The VPN end-to-end tests ran only when someone ran them by hand.

## Rules now checked by tests

| Rule | Where | What fails |
|---|---|---|
| Every command says whether it reads or changes things | `internal/cli/kinds.go`, `TestEveryCommandHasKind` | a command without a kind; a `reads` command with `--allow-dangerous` or `--write` |
| The JSON answers keep their shape | `internal/cli/testdata/shapes.json`, `TestOutputShapes` | a field that is renamed, removed or changes type; a changed error code |
| Functions up to 100 lines, files up to 800 | `internal/codesize` | new code over the limit; old code (listed in `testdata/allowed.txt`) that grows |
| Coverage does not drop | `test/coverage.sh`, `test/coverage-floor.txt` (`make cover`, in CI) | a package below its floor |
| VPN clients work against real servers | `.github/workflows/vpn-e2e.yml` | nightly, and on pull requests that touch VPN code |

The kind is also in `komando schema` (`kind`, `kind_note`), so agents see
it before they run a command.

## What was deliberately not done

- **One shared safety function instead of six.** The six checks look
  alike but take different input: a shell command, a driver verdict, a
  list of protected names. Merging them would change behaviour in small
  ways, and behaviour must not change. The kinds table makes the gap
  visible first; merging can follow, one check at a time, with the shape
  test and the e2e tests as a net.
- **Removing the line numbers in `docs/design/gap/`.** Those reports are
  a snapshot of commit `4784fc9`, and the line numbers are evidence for
  that commit. They are read as such, not as pointers into today's code.

## Next steps

Do these in order, one area per pull request. Each one must keep every
test green, including `TestOutputShapes`, and `make e2e`.

1. **Raise the weakest coverage first:** `storex`, `ipsec`, `netx`,
   `dbx`, `cachex`. Raise the floor in `test/coverage-floor.txt` with
   each.
2. **Shrink what is in `internal/codesize/testdata/allowed.txt`.** Start
   with the longest functions (`vpnAddCmd`, `kctlRun.create`,
   `secretCmd`, `startSession`, `runFleet`). The usual cut: the cobra
   builder only reads flags and calls one function that does the work.
3. **Move areas out of `internal/cli` into their own packages**, so that
   `internal/cli` only turns flags into calls. The cluster code
   (`cluster*.go`, `clu_*.go`, `kctl*.go`, about 11,000 lines) is the
   biggest, but it uses about 35 names from the rest of `internal/cli`
   (`g`, `toErr`, `loadState`, `guard`, `audit`, `withClient`, ...).
   First move those shared pieces into a small package that both can
   use, then move one area at a time: cluster, then vpn, then fs.
4. **Merge the safety checks** into one entry point that takes the kind,
   the targets and the verdict, one check at a time (see above).
5. **Describe the `data` of each answer** in `komando schema`, built from
   the same shapes `TestOutputShapes` keeps.

## Rules for every new feature

- Add the command to `commandKinds`.
- Keep functions under 100 lines and files under 800.
- Add a check to `test/e2e/checks/coverage.sh` so the command runs at
  least once end to end.
- Never rename or remove a JSON field; add a new one instead.
