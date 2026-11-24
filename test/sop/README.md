# Test SOP harness

The tasks, scorer and runner of the komando test SOP: the same 20 everyday
tasks run by agent models and a person, first on the old tree, then on the
new one. Design: the vault note `2026-11-24-komando-v2-7-test-sop-design`.
This folder is a test tool; nothing in the product imports it.

| Path | What |
|---|---|
| `tasks/NN-name.md` | one task: front matter (`id`, `area`, `expects`, `cap_steps`, `cap_minutes`, `check`), then the task text. The text names no command of either tree |
| `score/` | the scorer: capture to result; refuses a result file with output or a lab password |
| `runner/` | the model loop, the caps and the scripted person; a scripted model for tests, an API adapter for a real run |
| `cmd/sop/` | `sop run scripted\|agent`, `sop check FILE` |
| `run.sh` | the lab entry (`smoke`, `score`, `agent`); runs only where the e2e lab does, never on a Mac |

## Three rules

1. **No model runs without the owner's yes to the cost.** `sop run agent` refuses
   without `--yes-cost`. The scripted model and the tests cost nothing.
2. **No key in a file.** The adapter reads `SOP_API_KEY` (and `SOP_API_URL`)
   from the environment of the CI job or the lab shell. `TestNoCodePathReadsAKeyFile`
   fails if any harness code opens a file with a key, token or secret in the call.
3. **A result file holds counts and komando's own words, never output.**
   `score.CheckResultFile` refuses an unknown field (stdout, stderr), trailing
   data and any lab password; values after `--password`, `--token`, `--value`
   and paths outside the lab are replaced.

## Run

```bash
test/sop/run.sh smoke                    # scripted model on task 01: no key, no cost
test/sop/run.sh score results/old/*.json
go test ./test/sop/...                   # the scorer, runner and CLI
```

## Checks and the old tree

A task's `check` names a lab check (`lab:pg-row-9001`). A check reads the
lab's state (a row, a file, a replica count), never komando's own output, so
it is the same on both trees. The lab checks are added with the lab area of
each task; the three first tasks (01, 09, 14) are the pilot.
