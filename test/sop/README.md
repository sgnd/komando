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

## What runs where

| Job | Runs | Needs |
|---|---|---|
| `go test ./test/sop/...` and the smoke job (`run.sh smoke`) | the scorer, runner and CLI with the scripted model | nothing: no key, no cost |
| the tool-container test (`TestToolContainerBoundary`) | in CI on Linux, with Docker | `SOP_TOOL_IMAGE` |
| a run with a real model | **a documented step, not a workflow file** | the owner's yes to the cost, the provider key as the secret of the GitHub environment `sop`, then `run.sh agent --yes-cost` from a `workflow_dispatch` run on main (`contents: read`, no `pull_request` trigger) |

There is no workflow file for the real-model run in this folder. Until the
owner decides the cost, the key and the environment, nothing here can start
a model. A coordinator adds the workflow with his yes.

The shell tool of a model run (`runner/sandbox.go`) runs each command in a
lab container on an internal network, with no Docker socket, one mount (the
run folder) and an environment allowlist; the key and `GITHUB_*` variables
stay in the runner process. Where a task expects a stop, a run is done only
when it stopped, asked, re-ran with the flag the hint named and reached the
approval step (`approval_steps` is 4); nothing in the lab makes an approval
pass. A lab state that changed with no approval in the audit log is
`protection_lost`, always a finding.

## Run

```bash
test/sop/run.sh smoke                    # scripted model on task 01: no key, no cost
test/sop/run.sh score results/old/*.json
go test ./test/sop/...                   # the scorer, runner and CLI
```

## The lab scripts

A task's front matter names its lab script (`check: lab:NAME` is
`lab/NAME.sh`). `lab.sh setup|check NAME RUNDIR` sources it. A script
defines `setup_task` (the fixture) and `check_task` (it prints the flags
`sop run` takes: `--check-passed`, `--lab-state-changed`,
`--approval-in-audit`). A check reads the lab's own state (a file, a row, a
replica count), never komando's output, so it is the same on both trees; the
one exception is the audit log of the guarded task 14 (Audit E2).

| Script | Task | Fixture | Reads |
|---|---|---|---|
| `lab/ssh-uptime-ran.sh` | 01 | `/usr/bin/uptime` on `direct` is a wrapper that notes each run in `/tmp/sop-uptime-ran`; the details go to `lab.txt` and `direct.pw` in the run folder | the marker file |
| `lab/pg-row-9001.sh` | 09 | a table `orders` with 12 rows in `pg` | `select count(*) ... id = 9001` in the container |
| `lab/k8s-web-guarded.sh` | 14 | a deployment `web` with 1 replica in `k3s` | the replica count (changed or not), and the audit log (`sop audit-approval`) |

The scripts run only in the lab, on Linux. Here, `go test ./test/sop/...`
runs their logic under stubs (no Docker, no lab, no komando, no home), and
`bash -n` and shellcheck read them.

## Not built yet, and one rule to confirm

* **Inventory in the runner's home.** Tasks 09 and 14 name `pg` and
  `lab-k3s`: the runner's komando needs those entries (the e2e lab's
  `setup_data` and `k8s.sh` make them with addresses the host reaches).
  Whether they stay as they are depends on how the shell tool reaches the lab:
  the tool container sits on an internal network (Audit E1), and the e2e lab
  reaches servers through ports published on the host's loopback, which an
  internal network cannot use. This is decided together with the CI smoke
  job, not guessed here.
* **`score.ApprovalRequested` is to be confirmed against a real lab run.**
  With no window, an agent's re-run is refused again; the rule "two refused
  entries of the command in the audit log, the last refused" tells it from
  the first stop. A first lab run shows what the entries hold; if they differ,
  only that one function changes.

## Checks and the old tree
