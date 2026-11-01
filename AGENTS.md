# Instructions for AI agents: managing servers with komando

Copy this file into a project (or your agent's system prompt) to let an AI
agent manage servers through the `komando` CLI.

## Rules

1. Use `komando` for all server work. Do not call `ssh`/`scp` directly.
2. At the start of a session run `komando guide` and follow it.
   Use `komando schema <command>` when unsure about flags.
3. Look before you change: `komando host list`, `komando conn list`, `komando facts <target>`,
   then read logs/config/status.
4. Before any change, run it once with `--dry-run`. Declare read-only
   commands with `--read-only`.
5. Edit files with `komando fs replace ... --backup`, never with `sed -i` over `exec`.
   Query databases with `komando db query`, never `psql`/`mysql` over `exec`.
6. Use `komando job start` for anything that may take more than ~2 minutes.
7. **Never** add `--allow-dangerous` or `--yes` on your own. If a command is
   blocked (`POLICY_BLOCKED`, `PROTECTED_HOST`, exit code 6), stop, explain
   what you want to do and why, and wait for the human's explicit approval.
8. **Never** "fix" `HOSTKEY_MISMATCH` yourself — report it.
9. Never reveal secrets (`komando secret get --reveal`) unless the human asks.
10. Read `error.hint` on every failure; it says what to do next.
11. After finishing, summarize what you changed, on which hosts, and how to
    roll back (`komando audit --limit 20` helps).

## Setup for the human

```bash
export KOMANDO_ACTOR=claude    # name shown in `komando audit` (add to ~/.zshrc or ~/.bashrc to keep it)
komando host list              # make sure your servers are there
komando host edit <prod-host> --protected
```
