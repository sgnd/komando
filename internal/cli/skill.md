---
name: komando
description: Manage servers, databases, caches, object storage, Kubernetes/Docker Swarm clusters, container registries, VPNs and secrets safely through the komando CLI. Use whenever a task touches a remote server or service - checking health, reading logs, editing config, restarting services, updating packages, querying a database, reading a cache, listing a bucket, deploying to a cluster - or when the user mentions komando, SSH, a host name, a database or a server.
---

# komando

komando is one safe command line for DevOps work. Do all server and service
work through it, never with `ssh`, `scp`, `psql`, `mysql`, `redis-cli`,
`kubectl` or `aws s3` directly: komando keeps the read-only default, the
safety checks, the audit log and the secrets out of sight.

## Start every session like this

1. `komando guide` - the full playbook for this komando version. Read it and
   follow it. It is the source of truth; this skill is only the summary.
2. `komando list` - which servers and conns (databases, caches, storage,
   clusters, registries) exist.
3. `komando schema <command>` whenever you are unsure about a flag.

If `komando` is not installed, stop and ask the human to install it:
`curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh`

## Rules

1. Look before you change: `komando test <target>`, `komando facts <target>`,
   then read logs, config and status.
2. Run every change once with `--dry-run` first. Declare read-only shell
   commands with `komando exec <target> --read-only -- '<cmd>'`.
   `db query`, `cache run` and `cluster run` are the other way round: they
   only read unless you add `--write`.
3. Edit files with `komando fs replace <target> <path> --old '...' --new '...' --backup`,
   never with `sed -i` over `exec`. Query databases with `komando db query`.
4. Use `komando job start` for anything that may take more than ~2 minutes.
5. **Never** add `--allow-dangerous` or `--yes` on your own. When a command
   is blocked (exit code 6: `POLICY_BLOCKED`, `PROTECTED_HOST`,
   `PROTECTED_TARGET`, `SAFETY_SETTING`, `WRITE_REQUIRES_FLAG`), stop,
   explain what you want to do and why, and wait for the human's explicit yes.
6. **Never** "fix" `HOSTKEY_MISMATCH` yourself: report it, it may be an attack.
7. `VPN_LOGIN_REQUIRED` or `VPN_DOWN`: ask the human to run
   `komando vpn up <name>`. Logins with a code (MFA) are always done by a human.
8. Secret values are for people only: `secret get --reveal` works only at a
   terminal (`REVEAL_NEEDS_HUMAN` otherwise). Refer to secrets as
   `secret:NAME`, and never put a secret value on a command line.
9. On every failure read `error.hint`: it says what to do next.
10. When done, summarize what you changed, on which targets, and how to roll
    back (`komando audit --limit 20` helps).

## Reading the output

When piped, every command prints one JSON object: branch on `ok`,
`error.code` and the exit code (0 ok, 2 usage, 3 not found, 4 connect/auth,
5 remote failure, 6 needs the human, 7 timeout, 8 precondition failed).
Targets the command could not use are listed in `meta.skipped`.
