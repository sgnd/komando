# Security

komando logs in to real servers, databases and caches, holds their passwords, and AI agents run it. So security problems matter a lot here.

## Report a problem

Please don't open a public issue for a security problem. Report it privately instead:

1. Open the [Security tab](https://github.com/sgnd/komando/security) of this repo.
2. Click **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do with it. You get an answer within a week. Once it is fixed, a new release says what changed.

## What counts

- A way to read a secret from the vault without a human at a terminal, for example through `--json` output, an error, a log or the audit log.
- A way to run something on a server that komando should block or refuse: a dangerous command without `--allow-dangerous`, a change on a protected target without `--yes`, a write in `db query` or `cache run` without `--write`.
- A way to inject shell code, SQL or file paths through a name, a flag or a recipe variable.
- Connecting to a server whose identity (host key) changed, without an error.
- Anything that lets an AI agent do more than the person allowed.

A security problem in OpenSSH, a database, a cache, Kubernetes or another tool that komando talks to belongs to that project. Report it there.

## How komando keeps you safe

- Passwords and keys live in an encrypted vault in `~/.komando/`. `secret get --reveal` works only at a terminal, so an AI agent never sees them.
- Dangerous commands (`rm -rf /`, `reboot`, `DROP TABLE`, `FLUSHALL`, ...) are blocked unless a human allows them.
- Protected servers and conns refuse changes without `--yes`. Database queries and cache commands only read unless you add `--write`.
- Every value sent to a remote shell is quoted.
- komando refuses to connect when a server's host key changes.
- Everything is written to the audit log: `komando audit`.

The dangerous-command filter catches accidents. It is not a sandbox: give komando (and your AI agent) a server user with only the permissions it needs, and keep `~/.komando/` private and backed up.

## Supported versions

Only the newest release gets fixes. `install.sh` always downloads the newest release, never `main`, and checks its checksum.
