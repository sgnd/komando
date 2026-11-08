# Security

komando logs in to real servers, databases and caches, holds their passwords, and is run by AI agents. Security problems matter a lot here.

## Report a problem

Please don't open a public issue for a security problem. Report it privately instead:

1. Open the [Security tab](https://github.com/sgnd/komando/security) of this repo.
2. Click **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do with it. You get an answer within a week. Once it is fixed, a new release says what changed.

## What counts

- A way to read a secret from the vault without a human approving it, for example through JSON output (`-o json`), an error message, a log or the audit log.
- A way to run something on a server that komando should block or refuse: a dangerous command without `--allow-dangerous`, a change on a protected target without `--yes`, a write in `db query` or `cache run` without `--write`.
- A way to inject shell code, SQL or file paths through a name, a flag or a recipe variable.
- Connecting to a server whose identity (host key) changed, without an error.
- Anything that lets an AI agent do more than the person allowed.

A security problem in OpenSSH, a database, a cache, Kubernetes or another tool that komando talks to belongs to that project. Report it there.

## How komando keeps you safe

- Passwords and keys live in an encrypted vault in `~/.komando/`. An AI agent refers to them as `secret:NAME` and never sees the values.
- Dangerous commands (`rm -rf /`, `reboot`, `DROP TABLE`, `FLUSHALL`, ...) are blocked unless a human allows them.
- Protected servers and conns refuse changes without `--yes`. Database queries and cache commands only read unless you add `--write`.
- Every value sent to a remote shell is quoted. A vault value given to a
  command (`-e DB_PASS=secret:NAME`) reaches it on its input, never on its
  command line, where other users of the server could read it.
- komando refuses to connect when a server's host key changes. The first
  time it trusts a key, it prints the fingerprint so you can compare it with
  the server's own, and writes it to the audit log.
- Database and cache conns: `komando doctor` lists every one that crosses
  the network without TLS that checks the server's certificate, with the
  line that fixes it.
- VPNs: IKEv1 offers no 3DES and no DH group below 14, and the server can
  only pick what was offered; PPP (L2TP) does not send your password with
  PAP. Only a person can allow either for one VPN
  (`komando vpn edit NAME --legacy-crypto` or `--allow-pap`). The OpenVPN
  client wants a certificate made for a server even when the profile does
  not ask for it.
- Everything is written to the audit log: `komando audit`.

## Supported versions

Only the newest release gets fixes. `install.sh` always downloads the newest release, never `main`, and checks its checksum.

## Check a download

Every release has `checksums.txt` (install.sh checks it) and signed build provenance (SLSA level 2). To check that a file was built by this repository's release workflow from its source:

```bash
gh attestation verify komando_darwin_arm64.tar.gz --repo sgnd/komando
```

## Standards

How komando measures up to OWASP ASVS, the OWASP Top 10 for LLM applications, NIST, ISO 27001 and SLSA, and what it does not cover: [docs/features/security-standards.md](docs/features/security-standards.md).

## Good practice for users

- Give komando (and your AI agent) a server user with only the permissions it needs.
- Mark production servers with `komando host edit NAME --protected`.
- Keep `~/.komando/` private and backed up; it holds your vault and keys. Set `KOMANDO_VAULT_PASS` (15+ characters) so a backup alone cannot open it.
- Run `komando doctor` now and then: it checks permissions, the vault, the audit log chain and connections without verified encryption.
- Run `komando guide install` so Claude Code cannot read `~/.komando`, private keys or `.env` files on your computer.
- When your AI agent asks for `--yes`, `--allow-dangerous` or `--reveal`, read the command in komando's window before you click "Allow once".
- The dangerous-command filter catches accidents. It is not a sandbox.
