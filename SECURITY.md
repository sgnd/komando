# Security policy

komando handles SSH access to real servers, so security reports matter a lot.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private
[security advisory form](https://github.com/sgnd/komando/security/advisories/new)
instead. You will get a reply within a few days.

Please include what you found, how to reproduce it, and the impact.

## Supported versions

Only the latest release receives security fixes.

## Checking a download

Every release has `checksums.txt` (install.sh checks it) and signed build
provenance (SLSA level 2). To check that a file was built by this
repository's release workflow from its source:

```bash
gh attestation verify komando_darwin_arm64.tar.gz --repo sgnd/komando
```

## Standards

How komando measures up to OWASP ASVS, the OWASP Top 10 for LLM
applications, NIST, ISO 27001 and SLSA, and what it does not cover:
[docs/features/security-standards.md](docs/features/security-standards.md).

## Good practice for users

- Give komando (and your AI agent) an SSH user with only the permissions it needs.
- Mark production servers with `komando host edit NAME --protected`.
- Keep `~/.komando/` private and backed up; it holds your vault and keys.
  Set `KOMANDO_VAULT_PASS` (15+ characters) so a backup alone cannot open it.
- Run `komando doctor` now and then: it checks permissions, the vault, the
  audit log chain and connections without verified encryption.
- Run `komando guide install` so Claude Code cannot read `~/.komando`,
  private keys or `.env` files on your computer.
- When your AI agent asks for `--yes`, `--allow-dangerous` or `--reveal`,
  read the command in komando's window before you click "Allow once".
- The dangerous-command filter catches accidents. It is not a sandbox.
