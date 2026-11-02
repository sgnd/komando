# Security policy

komando handles SSH access to real servers, so security reports matter a lot.

## Reporting a vulnerability

Please **do not** open a public issue. Use GitHub's private
[security advisory form](https://github.com/sgnd/komando/security/advisories/new)
instead. You will get a reply within a few days.

Please include what you found, how to reproduce it, and the impact.

## Supported versions

Only the latest release receives security fixes.

## Good practice for users

- Give komando (and your AI agent) an SSH user with only the permissions it needs.
- Mark production servers with `komando host edit NAME --protected`.
- Keep `~/.komando/` private and backed up; it holds your vault and keys.
- Run `komando guide install` so Claude Code cannot read `~/.komando`,
  private keys or `.env` files on your computer.
- When your AI agent asks for `--yes`, `--allow-dangerous` or `--reveal`,
  read the command in komando's window before you click "Allow once".
- The dangerous-command filter catches accidents. It is not a sandbox.
