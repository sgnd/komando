# Safety

The seatbelts, and what to do when one stops you. [All features](README.md)

| Seatbelt | What it does |
|----------|--------------|
| Dangerous-command filter | Blocks `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh` *on your servers*, firewall flush, stopping SSH and more. See `komando policy list`. |
| Protected servers and conns | Changes need `--yes`. Commands that only look (not change) can say so with `--read-only` and run without `--yes`. Removing a protected one, replacing it, or turning protection off needs `--yes` too. Anything at the same address (a `user@address` target, a second name, a second conn to the same database server) is protected as well. |
| Safety settings | Turning off the audit log or server identity checks, or removing a deny rule, needs `--yes`. |
| Asking a human | When you type a command yourself in a terminal, komando asks instead of failing: `[y/N]` for protected targets, and typing the target's name for dangerous commands. Agents and scripts never see these questions; they need the flags. |
| Dry run | `--dry-run` shows what would run and whether it would be blocked. |
| Safe edits | Atomic writes, exact-match replace, optional `.bak` backups. |
| Encrypted vault | Passwords are AES-256-GCM encrypted. Only names are ever shown. |
| Server identity | A changed server fingerprint stops the connection (`HOSTKEY_MISMATCH`). |
| History | Every action is in `komando audit`. |

Overriding a block needs `--allow-dangerous` — a human decision.
Secrets are never accepted as command arguments (they would land in your
shell history): `komando secret set NAME` asks for the value, or use
`--from-env VAR` or a pipe.
Add your own rules with `komando policy deny 'REGEX'`.

> The filter catches common accidents; it is not a complete security
> boundary. Give automation an SSH user with only the permissions it needs.
