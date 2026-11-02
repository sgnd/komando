# Safety

The seatbelts, and what to do when one stops you. [All features](README.md) · [Security standards](security-standards.md)

| Seatbelt | What it does |
|----------|--------------|
| Dangerous-command filter | Blocks `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh` *on your servers*, firewall flush, stopping SSH and more. See `komando policy list`. |
| Protected servers and conns | Changes need `--yes`. Commands that only look (not change) can say so with `--read-only` and run without `--yes`. Removing a protected one, replacing it, or turning protection off needs `--yes` too. Anything at the same address (a `user@address` target, a second name, a second conn to the same database server) is protected as well. |
| Safety settings | Turning off the audit log or server identity checks, or removing a deny rule, needs `--yes`. |
| Asking a human | When you type a command yourself in a terminal, komando asks instead of failing: `[y/N]` for protected targets, and typing the target's name for dangerous commands. Agents and scripts never see these questions; they need the flags. |
| A person allows what an AI agent asks | When an AI agent (Claude Code, Codex, Gemini CLI, Cursor) adds `--yes`, `--allow-dangerous` or `--reveal`, komando opens a window on your screen showing the exact command; it runs only when you click **Allow once**. The agent cannot click it. With no screen to show it on (an SSH session, a server), the agent is refused and asks you to run the command in your own terminal. Scripts use the flags as before. |
| Secrets hidden from AI agents | For an AI agent, passwords, keys and tokens in any output (a `.env` file, `env`, a log line, a database row, a Kubernetes Secret, private keys, password hashes) show as `[hidden]`. You and your scripts see the real values. The agent can still set one: `fs replace --old 'DB_PASSWORD=[hidden]' --new 'DB_PASSWORD={{secret:db}}'` puts the vault value on the server without the agent seeing it. Text that still holds `[hidden]` is never written over a real file. |
| Secret files stay on the server | An AI agent cannot copy a file that is a secret by its name (`.env`, private keys, `credentials`, `shadow`, ...) to this computer; folder copies leave them out. It reads them with `fs cat`, masked. |
| Guard on this computer | `komando guide install` adds a guard to Claude Code: before Claude reads a file or runs a shell command, komando checks it and stops reading `~/.komando`, private keys, `.env` files, credential stores (`~/.kube`, `~/.aws/credentials`, keychain), listing all environment variables, and `ssh`/`scp` around komando. Skip it with `--no-guard`. |
| Dry run | `--dry-run` shows what would run and whether it would be blocked. |
| Safe edits | Atomic writes, exact-match replace, optional `.bak` backups. |
| Encrypted vault | Passwords are AES-256-GCM encrypted. Only names are ever shown, and only a person at a terminal can see a value (`secret get --reveal`). |
| Hidden in output | If a vault secret shows up in what a server sends back (a `.env` file, a log line, `env`), komando prints `[secret:NAME]` instead, also when it is base64- or URL-encoded. Values shorter than 6 characters are not hidden. |
| Server identity | A changed server fingerprint stops the connection (`HOSTKEY_MISMATCH`). |
| History | Every action is in `komando audit`, with the AI agent that asked and whether a person allowed it. Each record carries the hash of the one before, so `komando audit verify` (and `doctor`) notice an edited, added or removed record. If the audit log cannot be written, komando refuses to run (`AUDIT_UNAVAILABLE`); `komando doctor` shows why. |

Overriding a block needs `--allow-dangerous` — a human decision.
Secrets are never accepted as command arguments (they would land in your
shell history): `komando secret set NAME` asks for the value, or use
`--from-env VAR` or a pipe.
Add your own rules with `komando policy deny 'REGEX'`.

## What this does not stop

komando knows an AI agent by the variables agents set in their shell, and an
agent runs as your own user on your computer. The window, the masking and the
guard stop mistakes and prompt injection (a web page or a file telling the
agent to leak something). They do not stop a program that deliberately hides
what it is or edits the guard away: nothing that runs as you can. So:

- give komando, and so your agent, an SSH user with only the permissions it needs;
- mark production with `komando host edit NAME --protected`;
- keep the vault passphrase-protected (`KOMANDO_VAULT_PASS`) if other people
  or backups can reach `~/.komando`.

> The filter catches common accidents; it is not a complete security
> boundary. Masking is a best effort: a secret under an unusual name, or
> shorter than its neighbours, can still slip through.
