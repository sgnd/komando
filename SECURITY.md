# Security

komando logs in to real servers, databases and caches, holds their passwords, and is run by AI agents. A security bug in komando can reach all of them.

## Report a problem

Please don't open a public issue for a security problem. Report it privately instead:

1. Open the [Security tab](https://github.com/sgnd/komando/security) of this repo.
2. Click **Report a vulnerability**.

Include what you found, how to reproduce it, and what an attacker could do with it. You get an answer within a week. Once it is fixed, a new release says what changed.

## What counts

- A way to read a secret from the vault without a human approving it, for example through JSON output (`-o json`), an error message, a log or the audit log, or by having komando send it to a place the agent controls.
- A way to run something on a server that komando should block or refuse: a dangerous command without `--allow-dangerous`, a change on a protected target without `--yes`, a write in `db query` or `cache run` without `--write`.
- A way to inject shell code, SQL or file paths through a name, a flag or a recipe variable.
- Connecting to a server whose identity (host key) changed, without an error.
- Anything that lets an AI agent do more than the person allowed.

A security problem in OpenSSH, a database, a cache, Kubernetes or another tool that komando talks to belongs to that project. Report it there.

## How komando keeps you safe

- komando sends nothing on its own: no usage statistics, no crash reports,
  no background update check. It connects only to what you added or named
  (servers, conns, clusters, registries, VPNs, a password manager or cloud
  in a password reference), to AWS for `komando login aws`, and to GitHub
  when you run `komando update`.

- Passwords and keys live in an encrypted vault in `~/.komando/`. A new vault keeps its key in the OS keychain (the macOS keychain, the Secret Service on Linux), so a backup or a copy of the folder does not open it. Where there is no keychain, the key is a file beside the vault and `komando doctor` warns. An AI agent refers to a secret as `secret:NAME`. An agent komando recognises (Claude Code, Codex, Cursor, Gemini CLI, or any agent with `KOMANDO_AGENT=1` set) never sees the values. When an agent sends a secret somewhere (into a file on a server, a command's environment, or as the password of a new or moved server, conn or VPN), a person allows it in a window that names the secret and the place.
- An AI agent's komando uses your usual data folder: another `KOMANDO_HOME` needs a person's yes.
- Dangerous commands (`rm -rf /`, `reboot`, `DROP TABLE`, `FLUSHALL`, ...) are blocked unless a human allows them.
- On a protected server or conn, komando asks a person before any change; an agent or a script needs `--yes`, which a person approves. Database queries and cache commands only read unless you add `--write`. On a protected target `--read-only` skips `--yes` only for commands komando knows read; anything it does not recognise still needs `--yes`.
- Every value sent to a remote shell is quoted. A vault value given to a
  command (`-e DB_PASS=secret:NAME`) reaches it on its input, never on its
  command line, where other users of the server could read it.
- komando refuses to connect when a server's host key changes. The first
  time it trusts a key, it prints the fingerprint so you can compare it with
  the server's own, writes it to the audit log, and lists it in the JSON
  answer (`meta.host_keys_pinned`).
- Database, cache, queue and storage conns: a new one that crosses the
  network on its own checks the server's certificate unless its URL says
  otherwise (`sslmode=verify-full`, `tls=true`), and a plain one
  (`redis://`, `memcached://`, `amqp://`, `nats://`, an `http://`
  endpoint) needs `?insecure=1`. `komando doctor` lists every
  conn that crosses the network without TLS that checks the server's
  certificate, with the line that fixes it.
- VPNs: IKEv1 offers no 3DES and no DH group below 14, and the server can
  only pick what was offered; PPP (L2TP) does not send your password with
  PAP. Only a person can allow either for one VPN
  (`--legacy-crypto` or `--allow-pap` on `komando vpn add` or `vpn edit`). The OpenVPN
  client wants a certificate made for a server even when the profile does
  not ask for it.
- Another device's SSH key (the Komando app on a phone) can be limited to komando with `komando ssh-gate line`. That key gets:
  - no shell, no file copy and no forwarding, and one komando command at a time;
  - the rules of an AI agent: secrets hidden, `--reveal` and `--allow-dangerous` refused;
  - nothing written on the komando computer itself: no downloads there, no change to komando's servers, settings, rules, secrets or keys, and nothing at all, not even a read, on a sqlite file or a target at `localhost` or a loopback address;
  - optionally, only commands that read;
  - an audit log line for each command, with the key's name, even with the audit setting off.
- At a person's terminal komando asks for what a command is missing. A
  question never adds `--yes`, `--allow-dangerous`, `--reveal` or
  `--write`: a change asks "Run it?", and a step that cannot be undone asks
  for the target's name. Agents and scripts are never asked.
- Everything is written to the audit log: `komando audit`.

## Supported versions

Only the newest release gets fixes. `install.sh` downloads the newest release (or the one `KOMANDO_VERSION` names), never `main`, and checks its checksum.

## Check a download

Every release has `checksums.txt` (install.sh checks it), its signature `checksums.txt.sig`, and signed build provenance (SLSA level 2). `komando update` installs a release only when `checksums.txt.sig` is a signature by the komando project's key, whose public half is built into komando: someone who replaces a release's files cannot sign them. To check that a file was built by this repository's release workflow from its source:

```bash
gh attestation verify komando_darwin_arm64.tar.gz --repo sgnd/komando
```

## Standards

How komando measures up to OWASP ASVS, the OWASP Top 10 for LLM applications, NIST, ISO 27001 and SLSA, and what it does not cover: [docs/features/security-standards.md](docs/features/security-standards.md).

## Good practice for users

- Give komando (and your AI agent) a server user with only the permissions it needs.
- Mark production servers with `komando host edit NAME --protected`.
- Keep `~/.komando/` private and backed up; it holds your vault and keys. A new vault keeps its key in the keychain, so a backup alone cannot open it. A vault from an older komando moves its key there with `komando secret keychain`. On a computer without a keychain, set `KOMANDO_VAULT_PASS` to 15+ characters before your first secret; to change that passphrase later, run `komando secret passphrase` first (it re-encrypts the vault), then update the variable.
- Run `komando doctor` now and then: it checks permissions, the vault, the audit log chain and connections without verified encryption.
- Run `komando guide install`: its guard stops Claude Code, and Cursor, Gemini CLI and Codex where you use them, from reading `~/.komando`, private keys or `.env` files on your computer.
- When your AI agent asks for `--yes`, `--allow-dangerous` or `--reveal`, read the command in komando's window before you click "Allow once".
- Give a phone or another computer that reaches komando over SSH its own key, added with the line `komando ssh-gate line --name NAME` prints, and `--read-only` when it only needs to look.
- Do not list the komando computer itself as a server, conn or cluster under another name or address (its LAN IP, a DNS name, a tunnel back to it). ssh-gate refuses targets that are not in the inventory and every command on `localhost` and loopback addresses, but cannot tell that such a target is the same computer. Any key, a read-only one too, could then read files or run a shell on it (`--read-only` is a filter, not a sandbox).
- The dangerous-command filter catches accidents. It is not a sandbox.
