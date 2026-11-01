# komando

**A command-line remote control for your servers, built for AI agents.**

🇮🇩 [Baca dalam Bahasa Indonesia](README.id.md)

---

## What is this, in plain words?

Imagine you have a few computers in the cloud ("servers") that run your website,
database, or app. Normally, to take care of them, a person opens a program like
**Termius** or **PuTTY**, logs in to each server, and types commands.

**komando** does the same job, but it is designed so that an **AI assistant**
(like Claude Code, Codex, or your own bot) can do it for you — safely:

- 📒 **It remembers your servers** — like a phone contact list, but for servers.
- 🔑 **It keeps passwords and keys locked** in an encrypted vault. The AI only
  ever sees a *name* like `secret:db-password`, never the password itself.
- 🧾 **Every answer is structured** (JSON), so the AI understands exactly what
  happened instead of guessing from messy text.
- 🛑 **It has seatbelts.** Dangerous commands (wiping a disk, rebooting,
  deleting a database) are blocked unless a human explicitly allows them.
  Production servers can be marked *protected*.
- 📜 **It writes a diary.** Every action is logged, so you can see later what
  the AI did, where, and whether it worked.

It is **100% command line** — no windows, no menus, no interactive screens.
That is exactly what AI agents need.

```
 You ──ask──▶ AI agent ──runs──▶ komando ──SSH──▶ your servers
                  ▲                  │
                  └──── JSON result ◀┘
```

## What can it do?

| Area | Commands | Example |
|------|----------|---------|
| Server list (inventory) | `host`, `group` | add, import from `~/.ssh/config`, test connections |
| Keys & passwords | `key`, `secret` | generate SSH keys, install them on servers, encrypted vault |
| Run commands | `exec`, `script` | run on one server or 100 in parallel |
| Long tasks | `job` | start a backup, come back later for the result |
| Files | `fs`, `cp` | read/edit config safely, upload/download |
| Tunnels | `tunnel` | reach a private database through a gateway server |
| Health checks | `facts`, `ops` | 39 ready-made checks: disk, memory, ports, certificates, updates… |
| Services | `svc`, `logs` | start/stop/restart, read logs |
| Docker | `docker` | containers, logs, compose |
| Packages | `pkg` | install/upgrade on any Linux (apt, dnf, yum, apk, zypper, pacman) |
| Network | `net` | "can this server reach the database?", HTTP checks, open ports |
| Users & cron | `user`, `cron` | create accounts, schedule jobs |
| For the AI | `guide`, `schema`, `audit`, `policy` | instructions, full command reference, history |

## Install

You need [Go](https://go.dev/dl/) 1.26 or newer.

```bash
go install github.com/sgnd/komando/cmd/komando@latest
```

Or build from this folder:

```bash
make build        # creates ./bin/komando
```

Check it works:

```bash
komando version
```

## 5-minute quickstart

**1. Add a server.** Replace with your own user and address.

```bash
komando host add web1 ubuntu@203.0.113.10 --group web
```

Already use `~/.ssh/config`? Import everything at once:

```bash
komando host import --ssh-config ~/.ssh/config
```

**2. Tell komando how to log in.** If you already log in with an SSH key, it
just works (komando reads `~/.ssh/id_ed25519` and your ssh-agent). If you use a
password, store it in the vault first — it is never shown again:

```bash
echo -n 'my-password' | komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

Better: create a key and install it, so no password is needed anymore:

```bash
komando key gen deploy
komando key deploy deploy web1 --set-default
```

**3. Check the connection.**

```bash
komando host test web1
```

**4. Ask something.**

```bash
komando facts web1                 # what OS, how much memory/disk, which tools
komando ops run health web1        # quick health check
komando exec web1 -- uptime        # any command you like
```

Prefer readable text instead of JSON? Add `-o text`:

```bash
komando -o text exec web1 -- df -h
```

**5. Mark production servers as protected.**

```bash
komando host edit web1 --protected
```

Now any *changing* action on `web1` needs an explicit `--yes`.

## Connect your AI agent

Tell your agent to use komando. For Claude Code, Codex and most agents, copy
[`AGENTS.md`](AGENTS.md) into your project (or paste it into your agent's
instructions). The short version:

> Use the `komando` CLI to manage servers. Run `komando guide` first and
> follow it. Never use `--allow-dangerous` or `--yes` without asking me.

The agent can learn everything by itself:

```bash
komando guide            # how to work safely (step by step)
komando schema           # every command and flag, machine-readable
```

Set a name so the history shows who did what:

```bash
export KOMANDO_ACTOR=claude
komando audit            # see recent actions
```

## Everyday examples

```bash
# Which servers are running low on disk?
komando ops run disk @web

# Why is the website slow? Look at errors in the last 30 minutes
komando logs web1 --unit nginx --since -30m --grep 'error|crit'

# Change one line in a config, keep a backup, then reload
komando fs replace web1 /etc/nginx/nginx.conf \
  --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
komando ops run nginx-test web1
komando svc reload web1 nginx

# Upload a file to every web server
komando cp ./release.tar.gz @web:/tmp/

# Start a long backup and check on it later
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
komando job wait <job-id>

# Reach a private database through a gateway ("bastion")
komando host add db1 admin@10.0.0.5 --jump bastion
komando tunnel start db1 -L 15432:localhost:5432
# now connect your DB tool to localhost:15432

# When does the HTTPS certificate expire?
komando ops run cert-expiry web1 --param name=example.com
```

## Choosing servers ("targets")

Most commands take a *target* — which servers to act on:

| You write | It means |
|-----------|----------|
| `web1` | the server named web1 |
| `web-*` | every server whose name starts with `web-` |
| `@web` | every server in the group `web` |
| `tag:prod` | every server tagged `prod` |
| `label:dc=jkt` | every server with label `dc=jkt` |
| `all` | every server |
| `@web,!web3` | the web group except web3 |
| `root@1.2.3.4:22` | a one-off server not in your list |

## How it keeps you safe

| Seatbelt | What happens |
|----------|--------------|
| Dangerous-command filter | `rm -rf /`, `mkfs`, `reboot`, `DROP DATABASE`, `curl … \| sh`, firewall flush, stopping SSH, and more are blocked (exit code 6). See `komando policy list`. |
| Protected servers | Changing anything needs `--yes`. Reading is always allowed with `--read-only`. |
| Dry run | `--dry-run` shows exactly what *would* run, and whether it would be blocked. |
| Safe edits | `fs replace` only edits when the old text appears exactly once; writes are atomic; `--backup` keeps the old file. |
| Encrypted vault | Passwords are encrypted (AES-256-GCM). The AI sees references, not values. |
| Server identity check | The first connection remembers each server's fingerprint. If it changes later (possible attack), komando refuses to connect (`HOSTKEY_MISMATCH`). |
| Audit log | Every action is written to `~/.komando/audit.jsonl`. |

> The filter catches common accidents; it is **not** a full security boundary.
> Give the agent an SSH user with only the permissions it really needs.

## Understanding the results

Every command prints one JSON object:

```json
{
  "ok": false,
  "command": "exec",
  "data": { "results": [ { "host": "web1", "ok": false, "exit_code": 3, "stdout": "…", "stderr": "…" } ] },
  "error": { "code": "FAILED", "message": "host web1 failed", "hint": "inspect per-host results in data.results" },
  "meta": { "version": "0.1.0", "duration_ms": 211 }
}
```

- `ok` — did everything succeed?
- `data` — the actual answer.
- `error.hint` — **what to do next**. Always read it.

Exit codes: `0` ok · `1` error · `2` wrong usage · `3` not found ·
`4` cannot connect/log in · `5` command failed on the server · `6` blocked for
safety · `7` timeout · `8` edit precondition failed.

## Glossary (for beginners)

| Word | Meaning |
|------|---------|
| **Server** | A computer, usually in a data center or cloud, that runs your apps. |
| **SSH** | The secure "remote control" protocol used to log in to Linux servers. |
| **CLI** | Command-line interface: you type commands instead of clicking. |
| **AI agent** | An AI that can run tools/commands by itself to finish a task. |
| **Inventory** | Your list of servers and how to reach them. |
| **SSH key** | A pair of files that proves who you are, safer than a password. The *private* part stays with you; the *public* part goes on the server. |
| **Vault / secret** | Encrypted storage for passwords. |
| **sudo** | Running a command as the administrator (root). |
| **Jump host / bastion** | A gateway server you go through to reach private servers. |
| **Tunnel / port forwarding** | Making a remote service (e.g. a database) appear on your own computer. |
| **SOCKS proxy** | A tunnel for many destinations at once (`tunnel -D`). |
| **Host key / fingerprint** | A server's ID card. Changes unexpectedly = warning sign. |
| **systemd / service** | How Linux starts and watches background programs (nginx, databases…). |
| **Job** | A long task left running on the server while you do other things. |
| **Exit code** | A number a program returns: 0 = success, anything else = a problem. |
| **JSON** | A structured text format that programs (and AIs) read easily. |
| **Idempotent** | Safe to run twice: the second run changes nothing. |

## Troubleshooting

| Error code | Usually means | Try |
|------------|---------------|-----|
| `AUTH_FAILED` | wrong user, key or password | `komando host show NAME`, `komando key deploy` |
| `CONNECTION_REFUSED` / `CONNECT_TIMEOUT` | server down, wrong port, firewall | check address/port, `--connect-timeout 30s` |
| `HOSTKEY_MISMATCH` | server was rebuilt — or someone is intercepting | verify with your provider, then `komando host trust NAME --reset` |
| `SECRET_UNRESOLVED` | the referenced password/env var is missing | `komando secret list` |
| `sudo: a password is required` | sudo needs a password | `komando host edit NAME --sudo-ref secret:NAME` |
| `POLICY_BLOCKED` | looks destructive | double-check, then (human) `--allow-dangerous` |

Run `komando doctor` to check your local setup.

## Where things are stored

Everything lives in `~/.komando/` (change with `KOMANDO_HOME`):
`state.json` (servers, keys, settings), `vault.json` + `vault.key` (encrypted
secrets), `keys/` (generated SSH keys), `known_hosts`, `audit.jsonl`.
Back this folder up; keep it private.

## Project layout (for contributors)

```
cmd/komando/        entry point
internal/cli/       every command (one file per area: host.go, exec.go, fs.go, …)
internal/sshx/      SSH connections, jump hosts, authentication, running commands
internal/store/     saving state to ~/.komando
internal/vault/     encrypted secrets
internal/policy/    dangerous-command rules
internal/out/       JSON envelope and exit codes
test/e2e/           real end-to-end tests using Docker SSH servers
```

See [CONTRIBUTING.md](CONTRIBUTING.md). Tests: `make test` (fast) and
`make e2e` (needs Docker).

## License

[MIT](LICENSE)
