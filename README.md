# komando

[![CI](https://github.com/sgnd/komando/actions/workflows/ci.yml/badge.svg)](https://github.com/sgnd/komando/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**One safe command line for all your DevOps work — servers, databases, caches, storage and more. For you and your AI agent.**

🇮🇩 [Bahasa Indonesia](README.id.md)

Most people juggle many tools: Termius for servers, TablePlus for databases,
`redis-cli` for caches, a web console for storage, `kubectl` for clusters.
Each has its own logins, its own commands and its own way to break things.
**komando** puts them behind one command line, built so that both you and
AI agents (Claude Code, Codex, your own bot) can use it well:

- **Remembers everything you manage** in one list: servers, databases, caches, storage.
- **Keeps passwords locked** in an encrypted vault. The AI never sees them.
- **Gives clear answers**: readable text for you, structured data (JSON) for the AI.
- **Has seatbelts**: read-only unless you say otherwise, dangerous commands are blocked, production can be protected.
- **Keeps a history** of everything that was done.

```
You ──ask──▶ AI agent ──▶ komando ──▶ servers, databases, caches, storage, ...
```

No windows, no menus. Just commands.

## Install

Open a terminal (macOS: the **Terminal** app; Linux: your terminal; Windows:
install [WSL](https://learn.microsoft.com/windows/wsl/install) first) and paste:

```bash
curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh
```

Check it worked:

```bash
komando version
```

Other ways: download a file from
[Releases](https://github.com/sgnd/komando/releases), or read the script
first with `curl -fsSLO https://raw.githubusercontent.com/sgnd/komando/main/install.sh`
and then run `sh install.sh`. Developers with Go can use
`go install github.com/sgnd/komando/cmd/komando@latest`.

## First steps

You need your server's **user name** and **IP address**. Your hosting
provider shows them in its dashboard. Below, `ubuntu` and `203.0.113.10` are
examples; replace them with yours.

```bash
# 1. Add a server and give it a short name (web1)
komando host add web1 ubuntu@203.0.113.10

# 2. Check that it works
komando test web1

# 3. Ask something
komando facts web1            # what is this server?
komando recipe run health web1   # is it healthy?
komando exec web1 -- uptime   # run any command
```

Logging in with a password? Store it once. You type it, nothing is shown,
and it is saved encrypted:

```bash
komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

Mark production servers as protected. Then nothing can be changed there
unless the command includes `--yes` (a deliberate "yes, I'm sure"):

```bash
komando host edit web1 --protected
```

### Databases and caches

Add them the same way, by name. A private database is reached through a
server (`--via`), so it never has to be open to the internet:

```bash
komando secret set app-db-pass
komando conn add app-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:app-db-pass --protected

komando db schema app-db                          # what tables are there?
komando db query app-db "select count(*) from users"
komando cache info my-cache                       # a Redis cache, added with conn add
```

Queries only read unless you add `--write`. Try a change first with
`--write --dry-run`: it runs, shows what would change, and is rolled back.

## Give it to your AI agent

Copy the text of [`AGENTS.md`](AGENTS.md) into your agent's instructions
file (Codex: `AGENTS.md`, Claude Code: `CLAUDE.md`, in the folder you work in),
or simply tell your agent:

> Use the `komando` CLI to manage my servers and databases. Run `komando guide` first and
> follow it. Never use `--allow-dangerous` or `--yes` without asking me.

Then just ask: *"Why is web1 slow?"*, *"Update all servers"*, *"How many
users signed up today?"*, *"Renew the certificate on web2"*.

## What it can do

| Task | Commands |
|------|----------|
| See and check everything at once (servers and conns) | `list`, `test` |
| Keep a list of servers and how to log in | `host`, `group`, `key`, `secret` |
| Bring in what you have (ssh config, .pgpass, my.cnf, .env) or move computers | `import`, `export` |
| Run commands on one or many servers | `exec`, `script`, `job` (long tasks) |
| Read, edit and copy files | `fs`, `upload`, `download` |
| Check health (39 ready-made checks) | `facts`, `recipe` |
| Manage services, logs, Docker, software, users, schedules | `svc`, `logs`, `docker`, `pkg`, `user`, `cron` |
| Test the network, reach private servers | `net`, `tunnel` |
| Reach things behind VPNs, several at once without switching | `vpn`, `--via` |
| Keep a list of databases, caches and storage | `conn` |
| Query and back up databases (PostgreSQL, MySQL, SQLite) | `db` |
| Read and change caches (Redis, Valkey) | `cache` |
| Kubernetes and Docker Swarm: status, logs, apply, restart, scale | `cluster` |
| Browse, download and upload files in object storage (S3, MinIO, R2, ...) | `storage`, `upload`, `download` |
| See history and safety rules | `audit`, `policy` |

Coming next: clusters (Kubernetes, k3s, Swarm),
container registries, FTP, and importing what you already have (kubeconfig,
`.pgpass`, AWS profiles, ...). See the
[roadmap](docs/design/vision.md) (in Bahasa Indonesia).

Every task, step by step, one page per feature: **[docs/features](docs/features/README.md)**.
Help for any command: `komando <command> --help`.

## Safety, in one minute

- Commands like `rm -rf /`, `reboot`, `DROP TABLE` or `FLUSHALL` are **blocked** unless a human allows them.
- **Protected** servers and databases refuse changes without `--yes` (looking is still allowed; mark `exec` commands with `--read-only`).
- Database queries and cache commands **only read** unless you add `--write`. For databases, the database itself enforces it.
- `--dry-run` shows what *would* happen.
- File edits change exactly the text you name, never leave a half-written file, and can keep a backup.
- If a server's identity changes, komando **refuses to connect**.
- Everything is recorded: `komando audit`.

## Key terms

| Word | Meaning |
|------|---------|
| Server | A computer (usually in the cloud) that runs your apps. |
| Terminal / CLI | A window where you type commands instead of clicking. |
| SSH | The secure way to log in to and control a Linux server remotely. |
| Database | Where an app keeps its data in tables (PostgreSQL, MySQL, SQLite). |
| Cache | A fast, temporary store an app uses to speed things up (Redis). |
| Conn | komando's word for anything you connect to that isn't a server: a database, cache or storage bucket. |
| AI agent | An AI that can run commands by itself to finish a task. |
| SSH key | A pair of files that proves who you are; safer than a password. |
| Flag | An option added to a command, like `--yes` or `--dry-run`. |
| sudo | Running a command as the administrator. |
| JSON | Structured text that programs read easily. |

More in the [glossary](docs/features/glossary.md).

## Contributing

Bug reports, ideas and pull requests are welcome — in English or Bahasa
Indonesia. See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues:
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
