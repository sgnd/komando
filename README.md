# komando

[![CI](https://github.com/sgnd/komando/actions/workflows/ci.yml/badge.svg)](https://github.com/sgnd/komando/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

**One safe command line for your servers, databases, caches, queues, storage, clusters and VPNs. For you and your AI agent.**

You may use one tool for servers, another for databases, another for
storage and another for clusters. Each has its own logins, its own commands
and its own way to break things. komando puts them behind one command that
you and an AI agent (Claude Code, Codex, Cursor, Gemini CLI, your own bot)
can both use safely:

- **One list** of everything you manage.
- **Passwords stay in an encrypted vault.** An AI agent never sees them.
- **It reads unless you say otherwise.** Dangerous commands stop, and
  production can be protected.
- **Readable text for you, JSON for an agent.**
- **A record of everything** that was done, and by whom.
- **One file to install**, with its own SSH, database and VPN clients
  built in.

## Install

On macOS or Linux, open a terminal and paste:

```bash
curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh
```

On Windows, download `komando_windows_amd64.zip` from
[Releases](https://github.com/sgnd/komando/releases) and put `komando.exe`
in a folder on your `PATH`.

Check that it works:

```bash
komando version
```

Other ways to install, how to update, tab completion and how to remove
komando: [Install, update, remove](docs/features/install.md).

## Your first five minutes

You need a server's **address** and the **user** you log in as. komando
logs in like `ssh`: with your SSH key, a key file or a password.

### 1. See what komando does

```bash
komando
```

At your terminal it lists the commands by what they work on:

```text
komando: one safe command line for servers, databases, caches, queues, storage, clusters and VPNs

Nothing added yet: komando host add  or  komando import ssh-config

START        host add · conn add · import ssh-config · list · test TARGET · guide install
SERVERS      exec  logs  facts  fs  svc  job  docker  pkg  cron  user  reboot  shell
DATA         db  cache  queue  storage
...
```

Already have servers in `~/.ssh/config`? `komando import ssh-config`
brings them in.

### 2. Add a server

```bash
komando host add
```

Typed alone, it asks one question per line: a name, the address, the user,
how you log in, and whether the server is production. Enter takes the
default in brackets, `?` explains the question. Then it shows the full
command it made, and asks before it runs:

```text
$ komando host add web1 ubuntu@203.0.113.10 --protected
Run it? [y/N, d = --dry-run first]: y
```

Next time you can type that line yourself. A production server is
**protected**: komando asks you before every change there.

### 3. Test it and look around

```bash
komando test web1                 # can komando reach it and log in?
komando facts web1                # what is this server?
komando logs web1 --unit nginx    # read a service's logs
komando exec web1 -- uptime       # run any command (words for the server go after --)
```

Leave out an argument and komando asks for it, with a numbered list of
your servers.

### 4. Give it to your AI agent

```bash
komando guide install
```

This teaches Claude Code, Codex, Cursor and Gemini CLI to use komando, for
every project on this computer. Restart the agent, then ask in your own
words: *"Why is web1 slow?"* For any other agent, see [AGENTS.md](AGENTS.md).

When an agent wants to change something that needs your yes, komando shows
you a window to allow it once. The agent never sees your passwords.

## What it can do

| Task | Commands |
|------|----------|
| See and check everything at once | `list`, `test`, `status` |
| Keep your list of servers and how to log in | `host`, `group`, `key`, `secret`, `login` |
| Bring in what you already have, or move to another computer | `import`, `export` |
| Run commands on one or many servers | `exec`, `job`, `shell` |
| Read, edit and copy files | `fs`, `upload`, `download`, `cp`, `sync` |
| Check health and certificates | `facts`, `recipe`, `cert` |
| Services, logs, Docker, packages, users, schedules, restarts | `svc`, `logs`, `docker`, `pkg`, `user`, `cron`, `reboot` |
| Test the network, reach private servers | `net`, `tunnel`, `--via` |
| Reach things behind a VPN | `vpn` |
| Databases: query, back up, restore | `db` |
| Caches (Redis, Valkey, memcached) | `cache` |
| Message queues (Kafka, RabbitMQ, NATS, SQS, Pub/Sub) | `queue` |
| Files in buckets and on file servers | `storage` |
| Kubernetes and Docker Swarm | `cluster` |
| Container registries | `registry` |
| History, your own rules, a check of your setup | `audit`, `policy`, `doctor` |

Every task, step by step: **[the feature guide](docs/features/README.md)**.
Help for one command: `komando <command> --help`.

## Safety in one minute

- Commands like `rm -rf /`, `reboot` or `DROP TABLE` stop until a person
  allows them.
- On a protected server or conn, komando asks you before any change. An
  agent or a script needs `--yes`, which only you can approve.
- Database queries and cache commands only read unless you add `--write`.
- `--dry-run` shows what would happen and changes nothing.
- If a server's identity (host key) changes, komando will not connect.
- Everything is recorded: `komando audit`.

More: [Safety](docs/features/safety.md) and [Security](SECURITY.md).

## Something wrong?

Every error has a code and a hint with the next step. `komando doctor`
checks your setup. Common errors and fixes:
[Troubleshooting](docs/features/output.md#troubleshooting).

## Contributing

Bug reports, ideas and pull requests are welcome: see
[CONTRIBUTING.md](CONTRIBUTING.md). Security problems:
[SECURITY.md](SECURITY.md). The rules komando follows:
[docs/design/principles.md](docs/design/principles.md).

## License

komando is free and open source under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0). You can use it
for any purpose, at home or at work. If you change komando and give it to
others, or let them use it over a network, you must share the source code
of your version under the same license.

Want to build komando into a closed-source product, or does your company
not allow AGPL software? A [commercial license](COMMERCIAL-LICENSE.md) is
available. Contributors sign a short
[Contributor License Agreement](CLA.md) once.

Versions up to v0.2.0 were released under the MIT License and stay under it.

© Sugeng Agung Suganda
