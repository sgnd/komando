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
- **Credentials stay in an encrypted vault.** An AI agent never sees them.
- **It reads unless you say otherwise.** Dangerous commands stop, and
  production can be protected.
- **Readable text for you, JSON for an agent.**
- **A record of everything** that was done, and by whom.
- **One file to install**, with its own SSH, database and VPN clients
  built in.

## Install

On macOS or Linux, open a terminal and paste:

```bash
curl --proto '=https' --tlsv1.2 -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh
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
logs in like `ssh`: with your SSH key or a password, kept as a credential.

### 1. See what komando does

```bash
komando
```

At your terminal it lists the commands by group:

```text
komando: one safe command line for servers, databases, caches, queues, storage, clusters and VPNs

Nothing added yet: komando host ssh add

BUILT-INS      list · test · config · update · version · schema
TYPES          host · database · cache · queue · storage · cluster · registry · vpn · cloud
KOMANDO'S OWN  credential · group · policy · snippet
ACROSS TYPES   copy · import · export · status
ABOUT KOMANDO  agent · audit · doctor · ssh-gate
```

<!-- TODO(cut): this sample waits on the help builder and its golden (PR B). -->

A command is `komando TYPE PROVIDER VERB NAME`: the type (`host`), the
provider (`ssh`), what to do (`exec`), then the entry's name (`web1`).
komando's own things have no provider: `komando credential password add`.

### 2. Add a login and a server

```bash
komando credential password add admin-web --user ubuntu
komando host ssh add
```

The first line asks for the password and hides it. The second, typed alone,
asks one question per line: a name, the address, the port, which credential
logs in, and whether the server is production. Enter takes the default in
brackets, `?` explains the question. Then it shows the full command it
made, and asks before it runs:

```text
$ komando host ssh add web1 203.0.113.10 --credential admin-web --protected
Run it? [y/N, d = --dry-run first]: y
```

Next time you can type that line yourself. A production server is
**protected**: komando asks you before every change there.

### 3. Test it and look around

```bash
komando test web1                                              # can komando reach it and log in?
komando host ssh exec web1 --read-only -- uname -a             # what is this server?
komando host ssh exec web1 --read-only -- journalctl -u nginx -n 50
komando host ssh exec web1 -- uptime                           # run any command (words for the server go after --)
```

Leave out an argument and komando asks for it, with a numbered list of
your servers.

### 4. Give it to your AI agent

```bash
komando agent skill install
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
| Keep your list of servers and how to log in | `host`, `credential`, `group` |
| Move to another computer | `export`, `import` |
| Run commands on one or many servers, long runs that survive a drop | `host ssh exec`, `host ssh shell` |
| Copy files and folders, to and from servers and storage | `copy` |
| Saved and ready-made commands, such as health checks | `snippet` |
| Reach private servers | `host ssh tunnel`, `--via` |
| Reach things behind a VPN | `vpn` |
| Databases: query, back up, restore | `database` |
| Caches (Redis, Valkey, memcached) | `cache` |
| Message queues (Kafka, RabbitMQ, NATS, SQS, Pub/Sub) | `queue` |
| Files in buckets and on file servers | `storage` |
| Kubernetes and Docker Swarm | `cluster` |
| Container registries | `registry` |
| Cloud accounts | `cloud` |
| History, your own rules, a check of your setup | `audit`, `policy`, `doctor` |

Every task, step by step: **[the feature guide](docs/features/README.md)**.
Help for one command: `komando <command> --help`.

## Safety in one minute

- Commands like `rm -rf /`, `reboot` or `DROP TABLE` stop until a person
  allows them.
- On a protected entry, komando asks you before any change. An
  agent or a script needs `--yes`, which only you can approve.
- Database queries and cache commands only read unless you add `--write`.
- `--dry-run` shows what would happen and changes nothing.
- If a server's identity (host key) changes, komando will not connect.
- Everything is recorded: `komando audit list`.

More: [Safety](docs/features/safety.md) and [Security](SECURITY.md).

## What komando sends

Nothing on its own. komando has no usage statistics, no crash reports and
no update check in the background. It connects only where you send it: the
servers, databases, caches, queues, storage, clusters, registries and VPNs
you added, the credential store (password manager or cloud secret service)
you added, and the cloud account you log in to with `komando test NAME`.
`komando update` asks GitHub for the newest release only when you run it.

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
