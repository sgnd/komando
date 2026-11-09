# komando

[![CI](https://github.com/sgnd/komando/actions/workflows/ci.yml/badge.svg)](https://github.com/sgnd/komando/actions/workflows/ci.yml)
[![License: AGPL-3.0](https://img.shields.io/badge/License-AGPL--3.0-blue.svg)](LICENSE)

**One safe command line for all your DevOps work — servers, databases, caches, storage and more. For you and your AI agent.**

Most people juggle many tools: Termius for servers, TablePlus for databases,
`redis-cli` for caches, a web console for storage, `kubectl` for clusters.
Each has its own logins, its own commands and its own way to break things.
**komando** puts them behind one command line, built so that both you and
AI agents (Claude Code, Codex, your own bot) can use it well:

- **One list for everything you manage**: servers, databases, caches, storage, clusters, registries and VPNs.
- **Passwords stay locked** in an encrypted vault (or your own password manager). The AI never sees them.
- **Clear answers**: readable text for you, structured data (JSON) for the AI.
- **Seatbelts**: read-only unless you say otherwise, dangerous commands are blocked, production can be protected.
- **A full history** of everything that was done, and by whom.
- **Nothing else to install**: one file, with its own SSH, database and VPN clients built in.

```text
You ──ask──▶ AI agent ──▶ komando ──▶ servers, databases, caches, storage, ...
```

No windows. Just commands. A person who types `komando` alone gets a menu:
pick what to do, answer one plain question at a time (a name, an address, a
user ...), check the command it builds, and run it.

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

It says `command not found`? The installer put komando in a folder your
terminal does not look in yet. Run the `export PATH=...` line it printed,
and add that line to `~/.zshrc` (macOS) or `~/.bashrc` (Linux) so it stays.

Other ways: download a file from
[Releases](https://github.com/sgnd/komando/releases), or read the script
first with `curl -fsSLO https://raw.githubusercontent.com/sgnd/komando/main/install.sh`
and then run `sh install.sh`. `KOMANDO_INSTALL_DIR=DIR` picks the folder and
`KOMANDO_VERSION=v0.5.0` one version. To check that a downloaded archive was
built by komando's release workflow, run
`gh attestation verify FILE --repo sgnd/komando`. Developers with Go 1.27.3 or
newer can use `go install github.com/sgnd/komando/cmd/komando@latest`.

### Update

```bash
komando update --dry-run   # is there a newer version?
komando update             # install it
```

`komando update` downloads the newest release, checks it against the
release's checksums (as the install line does) and replaces the `komando`
program. Your servers, secrets and history in `~/.komando` stay as they are.
Then run `komando guide install` again, so your AI agents get the new skill.

- komando is in a folder only root may change, such as `/usr/local/bin`? Run
  `sudo komando update`.
- Go back to an older version with `komando update v0.6.0`. It asks first:
  an older version may lack safety checks the newer one has.

komando 0.6.0 and older have no `update` command: run the install line again.
Did you install it with `sudo`? Then update with `sudo` too:
`curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sudo sh`.
Without it, the installer cannot write there and puts the new version in
`~/.local/bin`, and your terminal may keep running the old one. `komando version`
shows which one runs.

### Tab completion

Press Tab to complete commands, flags and the names of your servers,
conns, groups and tags. Turn it on once (then open a new terminal):

```bash
echo 'source <(komando completion zsh)' >> ~/.zshrc     # zsh (macOS)
echo 'source <(komando completion bash)' >> ~/.bashrc   # bash (Linux)
```

For fish and PowerShell, see `komando completion --help`.

### Uninstall

1. Stop what komando still runs: `komando status` lists it; `komando vpn down
   --all` and `komando tunnel stop --all` stop it.
2. Take the skill and the guard out of your AI agents: `komando guide
   uninstall` (add `--project` in a folder where you ran `guide install
   --project`).
3. Keep a copy of `~/.komando` if you may need your servers or secrets again
   (see [Move to another computer](docs/features/import.md#move-to-another-computer)),
   then delete the folder. Did you move the vault key into the system keychain
   (`komando secret keychain`)? Run `komando secret keychain --off --yes`
   first if you keep the copy; otherwise remove the item named `komando vault
   ...` from the keychain (macOS: the Keychain Access app).
4. Delete the program: `rm "$(command -v komando)"` (with `sudo` when it is in
   `/usr/local/bin`), and the `export PATH=...` line the installer asked you to
   add, if you added one.

## First steps

You need your server's **user name** and **IP address**. Your hosting
provider shows them in its dashboard. Below, `ubuntu` and `203.0.113.10` are
examples; replace them with yours.

komando logs in like `ssh` does: with your SSH key (in `~/.ssh/` or your
SSH agent). The first time, it remembers the server's identity (its host
key) and checks it on every later visit. Did your cloud provider give you a
key file to download (AWS calls it a key pair)? Name it when you add the
server: `komando host add web1 ubuntu@203.0.113.10 --identity ~/Downloads/my-key.pem`.

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

Logging in with a password instead of a key? At your terminal komando asks
for it, as `ssh` does, and also for a one-time code if the server wants
one (two-factor login). Store the password once to skip the question and to
let your AI agent use the server too. You type it, nothing is shown, and
it is saved encrypted:

```bash
komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

A two-factor server needs a fresh code, so a stored password is not enough.
Log in once and komando keeps that login for 8 hours, for your AI agent too:

```bash
komando login web1
```

A new vault keeps its key in the system keychain (the macOS keychain, or
the Secret Service on Linux), so a backup or a synced copy of `~/.komando`
does not open it. Where there is no keychain (a Linux server, a container),
the key is a file in `~/.komando` and `komando doctor` says so. A vault from
an older komando keeps its key file until you move the key, once (nothing is
re-encrypted):

```bash
komando secret keychain
```

On macOS this uses the system keychain as it is. On Linux it needs
`secret-tool` (`sudo apt install libsecret-tools`) and a desktop session
with a keyring; on a server without one, give the vault a passphrase
instead (`komando secret passphrase`).

You do not need `KOMANDO_VAULT_PASS`: a vault passphrase is optional, mainly
for a computer without a keychain (see [Settings](docs/features/settings.md#where-komando-keeps-its-data)).
`komando doctor` checks your whole setup.

Mark production servers as protected. Then nothing can be changed there
unless the command includes `--yes` (a deliberate "yes, I'm sure"). Looking
around is still allowed (for `exec`, say the command only reads with
`--read-only`, for example `komando exec web1 --read-only -- uptime`):

```bash
komando host edit web1 --protected
```

### Databases and caches

Add them the same way, with `conn add` and a short name. A private database
is reached through a server (`--via`), so it never has to be open to the
internet:

```bash
komando secret set app-db-pass
komando conn add app-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:app-db-pass --protected
komando conn add app-cache redis://default@10.0.0.7:6379/0 --via web1

komando db schema app-db                          # what tables are there?
komando db query app-db "select count(*) from users"
komando cache info app-cache                      # memory, clients, keys
```

Queries only read unless you add `--write`. Try a change first with
`--write --dry-run`: it runs, shows what would change, and is rolled back.

Already have servers and databases somewhere? `komando import` brings them
in from `~/.ssh/config`, `.pgpass`, `my.cnf`, `.env`, kubeconfig, Docker,
FileZilla, rclone, DBeaver, AWS profiles (S3 buckets) and CSV spreadsheets. Try it with `--dry-run` first.

## Give it to your AI agent

One command teaches your AI agents (Claude Code, Codex, Cursor, Gemini CLI)
to use komando, for every project on this computer:

```bash
komando guide install
```

It adds the komando *skill*: a short note the agent reads by itself whenever
a task touches a server, database, cache or storage. Restart the agent after
it. Run it again after you update komando. In Codex, open `/hooks` once and
approve komando's guard; Codex asks before it runs a new hook.

Other agents: copy the text of [`AGENTS.md`](AGENTS.md) into your agent's
instructions file (for example `AGENTS.md` or `CLAUDE.md` in the folder you
work in), or simply tell your agent:

> Use the `komando` CLI to manage my servers and databases. Run `komando guide` first and
> follow it. Never use `--allow-dangerous` or `--yes` without asking me.

Also set `KOMANDO_AGENT=1` in that agent's environment. komando knows only
the four agents above by themselves, and its
[seatbelts for AI agents](docs/features/safety.md#seatbelts-for-ai-agents)
(secrets hidden in output, a person allows `--yes`) apply only to an agent
it knows.

Then just ask: *"Why is web1 slow?"*, *"Update all servers"*, *"How many
users signed up today?"*, *"Renew the certificate on web2"*.

## What it can do

| Task | Commands |
|------|----------|
| See and check everything at once | `list`, `test`, `status` |
| Keep a list of servers and how to log in | `host`, `group`, `key`, `secret`, `login` |
| Bring in what you already have, or move to another computer | `import`, `export` |
| Run commands on one or many servers | `exec`, `script`, `job` (long tasks), `shell` (people only) |
| Read, edit and copy files; copy whole folders | `fs`, `upload`, `download`, `cp`, `sync` |
| Check health (36 ready-made checks, plus your own) and certificates | `facts`, `recipe`, `cert` |
| Manage services, logs, Docker, software, users, schedules; restart servers | `svc`, `logs`, `docker`, `pkg`, `user`, `cron`, `reboot` |
| Test the network, reach private servers | `net`, `tunnel`, `--via` |
| Reach things behind VPNs, several at once (WireGuard, OpenVPN, Tailscale, AnyConnect, L2TP/IPsec, IKEv2, Cisco IPsec, GlobalProtect, Fortinet, Pulse, F5, ...) | `vpn` |
| Keep a list of databases, caches, storage, clusters and registries | `conn` |
| Query, back up and restore databases (PostgreSQL, MySQL/MariaDB; SQLite: query and back up) | `db` |
| Read and change caches (Redis, Valkey, memcached) | `cache` |
| Files in S3, MinIO, R2 and on FTPS/SFTP/FTP servers | `storage`, `upload`, `download`, `sync` |
| Kubernetes and Docker Swarm: status, logs, apply, restart, scale | `cluster` |
| Container registries: tags, image details, copy, clean up | `registry` |
| History, safety rules and a health check of your setup | `audit`, `policy`, `doctor` |
| What is still running; settings | `status`, `prompt`, `config` |
| Help for AI agents | `guide`, `schema` |

Every task, step by step, one page per feature: **[docs/features](docs/features/README.md)**.
Help for any command: `komando <command> --help`. What comes next: the
[roadmap](docs/design/vision.md).

## Safety, in one minute

- Commands like `rm -rf /`, `reboot`, `DROP TABLE` or `FLUSHALL` are **blocked** unless a person allows them.
- **Protected** servers and conns refuse changes without `--yes`. Looking is still allowed (mark read-only `exec` commands with `--read-only`).
- Database queries and cache commands **only read** unless you add `--write`. For databases, the database itself enforces it.
- `--dry-run` shows what *would* happen, without changing anything.
- File edits change exactly the text you name, never leave a half-written file, and can keep a backup.
- If a server's identity (host key) changes, komando **refuses to connect**.
- When an AI agent asks for `--yes`, `--allow-dangerous` or `--reveal`, komando shows **you** a window to allow it once.
- Everything is recorded: `komando audit`, and `komando audit verify` checks that nobody edited the record.

More: [Safety](docs/features/safety.md) and [Security](SECURITY.md).

## Something wrong?

Every error has a code and a hint with the next step. `komando doctor` checks
komando's folder, vault, keys and servers. The common errors and their fixes
are in [Troubleshooting](docs/features/output.md#troubleshooting).

## Key terms

| Word | Meaning |
|------|---------|
| Server | A computer (usually in the cloud) that runs your apps. |
| Host | komando's word for a server in its list. You add one with `komando host add`. |
| Terminal / CLI | A window where you type commands instead of clicking. |
| SSH | The secure way to log in to and control a Linux server remotely. |
| Conn | komando's word for anything you connect to that isn't a server: a database, cache, storage bucket, cluster or registry. |
| Target | What a command works on: one name, a group (`@web`), a tag, or `all`. |
| Flag | An option added to a command, like `--yes` or `--dry-run`. |
| AI agent | An AI that can run commands by itself to finish a task. |

Every other word is in the [glossary](docs/features/glossary.md).

## Contributing

Bug reports, ideas and pull requests are welcome. See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues:
[SECURITY.md](SECURITY.md).

## License

komando is free and open source under the
[GNU Affero General Public License v3.0](LICENSE) (AGPL-3.0). You can use it
for any purpose, at home or at work. If you change komando and give it to
others, or let them use it over a network, you must share the source code of
your version under the same license.

Want to build komando into a closed-source product, or does your company not
allow AGPL software? A [commercial license](COMMERCIAL-LICENSE.md) is available.

Contributors sign a short [Contributor License Agreement](CLA.md) once.

Versions up to v0.2.0 were released under the MIT License and stay under it.

© Sugeng Agung Suganda
