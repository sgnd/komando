# komando

[![CI](https://github.com/sgnd/komando/actions/workflows/ci.yml/badge.svg)](https://github.com/sgnd/komando/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Let an AI agent take care of your servers — safely, from the command line.**

🇮🇩 [Bahasa Indonesia](README.id.md)

People usually manage servers with apps like Termius: log in, type commands,
repeat. **komando** does the same job in a form AI agents (Claude Code, Codex,
your own bot) can use well:

- **Remembers your servers**, like a contact list.
- **Keeps passwords locked** in an encrypted vault. The AI never sees them.
- **Gives clear answers**: readable text for you, structured data (JSON) for the AI.
- **Has seatbelts**: dangerous commands are blocked, production servers can be protected.
- **Keeps a history** of everything that was done.

```
You ──ask──▶ AI agent ──▶ komando ──SSH──▶ your servers
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
komando host test web1

# 3. Ask something
komando facts web1            # what is this server?
komando ops run health web1   # is it healthy?
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

## Give it to your AI agent

Copy the text of [`AGENTS.md`](AGENTS.md) into your agent's instructions
file (Codex: `AGENTS.md`, Claude Code: `CLAUDE.md`, in the folder you work in),
or simply tell your agent:

> Use the `komando` CLI to manage my servers. Run `komando guide` first and
> follow it. Never use `--allow-dangerous` or `--yes` without asking me.

Then just ask: *"Why is web1 slow?"*, *"Update all servers"*, *"Renew the
certificate on web2"*.

## What it can do

| Task | Commands |
|------|----------|
| Keep a list of servers and how to log in | `host`, `group`, `key`, `secret` |
| Run commands on one or many servers | `exec`, `script`, `job` (long tasks) |
| Read, edit and copy files | `fs`, `cp` |
| Check health (39 ready-made checks) | `facts`, `ops` |
| Manage services, logs, Docker, software, users, schedules | `svc`, `logs`, `docker`, `pkg`, `user`, `cron` |
| Test the network, reach private servers | `net`, `tunnel` |
| See history and safety rules | `audit`, `policy` |

Every task, step by step: **[docs/usage.md](docs/usage.md)**.
Help for any command: `komando <command> --help`.

## Safety, in one minute

- Commands like `rm -rf /`, `reboot` or `DROP DATABASE` are **blocked** unless a human allows them.
- **Protected** servers refuse changes without `--yes` (commands marked `--read-only` may still look).
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
| AI agent | An AI that can run commands by itself to finish a task. |
| SSH key | A pair of files that proves who you are; safer than a password. |
| Flag | An option added to a command, like `--yes` or `--dry-run`. |
| sudo | Running a command as the administrator. |
| JSON | Structured text that programs read easily. |

More in the [glossary](docs/usage.md#glossary).

## Contributing

Bug reports, ideas and pull requests are welcome — in English or Bahasa
Indonesia. See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues:
[SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
