# komando features

One page per feature, task by task. AI agents: run `komando guide`.

## Start here

New to komando? Follow these four steps in order:

1. **Install it**: see [Install](../../README.md#install).
2. **Add your first server**: `komando host add web1 ubuntu@203.0.113.10`
   ([Servers](servers.md)). Already have a list? [Import it](import.md).
3. **Run your first command**: `komando test web1`, then
   `komando facts web1` ([Health and network checks](health.md)).
4. **Connect your AI agent**: `komando guide install`
   ([Give it to your AI agent](../../README.md#give-it-to-your-ai-agent)).

Unsure about a word? See the [glossary](glossary.md).

## All features

| Feature | What you can do | Commands |
|---------|-----------------|----------|
| [Servers](servers.md) | add servers, log in with keys, passwords or your password manager | `host`, `key`, `secret`, `login` |
| [Windows servers](windows.md) | run PowerShell, files, copies and services on Windows servers | `host add --os windows`, `exec`, `svc` |
| [Moving in and moving computers](import.md) | import ssh config, .pgpass, my.cnf, .env; export to another computer | `import`, `export` |
| [Targets](targets.md) | pick what a command works on: one name, a group, a tag, everything | `list`, `test`, `group` |
| [Running commands](commands.md) | run commands and scripts, long tasks, saved commands | `exec`, `script`, `job`, `recipe`, `shell` |
| [Health and network checks](health.md) | what is this server, is it healthy, what can it reach, when do certificates expire | `facts`, `recipe`, `net`, `cert` |
| [Files](files.md) | read, edit and copy files safely; copy whole folders | `fs`, `upload`, `download`, `cp`, `sync` |
| [Services, logs, Docker, packages, users](system.md) | day-to-day administration, security updates, restarts | `svc`, `logs`, `docker`, `pkg`, `user`, `cron`, `reboot` |
| [Private servers and tunnels](tunnels.md) | reach servers and services that are not on the internet | `--via`, `tunnel` |
| [VPNs](vpn.md) | reach targets behind WireGuard, OpenVPN, Tailscale, AnyConnect, IPsec and other VPNs, several at once | `vpn`, `--via` |
| [Databases](databases.md) | query, back up and restore PostgreSQL and MySQL/MariaDB; query and back up SQLite | `conn`, `db` |
| [Caches](caches.md) | read and change Redis, Valkey and memcached | `cache` |
| [Queues](queues.md) | Kafka topics, messages and consumer groups: list, peek, lag, send | `queue` |
| [Storage](storage.md) | browse, download, upload and share files in S3 buckets and on FTPS/SFTP/FTP servers | `storage`, `upload`, `download`, `sync` |
| [Clusters](cluster.md) | Kubernetes and Docker Swarm: status, list, logs, apply, restart, scale | `cluster` |
| [Container registries](registry.md) | list repositories and tags, inspect images, delete old ones | `registry` |
| [Rotate keys and passwords](rotate.md) | change a key or a password everywhere, in order; when someone leaves | `key`, `secret`, `db user`, `audit` |
| [Safety](safety.md) | the seatbelts and what to do when one stops you | `policy`, `audit`, `ssh-gate` |
| [Security standards](security-standards.md) | how komando measures up to OWASP, NIST, ISO 27001 and SLSA | `doctor`, `audit verify` |
| [Results and errors](output.md) | JSON and text output, exit codes, common errors, what is still running | `status`, `prompt`, `schema` |
| [Settings and files](settings.md) | settings, environment variables, where komando keeps its data, and updating komando | `config`, `doctor`, `update` |
| [Glossary](glossary.md) | the words, in plain language | none |

Help for any command: `komando <command> --help`. The full machine-readable
reference is `komando schema`.

## Writing these pages

- One feature per file. A new feature gets its own page and a row above.
- Write for beginners: short sentences, a real example first, then details.
- Page shape: a one-line intro, a **Quick start** block with the most common
  commands, then one section per task (most common first), then *Good to
  know* or *Troubleshooting* if needed.
- Update the page in the same commit as the feature, together with
  `komando guide` (`internal/cli/guide.md`), the agent skill
  (`internal/cli/skill.md`, copied to `skills/komando/SKILL.md`) and `CHANGELOG.md`.
- The rules for commands and flags are in [docs/design/ux.md](../design/ux.md).
- Write in plain English.
