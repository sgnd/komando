# komando features

One page per feature, task by task. AI agents: run `komando guide`.

## Start here

New to komando? Do these in order:

1. [Install komando](install.md).
2. Add a server: type `komando host add` and answer one question per
   line. komando then shows the full command, so next time you can type
   it yourself ([Servers](servers.md)). Already have a list of servers?
   [Import it](import.md).
3. Check it and look around: `komando test web1`, then `komando facts web1`
   ([Health and network checks](health.md)).
4. Connect your AI agent: `komando guide install`
   ([Running commands](commands.md) shows what an agent can do).

Unsure about a word? See the [glossary](glossary.md).

## Every feature

| Feature | What you can do | Commands |
|---------|-----------------|----------|
| [Install, update, remove](install.md) | install komando on macOS, Linux or Windows, update it, tab completion, remove it | `update`, `completion` |
| [Servers](servers.md) | add servers, log in with keys, passwords or your password manager | `host`, `key`, `secret`, `login` |
| [Secrets](secrets.md) | save passwords and tokens once, use them as secret:NAME, read them from Vault, cloud secret managers, 1Password, Bitwarden or KeePass | `secret` |
| [Windows servers](windows.md) | run PowerShell, files, copies and services on Windows servers | `host add --os windows`, `exec`, `svc` |
| [Moving in and moving computers](import.md) | import ssh config, .pgpass, my.cnf, .env; export to another computer | `import`, `export` |
| [Targets](targets.md) | pick what a command works on: one name, a group, a tag, everything | `list`, `test`, `group` |
| [Running commands](commands.md) | run commands and scripts, long tasks, saved commands, what komando asks at your terminal | `exec`, `job`, `recipe`, `shell` |
| [Health and network checks](health.md) | what is this server, is it healthy, what can it reach, when do certificates expire | `facts`, `recipe`, `net`, `cert` |
| [Files](files.md) | read, edit and copy files safely; copy whole folders | `fs`, `upload`, `download`, `cp`, `sync` |
| [Services, logs, Docker, packages, users](system.md) | day-to-day administration, security updates, restarts | `svc`, `logs`, `docker`, `pkg`, `user`, `cron`, `reboot` |
| [Private servers and tunnels](tunnels.md) | reach servers and services that are not on the internet | `--via`, `tunnel` |
| [VPNs](vpn.md) | reach targets behind WireGuard, OpenVPN, Tailscale, AnyConnect, IPsec and other VPNs, several at once | `vpn`, `--via` |
| [Databases](databases.md) | query, back up and restore PostgreSQL and MySQL/MariaDB; query and back up SQLite; query SQL Server, Oracle, ClickHouse, Snowflake, BigQuery and MongoDB | `conn`, `db` |
| [Caches](caches.md) | read and change Redis, Valkey and memcached | `cache` |
| [Queues](queues.md) | Kafka topics, RabbitMQ queues, NATS JetStream streams, Amazon SQS queues and Google Cloud Pub/Sub topics: list, peek, lag, send | `queue` |
| [Storage](storage.md) | browse, download, upload and share files in S3, Google Cloud and Azure buckets, on WebDAV/FTPS/SFTP/FTP servers and Windows (SMB) shares | `storage`, `upload`, `download`, `sync` |
| [Clusters](cluster.md) | Kubernetes and Docker Swarm: status, list, logs, apply, restart, scale | `cluster` |
| [Cloud logins](cloud.md) | log in to AWS SSO once; S3, SQS and ECR conns that use your AWS profile; a conn per S3 bucket | `login aws`, `import aws` |
| [Container registries](registry.md) | list repositories and tags, inspect and copy images, delete old ones | `registry` |
| [Rotate keys and passwords](rotate.md) | change a key or a password everywhere, in order; when someone leaves | `key`, `secret`, `db user`, `audit` |
| [Safety](safety.md) | the seatbelts and what to do when one stops you | `policy`, `audit`, `ssh-gate` |
| [Security standards](security-standards.md) | how komando measures up to OWASP, NIST, ISO 27001 and SLSA | `doctor`, `audit verify` |
| [Results and errors](output.md) | JSON and text output, exit codes, common errors, what is still running | `status`, `schema` |
| [Error codes](error-codes.md) | every error code, its exit code and the usual next step | `schema` |
| [Settings and files](settings.md) | settings, environment variables, where komando keeps its data | `config`, `doctor` |
| [Glossary](glossary.md) | the words, in plain language | none |

Help for any command: `komando <command> --help`. The full machine-readable
reference is `komando schema`.

## Writing these pages

- One feature per page. A new feature gets its own page and a row in the
  table above.
- Write for a beginner who knows the task but not komando: plain words,
  short sentences, one idea per paragraph. Explain a word the first time,
  or link the [glossary](glossary.md).
- Every page has the same shape: what it is for (one or two lines), the
  most common task as a command, more tasks, `## Limits`, then
  `## Troubleshooting` (error code, what it means, what to do).
- Every task shows the exact command, what komando asks if an argument is
  left out (where that helps), and a short sample of the output. Every
  example must work as written.
- One topic, one place: link to another page instead of repeating it.
  Approvals are explained once, in [Safety](safety.md).
- Use the command's own words and only the primary names; no old names, no
  history, no dates.
- Update the page in the same commit as the feature, together with
  `komando guide` (`internal/cli/guide.md`), the agent skill
  (`internal/cli/skill.md`, copied to `skills/komando/SKILL.md`) and
  `CHANGELOG.md`.
- The rules for commands and flags are in the
  [command standard](../design/command-standard.md); the words of messages
  in [message-style.md](../design/message-style.md).
