# komando features

One page per feature, task by task. New here? Start with the
[README](../../README.md). Agents: run `komando guide`.

| Feature | What you can do | Commands |
|---------|-----------------|----------|
| [Servers](servers.md) | add servers, log in with keys or passwords | `host`, `key`, `secret` |
| [Moving in and moving computers](import.md) | import ssh config, .pgpass, my.cnf, .env; export to another computer | `import`, `export` |
| [Targets](targets.md) | pick what a command works on: one name, a group, a tag, everything | `list`, `test`, `group` |
| [Running commands](commands.md) | run commands and scripts, long tasks, saved commands | `exec`, `script`, `job`, `recipe`, `shell` |
| [Health and network checks](health.md) | what is this server, is it healthy, can it reach X | `facts`, `recipe`, `net` |
| [Files](files.md) | read, edit and copy files safely | `fs`, `upload`, `download` |
| [Services, logs, Docker, packages, users](system.md) | day-to-day administration | `svc`, `logs`, `docker`, `pkg`, `user`, `cron` |
| [Private servers and tunnels](tunnels.md) | reach servers and services that are not on the internet | `--via`, `tunnel` |
| [VPNs](vpn.md) | reach targets through WireGuard, SOCKS or your own VPN, several at once | `vpn`, `--via` |
| [Databases](databases.md) | query, back up and restore PostgreSQL, MySQL, SQLite | `conn`, `db` |
| [Caches](caches.md) | read and change Redis and Valkey | `cache` |
| [Object storage](storage.md) | browse, download and upload S3 and compatibles | `storage`, `upload`, `download` |
| [Safety](safety.md) | the seatbelts and what to do when one stops you | `policy`, `audit` |
| [Results and errors](output.md) | JSON and text output, exit codes, common errors | — |
| [Settings and files](settings.md) | settings, and where komando keeps its data | `config`, `doctor` |
| [Glossary](glossary.md) | the words, in plain language | — |

Help for any command: `komando <command> --help`. The full machine-readable
reference is `komando schema`.

## Writing these pages

- One feature per file. A new feature gets its own page and a row above.
- Write for beginners: short sentences, a real example first, then details.
- Update the page in the same commit as the feature, together with
  `komando guide` (`internal/cli/guide.md`) and `CHANGELOG.md`.
- The rules for commands and flags are in [docs/design/ux.md](../design/ux.md).
