# komando vision and roadmap

Status: **approved, 2026-11-02; v0.2–v0.7 done** (see [Decisions](#decisions-and-open-questions)). This document replaces the old goal ("an SSH CLI
for AI agents") with a new goal. The design for each feature stays in its own
document, for example [resources-and-db.md](resources-and-db.md).

## Vision

> **komando is one universal client for all devops work:
> servers, databases, caches, object storage, clusters, registries, secrets, and
> files. One inventory, one way of working, one safety layer. Usable by
> people and AI agents.**

Imagine Termius + TablePlus + Lens + Cyberduck + `docker`/`kubectl`/`aws s3`
merged into one CLI. All its commands follow the same rules, and
passwords are never visible to the AI.

## Four goals

| # | Goal | What it means, and how to measure it |
|---|---|---|
| 1 | **Universal client** | One inventory (`host` + `conn`) for every kind of target. Measurable: a new kind only needs to be registered in `internal/driver`, without creating a new model or new flags. |
| 2 | **Rich devops features** | Every family has the commands that are really used day to day: view, search, read, change, back up, and restore. Rarely used features are not added. |
| 3 | **Manage many things** | Servers, databases, caches, object storage, clusters (k8s/k3s/swarm), secrets, ftp/sftp, container registries, and other kinds that pass the [criteria](#criteria-for-adding-a-family). |
| 4 | **Useful, easy to use, easy to migrate to** | Useful in the first five minutes. All commands use the same pattern, and existing configuration can be imported in one go. No lock-in: state is plain JSON that can be exported. |

Two extra principles from the owner (2026-11-02): **no overlapping
features**, and **every native CLI feature can still be used** through
komando. The rules are in [ux.md](ux.md) sections 11 and 12.

The design principles (KISS, secure by default, no confusing flags, beginner
friendly, and so on) still apply to everything.

## Review of the current state

As of `feat/v0.3` after phase 1 of the gap analysis (± 22,000 lines of Go, release binary
± 35 MB). The full list of what is still missing is in
[gap/README.md](gap/README.md).

| Area | Status |
|---|---|
| Server (SSH): inventory, keys, vault, parallel exec, jobs, safe fs, cp/SFTP, tunnel, shell | ✅ mature |
| Devops modules on top of SSH: svc, logs, docker, pkg, cron, user, net, facts, 39 `ops` recipes | ✅ mature |
| Safety layer: policy, protected, dry-run, host key check, audit, JSON envelope + exit codes | ✅ mature |
| `conn` + `db` (PostgreSQL, MySQL, SQLite; query/schema/explain/dump/restore; `audit_sql`) | ✅ done |
| `cache` (Redis, Valkey) | ✅ done |
| `storage` (S3, FTP/FTPS, SFTP: ls/download/upload/rm/link) | ✅ done |
| `cluster` (Kubernetes, Docker Swarm) | ✅ done (rollout/rollback/diff: see gap) |
| `registry` (ls, inspect, rm, copy) | ✅ done |
| `vpn` (WireGuard, OpenVPN, openconnect, Tailscale, SOCKS, OS VPN) | ✅ done |
| External secret refs (`op://`, `vault:`, `aws-sm:`, `gcp-sm:`) | ✅ done |
| One inventory: universal selectors, `komando list`, `komando test` | ✅ done |
| Migration | ✅ `import` (ssh-config, pgpass, mycnf, env, komando) and `export` |

**Strengths.** The foundation is already right for the universal goal. The output contract,
exit codes, risk-based guards (`read`/`write`/`destructive`), `--via HOST`
without a local port, and secret references (`secret:`/`env:`/`file:`) are all
general, not specific to SSH. The `db` phase proved this pattern works outside
SSH.

**Gaps to close before adding many families:**

1. **Positioning.** The README and `--help` still say "manage fleets of servers"
   and "like Termius". That is too narrow for the new goal.
2. **Command names per family have no rule yet.** `Families` maps
   `s3 → s3`, while other families are given category names (`db`, `cache`). If
   this is not settled now, the top level will become a mix of product names and
   categories.
3. **Verbs are not uniform across families yet.** `db` has `query/schema/dump`. Other
   families need the same verb pattern so users do not have to learn again.
4. **Migration is still split per command** (`host import`). For many sources
   (kubeconfig, pgpass, aws, filezilla, ...) we need one entry point.
5. **Binary size.** It is already 26 MB. Heavy SDKs (client-go, the full AWS SDK)
   could double it. We need a dependency rule.
6. ~~**The `@group` selector only picks hosts.**~~ Done: selectors pick
   servers and conns together (see [ux.md](ux.md)).

## Core model

Every feature must fit into these four concepts. If it cannot, the
feature is not ready yet.

```
target   = host (SSH, can exec)  |  conn (everything else, has a kind)
kind     = concrete product: postgres, redis, s3, k8s, ftp, oci, ...
family   = group of kinds with the same verbs  →  one top-level command
risk     = read | write | destructive  →  the same guard for all
```

### Families and their commands

Command names are always a **category**, not a product name.

| Command | Family | Kind | Status |
|---|---|---|---|
| `exec`, `fs`, `cp`, `svc`, `docker`, ... | host | SSH (Linux) | ✅ |
| `db` | sql | postgres, mysql/mariadb, sqlite; later: mssql, clickhouse | ✅ |
| `cache` | kv | redis, valkey, keydb, dragonfly; later: memcached | ✅ |
| `storage` | object/file | s3 (AWS, MinIO, R2, Spaces, Wasabi, B2), ftp/ftps, sftp; later: gcs, azblob, webdav | ✅ |
| `cluster` | orchestrator | k8s (k3s, EKS, GKE, AKS, kind), swarm; later: nomad | ✅ |
| `registry` | oci | Docker Hub, GHCR, GitLab, Harbor, registry:2; ECR needs a refreshed token (see gap) | ✅ |
| `secret` | secret | local vault; external refs: `op://`, `vault:`, `aws-sm:`, `gcp-sm:` | ✅ |
| `vpn` | path | wireguard, socks, system, tailscale, GlobalProtect/Fortinet/AnyConnect/Pulse/F5 (openconnect), OpenVPN/Pritunl, L2TP/IPsec (system). komando connects the VPN itself when `--via` needs it | ✅ ([network.md](network.md)) |

Decisions (approved 2026-11-02):

- **Command names use human words**, not product names, so they are easy to
  remember: `storage`, `cache`, `cluster`, `registry`. Product names may be
  aliases (`s3`, `redis`, `sql`).

- **`s3` is renamed to `storage`.** This name covers S3 and FTP with the same
  verbs (`ls/get/put/rm/sync`). Users do not need to know the protocol.
- **SFTP stays under host** (`cp`, `fs`). Accounts that only have SFTP without a shell
  (for example hosting) are registered as an `sftp://` conn in `storage`.
- **Swarm goes into `cluster`, not `docker`.** `docker` stays for a single host.
  `cluster` is for orchestrators. Verbs that exist in every engine sit directly under
  `cluster` and work on any cluster, because the conn already knows its kind
  (`komando cluster status prod`, `komando cluster logs prod api`). Things that
  exist in only one engine go into that engine's subcommand
  (`komando cluster k8s ...`, `komando cluster swarm ...`).

### The same verbs in every family

The list of verbs and flags in effect is in [ux.md](ux.md). The table below
is a summary.

| Verb | Meaning | Default risk |
|---|---|---|
| `list` / `ls` | list contents (tables, keys, objects, pods, tags) | read |
| `get` / `show` | read one item | read |
| `schema` / `info` / `status` | structure and state | read |
| `logs` | logs (pod, service) | read |
| `put` / `set` / `apply` | change, `--dry-run` required first | write |
| `rm` / `delete` | remove | destructive |
| `dump` / `restore` / `sync` | back up, move data; through `job` if it takes long | write |
| `run` | that family's raw command (SQL, redis cmd), classified | per classification |

Flags that are the same in every family: `--write`, `--dry-run`, `--yes`,
`--allow-dangerous`, `--via`, `--limit`, `--timeout`, `-o`. These flags must
never change meaning in any family.

### Safety contract per family

A new family counts as done when all of these points are met:

- [ ] Registered as a kind in `internal/driver` (URL scheme, port, example)
- [ ] `conn add/test` works, including `--via HOST`
- [ ] Passwords only through refs; refused if they are in the URL
- [ ] Read-only by default, preferably **enforced by the server itself** (read-only
      transaction, read-only token, k8s `--dry-run=server`), not only by
      classification
- [ ] Risk classification before anything is sent; the rules show up in `komando policy`
- [ ] A real `--dry-run`, or an honest report if that is not possible
- [ ] Protected → `--yes`; destructive → `--allow-dangerous`
- [ ] One audit line per command, without secrets
- [ ] Structured JSON output + easy-to-read text
- [ ] A section in `komando guide`, its own page in `docs/features/`, and an importer if there is a common source

## Migration: one entry point

```
komando import SOURCE [FILE] [--dry-run] [--group G]
komando export [--to FILE]          # the whole inventory, without secrets (or encrypted)
```

| SOURCE | Reads | Result |
|---|---|---|
| `ssh-config` | `~/.ssh/config` | host (already in `host import`) |
| `kubeconfig` | `~/.kube/config` | a `k8s` conn per context |
| `pgpass`, `mycnf` | `~/.pgpass`, `~/.my.cnf` | `db` conn + password into the vault |
| `aws` | `~/.aws/config` + `credentials` | `storage` conn + key into the vault |
| `docker` | `~/.docker/config.json` | `registry` conn (uses the credential helper if there is one) |
| `rclone` | `rclone.conf` | `storage` conn |
| `filezilla` | `sitemanager.xml` | `storage` conn (ftp/sftp) |
| `termius`, `tableplus`, `dbeaver` | each tool's export file | host/conn |
| `env` | `.env` file (`DATABASE_URL`, `REDIS_URL`, ...) | conn |
| `komando` | `export` file | everything (moving to another machine) |

The rules: imported secrets **always go into the vault**, `--dry-run` shows
what will be created, and existing entries are not overwritten except with
`--overwrite`. `host import` keeps working as an alias.

## Technical rules

- **Pure Go, no cgo, one binary.** This is already in effect and is kept.
- **Talk directly to the API, not through a giant SDK.** k8s: REST API +
  kubeconfig (no client-go). Registry: OCI Distribution API. Swarm: Docker
  Engine API through the socket on the SSH host. S3: a light client (`minio-go` or
  our own SigV4 signer), not the full AWS SDK.
- **One binary for everyone, no size limit** (no
  `lite`/`full` builds; one binary is easier to install and support). Binary size
  is not limited: features needed day to day matter more. Still
  choose reasonable dependencies (a light client when there is one) and no plugin
  system.
- **No pool and no daemon.** One connection per command. Tunnels and jobs
  stay the only background processes.
- Integration tests per family in CI use service containers (postgres, redis,
  minio, k3s, registry:2).

## Roadmap

| Release | Contents | Goals reached |
|---|---|---|
| **v0.2** ✅ | `db`, `cache`, `storage` (S3), one inventory (`list`, `test`, selectors for everything), UX rules, new positioning | 1, 3, 4 |
| **v0.3** ✅ | Overlaps removed (`--via` for everything, `upload`/`download`, `recipe`, `host/conn list/test` aliases, `logs`); `tunnel start TARGET`; `komando import` (ssh-config, pgpass, mycnf, env, kubeconfig, docker, filezilla, rclone, dbeaver, komando) and `export`; `logs --follow` | 1, 4 |
| **v0.4** ✅ | `komando vpn`: WireGuard in-process; SOCKS; OpenVPN/Pritunl in a Docker container (the laptop's network does not change; `--os-mode` optional); GlobalProtect/Fortinet/AnyConnect/Pulse/F5 through openconnect+ocproxy; Tailscale userspace; OS VPN through `--service`; `vpn up/down/status` sessions, automatic disconnect when idle; MFA always done by a person | 1, 3, 4 |
| **v0.5** ✅ | `cluster` for Kubernetes (direct API, through `--via`/VPN) and Docker Swarm: status, ls, get, logs, apply, restart, scale, rm, `run` | 2, 3 |
| **v0.6** ✅ | `registry` (ls, inspect, rm, copy) | 3 |
| **v0.7** ✅ | `storage` for FTP/FTPS/SFTP; external secret refs (`op://`, `vault:`, `aws-sm:`, `gcp-sm:`); `db shell` | 3, 4 |
| **v1.0** | Contract frozen (`schema` version 1), every family passes the checklist, complete documentation in English (the project is English-only; the Indonesian translations were removed) | all |

Candidates after v1.0, judged by the criteria below: DNS (Cloudflare,
Route 53), message queues (RabbitMQ, Kafka, NATS), search (Elasticsearch,
OpenSearch), metrics queries (Prometheus), certificates/ACME, cloud VMs
(DigitalOcean, Hetzner, AWS EC2), and mongodb.

## Criteria for adding a family

A new family is only added when **all** of these are met:

1. It fits the existing `conn` + kind + verb model, with no new concepts.
2. It can have read-only by default and an honest risk classification.
3. It can be built without cgo (pure Go).
4. There is a real need: used day to day, not just "nice to have".
5. Someone is willing to maintain it: integration tests in CI and documentation.

## Non-goals

- Replacing full tools (`psql`, `kubectl`, `terraform`, `helm`). komando
  handles 80% of daily work safely. The rest can still be done
  through `exec` on a host or with the original tool.
- Infrastructure as Code, cloud provisioning, or GitOps.
- GUI, TUI, plugin system, or daemon/server. komando stays a pure CLI.
- Monitoring or alerting that runs continuously.

## Decisions and open questions

| # | Question | Decision |
|---|---|---|
| 1 | `storage` or `s3`? | ✅ `storage`. All command names use human words; product names become aliases. |
| 2 | One `cluster`, or separate `k8s`/`swarm`? | ✅ One `cluster`. General verbs sit directly under it; engine-specific features in `cluster k8s ...` / `cluster swarm ...`. |
| 3 | Does `@prod` pick hosts and conns together? | ✅ Yes, everything. The full rules are in [ux.md](ux.md#2-targets-and-selectors-apply-to-hosts-and-conns). |
| 4 | Binary budget? | ✅ One binary, pure Go, **no size limit** (the 40 MB limit was removed). |
| 5 | TUI? | ✅ No. Pure CLI. |

### Example for number 3

```bash
komando host add web1 ubuntu@10.0.0.2 --group prod
komando conn add app-db postgres://app@10.0.0.5/app --group prod

komando list @prod                  # servers and conns in prod, in one list
komando test @prod                  # check that all of them can be reached
komando exec @prod -- uptime        # runs on web1; app-db is reported in "skipped"
komando db query @prod "select 1"   # runs on app-db; web1 is reported in "skipped"
```

From now on, technical and UX decisions are made based on best practice and
recorded in [ux.md](ux.md). The product owner sets the direction (what komando
manages and for whom).
