# Feature gap analysis: komando vs popular CLI tools

This document compares all komando features (`feat/v0.3`, commit 4784fc9,
178 commands) with popular CLI tools in each field. The goal: know what
is still missing, and what must be done first.

> **Status (2026-11-03):** Phases 1–5 below are done, and since then every
> feature is built in ([built-in.md](../built-in.md)). The field reports in
> this folder are a snapshot of `feat/v0.3`: many of their MISSING and
> PARTIAL rows are done now. What is still open is in
> [Still open](#still-open) and [section 4](#4-biggest-p2-themes).

## How to read

Each capability gets a status:

| Status | Meaning |
|---|---|
| **PRESENT** | komando already has it, with the named command or flag |
| **PARTIAL** | it exists, but something is lacking (what is lacking is written down) |
| **MISSING** | not there yet (often still possible through `exec`, `db query`, `cache run`, `cluster run`) |
| **NON-GOAL** | deliberately not built, according to [vision.md](../vision.md#non-goals) |

Gap priority: **P1** daily need, security problem, or agent blocker ·
**P2** useful · **P3** rarely used.

Every status was checked against the code (`internal/`), the docs, and
`komando --help`, not from memory. After that, **every row in the five
reports (1,010 rows, all statuses and priorities) was re-checked one by one**
directly in the code. The results are in the "Per-row verification" section at the end
of each report. All 178 komando commands were also matched to the reports:
every command is covered by at least one row. One more audit looked for tools and fields that were not
compared at all; the result is [extra-coverage.md](extra-coverage.md).

## Results per field

| Field | Compared with | PRESENT | PARTIAL | MISSING | NON-GOAL | P1 |
|---|---|---|---|---|---|---|
| [SSH, files, fleet, system modules](ssh-files-system.md) | OpenSSH, rsync, pssh, Ansible, Fabric, pyinfra, Salt, Teleport, tmux, systemctl, apt/dnf, certbot, ufw | 104 | 41 | 115 | 13 | 13 |
| [Database and cache](database-cache.md) | psql, pgcli, mysql, mycli, sqlite3, usql, pg_dump, pg_activity, migrate/Atlas, redis-cli, mongosh, sqlcmd, clickhouse, kcat | 66 | 71 | 67 | 15 | 12 |
| [Storage and registry](storage-registry.md) | aws s3, mc, rclone, s3cmd, gsutil, azcopy, lftp, crane, skopeo, regctl, oras, cosign, trivy | 26 | 19 | 81 | 12 | 10 |
| [Kubernetes, Swarm, Docker](cluster-docker.md) | kubectl, k9s, stern, helm, kustomize, docker, compose, lazydocker, Swarm CLI | 46 | 83 | 43 | 11 | 23 |
| [VPN, secrets, platform UX](vpn-secrets-platform.md) | wg, openvpn, openconnect, tailscale, SSM, cloudflared, op, Vault, sops, gh, aws, kubectl, gcloud | 68 | 40 | 81 | 8 | 10 |
| [Extra areas](extra-coverage.md) | macOS/BSD hosts, network devices, IPMI/Redfish, Proxmox, cloud VMs, DNS providers, pm2/supervisor, restic/borg, SMART/RAID/ZFS, fail2ban, output redaction, basic inventory lifecycle, Terraform/IaC | 6 | 3 | 57 | 1 | 1 |
| **Total** | | **316** | **257** | **444** | **60** | **69** |

Total 1,077 capabilities. After per-row verification, 59 rows were corrected
(status, evidence, or priority); no P1 finding turned out to be wrong.

Short conclusion: the komando foundation (inventory, `exec`, `fs`, security, VPN,
output format) is already equal to or better than similar tools for safe
work. The biggest gaps are in three places: **the deploy cycle on clusters**
(rollout, rollback, change image, diff), **bulk transfer** (sync, folders,
large files), and **daily DBA work** (activity, locks, sizes, custom-format
backups).

## Phase 1 status (done)

Phase 1 closes the doc promises and security holes in sections 1 and 2, in three
commits (`fa38148`, `0c3eb85`, `23d1f97`), each passing gofmt, vet,
staticcheck, `go test -race` and Docker e2e (100, 108, 120 checks).

- **Section 1:** numbers 1–8 and 12 are done. Number 9 (`sync`) moved to Phase 3,
  number 10 (ECR) to Phase 5, number 11 (import termius/tableplus/aws,
  memcached) to a later phase.
- **Section 2:** all 12 are done. Upload to a server still overwrites the file
  (like `storage upload` and `fs write`); what does not overwrite without
  `--overwrite` is download to this computer.
- **Bugs found along the way:** registry catalog, `docker logs -f`,
  `svc logs -f` and the `statement_timeout` option are done. Login fan-out to the
  bastion (`exec -P 10`) is not done yet.

## Phase 2 status (done)

The cluster deploy cycle from section 3: `cluster deploy` (change image),
`cluster status TYPE/NAME --wait` (rollout status), `cluster history` and
`cluster rollback`, a `cluster status` that names CrashLoopBackOff, missing
replicas and problem nodes, `cluster describe`, `cluster events`,
`cluster ls -l` with columns for more kinds, `cluster logs` per
workload, per label and `-f`, `cluster exec` (with a policy check and
`--read-only`) and `cluster forward`. Diff before apply has existed since
Phase 1. Passes e2e 140/140 on k3s and Docker Swarm.

## Phase 3 status (done)

Bulk transfer from section 3: `komando sync` (many servers at once,
storage, and this computer; only new and changed files; `--exclude`,
`--delete`, per-file dry-run), `upload -r` and `download -r` for storage,
`storage cat`, `storage rm --prefix --older-than` with `--limit`, streaming upload
to servers (files of any size), and `key revoke`. The `sync` verb
promised by vision.md (section 1 number 9) now exists. Passes
e2e 161/161.

## Phase 4 status (done)

Daily DBA work from section 3: `db info`, `db activity`, `db locks` (MySQL without
the PROCESS privilege gets `DB_PRIVILEGE` with a hint), `db sizes`,
`db kill` (cancel a query; `--session` needs `--allow-dangerous`), foreign
keys and constraints in `db schema`, `db dump --format custom` with
automatic `pg_restore`, plus `--table` and `--schema-only`. Managing users and
roles is still done through `db query --write`. Passes e2e 177/177.

## Phase 5 status (done)

Cloud access from section 3: `host --proxy-command` (like OpenSSH
ProxyCommand: AWS SSM, GCP IAP, Cloudflare Access, Teleport) with the shortcut
`--ssm`, so a conn such as RDS can use that host as `--via`;
`import ssh-config` now carries ProxyCommand (section 1 number 7). S3 conns
can log in with an AWS CLI profile (`--option aws_profile`: SSO, role,
temporary keys), and ECR registries get a fresh login from the aws CLI every
time (section 1 number 10). Passes e2e 183/183.

## Built in (done)

No feature needs another program any more: the aws, vault, gcloud and op
CLIs, kubectl, psql/pg_dump/mysqldump, openvpn, openconnect and Docker are
replaced by komando's own clients, including AWS SSM sessions and ECR
logins through the AWS SDK. Plan, status and what is left (the
experimental VPN clients and SSM sessions): [built-in.md](../built-in.md).

## Still open

Sections 1–3 of the first version (doc promises, security holes and daily
P1 features, all from before Phase 1) are done, except:

- `import termius` and `import tableplus`
  (Termius and TablePlus have no open export format; see
  [import.md](../../features/import.md)).
- `exec -P 10` through one bastion opens one bastion login per host; a
  shared bastion connection would stay under the server's `MaxStartups`.
- Users, roles and grants with passwords from the vault; today through
  `db query --write`.

## 4. Biggest P2 themes

- **Access**: SSH certificates (user cert, `@cert-authority`), agent forwarding, SAML/SSO logins for the corporate VPN clients, `HTTPS_PROXY` for the kube and registry clients, `vpn edit`.
- **Fleet**: staged execution (Ansible-style `serial`), idempotent `lineinfile`/`blockinfile`, `user unlock` and groups, `download --sudo`, Ansible inventory import.
- **Secrets**: `vault.key` in the OS keyring, refs for Azure Key Vault/pass/sops/SSM Parameter Store (Bitwarden and KeePass are done), Vault dynamic credentials, encrypted export including secrets.
- **Cluster**: commands to many clusters at once (`@group`), read-only helm (list/status/history), capacity (`top` is done through `cluster run`), redaction of `docker inspect` and `compose config`.
- **Database**: new engines (MongoDB most requested; HTTP-based ones like Elasticsearch/OpenSearch, RabbitMQ, Consul are cheapest for binary size), Redis Cluster/Sentinel, TLS with your own CA, schema migrations.
- **Storage**: GCS, Azure Blob, WebDAV; self-signed TLS for S3/registry (filezilla/rclone import is done).
- **Platform**: `--debug`/verbose, CSV output, Homebrew, signed releases + SBOM, Windows build, MCP server, dynamic inventory from the cloud (EC2, GCP, DO, Hetzner), send audit to syslog/SIEM, time filter in `audit`.

## 5. What is deliberately not built (NON-GOAL)

According to [vision.md](../vision.md#non-goals), and still true after
this comparison: TUI/dashboard (k9s, Lens, lazydocker, Portainer,
RedisInsight), helm install/upgrade/template, kustomize, GitOps, Terraform/IaC,
mount/serve storage, continuous monitoring (`MONITOR`, watch), image
mutate/sign, own vulnerability scanning, plugin system, daemon. For all of these,
the answer stays "use the original tool, or `exec`".

## 6. Technical limits that need a decision

- **Binary size**: not limited (owner decision; the 40 MB limit in
  vision.md was removed). Release builds are now 35–37 MB. Big drivers such as
  MongoDB, MSSQL, Azure SDK or Sigstore are no longer blocked by size;
  what still applies is only pure Go (no cgo) and daily need.

## Verification

Two rounds. First round: all P1 rows and the 12 promises in section 1 were checked
directly in the code. Second round: **every row** in the five reports was
re-checked (evidence per row is in the "Per-row verification" section of each report),
with 59 corrections: SSH 15, database 10, storage 4, cluster 15, platform 15.
Important status corrections: SSH password login went down to PARTIAL (P1,
`--password-ref` is not validated), large files went up to PARTIAL (download
and `upload -r` already stream), several NON-GOALs that turned out not to be
named in vision.md were changed to MISSING P3.

In the first round no P1 was wrong; three were clarified
(the overwriting download is only from a server; `cluster ls` vs `cluster status`;
DB recipes), and one was removed from the list of promises (`logs -f`, because ux.md
itself notes it as "not there yet").

| Field | Main evidence in code |
|---|---|
| SSH/file | no command or code removes `authorized_keys` lines; `cp.go:173` `os.ReadFile` for upload; `cp.go:210,284` `O_TRUNC`; `fs write --dry-run` only prints the byte count (`unifiedDiff` is only used by `fs replace`); no `validate`, `daemon-reload`, or reboot command (only a recipe that reads `reboot-required`) |
| Database | `testConn` only `r.Check = "tcp"` (`conn.go:491`); `dbx/schema.go` without foreign keys; `dbdump.go` without `-Fc`/`pg_restore`; no activity/lock/kill/size/role command; `db.go` without password redaction |
| Storage/registry | `transfer.go:64` "storage takes one file"; storage commands are only `ls/download/upload/rm/link`; `storex.go:79` `NewStaticV4`; `registry.go` `Catalog` one `getJSON` call without `Link`; `registry rm` only `would_delete: repo@digest` |
| Cluster/Docker | `cluster ls` without a selector flag; no describe/events/rollout/rollback/set image command; Swarm uses `--detach` (`cluster.go:562,631,684`); `classifyKubectl` rates `get` read (secret leaks through `cluster run`) and `exec` destructive; `docker rm/raw` go through `runOne(..., true)` without `classifyDocker` (`modules.go:311,387`); `tunnel.go` without k8s |
| Platform | no SSM/IAP/cloudflared code; `ProxyCommand` and `Match` blocks are silently ignored (`host.go:509`); `secret get --reveal` without a terminal check (`key.go:449`); `secret rm` without a usage check/audit; `audit()` does `return` on failure; 0 `ValidArgsFunction`; `schema` `secret_refs` only `secret:\|env:\|file:` |

### Third round: completeness

- **Row counts re-matched** with a parser that understands `\|`. The five
  reports match exactly: 1,010 rows in the main tables, 1,010 rows in
  "Per-row verification", and the status in both is the same for every row.
  Five rows that use `|` inside backticks (for example
  `--type ed25519|rsa`) broke the table on GitHub; they are now escaped.
- **[extra-coverage.md](extra-coverage.md) was re-checked by an independent
  reviewer who read the code directly** (not grep), for its 67 rows.
  Result: K2 (SSSD/FreeIPA) went down to MISSING, row N4 (Terraform/IaC,
  NON-GOAL) was added because it had no comparison row yet, and the evidence in 10
  rows was fixed. Of the 27 "Already covered" areas, 25 really have a
  comparison row and 2 were fixed (image build, Terraform/IaC).
- **All 178 komando commands are strictly mapped** to comparison rows:
  a row that names the command inside backticks **and** has a comparison
  tool (see the [appendix](#appendix-map-of-178-commands-to-comparison-rows)).
  The earlier loose matching (the same word in one row) is not used.
  Commands that had no row of their own were added: `conn kinds/rm/show`,
  `vpn show/rm`, `recipe rm` and all aliases (area T), then `guide install`,
  `secret list` and `storage download` are named explicitly in existing rows,
  complete with their comparison tool.

## Appendix: map of 178 commands to comparison rows

Every komando command is matched strictly: a row that **names the command inside backticks** (including combined forms like `svc start/stop/restart`) **and** has a comparison tool. The "Rows" column gives the number of matching rows; one example is shown.

| Command | Rows | Example: report § capability | Comparison tool (example) |
|---|---|---|---|
| `audit` | 5 | [Cluster](cluster-docker.md) §7 Audit every change | kubectl (no), Lens (no) |
| `cache` | 43 | [DB](database-cache.md) §7 Server summary: version, uptime, DB size, connections/max_connections, r | `\conninfo`, `SELECT version()`, `mysqladmin status`, pg_activity head |
| `cache get` | 5 | [DB](database-cache.md) §13 Read a key of any type + TTL + size | redis-cli `GET/HGETALL/...`, RedisInsight browser |
| `cache info` | 8 | [DB](database-cache.md) §7 Server summary: version, uptime, DB size, connections/max_connections, r | `\conninfo`, `SELECT version()`, `mysqladmin status`, pg_activity head |
| `cache keys` | 7 | [DB](database-cache.md) §12 Redis Cluster (MOVED/ASK, ElastiCache cluster mode, `redis-cli -c`) | redis-cli `-c` |
| `cache rm` | 3 | [DB](database-cache.md) §14 Delete an exact key | redis-cli `DEL/UNLINK` |
| `cache run` | 24 | [DB](database-cache.md) §12 Sentinel (find the master) | redis-cli `-p 26379`, `SENTINEL get-master-addr-by-name` |
| `cache set` | 4 | [DB](database-cache.md) §14 Set string + TTL | redis-cli `SET ... EX` |
| `cluster` | 98 | [Cluster](cluster-docker.md) §1 Switch cluster/context | kubectx, `kubectl config use-context` |
| `cluster apply` | 6 | [Cluster](cluster-docker.md) §5 Apply multi-document YAML, server-side apply | `kubectl apply --server-side` |
| `cluster get` | 11 | [Cluster](cluster-docker.md) §2 Full object (YAML/JSON) | `kubectl get -o yaml` |
| `cluster logs` | 5 | [Cluster](cluster-docker.md) §3 Log of one pod, tail N, since, timestamps | `kubectl logs --tail --since --timestamps` |
| `cluster ls` | 13 | [Cluster](cluster-docker.md) §1 Switch cluster/context | kubectx, `kubectl config use-context` |
| `cluster restart` | 3 | [Cluster](cluster-docker.md) §5 Rollout status / wait until done | `kubectl rollout status`, `kubectl wait` |
| `cluster rm` | 5 | [Cluster](cluster-docker.md) §5 Delete object | `kubectl delete` |
| `cluster run` | 64 | [Cluster](cluster-docker.md) §1 List contexts | `kubectl config get-contexts` |
| `cluster scale` | 2 | [Cluster](cluster-docker.md) §5 Scale | `kubectl scale` |
| `cluster status` | 8 | [Cluster](cluster-docker.md) §1 Check cluster connection | `kubectl cluster-info`, `kubectl version` |
| `config` | 7 | [Cluster](cluster-docker.md) §1 List contexts | `kubectl config get-contexts` |
| `config set` | 6 | [SSH](ssh-files-system.md) §1 Connect timeout | ssh `ConnectTimeout` |
| `config show` | 1 | [Platform](vpn-secrets-platform.md) §C1 One config file + `config show/set` | `aws configure`, `gh config` |
| `conn` | 12 | [Cluster](cluster-docker.md) §1 List contexts | `kubectl config get-contexts` |
| `conn add` | 4 | [DB](database-cache.md) §1 Register a DB with a URL, password in the vault | psql (`PG*` env, `.pgpass`), mysql (`.my.cnf`), usql, DBeaver |
| `conn edit` | 3 | [Cluster](cluster-docker.md) §1 Default namespace per cluster (change) | kubens, `kubectl config set-context --namespace` |
| `conn kinds` | 1 | [Extra](extra-coverage.md) §T List of supported resource kinds with example URLs | `rclone help backends`, usql `\drivers` |
| `conn list` | 2 | [Cluster](cluster-docker.md) §1 List contexts | `kubectl config get-contexts` |
| `conn rm` | 1 | [Extra](extra-coverage.md) §T View and delete conns (secrets stay refs, protected conns are guarded) | DBeaver, `rclone config show/delete` |
| `conn show` | 1 | [Extra](extra-coverage.md) §T View and delete conns (secrets stay refs, protected conns are guarded) | DBeaver, `rclone config show/delete` |
| `conn test` | 2 | [Extra](extra-coverage.md) §T Aliases per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `cp` | 9 | [Cluster](cluster-docker.md) §4 Copy files to/from pod | `kubectl cp` |
| `cron` | 10 | [DB](database-cache.md) §6 Scheduled backup + retention | pgBackRest, cron |
| `cron list` | 2 | [SSH](ssh-files-system.md) §14 List entries (with IDs) | crontab -l |
| `cron rm` | 3 | [SSH](ssh-files-system.md) §14 Delete an entry | Ansible `cron state=absent` |
| `cron set` | 7 | [DB](database-cache.md) §6 Scheduled backup + retention | pgBackRest, cron |
| `db` | 65 | [DB](database-cache.md) §1 Postgres TLS (sslmode, sslrootcert, client cert) | psql `sslmode`/`sslrootcert`/`sslcert` |
| `db dump` | 9 | [DB](database-cache.md) §1 Postgres TLS (sslmode, sslrootcert, client cert) | psql `sslmode`/`sslrootcert`/`sslcert` |
| `db explain` | 1 | [DB](database-cache.md) §2 EXPLAIN / EXPLAIN ANALYZE | psql, pgcli, DataGrip |
| `db query` | 40 | [DB](database-cache.md) §1 Query many DBs at once (`db query @prod`) | usql (no), loop script, DataGrip "run on multiple" |
| `db restore` | 2 | [DB](database-cache.md) §3 Copy data between DBs (table A in prod → staging) | DBeaver data transfer, pg_dump `-t` \| psql |
| `db schema` | 10 | [DB](database-cache.md) §1 Other Postgres-wire: CockroachDB, YugabyteDB, Neon, Supabase, Timescale | cockroach sql, psql |
| `db shell` | 9 | [DB](database-cache.md) §1 Postgres TLS (sslmode, sslrootcert, client cert) | psql `sslmode`/`sslrootcert`/`sslcert` |
| `docker` | 47 | [Cluster](cluster-docker.md) §1 Remote Docker host | `docker context`, `DOCKER_HOST=ssh://` |
| `docker compose` | 3 | [Cluster](cluster-docker.md) §3 Compose project log (all services) | `docker compose logs --tail -f` |
| `docker exec` | 7 | [Cluster](cluster-docker.md) §4 Exec command in pod (non-interactive) | `kubectl exec POD -- cmd` |
| `docker images` | 2 | [Cluster](cluster-docker.md) §10 Structured images | `docker images` |
| `docker inspect` | 1 | [Cluster](cluster-docker.md) §10 Inspect | `docker inspect` |
| `docker logs` | 2 | [Cluster](cluster-docker.md) §3 Container log on host (tail/since/until/grep/follow) | `docker logs`, lazydocker |
| `docker ps` | 3 | [Cluster](cluster-docker.md) §10 Structured ps (all containers) | `docker ps -a`, lazydocker, ctop |
| `docker pull` | 4 | [Cluster](cluster-docker.md) §10 Pull image | `docker pull` |
| `docker raw` | 17 | [Cluster](cluster-docker.md) §4 Copy files host<->container | `docker cp` |
| `docker restart` | 1 | [Cluster](cluster-docker.md) §10 Start/stop/restart | `docker start/stop/restart` |
| `docker rm` | 1 | [Cluster](cluster-docker.md) §10 Delete container | `docker rm` |
| `docker start` | 1 | [Cluster](cluster-docker.md) §10 Start/stop/restart | `docker start/stop/restart` |
| `docker stats` | 2 | [Cluster](cluster-docker.md) §10 Structured CPU/mem stats | `docker stats --no-stream`, ctop |
| `docker stop` | 1 | [Cluster](cluster-docker.md) §10 Start/stop/restart | `docker start/stop/restart` |
| `doctor` | 2 | [SSH](ssh-files-system.md) §1 Use ssh-agent (including 1Password/Secretive agent through `SSH_AUTH_SO | ssh-agent, `IdentityAgent` |
| `download` | 12 | [Extra](extra-coverage.md) §G Back up a server folder to storage (snapshot, dedup, encryption, retention) | restic, borg, kopia, duplicity |
| `exec` | 41 | [Cluster](cluster-docker.md) §1 Podman as engine | podman CLI, podman-remote |
| `export` | 5 | [SSH](ssh-files-system.md) §4 Export / move to another computer | Termius sync |
| `facts` | 12 | [Extra](extra-coverage.md) §A macOS host (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt |
| `fs` | 41 | [Cluster](cluster-docker.md) §11 Edit compose file/env on host | editor + ssh |
| `fs cat` | 7 | [Extra](extra-coverage.md) §J Secret redaction in the **output** of remote commands (`fs cat .env`, `exec --  | gitleaks/trufflehog rules, Teleport (session redaction) |
| `fs chmod` | 2 | [SSH](ssh-files-system.md) §10 mkdir -p, mv, chmod (recursive), rm (recursive) | Ansible `file` |
| `fs ls` | 3 | [SSH](ssh-files-system.md) §9 Interactive browsing like an sftp shell | sftp, Cyberduck |
| `fs mkdir` | 1 | [SSH](ssh-files-system.md) §10 mkdir -p, mv, chmod (recursive), rm (recursive) | Ansible `file` |
| `fs mv` | 3 | [SSH](ssh-files-system.md) §9 Copy files within one server | Ansible `copy remote_src` |
| `fs replace` | 9 | [Cluster](cluster-docker.md) §11 Edit compose file/env on host | editor + ssh |
| `fs rm` | 1 | [SSH](ssh-files-system.md) §10 mkdir -p, mv, chmod (recursive), rm (recursive) | Ansible `file` |
| `fs stat` | 4 | [SSH](ssh-files-system.md) §9 Interactive browsing like an sftp shell | sftp, Cyberduck |
| `fs write` | 19 | [SSH](ssh-files-system.md) §9 Upload with mode, create parent folders, install via sudo | Ansible `copy mode/become` |
| `group` | 1 | [SSH](ssh-files-system.md) §4 Groups, tags, key=value labels, notes | Termius tags, Ansible groups/vars |
| `group add` | 1 | [SSH](ssh-files-system.md) §4 Groups, tags, key=value labels, notes | Termius tags, Ansible groups/vars |
| `group list` | 1 | [SSH](ssh-files-system.md) §4 Groups, tags, key=value labels, notes | Termius tags, Ansible groups/vars |
| `group rm` | 1 | [SSH](ssh-files-system.md) §4 Groups, tags, key=value labels, notes | Termius tags, Ansible groups/vars |
| `guide` | 2 | [Platform](vpn-secrets-platform.md) §C3 Offline docs | `gh help`, `az find` |
| `guide install` | 1 | [Platform](vpn-secrets-platform.md) §C8 Skill for Claude Code, Codex, Cursor, Gemini CLI | `claude mcp add`, `npx skills add`, Cursor rules (`.cursor/rules`) |
| `host` | 22 | [Extra](extra-coverage.md) §T Deleting a host that is still a `--via` path for another host/conn is rejected | Termius (no check), Ansible (no check) |
| `host add` | 4 | [SSH](ssh-files-system.md) §1 Login with a private key file | ssh `-i`, `IdentityFile` |
| `host edit` | 4 | [SSH](ssh-files-system.md) §1 Login with a private key file | ssh `-i`, `IdentityFile` |
| `host export` | 2 | [SSH](ssh-files-system.md) §1 Export inventory to `ssh_config` (so that ssh/scp/VS Code Remote use | Termius, Teleport `tsh config` |
| `host import` | 3 | [SSH](ssh-files-system.md) §1 `Match` blocks in ssh_config (Match host/user/exec) | ssh_config |
| `host list` | 1 | [Extra](extra-coverage.md) §T Aliases per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `host rm` | 2 | [Extra](extra-coverage.md) §T Deleting a host that is still a `--via` path for another host/conn is rejected | Termius (no check), Ansible (no check) |
| `host show` | 1 | [SSH](ssh-files-system.md) §4 Add/change/delete/view hosts | Termius, Ansible inventory |
| `host ssh-command` | 1 | [SSH](ssh-files-system.md) §1 Export inventory to `ssh_config` (so that ssh/scp/VS Code Remote use | Termius, Teleport `tsh config` |
| `host test` | 1 | [Extra](extra-coverage.md) §T Aliases per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `host trust` | 4 | [SSH](ssh-files-system.md) §3 Fetch & pin host key (keyscan), also behind a bastion | ssh-keyscan |
| `import` | 16 | [Cluster](cluster-docker.md) §1 Import kubeconfig, one conn per context | kubectl config, Lens |
| `job` | 20 | [Cluster](cluster-docker.md) §5 Run a Job from a CronJob now | `kubectl create job --from=cronjob/x` |
| `job kill` | 2 | [SSH](ssh-files-system.md) §7 Stop (signal to the process group) | kill |
| `job list` | 1 | [SSH](ssh-files-system.md) §7 Status, exit code, runtime, log tail | `jobs`, tmux |
| `job logs` | 2 | [SSH](ssh-files-system.md) §7 Read logs incrementally | `tail -f` |
| `job rm` | 1 | [Platform](vpn-secrets-platform.md) §C9 Detached long jobs | `nohup`, Ansible async |
| `job start` | 10 | [Extra](extra-coverage.md) §S Diagnostic bundle for vendors | `sosreport`, `supportconfig` |
| `job status` | 2 | [SSH](ssh-files-system.md) §7 Status, exit code, runtime, log tail | `jobs`, tmux |
| `job wait` | 4 | [SSH](ssh-files-system.md) §7 Wait until done with a time limit | Ansible `async_status`, `wait` |
| `key` | 14 | [SSH](ssh-files-system.md) §1 Encrypted key (passphrase from the vault) | ssh + ssh-agent |
| `key add` | 4 | [SSH](ssh-files-system.md) §1 Encrypted key (passphrase from the vault) | ssh + ssh-agent |
| `key deploy` | 6 | [SSH](ssh-files-system.md) §2 Install a public key on servers (idempotent) | ssh-copy-id, Ansible `authorized_key` |
| `key edit` | 2 | [SSH](ssh-files-system.md) §1 Encrypted key (passphrase from the vault) | ssh + ssh-agent |
| `key gen` | 5 | [SSH](ssh-files-system.md) §2 Create an ed25519 / RSA key pair | ssh-keygen |
| `key list` | 2 | [SSH](ssh-files-system.md) §2 View public key and fingerprint | ssh-keygen `-y`, `-l` |
| `key rm` | 1 | [Platform](vpn-secrets-platform.md) §B3 Generate/register/deploy SSH keys | `ssh-keygen`, `ssh-copy-id` |
| `key show` | 2 | [SSH](ssh-files-system.md) §2 View public key and fingerprint | ssh-keygen `-y`, `-l` |
| `list` | 9 | [Cluster](cluster-docker.md) §1 List contexts | `kubectl config get-contexts` |
| `logs` | 23 | [Cluster](cluster-docker.md) §2 Watch changes (`-w`) | `kubectl get -w`, k9s |
| `net` | 10 | [Extra](extra-coverage.md) §D Manage DNS records at the provider (list/set/rm A, CNAME, TXT) with dry-r | dnscontrol, octoDNS, `flarectl`/Cloudflare API, `aws route53`, `doctl  |
| `net check` | 3 | [Extra](extra-coverage.md) §L Test sending SMTP from a server (auth, STARTTLS) | swaks, `openssl s_client -starttls smtp` |
| `net dns` | 2 | [Extra](extra-coverage.md) §D Manage DNS records at the provider (list/set/rm A, CNAME, TXT) with dry-r | dnscontrol, octoDNS, `flarectl`/Cloudflare API, `aws route53`, `doctl  |
| `net http` | 2 | [SSH](ssh-files-system.md) §17 HTTP from a server (status, timing, IP) | curl -w |
| `net ports` | 2 | [SSH](ssh-files-system.md) §16 Open files / who holds a file/port | lsof, fuser |
| `pkg` | 10 | [Extra](extra-coverage.md) §A macOS host (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt |
| `pkg install` | 1 | [SSH](ssh-files-system.md) §12 Install / remove / update index / upgrade (all managers, auto-detect) | apt, dnf, Ansible `package` |
| `pkg installed` | 1 | [SSH](ssh-files-system.md) §12 Installed version | dpkg-query, rpm -q |
| `pkg rm` | 1 | [SSH](ssh-files-system.md) §12 Install / remove / update index / upgrade (all managers, auto-detect) | apt, dnf, Ansible `package` |
| `pkg update` | 1 | [SSH](ssh-files-system.md) §12 Install / remove / update index / upgrade (all managers, auto-detect) | apt, dnf, Ansible `package` |
| `pkg upgradable` | 1 | [SSH](ssh-files-system.md) §12 List of pending upgrades | apt list --upgradable |
| `pkg upgrade` | 5 | [SSH](ssh-files-system.md) §7 Slow modules automatically become jobs (`pkg upgrade`, `db dump` on the server) | Ansible async per task |
| `policy` | 2 | [DB](database-cache.md) §2 Risk classification before sending | (none) |
| `policy allow` | 1 | [SSH](ssh-files-system.md) §5 Guardrail for dangerous commands | — (Teleport only RBAC) |
| `policy check` | 2 | [DB](database-cache.md) §2 Risk classification before sending | (none) |
| `policy deny` | 1 | [SSH](ssh-files-system.md) §5 Guardrail for dangerous commands | — (Teleport only RBAC) |
| `policy list` | 1 | [SSH](ssh-files-system.md) §5 Guardrail for dangerous commands | — (Teleport only RBAC) |
| `recipe` | 9 | [Extra](extra-coverage.md) §F App framework commands (`artisan`, `manage.py`, `rails runner`),  | artisan, Django, Rails, `php-fpm -t` |
| `recipe add` | 3 | [Extra](extra-coverage.md) §F App framework commands (`artisan`, `manage.py`, `rails runner`),  | artisan, Django, Rails, `php-fpm -t` |
| `recipe list` | 1 | [SSH](ssh-files-system.md) §19 39 built-in recipes (health, disk, certs, security, network, db, web) | Termius snippets, Salt modules |
| `recipe rm` | 1 | [Extra](extra-coverage.md) §T Delete your own recipes; built-in recipes cannot be deleted | Termius snippets, Fabric |
| `recipe run` | 3 | [SSH](ssh-files-system.md) §4 Per-host variables for recipes/templates (`{{app}}` per host) | Ansible host_vars |
| `registry` | 15 | [Cluster](cluster-docker.md) §9 Stack deploy with registry auth | `docker stack deploy --with-registry-auth` |
| `registry copy` | 4 | [Cluster](cluster-docker.md) §10 Tag/push image | `docker tag/push` |
| `registry inspect` | 2 | [Cluster](cluster-docker.md) §10 Image layer analysis | dive |
| `registry ls` | 4 | [Storage](storage-registry.md) §H List repositories (catalog) | `crane catalog`, `regctl repo ls`, `skopeo` (no), Harbor API |
| `registry rm` | 2 | [Cluster](cluster-docker.md) §10 Delete image (rmi) | `docker rmi`, `image rm` |
| `schema` | 5 | [DB](database-cache.md) §4 List tables/views + estimated rows (`\dt`, `.tables`, `SHOW TABLES`) | psql, sqlite3, mysql |
| `script` | 2 | [SSH](ssh-files-system.md) §5 Run a local script on a remote without copying | Ansible `script`, pyinfra, `ssh 'bash -s' < x` |
| `secret` | 13 | [Cluster](cluster-docker.md) §5 Create Secret/ConfigMap from file/literal | `kubectl create secret generic --from-literal`, `create configmap` |
| `secret get` | 3 | [Cluster](cluster-docker.md) §7 See one Secret value on human request | `kubectl get secret -o jsonpath \| base64 -d` |
| `secret list` | 1 | [Platform](vpn-secrets-platform.md) §B1 Encrypted vault (AES-256-GCM, scrypt), list of secret names without valu | `pass`/`pass ls`, `gopass ls`, ansible-vault, `vault kv list` |
| `secret rm` | 2 | [Extra](extra-coverage.md) §T View and delete VPNs; delete is rejected if still used by `--via` | `nmcli con show/delete`, `tailscale logout` |
| `secret set` | 3 | [Platform](vpn-secrets-platform.md) §B1 Secret input without arguments (hidden prompt, `--from-env`, stdin) | `gh secret set` |
| `shell` | 6 | [Extra](extra-coverage.md) §B Serial console / Serial-over-LAN | `ipmitool sol activate`, conserver, `screen /dev/ttyUSB0` |
| `storage` | 14 | [Extra](extra-coverage.md) §G Back up a server folder to storage (snapshot, dedup, encryption, retention) | restic, borg, kopia, duplicity |
| `storage download` | 2 | [Extra](extra-coverage.md) §T Aliases per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `storage link` | 1 | [Storage](storage-registry.md) §C Presigned download URL | `aws s3 presign`, `mc share download`, `rclone link`, `gsutil signurl` |
| `storage ls` | 3 | [Storage](storage-registry.md) §A List one level (folders as prefixes) | `aws s3 ls`, `mc ls`, `rclone lsf`, `s3cmd ls`, `gsutil ls`, `lftp ls` |
| `storage rm` | 1 | [Storage](storage-registry.md) §A Delete an exact object | `aws s3 rm`, `mc rm`, `rclone deletefile`, `s3cmd del`, `lftp rm` |
| `storage upload` | 3 | [Extra](extra-coverage.md) §G Back up a server folder to storage (snapshot, dedup, encryption, retention) | restic, borg, kopia, duplicity |
| `svc` | 12 | [Extra](extra-coverage.md) §A macOS host (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt |
| `svc disable` | 1 | [SSH](ssh-files-system.md) §11 enable/disable | systemctl |
| `svc enable` | 1 | [SSH](ssh-files-system.md) §11 enable/disable | systemctl |
| `svc list` | 1 | [SSH](ssh-files-system.md) §11 List units + failed/state filter | systemctl list-units |
| `svc logs` | 1 | [Extra](extra-coverage.md) §T Aliases per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `svc reload` | 2 | [SSH](ssh-files-system.md) §11 start/stop/restart/reload + state report + journal on failure | systemctl, Ansible `systemd` |
| `svc restart` | 1 | [SSH](ssh-files-system.md) §11 start/stop/restart/reload + state report + journal on failure | systemctl, Ansible `systemd` |
| `svc start` | 1 | [SSH](ssh-files-system.md) §11 start/stop/restart/reload + state report + journal on failure | systemctl, Ansible `systemd` |
| `svc status` | 1 | [SSH](ssh-files-system.md) §11 Structured status | systemctl show |
| `svc stop` | 1 | [SSH](ssh-files-system.md) §11 start/stop/restart/reload + state report + journal on failure | systemctl, Ansible `systemd` |
| `test` | 16 | [Cluster](cluster-docker.md) §1 Check cluster connection | `kubectl cluster-info`, `kubectl version` |
| `tunnel` | 14 | [Cluster](cluster-docker.md) §4 Port-forward to pod/service | `kubectl port-forward`, k9s, Lens |
| `tunnel list` | 2 | [SSH](ssh-files-system.md) §8 Background tunnels, list, stop | autossh `-f`, Termius |
| `tunnel start` | 9 | [Cluster](cluster-docker.md) §4 Port-forward to pod/service | `kubectl port-forward`, k9s, Lens |
| `tunnel stop` | 2 | [SSH](ssh-files-system.md) §8 Background tunnels, list, stop | autossh `-f`, Termius |
| `upload` | 16 | [Extra](extra-coverage.md) §A macOS host (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt |
| `user` | 11 | [Extra](extra-coverage.md) §K Domain-joined hosts (SSSD/FreeIPA): check that directory users can log in, b | `id`, `getent passwd`, `sss_cache -E`, `ipa` |
| `user add` | 4 | [SSH](ssh-files-system.md) §2 Revoke / remove a public key from `authorized_keys` on many servers (offb | Ansible `authorized_key state=absent`, Teleport |
| `user list` | 2 | [Extra](extra-coverage.md) §K Domain-joined hosts (SSSD/FreeIPA): check that directory users can log in, b | `id`, `getent passwd`, `sss_cache -E`, `ipa` |
| `user lock` | 1 | [SSH](ssh-files-system.md) §13 Lock account | usermod -L |
| `user rm` | 1 | [SSH](ssh-files-system.md) §13 Delete user (dangerous) | userdel |
| `version` | 1 | [Platform](vpn-secrets-platform.md) §C5 Version check / self-update | `gh` (notification), `flyctl version upgrade` |
| `vpn` | 16 | [Extra](extra-coverage.md) §T View and delete VPNs; delete is rejected if still used by `--via` | `nmcli con show/delete`, `tailscale logout` |
| `vpn add` | 6 | [SSH](ssh-files-system.md) §1 Password login (stored safely) | ssh + sshpass |
| `vpn down` | 1 | [Platform](vpn-secrets-platform.md) §A1 Background session per VPN reused + disconnect when idle | `tailscale up`, `nmcli` |
| `vpn list` | 1 | [Extra](extra-coverage.md) §T Aliases per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `vpn rm` | 1 | [Extra](extra-coverage.md) §T View and delete VPNs; delete is rejected if still used by `--via` | `nmcli con show/delete`, `tailscale logout` |
| `vpn show` | 1 | [Extra](extra-coverage.md) §T View and delete VPNs; delete is rejected if still used by `--via` | `nmcli con show/delete`, `tailscale logout` |
| `vpn status` | 4 | [Platform](vpn-secrets-platform.md) §A1 Background session per VPN reused + disconnect when idle | `tailscale up`, `nmcli` |
| `vpn test` | 1 | [Extra](extra-coverage.md) §T Aliases per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `vpn up` | 4 | [Platform](vpn-secrets-platform.md) §A1 Background session per VPN reused + disconnect when idle | `tailscale up`, `nmcli` |
