# Feature gap analysis: komando vs popular CLI tools

komando was compared row by row with the popular tools of each field at
commit 4784fc9 (178 commands). Most of what that comparison found missing
is built now. This page keeps only what is still open:
[Still open](#still-open), [section 4](#4-biggest-p2-themes), what is
deliberately not built, and the technical limits. The row-by-row reports
(six files, including the P3 gaps not listed here) are in the v0.9.0 tag:
`git show v0.9.0:docs/design/gap/database-cache.md`.

Gap priority: **P1** daily need, security problem, or agent blocker ·
**P2** useful · **P3** rarely used. **NON-GOAL** means deliberately not
built, according to [vision.md](../vision.md#non-goals).

## Still open

Every doc promise, security hole and daily P1 feature from the first
comparison is done, except:

- `import termius` and `import tableplus`
  (Termius and TablePlus have no open export format; see
  [import.md](../../features/import.md)).

## 4. Biggest P2 themes

What is still open. Items that were on this list and now exist in the
code are under "Done" in each theme.

- **Access**: SSH certificates (user cert, `@cert-authority`), agent forwarding, SAML/SSO logins for the corporate VPN clients (they stay with a person). Done: `HTTPS_PROXY` for the kube and registry clients, `vpn edit`.
- **Fleet**: staged execution in batches larger than one server (Ansible-style `serial`), idempotent `lineinfile`/`blockinfile`, user groups other than the admin group, Ansible inventory import. Done: `user unlock`, `download --sudo`, one server at a time with `exec --fail-fast` (parallel 1) and `reboot`.
- **Secrets**: refs for pass/sops/SSM Parameter Store, Vault dynamic credentials, encrypted export including secrets. Done: Bitwarden, KeePass and Azure Key Vault (`azure-kv:`) refs.
- **Cluster**: capacity (`top` is done through `cluster run`). Done: read commands on many clusters at once (`@group`, `cluster_many.go`), read-only helm (`cluster helm ls/status/history/values`), masking of secrets in all agent output, `docker inspect` and `compose config` included.
- **Database**: more engines (HTTP-based ones like Elasticsearch/OpenSearch and Consul), schema migrations. Done: MongoDB (`mongo.go`), SQL Server, Oracle, ClickHouse, Snowflake, BigQuery, message queues (`komando queue`: Kafka, RabbitMQ, NATS, SQS, Pub/Sub), Redis Cluster/Sentinel, TLS with your own CA (`?ca=secret:NAME`).
- **Storage**: self-signed TLS or your own CA for S3. Done: GCS, Azure Blob, WebDAV, SMB shares, your own CA for registries, filezilla/rclone import.
- **Platform**: `--debug`/verbose, CSV output outside `db query`, Homebrew, SBOM, Windows build, MCP server, dynamic inventory from the cloud (EC2, GCP, DO, Hetzner). Done: signed build provenance for releases, `db query -o csv`, time filter in `audit` (`--since`/`--until`), sending the audit to syslog/SIEM.

## 5. What is deliberately not built (NON-GOAL)

According to [vision.md](../vision.md#non-goals), and still true after
this comparison: TUI/dashboard beyond the grouped help `komando` alone prints for a
person (k9s, Lens, lazydocker, Portainer, RedisInsight), helm
install/upgrade/template, kustomize, GitOps, Terraform/IaC,
mount/serve storage, continuous monitoring (`MONITOR`, watch), image
mutate/sign, own vulnerability scanning, plugin system, daemon. For all of these,
the answer stays "use the original tool, or `exec`".

## 6. Technical limits

- **Binary size**: not limited (owner decision; the 40 MB limit in
  vision.md was removed). Big drivers such as MongoDB, MSSQL, Azure SDK
  or Sigstore are no longer blocked by size;
  what still applies is only pure Go (no cgo) and daily need.
