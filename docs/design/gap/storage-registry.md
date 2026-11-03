# Gap analysis: object storage, file servers, and container registries

> **Snapshot of `feat/v0.3` (commit 4784fc9), 2026-11-02.** Many MISSING and
> PARTIAL rows below were done in Phases 1–5 and the built-in work, and no
> feature needs kubectl, psql, the aws CLI, openvpn or openconnect any more.
> Current status: [README.md](README.md#still-open).

Basis: commit `4784fc9` (branch `feat/v0.3`), binary `bin/komando`, code
`internal/cli/storage.go`, `transfer.go`, `cp.go`, `registry.go`,
`registrycopy.go`, `internal/storex/{storex,ftp,sftp}.go`,
`internal/registry/{registry,copy}.go`, `internal/driver/driver.go`,
`internal/cli/importer.go`, docs `docs/features/{storage,registry,files}.md`,
`docs/design/{vision,ux}.md`. No server was contacted.

## Summary of the commands that exist today

| Area | Command | Notes |
|---|---|---|
| storage | `storage ls CONN [PREFIX] [-r] [-n]`, `storage download CONN KEY [--to]` (= `download`), `storage upload CONN FILE [KEY]` (= `upload`), `storage rm CONN KEY... --allow-dangerous`, `storage link CONN KEY [--expires ≤168h]` (alias `presign`, `share`) | Kinds: `s3` (minio-go v7, URL options only `endpoint`, `region`), `ftp` (`?insecure=1`), `ftps` (explicit TLS, `?tls=skip-verify`), `sftp` (through sshx, host key checked). One conn = one bucket + prefix; keys cannot leave the folder (`..` is rejected). |
| host files | `cp`, `upload`/`download` to a host (SFTP, `-r`, `--sudo`, `-p`, `--mode`, fan-out `@group`, sha256 for 1 file), `fs ls/stat --sha256/cat/write/replace/rm/mkdir/mv/chmod` | Remote-to-remote `cp` is rejected ("download then upload"). `cp` to a storage conn is rejected (`NO_MATCHING_TARGETS`, hint points to `storage`). |
| registry | `registry ls CONN [REPO] [-n]`, `registry inspect CONN REPO[:TAG\|@DIGEST]`, `registry copy SRC:IMG DST:[IMG]` (alias `cp`), `registry rm CONN IMG --allow-dangerous` | OCI Distribution API directly, basic + bearer token, `?tls=false`, `--via`/VPN. Import `docker` (config.json + credential helper). |
| host docker | `docker pull`, `docker images`, `docker raw ...` (push/tag/login/save/load/buildx through raw on the host) | Raw path on the SSH host. |

Status legend: **PRESENT**, **PARTIAL**, **MISSING**, **NON-GOAL** (with a quote from
`vision.md`). Priority: **P1** daily need / security / agent blocker,
**P2** useful and frequent, **P3** rare or niche.

Non-goal quotes used (vision.md, "Non-goals"):
- NG-a: "Replacing full tools (`psql`, `kubectl`, `terraform`, `helm`). komando handles 80% of daily work safely."
- NG-b: "Infrastructure as Code, cloud provisioning, or GitOps."
- NG-c: "GUI, TUI, plugin system, or daemon/server. komando stays a pure CLI."
- NG-d: "Monitoring or alerting that runs continuously."
- Technical rules: "No pool and no daemon", "Pure Go, no cgo". (The 40 MB binary size limit was removed by the owner.)

---

## A. Storage: basic object / file transfer

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List one level (folders as prefixes) | `aws s3 ls`, `mc ls`, `rclone lsf`, `s3cmd ls`, `gsutil ls`, `lftp ls` | PRESENT | `storage ls CONN [PREFIX]`, DIR for prefixes | - |
| Recursive list | `aws s3 ls --recursive`, `mc ls -r`, `rclone ls` | PRESENT | `storage ls -r`, `--limit` (default 1000) + `more:true` | - |
| Pagination / continue from a token (`--starting-token`, `--start-after`) | `aws s3api list-objects-v2`, `mc ls` | MISSING | Only `--limit`; a list longer than the limit cannot be continued, only "narrow the prefix". An agent cannot read a large bucket to the end | P2 — agent cannot iterate a large bucket |
| Total size/count summary (`--summarize`, `du`, `size`) | `aws s3 ls --summarize --human-readable`, `mc du`, `rclone size`, `gsutil du -s` | MISSING | `ls` only gives `count`; no total bytes. Workaround: `ls -r -o json` + sum it yourself | P2 — checking backup capacity is frequent |
| Tree | `mc tree`, `rclone tree` | MISSING | | P3 |
| Download one object | `aws s3 cp s3://.. .`, `mc cp`, `rclone copy`, `s3cmd get`, `gsutil cp`, `azcopy copy`, `lftp get`, `curl ftp://` | PRESENT | `download CONN KEY [--to]` (alias `storage download`), atomic, does not overwrite files (`FILE_EXISTS`), mode 0600 | - |
| Recursive folder/prefix download | `aws s3 cp --recursive`, `mc cp -r`, `rclone copy`, `lftp mirror`, `s3cmd get -r`, `azcopy --recursive` | MISSING | `download -r` from storage is rejected: "-r is for servers; storage downloads one object" (`transfer.go`) | **P1** — daily restore of backups/site folders; the agent has to loop per key |
| Upload one file | `aws s3 cp`, `mc cp`, `rclone copyto`, `s3cmd put`, `lftp put`, `curl -T` | PRESENT | `upload CONN FILE [KEY]`, `replaced:true`, content-type from the extension; FTP/SFTP through a temporary name, then rename | - |
| Recursive folder upload | `aws s3 cp --recursive`, `mc cp -r`, `rclone copy`, `lftp mirror -R`, `azcopy`, `s3cmd put -r` | MISSING | `upload` to storage rejects `-r`: "storage takes one file"; `storageUpload` rejects directories | **P1** — deploy a site to FTPS/S3 static hosting, upload backup folders |
| Upload from stdin / download to stdout (stream, pipe) | `aws s3 cp - s3://..`, `aws s3 cp s3://.. -`, `mc pipe`, `mc cat`, `rclone rcat`/`cat`, `gsutil cat` | MISSING | `upload` needs a regular file (`os.Stat` + `!IsDir`); `--to -` would create a file named `-` | P2 — `db dump \| upload` without a temporary file |
| Read object content in the terminal (`cat` with head/tail/limit) | `mc cat`, `mc head`, `rclone cat --head/--tail`, `gsutil cat -r`, `aws s3 cp .. -` | MISSING | There is `fs cat --head/--tail` for hosts, but no `storage cat`. The agent has to download to a file and then read it | **P1** — agent pattern (reading logs/config in a bucket/FTP) same as `fs cat` |
| Stat/head one object (size, ETag, content-type, metadata, version-id, storage class) | `aws s3api head-object`, `mc stat`, `rclone lsjson --stat`, `gsutil stat`, `s3cmd info` | MISSING | Only an internal `Exists()`; `ls` gives size+modified | P2 — verifying uploads/backups |
| Checksum verification (MD5/ETag/sha256) | `rclone check`, `rclone md5sum/hashsum`, `aws s3api --checksum-algorithm`, `gsutil hash`, `fs stat --sha256` | PARTIAL | Host: `cp` reports sha256 (1 file), `fs stat --sha256`. Storage: no hash in `upload`/`download` results | P2 — backup integrity |
| Multipart upload for large files | `aws s3 cp` (automatic), `aws s3api create-multipart-upload`, `mc cp`, `rclone --s3-chunk-size` | PRESENT (implicit) | minio-go `PutObject` is automatically multipart when the size is known (>16 MiB). No part size/concurrency settings; no `abort`/listing of orphaned uploads | P3 (settings) |
| Clean up orphaned multipart uploads | `aws s3api list-multipart-uploads/abort-multipart-upload`, `mc rm --incomplete` | MISSING | | P3 |
| Resume an interrupted transfer | `rclone` (retry), `lftp get -c`, `curl -C -`, `rsync --partial`, `azcopy jobs resume` | MISSING | Failure = start over from the beginning; S3 `MaxRetry = 2` | P2 — large files over VPN/bastion |
| Progress bar / transfer rate on stderr | `aws s3 cp` (progress), `mc`, `rclone -P`, `azcopy` | MISSING | ux.md edge case: "very large file (progress on stderr)" not built yet | P2 — humans wait without feedback |
| Parallel transfer (many files at once) | `aws s3 --max-concurrent-requests`, `rclone --transfers`, `lftp mirror -P`, `azcopy` | MISSING (storage) | Host `upload @group` is parallel per host; storage is only 1 object per command | P2 (depends on recursive/sync) |
| Bandwidth limit | `rclone --bwlimit`, `aws s3 --max-bandwidth`, `lftp net:limit-rate`, `rsync --bwlimit` | MISSING | | P3 |
| Long transfers in the background | `azcopy jobs`, `rclone rc`/`--daemon` | MISSING | `job start` only on a remote host; storage runs on the laptop and the command has to wait until it finishes (time limit only when `--timeout` is given, no default for storage). Workaround: `job start` on a host that has `aws`/`rclone` | P2 |
| Delete exact objects | `aws s3 rm`, `mc rm`, `rclone deletefile`, `s3cmd del`, `lftp rm` | PRESENT | `storage rm CONN KEY... --allow-dangerous`; protected needs `--yes`; partial failure reports `already deleted` | - |
| Delete a prefix/folder recursively, by pattern, or by age (`--older-than`) | `aws s3 rm --recursive --exclude/--include`, `mc rm -r --older-than`, `rclone delete --min-age`, `rclone purge`, `s3cmd del -r`, `lftp rm -r` | MISSING (on purpose) | `rm` rejects a trailing `/` and `*?`: "rm takes exact keys". Cleaning up old backups requires `ls` + a manual key list | **P1** — daily backup retention; needs a safe version: preview of count/list in `--dry-run`, `--allow-dangerous`, a maximum limit |
| Dry-run for changes | `aws s3 --dryrun`, `rclone --dry-run`, `mc mirror --dry-run`, `rsync -n` | PARTIAL | `--dry-run` in `upload`/`rm`/`link` is only "nothing sent: the change would be allowed"; does not check whether the key exists / will be overwritten / how many bytes | P2 — honest dry-run for bulk sync/rm |
| Include/exclude/glob filter | `aws s3 --include/--exclude`, `rclone --include/--exclude/--filter`, `mc --exclude`, `rsync --exclude`, `lftp mirror -x` | MISSING | Only prefix | P2 (required once sync/recursive is built) |
| Find objects (name, age, size) | `mc find --name --older-than --larger`, `rclone lsf --min-age`, `gsutil ls` wildcard | MISSING | Workaround: `ls -r -o json` + filter on the agent side | P2 |
| Rename/move objects | `aws s3 mv`, `mc mv`, `rclone moveto`, `s3cmd mv`, `lftp mv`, `sftp rename` | MISSING | Hosts have `fs mv`; storage does not | P2 — FTP hosting often needs renames |
| Server-side copy within/between buckets | `aws s3 cp s3://a s3://b`, `mc cp`, `rclone copy` (server-side), `gsutil cp gs://..` | MISSING | | P2 |
| Copy between conns/areas (bucket↔bucket, host↔bucket, FTP→S3) without going through the laptop disk | `rclone copy a: b:`, `mc mirror`, `aws s3 cp` on the server | MISSING | `cp` rejects remote-to-remote; `registry copy` has a `CONN:PATH` pattern but storage does not. Workaround: download then upload, or `exec` `aws`/`rclone` on the host | P2 — back up a server to S3 without credentials on the server |
| Create an empty folder | `mc mb` (folder), `rclone mkdir`, `lftp mkdir`, `sftp mkdir` | PARTIAL | Folders are created automatically on upload (FTP/SFTP); no `storage mkdir` | P3 |
| chmod/chown on file servers (hosting) | `lftp chmod`, `sftp chmod`, `curl -Q "SITE CHMOD"` | MISSING | `fs chmod` is SSH hosts only; sftp/ftp conns without a shell cannot | P2 — 644/755 permissions on shared hosting are common |
| Symlinks, owner/permission info in listings | `lftp ls -l`, `sftp ls -l`, `rclone --links` | MISSING | `Object` has only key/size/modified/dir | P3 |

## B. Storage: synchronization and comparison

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| One-way sync local folder ↔ bucket/FTP (optional `--delete`) | `aws s3 sync [--delete]`, `mc mirror [--remove]`, `rclone sync`, `rclone copy`, `s3cmd sync`, `gsutil rsync`, `azcopy sync`, `lftp mirror [-R] [--delete]`, `rsync -a --delete` | MISSING | vision.md promises a `sync` verb for storage ("`ls/get/put/rm/sync`") and the verb table `dump/restore/sync`; not built yet | **P1** — site deploys, folder backups, mirrors; the core of "80% daily" |
| Sync a folder to an SSH host (rsync-like, delta) | `rsync -az --delete`, `lftp mirror` over sftp | PARTIAL | `upload -r` copies all files every time (no delta/delete); `fs write --if-changed` is only 1 file. Workaround: `exec` rsync between servers | P2 (P1 if storage sync is built, one verb for both) |
| Two-way sync | `rclone bisync`, `unison` | MISSING | | P3 — prone to conflicts, not a daily devops pattern |
| Mirror bucket to bucket (across providers) | `mc mirror`, `rclone sync a: b:`, `aws s3 sync s3:// s3://` | MISSING | | P2 |
| Watch/continuous mirror | `mc mirror --watch`, `mc watch`, `rclone` + cron | NON-GOAL | NG-c "daemon/server" and NG-d "runs continuously". Workaround: `cron set` on the host | - |
| Compare content (diff/check) | `rclone check`, `mc diff`, `rclone cryptcheck`, `rsync -n -i` | MISSING | | P2 — backup/deploy verification |
| Dedupe | `rclone dedupe` | MISSING | Specific to Google Drive (duplicate names) | P3 |
| `--size-only`/`--checksum`/`--update` modes | `rclone`, `aws s3 sync --size-only --exact-timestamps`, `rsync -c/-u` | MISSING | Part of the sync design | P2 (with sync) |

## C. Storage: sharing and access

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Presigned download URL | `aws s3 presign`, `mc share download`, `rclone link`, `gsutil signurl`, `az storage blob generate-sas` | PRESENT | `storage link --expires` (max 168h), risk write, protected needs `--yes`, URL is not written to the audit, `content-disposition: attachment` | - |
| Presigned upload URL (PUT/POST) | `mc share upload`, `aws s3api` presign put, SAS write | MISSING | | P3 |
| Permanent public link (public object) | `aws s3api put-object-acl --acl public-read`, `mc anonymous set` | MISSING | See also ACL/policy (NON-GOAL below) | P3 |
| Links for FTP/SFTP | (uncommon) | MISSING (not relevant) | Not a non-goal in vision.md (not in "Non-goals"); the FTP/SFTP protocols simply have no temporary links. `noLinks` rejects honestly: "FTP/SFTP servers have no temporary download links" | P3 |
| Restrict a conn to a prefix | IAM policy, `rclone` remote with a path | PRESENT | Folder in the conn URL, `keyIn` rejects `..` | - |

## D. Storage: advanced S3 features (objects)

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Content-Type on upload | `aws s3 cp --content-type`, `mc cp --attr` | PARTIAL | Automatic from the extension (`mime.TypeByExtension`); cannot be set | P3 |
| Cache-Control, Content-Encoding, custom metadata | `aws s3 cp --cache-control --metadata`, `mc cp --attr`, `rclone --header-upload`, `gsutil setmeta` | MISSING | | P3 (P2 for static sites) |
| Storage class (STANDARD_IA, GLACIER, ...) | `aws s3 cp --storage-class`, `mc cp --storage-class`, `rclone --s3-storage-class` | MISSING | | P3 |
| Restore from Glacier/archive | `aws s3api restore-object`, `rclone backend restore` | MISSING | | P3 |
| Server-side encryption SSE-KMS / SSE-C per object | `aws s3 cp --sse aws:kms --sse-kms-key-id`, `--sse-c`, `mc --enc-kms` | MISSING | The bucket's default SSE-S3 still applies on the server side | P3 |
| Client-side encryption | `rclone crypt` | MISSING | | P3 |
| Object tagging | `aws s3api put-object-tagging`, `mc tag` | MISSING | | P3 |
| Object ACL | `aws s3api put-object-acl`, `s3cmd setacl`, `gsutil acl` | MISSING | | P3 |
| Versioning: list versions, download old versions, undelete (remove delete marker) | `aws s3api list-object-versions`, `mc ls --versions`, `mc undo`, `mc cp --version-id`, `rclone --s3-versions` | MISSING | ux.md edge case mentions "bucket with versioning (delete marker)"; `rm` does not say that the object can still be recovered | P2 — recovery after a wrong delete/overwrite (security) |
| Object lock: retention, legal hold | `mc retention`, `mc legalhold`, `aws s3api put-object-retention` | MISSING | | P3 |
| Requester pays, transfer acceleration, dual-stack | `aws s3 --request-payer`, `s3-accelerate` | MISSING | | P3 |
| S3 Select / object query | `aws s3api select-object-content`, `mc sql` | MISSING | | P3 |

## E. Storage: buckets and administration

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List buckets in an account/endpoint | `aws s3 ls`, `mc ls alias`, `rclone lsd remote:`, `gsutil ls` | MISSING | A conn requires a bucket ("s3 URL needs a bucket"). For discovery: one conn per bucket | P2 — initial orientation ("which buckets are there?") |
| Create/remove buckets (`mb`/`rb`) | `aws s3 mb/rb`, `mc mb/rb`, `s3cmd mb`, `gsutil mb`, `rclone mkdir/rmdir` | NON-GOAL (partial) | NG-b "cloud provisioning". `mb` on a local MinIO is sometimes daily; could be P3 if requested | P3 |
| Bucket policy, CORS, lifecycle, replication, notification, website, default encryption, ownership | `aws s3api put-bucket-*`, `mc ilm`, `mc anonymous`, `mc replicate`, `mc event`, `gsutil cors/lifecycle` | NON-GOAL (change) / MISSING (read) | NG-b "Infrastructure as Code, cloud provisioning" — bucket config belongs to terraform. Reading (e.g. `storage info` showing versioning/lifecycle/policy) does not exist yet | P3 (read only) |
| Versioning on/off for a bucket | `aws s3api put-bucket-versioning`, `mc version enable` | NON-GOAL | NG-b | - |
| Bucket info (region, versioning enabled, object lock, size) | `mc stat alias/bucket`, `aws s3api get-bucket-*`, `gsutil ls -L -b` | MISSING | `komando test` only checks that it can be reached | P3 |
| MinIO admin (users, policies, heal, server info, quota) | `mc admin ...` | NON-GOAL (partial) | NG-a (replacing full tools). `mc admin info` (health) could be P3 | P3 |
| Mount as a filesystem | `rclone mount`, `s3fs`, `mc` (no) | NON-GOAL | NG-c "daemon/server"; FUSE also needs OS components/cgo | - |
| Serve (HTTP/WebDAV/SFTP/S3 from a remote) | `rclone serve`, `mc` | NON-GOAL | NG-c "daemon/server" | - |
| Interactive usage analysis | `rclone ncdu` | NON-GOAL | NG-c "TUI" (decision #5: "No. Pure CLI"); the non-interactive version = `du` (section A) | - |

## F. Storage: backends / protocols

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| AWS S3 | `aws s3`, `mc`, `rclone`, `s3cmd` | PRESENT | `s3://KEY@bucket/prefix?region=` (default AWS endpoint) | - |
| S3-compatible: MinIO, R2, Wasabi, Spaces, Backblaze B2 (S3 API), Garage, Ceph RGW | `mc`, `rclone`, `aws --endpoint-url` | PRESENT | `?endpoint=https://...`; e2e-tested with Garage (`test/e2e/run.sh`, `test/e2e/garage/`), not MinIO | - |
| Path-style vs virtual-host set explicitly | `aws configure set s3.addressing_style`, `mc --path`, `rclone force_path_style` | PARTIAL | minio-go BucketLookupAuto; no URL option (`path_style` is rejected: "known: endpoint, region") | P3 |
| Self-signed TLS for an S3 endpoint (internal MinIO) | `mc --insecure`, `aws --no-verify-ssl`, `rclone --no-check-certificate` | MISSING | No `tls=skip-verify`/custom CA for s3 (it exists for ftps). Workaround: an `http://` endpoint through `--via` | P2 — on-prem MinIO with an internal CA is common |
| Native Google Cloud Storage (service account, OAuth) | `gsutil`, `gcloud storage`, `rclone gcs` | PARTIAL | Through S3 interop (HMAC key, endpoint `https://storage.googleapis.com`) it probably works; no service-account JSON. vision: "later: gcs" | P2 |
| Azure Blob Storage | `az storage blob`, `azcopy`, `rclone azureblob` | MISSING | vision: "later: ... azblob"; needs a light REST client (SharedKey/SAS), not the full SDK (binary size is no longer limited, but a light client is still simpler) | P2 |
| WebDAV (Nextcloud, ownCloud, hosting) | `rclone webdav`, `curl`, `cadaver` | MISSING | vision: "later: webdav" | P2 |
| SFTP (accounts without a shell) | `sftp`, `lftp sftp://`, `rclone sftp` | PRESENT | `sftp://` as a storage conn, host key checked, key/agent/password, `--via` | - |
| Explicit FTPS (AUTH TLS) | `lftp`, `curl --ssl-reqd`, `ncftp` | PRESENT | `ftps://`, TLS 1.2+, session resume, `?tls=skip-verify` | - |
| Implicit FTPS (port 990) | `lftp ftps://`, `curl ftps://` | MISSING | Only `DialWithExplicitTLS` | P3 — still used by old hosting |
| Plain FTP | `lftp`, `ncftp`, `curl ftp://` | PRESENT | Rejected without `?insecure=1` (secure by default) | - |
| FTP active mode / passive options (EPSV off) | `lftp set ftp:passive-mode`, `curl --ftp-port` | MISSING | Only the library's built-in passive mode | P3 |
| SMB/CIFS | `smbclient`, `rclone smb` | MISSING | | P3 |
| Google Drive, Dropbox, OneDrive, Box | `rclone` | MISSING | Needs interactive OAuth; not daily devops | P3 |
| OpenStack Swift, HDFS, HTTP index, etc. (70+ rclone backends) | `rclone` | MISSING | Workaround: `exec` rclone on the host | P3 |

## G. Storage: credentials, import, security

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Static access key + secret in the vault | `aws configure`, `mc alias set`, `rclone config` | PRESENT | User = access key ID in the URL, secret through `--password-ref` (vault/env/file/op/vault/aws-sm/gcp-sm) | - |
| Temporary credentials: session token, AWS profile/SSO, AssumeRole, credential_process, IMDS | `aws sso login`, `aws --profile`, `AWS_SESSION_TOKEN`, `rclone env_auth` | MISSING | `credentials.NewStaticV4(t.User, secret, "")` — the token is always empty | **P1** — many AWS organizations forbid permanent keys; without this, storage cannot be used there |
| Import `~/.aws/config` + `credentials` | `aws` | MISSING | Planned in the vision.md migration table (`aws`), not in `importSources` | P2 |
| Import rclone S3/FTP/WebDAV remotes | `rclone.conf` | PARTIAL | `importRclone` only `sftp`; other types are noted as "is not imported" (S3 keys in rclone are not obscured, so they can be imported) | P2 |
| Import FileZilla FTP/FTPS | `sitemanager.xml` | PARTIAL | `importFileZilla` only Protocol 1 (SFTP); FTP/FTPS are skipped | P2 — FileZilla is the most common tool for FTP hosting |
| Import `mc` aliases (`~/.mc/config.json`), `.s3cfg` | `mc`, `s3cmd` | MISSING | | P3 |
| Import S3 URLs from `.env` | `.env` | PRESENT | `import env` recognizes `s3://` | - |
| Through a bastion / VPN | `aws` + proxy, `rclone` + ssh tunnel | PRESENT | `--via` for s3 (Transport.DialContext), ftp (data conn too), sftp (sshx) | - |
| Protected conn, `--yes`, `--allow-dangerous`, audit | (not in other tools) | PRESENT | `withStorage` → `guardConns`, audit without secrets for all storage commands (including `ls`/`download`) | - |
| Read-only enforced by the server | Read-only IAM key | PARTIAL | Recommended in the docs ("access key that can only do what you need"); komando itself does not distinguish read/write keys per conn | P3 |
| Downloads do not overwrite, atomic, mode 0600 | `aws s3 cp` (overwrites), `rclone` (overwrites) | PRESENT | Safer than the comparison tools | - |
| Accidental overwrite on upload (`--no-clobber`/`--if-none-match`) | `rclone --ignore-existing`, `aws s3api put-object --if-none-match`, `mc cp --disable-multipart` | PARTIAL | `replaced:true` is reported afterwards; no option to refuse if it already exists | P2 — the agent overwrites backups without noticing |

---

## H. Registry: reading

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List repositories (catalog) | `crane catalog`, `regctl repo ls`, `skopeo` (no), Harbor API | PARTIAL | `registry ls CONN`; **`Catalog()` does not follow the `Link` header** (only `n=limit`, one page), while `Tags()` does follow it. Registries that limit `n` (Harbor/GitLab/registry:2 with a limit) return a truncated list without `more` | **P1** — results are silently incomplete (the agent draws wrong conclusions) |
| List tags | `crane ls`, `skopeo list-tags`, `regctl tag ls`, `docker` (no) | PRESENT | `registry ls CONN REPO` with `Link` pagination, `--limit` | - |
| List tags with digest/date, sorted/semver, filter | `regctl tag ls` + `--include`, Harbor/ECR `describe-images`, `crane ls --full-ref` | MISSING | Only tag names; needs `inspect` per tag | P2 — the basis for cleanup |
| Inspect image: digest, size, platform, created, labels | `skopeo inspect`, `crane manifest`/`config`, `regctl image inspect`, `docker buildx imagetools inspect`, `docker manifest inspect` | PRESENT | `registry inspect CONN REPO[:TAG\|@DIGEST]` | - |
| Digest only | `crane digest`, `regctl image digest`, `skopeo inspect --format {{.Digest}}` | PRESENT | `digest` field in `inspect` | - |
| Full config (Env, Entrypoint, Cmd, ExposedPorts, User, WorkingDir) | `crane config`, `skopeo inspect --config`, `regctl image config` | MISSING | `Inspect` only takes `created`, `os/arch`, `Labels` | P2 — the agent needs ports/env for deploys |
| Raw manifest (JSON) | `crane manifest`, `regctl manifest get --format raw`, `skopeo inspect --raw` | MISSING | | P2 — debugging and the "native CLI features" path |
| Inspect per platform (`--platform linux/arm64`) | `crane --platform`, `skopeo --override-arch`, `regctl --platform` | MISSING | For an index, only the platform list; size/labels are not per platform | P2 |
| Layers & history (command per layer, size per layer) | `dive`, `crane config` (history), `regctl image config` | MISSING | Only the layer count + total size | P3 (interactive dive = NON-GOAL, NG-c "TUI") |
| Get a blob/file from an image without pulling (`crane export`, `regctl blob get`, `crane blob`) | `crane export`, `regctl blob get`, `regctl image get-file` | MISSING | | P3 |
| List manifests without tags (untagged) | Harbor/ECR API, `regctl` (not directly) | MISSING | The Distribution API has no standard endpoint | P3 |
| Referrers (attached signatures, SBOMs, attestations) | `oras discover`, `regctl artifact tree`, `cosign tree` | MISSING | Attestations in an index are skipped (`platform.os == "unknown"`) | P3 |
| Check Docker Hub rate limit | `curl` header `ratelimit-remaining`, `regctl` | MISSING | ux.md edge case mentions "Docker Hub rate limit" | P3 |
| Check login/access | `docker login`, `crane auth`, `skopeo login` | PARTIAL | `komando test CONN` / `conn test` only opens a TCP connection to the registry (`testConn`, `Check = "tcp"`), it does not log in. A wrong password/token only shows up at `registry ls`/`inspect` | P2 — the agent thinks the conn is healthy while the token has expired (see also ECR 12 hours) |

## I. Registry: writing and copying

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Copy images between registries (all platforms, same digest) | `crane copy`, `skopeo copy --all`, `regctl image copy`, `oras copy` | PRESENT | `registry copy SRC:IMG DST:[IMG]`; existing layers are skipped, mount on the same registry, `replaced:true`, protected destination needs `--yes`, `--dry-run` | - |
| Retag in the same registry | `crane tag`, `regctl image copy`, `docker buildx imagetools create -t` | PRESENT | `registry copy reg:app:latest reg:app:stable` (manifest only; blobs are mounted) | - |
| Copy only certain platforms | `skopeo copy --override-arch`, `crane copy --platform` | MISSING | Always all platforms | P3 |
| Copy all tags / sync a repo or an image list | `skopeo sync`, `regctl image copy` loop, `crane copy --all-tags` | MISSING | One image per command | P2 — registry migration, mirroring to an internal registry |
| Copy along with signatures/SBOMs (referrers, `sha256-*.sig` tags) | `cosign copy`, `oras copy -r`, `regctl image copy --referrers` | MISSING | The digest stays the same, so signatures stay valid, but the signature artifacts are not copied | P2 — verification fails at the destination registry |
| Push an image from the laptop (tarball/OCI layout/local daemon) | `docker push`, `crane push`, `skopeo copy docker-archive:/oci:`, `oras push` | MISSING | On a host: `docker raw push` (raw path). Nothing from the laptop | P3 — build/push belongs to CI |
| Pull/export to a tarball or OCI layout | `crane pull --format`, `skopeo copy ... docker-archive:`, `docker save` | MISSING | On a host: `docker pull`, `docker raw save` | P3 |
| Pull an image on a server (deploy) | `docker pull` | PRESENT | `komando docker pull TARGET IMAGE` (host) | - |
| Registry login on a server so a private `docker pull` works, without exposing the password to the agent | `docker login --password-stdin`, `crane auth login` | MISSING | The `docker raw login` workaround on the host would make the agent see/write the secret; there is no way to use a registry conn's `--password-ref` on a host (or for a k8s `imagePullSecret`) | P2 — secret safety during deploys |
| Image mutation (labels, env, entrypoint, append layer, flatten, rebase) | `crane mutate/append/flatten/rebase`, `regctl image mod` | NON-GOAL | NG-a "Replacing full tools"; this is build/CI work, not a daily operation | - |
| Create a multi-arch index from existing images | `docker buildx imagetools create`, `docker manifest create/push`, `regctl index create` | MISSING | | P3 |
| OCI artifacts (push/pull files, attach) | `oras push/pull/attach`, `regctl artifact put/get` | MISSING | `copy` copies the manifest as is, so tagged artifacts are probably copied too; no file push/pull | P3 |
| Create a repository before pushing (required by ECR) | `aws ecr create-repository`, Harbor project API | MISSING | `copy` to an ECR repo that does not exist yet will fail | P2 — for ECR, related to the ECR support claim |

## J. Registry: deleting and cleaning up

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Delete an image (manifest by digest) | `crane delete`, `skopeo delete`, `regctl manifest rm`, `regctl image delete` | PRESENT | `registry rm --allow-dangerous`, resolves tag → digest, protected `--yes`, GC note | - |
| Warning about other tags that disappear too | (regctl `tag rm` makes the distinction) | PARTIAL | Help/docs say "every tag that points at it goes too", but the `rm` and `--dry-run` result is only `would_delete: repo@digest` — **it does not say which tags are deleted along with it** (e.g. `latest`, `stable`) | **P1** — security: the agent deletes `old` and also deletes `prod` |
| Delete only a tag (untag) without deleting the manifest | `regctl tag rm` (OCI 1.1 tag delete / dummy manifest), Harbor/ECR `batch-delete-image --image-ids imageTag=` | MISSING | `rm` always deletes the manifest | P2 — a safe way to clean up tags |
| Bulk cleanup: keep the N newest tags / delete older than X, with a preview | `regctl` + scripts, Harbor tag retention, ECR lifecycle policy, `crane` + jq | MISSING | Docs: "clean up old ones", but only one image per `rm`; no dates in `ls` | **P1** — a full registry is a daily complaint; the agent has to `inspect` + `rm` one by one |
| Registry garbage collection | `registry garbage-collect` (registry:2), Harbor GC API, GitLab cleanup | MISSING | Workaround: `exec`/`docker exec` on the registry:2 host (`registry garbage-collect /etc/docker/registry/config.yml`) | P3 |
| Retention policy / immutable tags / tag protection (Harbor, ECR, GHCR) | Harbor API, `aws ecr put-lifecycle-policy`, `put-image-tag-mutability` | NON-GOAL | NG-b "cloud provisioning / IaC" — registry config is managed by terraform/the console | - |

## K. Registry: auth and specific providers

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Basic auth + bearer token (Docker Hub, GHCR, GitLab, Harbor, registry:2, Quay) | `docker login`, `crane auth`, `skopeo login`, `regctl registry login` | PRESENT | `registry.New`, token per scope, non-https realm rejected | - |
| Registry without TLS / self-signed | `--insecure-registry`, `skopeo --tls-verify=false`, `regctl registry set --tls disabled` | PARTIAL | `?tls=false` (plain HTTP). No `skip-verify`/custom CA for self-signed HTTPS | P2 — internal Harbor with its own CA is common |
| AWS ECR (12-hour `get-login-password` token) | `aws ecr get-login-password`, `docker-credential-ecr-login`, `crane` (ecr helper) | PARTIAL | The docs claim ECR, but there is no SigV4 token generator; the token has to be copied manually into the vault and expires after 12 hours. `import docker` can read from the `ecr-login` helper only once | **P1** — the support claim cannot be used reliably; the agent gets stuck every 12 hours |
| Google Artifact Registry / GCR | `gcloud auth configure-docker`, `docker-credential-gcr` | PARTIAL | Possible with user `_json_key` + the service account JSON as the secret (basic). `oauth2accesstoken` token (1 hour) without refresh | P2 |
| Azure ACR (AAD token) | `az acr login`, `az acr repository list` | PARTIAL | Admin user / service principal (basic) works; AAD token exchange is missing | P3 |
| Credential helper at runtime (not only at import) | `docker-credential-*`, `credHelpers` | PARTIAL | `credHelper()` is only called in `import docker`; the password is copied into the vault (not refreshed) | P2 (solves ECR/GCR at the same time) |
| Harbor-specific features (projects, robot accounts, scan results, replication) | Harbor API/UI | MISSING | Partly NG-a / NG-b | P3 |
| GHCR/Docker Hub repository listing (no catalog) | `gh api /orgs/x/packages`, Hub API | MISSING | Error `REGISTRY_UNSUPPORTED` "Docker Hub and GHCR have no catalog" — honest, but with no alternative | P3 |

## L. Registry: supply chain security

| Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Signature verification (cosign/notation) | `cosign verify`, `notation verify` | MISSING | The Sigstore SDK is heavy (binary size is no longer limited); workaround `exec cosign` on the host | P2 — verification before deploy (checking "is this image signed" via referrers could be light) |
| Image signing | `cosign sign`, `notation sign` | NON-GOAL | NG-a; CI work, signing keys are not for daily agents | - |
| View SBOMs / attestations | `cosign download sbom/attestation`, `oras discover`, `docker buildx imagetools inspect --format '{{json .SBOM}}'` | MISSING | | P3 |
| Image vulnerability scan | `trivy image`, `grype`, Harbor/ECR scan | MISSING | Large vulnerability DB + heavy scanner (needs constant DB downloads); workaround `exec trivy` on the host. Reading Harbor/ECR scan results (API) could be P3 | P3 (scanning itself is close to NON-GOAL NG-a) |
| Interactive layer analysis | `dive` | NON-GOAL | NG-c "TUI" | - |

---

## Extra notes found during verification

1. `registry.Catalog` does not paginate (see H) — a correctness bug, not just a feature.
2. `registry rm --dry-run` does not name the other tags that are deleted along with it (see J).
3. S3 does not support session tokens at all (`NewStaticV4(..., "")`), so AWS SSO/STS credentials cannot be used (see G).
4. `fileTarget`/`cp`: storage and hosts share the same verbs (`upload`/`download`), but the `-r` flag is for hosts only; the sync/recursive design should unify the two.
5. `bin/komando` at 51 MB is an unstripped dev build; the release build (`-s -w -trimpath`, CGO_ENABLED=0) is **34.7 MB**. Binary size is no longer limited, so Azure/GCS/cosign are not blocked by size.
6. FileZilla and rclone import only SFTP, even though storage already supports FTP/FTPS/S3 (see G).
7. `komando test` / `conn test` for registry and storage conns only opens a TCP connection (`testConn`, `internal/cli/conn.go`); login is not tried. Wrong credentials or an expired token only show up at a real command (see H, "Check login/access").

## Status count

Already corrected after per-row verification (see the last section).

| Status | Row count |
|---|---|
| PRESENT | 26 |
| PARTIAL | 19 |
| MISSING | 81 |
| NON-GOAL | 12 |
| **Total** | **138** |

Rows with a double status are counted by their first status: "PRESENT (implicit)" as PRESENT, "MISSING (storage/on purpose/not relevant)" as MISSING, "NON-GOAL (partial)" and "NON-GOAL (change) / MISSING (read)" as NON-GOAL.

Priority for gaps (PARTIAL + MISSING, 100 rows): P1 = 10, P2 = 44, P3 = 46. Apart from that, 4 other rows are also given P3 (multipart "PRESENT (implicit)" for its settings, and 3 NON-GOAL rows where a small part still makes sense).

## Top 10 P1 gaps

| # | Gap | Reason (vision) |
|---|---|---|
| 1 | `storage sync` folder ↔ bucket/FTP (with an honest `--dry-run`, `--delete` guarded by `--allow-dangerous`, include/exclude) | The `sync` verb is promised in vision.md; daily deploys/backups |
| 2 | `upload -r` folder to storage | 80% of daily work (FTPS sites, S3 static) |
| 3 | `download -r` prefix from storage | Backup restore; the agent does not need to loop |
| 4 | `storage cat` (stdout, `--head/--tail/--max-bytes`) | Agent pattern that already exists in `fs cat` |
| 5 | `storage rm` by prefix/age with a preview and a limit | Backup retention, secure by default |
| 6 | Temporary S3 credentials (session token, profile/SSO, AssumeRole) | Blocker in AWS organizations; secure by default (no permanent keys) |
| 7 | Automatic ECR token (or credential helper at runtime) | The docs claim ECR; the 12-hour token cuts off the agent |
| 8 | `Catalog` follows `Link` pagination | Silently truncated results = wrong answers for the agent |
| 9 | `registry rm` (and `--dry-run`) names all tags deleted along with it | Destructive-action safety |
| 10 | Registry tag cleanup: keep the N newest / older than X, with a preview | The docs promise "clean up old ones"; daily complaint about full registries |

## Per-row verification

Every row in sections A–L was re-checked against the code at commit `4784fc9` (not from the old "Evidence" text). Path abbreviations: `cli/` = `internal/cli/`, `storex/` = `internal/storex/`, `reg/` = `internal/registry/`, `driver.go` = `internal/driver/driver.go`. "grep X: 0 results" means a search in `internal/` (without `_test.go`) found nothing. The `storage` subcommands are only `ls`, `download`, `upload`, `rm`, `link` (`cli/storage.go:42`); the `registry` subcommands are only `ls`, `inspect`, `copy`, `rm` (`cli/registry.go:33`); there are no built-in recipes for storage/registry (`recipe list`: 39 recipes, grep rclone/aws s3/skopeo/crane/cosign/trivy: 0 results).

| # | Capability (short) | Final status | Check result | Evidence in code |
|---|---|---|---|---|
| 1 | List one level | PRESENT | Correct | `cli/storage.go:170` (`ls CONN [PREFIX]`), DIR at `cli/storage.go:157`; `storex/storex.go:111` |
| 2 | Recursive list | PRESENT | Correct | `cli/storage.go:195-196` (`-r`, `--limit` 1000), `more` `cli/storage.go:165` |
| 3 | Pagination / continuation token | MISSING | Correct | `storex/storex.go:111` without `StartAfter`; grep `StartAfter\|starting-token\|continuation`: 0 results |
| 4 | Total size (`du`/`--summarize`) | MISSING | Correct | `objectList` only `Count` (`cli/storage.go:145-151`); grep `summarize`: 0 results in storage |
| 5 | Tree | MISSING | Correct | grep `"tree"`: 0 results |
| 6 | Download one object | PRESENT | Correct | `cli/storage.go:311-336` (`FILE_EXISTS` :316, `writeAtomic` :321); 0600 in `cli/dbdump.go:341` |
| 7 | Recursive prefix download | MISSING | Correct | `cli/transfer.go:98` "-r is for servers; storage downloads one object" |
| 8 | Upload one file | PRESENT | Correct | `cli/storage.go:339-365` (`replaced` :350, mime :359); temp+rename `storex/ftp.go:209`, `storex/sftp.go:150` |
| 9 | Recursive folder upload | MISSING | Correct | `cli/transfer.go:64`; `fi.IsDir()` rejected `cli/storage.go:345` |
| 10 | Stream stdin/stdout | MISSING | Correct | `os.Stat` + `IsDir` `cli/storage.go:344-345`; `--to` is used directly as the file name `cli/storage.go:312-321` |
| 11 | `storage cat` | MISSING | Correct | No `cat` subcommand (`cli/storage.go:42`); `fs cat --head` is host only `cli/fs.go:313` |
| 12 | Stat/head object | MISSING | Correct | Only an internal `Exists` `storex/storex.go:146`; no `stat` subcommand |
| 13 | Checksum verification | PARTIAL | Correct | Host: `cli/cp.go:62`, `cli/fs.go:215`; storage: upload/download results without a hash `cli/storage.go:335,363` |
| 14 | Multipart for large files | PRESENT (implicit) | Correct | `storex/storex.go:167` `PutObject` with size; grep `PartSize\|NumThreads`: 0 results |
| 15 | Clean up orphaned multipart | MISSING | Correct | grep `ListIncompleteUploads\|RemoveIncompleteUpload\|AbortMultipart`: 0 results |
| 16 | Resume transfer | MISSING | Correct | `storex/storex.go:67` `MaxRetry = 2`; no offset/range in `Get` |
| 17 | Progress on stderr | MISSING | Correct | grep `progress` in `internal/`: 0 results; ux.md:321 |
| 18 | Parallel transfer (storage) | MISSING | Correct | One object per command `cli/storage.go:339`; parallel only in host `runCp` `cli/cp.go:88` |
| 19 | Bandwidth limit | MISSING | Correct | grep `bwlimit\|RateLimit\|rate.Limit`: 0 results |
| 20 | Long transfers in the background | MISSING | Corrected (evidence): "limited by `--timeout`" → limit only when `--timeout` is given | `cli/storage.go:73` (`if g.timeout > 0`); `cli/root.go:164` default 0 |
| 21 | Delete exact objects | PRESENT | Correct | `cli/storage.go:236-266`, `DataDelete` :250, `already deleted` :258 |
| 22 | Delete prefix/pattern/age | MISSING (on purpose) | Correct | `cli/storage.go:246` "rm takes exact keys" |
| 23 | Dry-run for changes | PARTIAL | Correct | `cli/storage.go:67-70` "nothing sent: the change would be allowed" (no server check) |
| 24 | Include/exclude | MISSING | Correct | `ls` flags only `-r`,`-n` `cli/storage.go:195-196`; grep `exclude` in storage: 0 results |
| 25 | Find objects | MISSING | Correct | No `find` subcommand; no age/size filter in `List` `storex/storex.go:31` |
| 26 | Rename/move objects | MISSING | Correct | `Bucket` interface without Move `storex/storex.go:28-41`; `Rename` only for temp uploads |
| 27 | Server-side copy | MISSING | Correct | grep `CopyObject\|ComposeObject`: 0 results |
| 28 | Copy between conns/areas | MISSING | Correct | `cli/cp.go:73` "remote-to-remote copy is not supported" |
| 29 | Create an empty folder | PARTIAL | Correct | Automatic on upload `storex/ftp.go:206`, `storex/sftp.go:126`; no `storage mkdir` |
| 30 | chmod/chown on file servers | MISSING | Correct | `Chmod` only internal on upload `storex/sftp.go:149`; `fs chmod` is host only |
| 31 | Symlinks/owner in listings | MISSING | Correct | `Object{Key,Size,Modified,Dir}` `storex/storex.go:97-102` |
| 32 | Sync local ↔ bucket/FTP | MISSING | Correct | No `sync` subcommand; promised in vision.md:107 and :130 |
| 33 | Sync to an SSH host (delta) | PARTIAL | Correct | `upload -r` through `runCp` `cli/cp.go:88` without skip/delete (grep `skip\|unchanged` in cp.go: 0 results); `--if-changed` 1 file `cli/fs.go:550` |
| 34 | Two-way sync | MISSING | Correct | grep `bisync`: 0 results |
| 35 | Mirror bucket to bucket | MISSING | Correct | grep `mirror` in storage: 0 results; copy between conns rejected `cli/cp.go:73` |
| 36 | Watch/continuous mirror | NON-GOAL | Correct | vision.md:227 (daemon/server), :228 (runs continuously) |
| 37 | Diff/check | MISSING | Correct | No subcommand; grep `diff\|check` in storage: 0 results |
| 38 | Dedupe | MISSING | Correct | grep `dedupe`: 0 results |
| 39 | `--size-only`/`--checksum` | MISSING | Correct | grep `size-only`: 0 results |
| 40 | Presigned download URL | PRESENT | Correct | `cli/storage.go:270-295` (max 168h :282, RiskWrite :286); `storex/storex.go:189-190` |
| 41 | Presigned upload URL | MISSING | Correct | grep `PresignedPut\|PresignedPost`: 0 results |
| 42 | Permanent public link | MISSING | Correct | grep `acl\|anonymous` in storex: 0 results |
| 43 | FTP/SFTP links | MISSING (not relevant) | Corrected: NON-GOAL → MISSING (P3) | Not in vision.md "Non-goals" (:221-228); `storex/ftp.go:244,249`, `storex/sftp.go:190` |
| 44 | Restrict a conn to a prefix | PRESENT | Correct | `storex/storex.go:45-56` (`..` rejected) |
| 45 | Content-Type on upload | PARTIAL | Correct | `cli/storage.go:359` `mime.TypeByExtension`; no `upload` flag (`cli/storage.go:217-234`) |
| 46 | Cache-Control/metadata | MISSING | Correct | Only `PutObjectOptions{ContentType}` `storex/storex.go:167`; grep `CacheControl\|UserMetadata`: 0 results |
| 47 | Storage class | MISSING | Correct | grep `StorageClass\|storage-class`: 0 results |
| 48 | Glacier restore | MISSING | Correct | grep `RestoreObject\|restore-object`: 0 results |
| 49 | SSE-KMS/SSE-C | MISSING | Correct | grep `ServerSideEncryption\|encrypt.` in storex: 0 results |
| 50 | Client-side encryption | MISSING | Correct | grep `crypt` in storex: 0 results other than `crypto/tls` |
| 51 | Object tagging | MISSING | Correct | grep `Tagging`: 0 results |
| 52 | Object ACL | MISSING | Correct | grep `ACL\|acl` in storex: 0 results |
| 53 | Object versioning | MISSING | Correct | grep `VersionID\|WithVersions`: 0 results; ux.md:331 |
| 54 | Object lock | MISSING | Correct | grep `Retention\|LegalHold`: 0 results |
| 55 | Requester pays/accel | MISSING | Correct | s3 URL options only `endpoint`,`region` `driver.go:293` |
| 56 | S3 Select | MISSING | Correct | grep `SelectObjectContent`: 0 results |
| 57 | List buckets | MISSING | Correct | `driver.go:265` "s3 URL needs a bucket"; grep `ListBuckets`: 0 results |
| 58 | `mb`/`rb` | NON-GOAL (partial) | Correct | vision.md:226 (cloud provisioning); grep `MakeBucket\|RemoveBucket`: 0 results |
| 59 | Bucket policy/CORS/lifecycle | NON-GOAL (change) / MISSING (read) | Correct | vision.md:226; grep `GetBucketPolicy\|Lifecycle`: 0 results |
| 60 | Bucket versioning on/off | NON-GOAL | Correct | vision.md:226 |
| 61 | Bucket info | MISSING | Correct | `testConn` TCP only `cli/conn.go:491,498` |
| 62 | MinIO admin | NON-GOAL (partial) | Correct | vision.md:223 (replacing full tools) |
| 63 | Mount filesystem | NON-GOAL | Correct | vision.md:227 (daemon/server), :180 (no cgo) |
| 64 | Serve | NON-GOAL | Correct | vision.md:227 |
| 65 | Interactive analysis (ncdu) | NON-GOAL | Correct | vision.md:227 (TUI), decision #5 vision.md:238 |
| 66 | AWS S3 | PRESENT | Correct | `driver.go:276` default AWS endpoint |
| 67 | S3-compatible | PRESENT | Corrected (evidence): e2e uses Garage, not MinIO | `driver.go:274-293`; `test/e2e/run.sh:143` (`region=garage`), compose without MinIO |
| 68 | Explicit path-style | PARTIAL | Correct | `storex/storex.go:78-83` without `BucketLookup`; `driver.go:293` |
| 69 | Self-signed TLS for S3 | MISSING | Correct | `storex/storex.go:71-84` without `TLSClientConfig`; `InsecureSkipVerify` only in `storex/ftp.go:40` and `internal/kube` |
| 70 | Native GCS | PARTIAL | Correct | Only the `s3` kind `driver.go:75`; grep `gcs\|googleapis`: 0 results; vision.md:94 |
| 71 | Azure Blob | MISSING | Correct | grep `azblob\|azure`: 0 results |
| 72 | WebDAV | MISSING | Correct | grep `webdav`: 0 results; storage kinds only s3/ftps/ftp/sftp `driver.go:75-82` |
| 73 | SFTP without a shell | PRESENT | Correct | `cli/storage.go:98-115` (sshx.Dial, host key), `driver.go:81` |
| 74 | Explicit FTPS | PRESENT | Correct | `storex/ftp.go:39-43,72`; `driver.go:251` |
| 75 | Implicit FTPS | MISSING | Correct | Only `DialWithExplicitTLS` `storex/ftp.go:72`; grep `DialWithImplicitTLS`: 0 results |
| 76 | Plain FTP | PRESENT | Correct | `driver.go:243` `INSECURE_PROTOCOL` without `?insecure=1` |
| 77 | FTP active/EPSV off | MISSING | Correct | grep `DisableEPSV\|ActiveMode`: 0 results |
| 78 | SMB/CIFS | MISSING | Correct | grep `smb`: 0 results |
| 79 | Google Drive/Dropbox/… | MISSING | Correct | No kind (`driver.go:62-82`) |
| 80 | Swift/HDFS/other backends | MISSING | Correct | grep `swift\|hdfs`: 0 results |
| 81 | Access key + vault secret | PRESENT | Correct | `storex/storex.go:79`; `--password-ref` `cli/conn.go:66` |
| 82 | Temporary AWS credentials | MISSING | Correct | `storex/storex.go:79` `NewStaticV4(t.User, secret, "")`; grep `SessionToken\|AssumeRole\|NewIAM\|AWS_PROFILE`: 0 results |
| 83 | Import `~/.aws` | MISSING | Correct | `importSources` `cli/importer.go:48-58` without `aws`; planned in vision.md:166 |
| 84 | Import rclone S3/FTP | PARTIAL | Correct | `cli/importer.go:771` only `sftp`, the rest "is not imported" :783 |
| 85 | Import FileZilla FTP/FTPS | PARTIAL | Correct | `cli/importer.go:711` `Protocol != 1` skipped |
| 86 | Import `mc`/`.s3cfg` | MISSING | Correct | `cli/importer.go:48-58`; grep `mc/config\|s3cfg`: 0 results |
| 87 | Import S3 URLs from `.env` | PRESENT | Correct | `cli/importer.go:499,508` (all kind schemes, including `s3`) |
| 88 | Through a bastion/VPN | PRESENT | Correct | S3 `storex/storex.go:73-75`; FTP data conn `storex/ftp.go:50-69`; SFTP `cli/storage.go:103` |
| 89 | Protected/`--yes`/audit | PRESENT | Correct | `cli/storage.go:64` guardConns, audit :68 and :87 (also for ls/download) |
| 90 | Read-only on the server | PARTIAL | Correct | Only a recommendation `docs/features/storage.md:30`; no read-only mode per conn |
| 91 | Safe downloads (0600, atomic) | PRESENT | Correct | `cli/storage.go:316,321`; `cli/dbdump.go:334-349` |
| 92 | Upload no-clobber | PARTIAL | Correct | `replaced` afterwards `cli/storage.go:350,363`; grep `no-clobber\|if-none-match\|ignore-existing`: 0 results |
| 93 | List repositories (catalog) | PARTIAL | Correct | `reg/registry.go:256-262` one request `n=limit`, without `nextLink`; output without `more` `cli/registry.go:137-141` |
| 94 | List tags | PRESENT | Correct | `reg/registry.go:265-290` (`nextLink` :278) |
| 95 | Tags + digest/date/filter | MISSING | Correct | `Tags` names only `reg/registry.go:265`; `ls` only `-n` `cli/registry.go:151` |
| 96 | Inspect image | PRESENT | Correct | `cli/registry.go:155`, `reg/registry.go:319-372` |
| 97 | Digest only | PRESENT | Correct | `reg/registry.go:340` `Docker-Content-Digest` |
| 98 | Full config | MISSING | Correct | Only `Created`, `OS`, `Arch`, `Labels` `reg/registry.go:356-368` |
| 99 | Raw manifest | MISSING | Correct | `inspect` without flags `cli/registry.go:155-168`; grep `raw` in registry: 0 results |
| 100 | Inspect per platform | MISSING | Correct | Index only lists platforms `reg/registry.go:341-349`; grep `--platform`: 0 results |
| 101 | Layers & history | MISSING | Correct | Only count + total size `reg/registry.go:350-353` |
| 102 | Get blob/file | MISSING | Correct | No subcommand (`cli/registry.go:33`); grep `export\|blob get`: 0 results |
| 103 | Untagged manifests | MISSING | Correct | No endpoint other than catalog/tags/manifests/blobs `reg/registry.go:155-175` |
| 104 | Referrers | MISSING | Correct | Attestations skipped `reg/registry.go:342`; grep `referrers`: 0 results in registry |
| 105 | Docker Hub rate limit | MISSING | Correct | grep `ratelimit-remaining`: 0 results; ux.md:333 |
| 106 | Check login/access | PARTIAL | Corrected: PRESENT → PARTIAL (P2) | `cli/conn.go:470-504`: `testConn` only `dial(tcp)` :491,498, without a `/v2/` request |
| 107 | Copy between registries | PRESENT | Correct | `cli/registrycopy.go:16-133`; skip `reg/copy.go:21`, mount :150, replaced :56; `--yes` :91, `--dry-run` :99 |
| 108 | Retag in the same registry | PRESENT | Correct | Blob mount `reg/copy.go:146-158`; example `cli/registrycopy.go:30` |
| 109 | Copy certain platforms | MISSING | Correct | `copy` without flags `cli/registrycopy.go:16-36` |
| 110 | Copy all tags / sync | MISSING | Correct | `cobra.ExactArgs(2)`, one image `cli/registrycopy.go:31`; grep `all-tags`: 0 results |
| 111 | Copy with signatures/SBOMs | MISSING | Correct | grep `referrers\|\.sig`: 0 results in `reg/copy.go` |
| 112 | Push from the laptop | MISSING | Correct | No push subcommand; host: `docker raw` `cli/modules.go:383` |
| 113 | Pull/export tarball | MISSING | Correct | grep `docker-archive\|oci-layout`: 0 results |
| 114 | Pull an image on a server | PRESENT | Correct | `docker pull` `cli/modules.go:304` |
| 115 | Registry login on a server without exposing the secret | MISSING | Correct | grep `password-stdin\|imagePullSecret\|docker login`: 0 results |
| 116 | Image mutation | NON-GOAL | Correct | vision.md:223 (replacing full tools) |
| 117 | Create a multi-arch index | MISSING | Correct | grep `index create\|imagetools`: 0 results |
| 118 | OCI artifacts | MISSING | Correct | No file push/pull; `copy` copies the manifest `reg/copy.go:77` |
| 119 | Create a repository (ECR) | MISSING | Correct | grep `CreateRepository\|create-repository`: 0 results |
| 120 | Delete an image | PRESENT | Correct | `cli/registry.go:171-199` (resolve via `Inspect`, GC note :195), `reg/registry.go:375` |
| 121 | Warning about tags that disappear too | PARTIAL | Correct | `cli/registry.go:189` only `would_delete: repo@digest`; help `cli/registry.go:174` mentions "every tag" |
| 122 | Untag only | MISSING | Correct | `Delete` always deletes the manifest by digest `reg/registry.go:375-382` |
| 123 | Bulk tag cleanup | MISSING | Correct | `rm` `cobra.ExactArgs(2)` `cli/registry.go:176`; docs promise `docs/features/registry.md:3-4` |
| 124 | Garbage collection | MISSING | Correct | grep `garbage-collect`: 0 results (only a text note `cli/registry.go:195`) |
| 125 | Retention/immutable tags | NON-GOAL | Correct | vision.md:226 |
| 126 | Basic + bearer token | PRESENT | Correct | `reg/registry.go:63-130`, scope `:155`, non-https realm rejected `:186` |
| 127 | Registry without TLS / self-signed | PARTIAL | Correct | `?tls=false` `cli/registry.go:92`, `reg/registry.go:38`; transport without `TLSClientConfig` `reg/registry.go:43` |
| 128 | AWS ECR token | PARTIAL | Correct | grep `GetAuthorizationToken\|SigV4\|ecr`: 0 results (only a comment `reg/registry.go:2`); claim in `docs/features/registry.md:4` |
| 129 | Google AR/GCR | PARTIAL | Correct | Only basic/bearer `reg/registry.go:99,203`; grep `oauth2accesstoken\|_json_key`: 0 results |
| 130 | Azure ACR | PARTIAL | Correct | Only standard basic/bearer; grep `acr\|aad`: 0 results in registry |
| 131 | Runtime credential helper | PARTIAL | Correct | `credHelper` only from `importDocker` `cli/registry.go:232,252` |
| 132 | Harbor-specific features | MISSING | Correct | grep `harbor` in code: only comments/examples |
| 133 | GHCR/Docker Hub listing | MISSING | Correct | 405 hint `cli/registry.go:105` |
| 134 | Signature verification | MISSING | Correct | grep `cosign\|notation\|sigstore`: 0 results |
| 135 | Image signing | NON-GOAL | Correct | vision.md:223 |
| 136 | View SBOMs/attestations | MISSING | Correct | grep `sbom\|attestation`: 0 results (only attestation comments `reg/registry.go:342-343`) |
| 137 | Vulnerability scan | MISSING | Correct | grep `trivy\|grype`: 0 results |
| 138 | Interactive layer analysis | NON-GOAL | Correct | vision.md:227 (TUI), :238 |

Verification summary: 138 rows checked, 4 corrected (2 status, 2 evidence). Status: #43 NON-GOAL → MISSING (P3), #106 PRESENT → PARTIAL (P2). Evidence: #20 (`--timeout` has no default for storage), #67 (e2e uses Garage, not MinIO). P1 priority stays at 10 rows.
