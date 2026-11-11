# Changelog

All notable changes are listed here, newest first. Each version starts with
its highlights; the sections below them give the details. Versions follow
[Semantic Versioning](https://semver.org), and the format follows
[Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### Security

- **Built with Go 1.27.4.** It fixes GO-2026-6859 in the standard
  `net/http` package. Building from source now needs Go 1.27.4 or newer.
- **No more ways to lock yourself out.** Stopping or disabling the SSH
  service is blocked on Debian and Ubuntu too (`ssh.service`, with any
  systemctl options), and `user lock`/`user rm` refuse root and the user
  komando logs in as.
- **`net http` takes only http:// and https:// URLs.** A URL that started
  with `-` reached curl as an option.
- **`tunnel start -R` on a protected server needs a person's yes,** like
  every other change there.
- **Every blocked attempt is in the audit log** (exit 6 stops, including
  safety settings and secrets sent somewhere), so `audit --failed` shows
  them. `guide install` is audited too.
- **An AI agent cannot run `secret keychain`;** it needs a person, as
  `secret passphrase` already did. It used to wait on the keychain prompt.

### Changed

- **One command for each job.** These old names still work in this
  release, print `komando: use X now`, and go away in the next one:
  - `cp`, `storage upload` and `storage download` run the same code as
    `upload` and `download`, with the same flags.
  - `script TARGET FILE` is now `exec TARGET --script FILE`.
  - `host import` is `import ssh-config` or `import komando`, and
    `host export` is `export` (`export kind:host` for servers only).
  - `prompt` is `status --short`.
  - `svc logs` and `docker logs` are `logs --unit` and `logs --container`.
  - `db query --csv`/`--tsv` are `db query -o csv`/`-o tsv`. An export
    has every row; one larger than `--max-output` fails instead of being
    cut.
- **Removed:** the aliases `ops`, `snippet`, `snippets` and `diag` (use
  `recipe`), `inspect` for `facts`, `systemd` for `svc`, the hidden
  `policy allow` (use `policy rm`), and the built-in recipes that a
  command already does (`recipe run ports` now names `net ports`).
- **One error code, one exit code.** Codes that exited differently in
  different places now always use the exit in `komando schema`:
  `DB_AUTH`, `QUEUE_AUTH`, `STORAGE_AUTH` and `DB_CONNECT` exit 4;
  `DB_PRIVILEGE`, `PERMISSION_DENIED`, `QUEUE_ERROR`, `TOOL_FAILED` and
  `UNSAFE_PATH` exit 5; `NOT_A_FOLDER` exits 8. A vault that cannot be
  opened for a server's password gives `VAULT_LOCKED`/`VAULT_KEY`/
  `VAULT_DECRYPT` instead of `SECRET_UNRESOLVED`.
- **`list` and `ls` work for every list.** Each command that lists takes
  both words.
- **A list for a TARGET that picks nothing of its kind fails** with
  `NO_MATCHING_TARGETS` (exit 3) instead of an empty success
  (`vpn list web1`, `host list kind:db`).
- **`db add`, `cache add` and the other family adds refuse another
  family's URL** (`WRONG_KIND`), and `cluster add k8s://...` asks for the
  kubeconfig it needs.
- **The names aws, gcp and azure are kept for `komando login`;** a server
  cannot take them.
- **`policy` rule ids come from the pattern** (`custom-1a2b3c4d`), so
  removing one rule no longer renumbers the others.
- **`registry rm` needs a tag or digest;** it used to pick `:latest`.

### Fixed

- **Over 150 bugs found by a hands-on review of every command.** The main
  ones:
  - **Dry runs:** a previewed edit says "would change", not "changed";
    `sync --delete`, `guide uninstall` and `vpn up` say what the real run
    would need; `registry copy --dry-run` checks both registries; a
    `--write --dry-run` on a missing SQLite file no longer creates it;
    Windows servers show the Windows command.
  - **Errors:** "not found" names the right kind ("web1 is a server") and
    never suggests the name you typed; hints name your real server or
    service instead of `NAME`; an AI agent reading text output gets the
    same advice as in JSON; a stray argument says the command takes none.
  - **Files and commands:** `fs cat --tail` on a big file reads its end;
    `cp` and `sync` accept `tag:`, `label:` and `kind:` and keep the port
    of `user@addr:port`; `--env KEY=a,b` keeps the comma; a script whose
    `#!` line uses `env -S` runs the right interpreter; uploading a file
    that holds a `[hidden]` value is refused everywhere;
    `upload CONN DIR -r` puts the folder under its own name.
  - **Databases and caches:** memcached keys with a TTL over 30 days no
    longer expire at once; `PRAGMA journal_mode=DELETE` is not called a
    mass delete; statements that load code (`CREATE EXTENSION`, `LOAD`)
    count as destructive; `cache run "SET a 1"` in one argument works;
    `XREAD` is a read; `MONITOR`/`SUBSCRIBE` are refused instead of
    hanging.
  - **Clusters:** `--timeout` now bounds every cluster and registry call
    (an unreachable cluster no longer hangs for minutes); `import
    kubeconfig` reads `$KUBECONFIG`, resolves relative certificate paths
    from the kubeconfig's folder and no longer gives one context's name to
    another; `cluster status` checks StatefulSets and DaemonSets.
  - **Servers:** `docker logs --sudo` uses sudo; `reboot` refuses Windows
    servers before it starts; `cert check` no longer fails at random on
    servers that reject post-quantum key shares; `pkg update` refuses
    package names it would have ignored.
  - **VPNs and settings:** `vpn up` that fails is audited as failed;
    `vpn mv` moves the VPN's own secrets to the new name, and adding a VPN again after `vpn rm` reuses them; `vpn edit`
    can change `--portal`; `config show` JSON lists every setting;
    `doctor` notices an agent guard that points to a missing program;
    `guide uninstall` checks first, then removes, so a stop changes
    nothing.
  - **Menu and forms:** Add something > Database no longer crashes;
    `komando db add` alone opens the database form; "Protect or unprotect"
    can unprotect; the review shows exactly the command that runs; Check
    everything runs `doctor` even when a server fails; a group's tasks
    leave out one-server tasks; risky tasks (`fs rm`, `docker prune`,
    `user rm`) get the "cannot be undone" warning.

- **Running now is what runs on this computer.** It lists and counts
  VPNs, logins and port forwards only. Background jobs run on the servers
  and keep going without this computer, so they sit under "Background
  jobs" (the same list as on a server) and are not counted; its count
  leaves out jobs that ended: komando remembers a job ended whenever it checks it (`job status`,
  `wait`, `list --refresh`, `rm`) and leaves out jobs whose server left
  your list. "Check which jobs still run" asks every server.

## [0.11.0] - 2026-11-11

### Highlights

- **A simpler menu: pick a thing, then what to do with it.** `komando`
  now shows your servers, databases and services, and VPNs first, then
  Add something, Check everything, History and undo, and Settings and
  help. Picking a server shows plain tasks such as Read logs, Restart a
  service or Edit a file. "All features" is gone; every feature is still
  reachable, and a test keeps it that way.
- **Undo for file edits:** `komando fs restore HOST PATH` puts the backup
  back, and `fs replace`/`fs write --backup` print the undo line.
- **Errors for people:** text output starts with what happened and that
  nothing was changed, then the hint, then the code. JSON is unchanged.
- **Plain words:** `db add`, `cache add`, `queue add`, `storage add`,
  `cluster add` and `registry add` open the same form as `conn add`, and
  "conn" no longer appears in menus, forms or messages.

## [0.10.0] - 2026-11-10

### Highlights

- **GlobalProtect with a browser sign-in,** including Prisma Access with
  the Cloud Authentication Service: `vpn up` opens a browser window for
  the password and one-time code, then picks the best gateway from the
  portal's list.
- **GlobalProtect sessions last the whole login.** They no longer drop
  after about 18 minutes: the tunnel is kept alive and set up again by
  itself.
- **Old flag names are gone** (`--jump`, `--force`, `--param`, `--lines`,
  and others kept since 0.1 to 0.3). See Removed for the new names.

### Added

- **GlobalProtect with a browser sign-in.** `komando vpn up` now logs in to
  GlobalProtect portals that use a web sign-in (SAML, or Palo Alto's Cloud
  Authentication Service, as Prisma Access does): it opens a window of
  Chrome, Edge, Brave or Chromium with an empty temporary profile, you sign
  in there with your password and one-time code, and komando reads the
  result and connects. It also reads the portal's list of gateways and
  takes the best one for your region; before, the portal address had to be
  the gateway itself. Add such a VPN with only `--portal`. A gateway
  with a sign-in of its own is shown in the same window. Tried against a
  real Prisma Access gateway. Not built yet: gateways behind a load
  balancer (the error names the portal's other gateways) and the device
  report (HIP).

### Removed

- Old flag names kept as aliases since 0.1 to 0.3 are gone. Use the new
  names: `--via` (was `--jump`), `--overwrite` (was `--force`), `recipe run
  --var` (was `--param`), `logs -n`/`--limit` (was `--lines`), `fs cat
  --line-numbers` (was `--number`), `job logs --max-bytes` (was `--limit`),
  `--target` (was `--host`), `host mv` and `conn mv` (was `host edit
  --rename` and `conn edit --rename`). `recipe add --mutating` is gone too:
  a recipe counts as a change unless you save it with `--read-only`.

### Fixed

- A GlobalProtect VPN no longer drops after about 18 minutes. komando
  now sends the keepalive the gateway expects, sets the tunnel up again
  before the gateway's own tunnel timeout, and after a drop reconnects
  with the same login (for up to 5 minutes) instead of ending the session.
- `vpn add` no longer says a VPN needs `openconnect` and `ocproxy` when
  komando's own client is the one that will run it.
- A second `komando vpn up NAME` that waits for another one (which may be
  waiting for a sign-in) now says so instead of standing still.

## [0.9.0] - 2026-11-10

### Highlights

- **Every feature as plain questions:** type `komando`, pick Add or All
  features, and answer one question at a time. Add has a form for every
  kind of server, database, cache, queue, storage, cluster, registry and
  VPN, and the last screen shows the exact commands before anything runs.
- **Windows servers,** over OpenSSH or WinRM: `test`, `exec`, `script`,
  `facts`, files, services and `shell` run PowerShell there, with Windows
  forms of the destructive rules.
- **`komando queue`: message queues.** Kafka, RabbitMQ, NATS JetStream,
  Amazon SQS and Google Cloud Pub/Sub: look at topics, queues and lag, peek
  at messages without removing any, send, create, and delete only with
  `--allow-dangerous`.
- **Five more databases:** SQL Server, Oracle, ClickHouse, Snowflake and
  BigQuery work with `db query`, `schema`, `explain`, `info` and the rest,
  read-only unless you add `--write`.
- **Windows (SMB) shares as storage,** with komando's own SMB 2 and 3
  client.
- **Azure and Google logins in more places:** `azure-kv:` reads secrets
  from Azure Key Vault, and registry conns for Azure Container Registry,
  Google Artifact Registry and Container Registry log in with your cloud
  login.

### Added

- **Every feature as questions, for people at a terminal.** Type `komando`,
  pick Add or All features, and answer one plain question at a time (a
  name, an address, a user ...), each with an example, a default Enter
  takes, and a check before the next question. Add has a form for every
  kind: Linux and Windows servers (OpenSSH or WinRM), PostgreSQL, MySQL,
  SQL Server, Oracle (service name or SID), MongoDB, ClickHouse, Snowflake
  (key pair or token), BigQuery (your Google login), SQLite, Redis,
  Memcached, Kafka, RabbitMQ, NATS, Amazon SQS, Google Pub/Sub, S3 (AWS,
  MinIO, R2, Wasabi, Spaces, B2), SFTP, FTP, Google Cloud Storage, Azure
  Blob, WebDAV, Windows shares (SMB), Kubernetes, container registries
  (also Amazon ECR, Azure and Google with their own logins) and every VPN
  kind.
  All features lists every command by area and asks for what it needs,
  picking servers, databases and VPNs from your list. The last screen shows
  the exact command lines before anything runs, and offers **Try it first**
  (`--dry-run`) for a change. Forms never hold a password (the command asks
  for it hidden) and never add `--yes`, `--allow-dangerous` or `--reveal`.
  A password pasted with an address is taken out before it is shown.
- `komando host add`, `conn add` and `vpn add` typed alone at a terminal ask
  the same questions; with any argument or flag, or for an AI agent, they
  work as before.
- `vpn add --ask-password` and `--ask-psk`: type the VPN login password or
  the pre-shared key (l2tp, ipsec, ikev2) once, hidden, as with `host add`;
  they are stored as `secret:NAME-pass` and `secret:NAME-psk`. AI agents get
  `NEEDS_PERSON`.
- **Windows servers over OpenSSH:** `komando host add win1
  Administrator@10.0.0.9 --os windows` marks a Windows server. komando then
  runs PowerShell there: `test`, `exec`, `script`, `facts` (Windows version
  and support dates, updates, pending reboot, ports), `fs ls/stat/cat/write`,
  `upload`, `download`, `cp` (single files), `svc
  status/list/start/stop/restart/enable/disable` and `shell` work; other
  commands stop with `NOT_SUPPORTED` and a hint before anything runs. See
  docs/features/windows.md.
- **Windows servers over WinRM:** `komando host add win2
  winrm://Administrator@10.0.0.9 --ask-password` reaches a Windows server
  through WinRM (what Ansible uses) with komando's own client: HTTPS on
  port 5986 with the certificate checked (`?ca=secret:NAME` for a private
  CA, `?tls=skip-verify` only when asked), NTLM login (`?auth=basic` for
  local accounts), `--via` bastions and VPNs. The same Windows commands
  work as over OpenSSH.
- `os:windows` and `os:linux` target selectors.
- **Windows (SMB) shares as storage conns:** `smb://alice@fileserver/team/reports?domain=CORP`
  (or `cifs://`, or `CORP;alice@` for the domain) reaches a Windows file
  server, Samba, a NAS or Azure Files with the same `storage ls`, `cat`,
  `download`, `upload` and `rm` as the other kinds, also `--via` an SSH host
  or a VPN. komando speaks SMB 2 and 3 itself (no `smbclient` needed), logs
  in with the password from `--password-ref`, signs every message and
  encrypts when the server asks for it. A guest login is refused, a key
  cannot climb out of the conn's folder with `..` (between `/` or `\`), an upload
  replaces a file only once the new one is complete, and `storage link`
  answers `NOT_SUPPORTED`. `komando doctor` warns about SMB conns that cross
  the network, since their encryption depends on the server.
- `azure-kv:VAULT/NAME[#JSON_KEY]` reads a secret from Azure Key Vault,
  everywhere a `--password-ref` or another secret reference is taken
  (`azure-kv:shop-vault/db-password`, or `.../NAME/VERSION` for an older
  version). komando signs in to Azure itself, without the `az` program: with
  a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
  `AZURE_CLIENT_SECRET`), a workload identity on AKS, a token the Azure CLI
  saved while it lasts, or the managed identity on Azure. The token goes
  only to Key Vault hosts, and komando keeps no token.
- A registry conn for Azure Container Registry
  (`registry://myregistry.azurecr.io`) without `--password-ref` logs in with
  your Azure login, as `az acr login` does: komando trades an Azure token for
  a fresh registry login each time, like it already does for Amazon ECR. It
  uses the same Azure logins as `azure-kv:`. Without one, the error is
  `AZURE_LOGIN_REQUIRED`. The Azure token is good for the whole
  subscription, so it goes only over https with the registry's certificate
  checked: a conn with `?tls=false` or `?tls=skip-verify` needs
  `--password-ref`.
- Registry conns for Google Artifact Registry (`REGION-docker.pkg.dev`) and
  Container Registry (`gcr.io`, `eu.gcr.io`, `us.gcr.io`, `asia.gcr.io`)
  without `--password-ref` log in with your Google login: komando gets a
  fresh access token each time and logs in as `oauth2accesstoken`, as
  `gcloud auth configure-docker` does, with the credentials it already uses
  for `gs://` storage and `gcp-sm:`. With no Google login at all, public
  images are read without one; an expired login, or a key file that is set
  but missing or broken, gives `GCP_LOGIN_REQUIRED`.
  The token goes only over https with the registry's certificate checked.
- **`komando queue`: message queues, starting with Apache Kafka** (and
  what speaks its protocol: Redpanda, Amazon MSK, Confluent Cloud). Add a
  cluster as a conn, `kafka://USER@BROKER1:9092,BROKER2:9092?tls=true&sasl=scram-sha-512`
  (SASL PLAIN or SCRAM with `--password-ref`, a private CA with
  `?ca=secret:NAME`, `--via` an SSH server or a VPN like any conn).
  `queue info`, `ls`, `describe`, `groups` and `lag` read the brokers,
  topics, partitions and consumer groups; `queue peek` reads the newest or
  oldest messages without joining a consumer group, so no application's
  position moves. `queue send` and `queue create` change; `queue rm` and
  `queue purge` delete messages and need `--allow-dangerous`. Every change
  has a real `--dry-run` (`create` asks the brokers to check the topic
  only). Design: docs/design/queue.md; guide: docs/features/queues.md.
- **RabbitMQ in `komando queue`:** add a server as a conn,
  `amqps://USER@HOST:5671/VHOST` (or `amqp://` --via an SSH server; the
  path is the vhost, `%2F` for `/`), with `?management=15671` to also use
  the management HTTP API. `queue info` and `describe` work over AMQP
  alone; `queue ls`, `queue peek`, the nodes and the cluster totals need
  the management API. `queue peek` takes the first messages of a queue and gives every
  one back, so nothing is removed (RabbitMQ marks them redelivered); on a
  quorum queue each peek counts as a delivery, so peek stops with
  `DELIVERY_LIMIT_NEAR` before a message gets close to its delivery limit.
  `queue send` publishes a persistent message and waits for the server's
  confirm; `queue create --type classic|quorum|stream` makes a durable
  queue (`--config x-max-length=1000` for its arguments); `rm` and `purge`
  need `--allow-dangerous`. `amqp://` straight over the network is refused
  like `redis://` unless `?insecure=1`. New error codes `QUEUE_NOT_FOUND`,
  `QUEUE_EXISTS` and `DELIVERY_LIMIT_NEAR`. Built on
  github.com/rabbitmq/amqp091-go (BSD-2).
- **NATS JetStream in `komando queue`:** add a server as a conn,
  `tls://USER@HOST:4222,HOST2:4222` (or `nats://` --via an SSH server),
  logging in with a user and `--password-ref`, a token (a password
  reference without a user), or a `.creds` file kept in the vault
  (`?creds=secret:NAME`); `?domain=` for a leaf node's JetStream.
  `queue ls` lists streams, `describe` shows a stream with its limits,
  cluster and consumers, `groups` and `lag` show consumers (pending, ack
  pending, waiting). `queue peek` reads messages by their sequence number,
  the newest or (`--oldest`) the first ones, with no consumer and no
  acknowledgement, so nothing is removed, also from a work-queue stream.
  `queue send` takes a subject, checks that a stream keeps it, and waits
  for the stream's acknowledgement; `queue create` makes a stream
  (`--config subjects='orders.>' --config max_age=7d`, `--replicas`);
  `rm` and `purge` need `--allow-dangerous`. `nats://` straight over the
  network is refused like `redis://` unless `?insecure=1`. New error codes
  `STREAM_NOT_FOUND`, `STREAM_EXISTS` and `CONSUMER_NOT_FOUND`. Built on
  github.com/nats-io/nats.go and github.com/nats-io/nkeys (Apache-2.0).
- **Amazon SQS in `komando queue`:** add a region as a conn,
  `sqs://eu-west-1`, logging in like komando's other AWS clients: the
  conn's `--option aws_profile=NAME` (SSO included, renewed with `komando
  login aws`), an access key ID in the URL (`sqs://AKIA...@eu-west-1`)
  with the secret key from `--password-ref`, or the usual AWS chain
  (variables, default profile, the server's role). `?endpoint=` for a VPC
  endpoint or an emulator (LocalStack, moto), `?account=` for queues
  another account shares. `queue ls` and `describe` show the waiting,
  in-flight and delayed messages, settings, dead-letter queue and tags.
  `queue peek` receives a sample with a visibility timeout of 0 and never
  deletes, so every message stays and stays visible; since each receive
  counts toward a dead-letter queue's `maxReceiveCount`, peek stops with
  `DELIVERY_LIMIT_NEAR` before a message runs out of receives. `queue
  send` sends text with `--header` values as message attributes (`--key`
  is a FIFO queue's message group); `queue create` makes a standard or
  (name.fifo) FIFO queue from SQS settings (`--config
  VisibilityTimeout=60`); `rm` and `purge` need `--allow-dangerous`. An
  `http://` endpoint straight over the network is refused unless
  `?insecure=1`. komando speaks the SQS API itself, signed with the AWS
  SDK's SigV4 signer it already had: no new dependency.
- **Google Cloud Pub/Sub in `komando queue`:** add a project as a conn,
  `pubsub://my-project`, logging in like gs:// storage: a service account
  key in `--password-ref`, or else gcloud's application default login; the
  emulator (`?endpoint=http://localhost:8085`) needs none, and a login is
  only ever sent over HTTPS. You send to a topic; `queue peek` and `purge`
  take a subscription, where the messages wait, and `queue groups` lists
  the subscriptions. `queue peek` pulls without acknowledging and gives
  every message straight back (ack deadline 0), so nothing is removed;
  with a dead-letter topic it stops with `DELIVERY_LIMIT_NEAR` before a
  message runs out of deliveries. `queue describe` shows a topic with its
  subscriptions, or one subscription; `queue create subscriptions/NAME
  --config topic=TOPIC` makes a subscription, with Pub/Sub's own setting
  names (`ackDeadlineSeconds=60`, `messageRetentionDuration=7d`);
  `purge` (a seek to now) and `rm` need `--allow-dangerous`, and `rm`
  deletes a subscription only when written `subscriptions/NAME`. Pub/Sub
  does not count messages, so the counts are -1 and the text says so. New
  error codes `SUBSCRIPTION_NOT_FOUND` and `SUBSCRIPTION_EXISTS`. komando
  speaks the Pub/Sub REST API itself: no new dependency.
- **SQL Server conns** (`sqlserver://app@db.internal:1433/sales?encrypt=true`,
  also `mssql://`): `db query`, `schema`, `explain` (SHOWPLAN; `--analyze`
  measures), `info`, `activity`, `locks`, `sizes`, `kill --session`, users
  and grants, `db shell` and `conn test`, through `--via` and VPNs, with
  `?ca=secret:NAME` and `tls=skip-verify`. New conns that cross the network
  get `encrypt=true`. SQL Server has no read-only transaction, so without
  `--write` komando rolls the SQL back and checks its own transaction after
  each statement; T-SQL gets stricter checks (a change anywhere in the text
  counts, a bare procedure name runs it, `BEGIN`/`COMMIT` are refused
  anywhere, and numbers are read as SQL Server reads them, so `1eDROP` is
  `1e DROP`). A URL option given twice (`encrypt=true&Encrypt=disable`) is
  refused. `db dump` and `restore` say `NOT_SUPPORTED` for now. Built in
  with go-mssqldb (BSD-3-Clause), pure Go.
- **Oracle conns** (`oracle://app@db.internal:1521/ORCLPDB1?tls=true`, the
  path is the service name; `?sid=` for old databases): `db query`,
  `schema`, `explain` (EXPLAIN PLAN and DBMS_XPLAN),
  `info`, `activity`, `locks`, `sizes`, `kill`, users and grants, `db shell`
  and `conn test`, through `--via` and VPNs, with TCPS (`tls=true`,
  `tls=skip-verify`) and `?ca=secret:NAME`. New conns that cross the network
  get `tls=true`. Without `--write` every run is `SET TRANSACTION READ ONLY`,
  checked after each statement. DDL commits on its own in Oracle, so it
  always needs `--write` and runs alone; PL/SQL blocks, calls to stored
  functions (which can commit on their own), database links and inline
  external tables need `--write` and `--allow-dangerous`; `COMMIT` and autonomous transactions are refused
  anywhere; `q'[...]'` quotes and `/` lines are read as Oracle does. `db
  dump` and `restore` say `NOT_SUPPORTED` (Data Pump runs on the server).
  Built in with go-ora (MIT), pure Go.
- **ClickHouse conns** (`clickhouse://app@ch.internal:8443/analytics?tls=true`)
  over ClickHouse's HTTP interface, with komando's own small client (no
  driver library): `db query` with `{p1:String}` placeholders, `schema`
  (engines, keys, skipping indexes), `explain` (`EXPLAIN indexes = 1`),
  `info`, `activity`, `sizes` (from `system.parts`), `kill` (by the `pid`
  `db activity` makes from the query id), users and grants, `db shell` and
  `conn test`, through `--via` and VPNs, with `tls=true`, `tls=skip-verify`
  and `?ca=secret:NAME`. New conns that cross the network get `tls=true`
  (port 8123 becomes 8443); the native ports 9000 and 9440 are refused with
  a hint. ClickHouse has no transactions: without `--write` every request
  carries the server's own `readonly=1` (also every query with rows), and a
  statement that is not a read needs `--write`, goes alone, and a dry run
  only reports it. Table functions and engines that reach other servers,
  files or programs (`url()`, `s3()`, `remote()`, `file()`,
  `executable()`, ...) need `--allow-dangerous`; `$$` heredocs and
  unquoted non-ASCII are refused. A user whose profile is read-only gets no
  settings it would refuse. `db user add` sends a salted SHA-256 hash
  komando computes, never the password. `db dump`, `restore` and `locks`
  say `NOT_SUPPORTED`.
- **Snowflake conns**
  (`snowflake://APP_RO@myorg-myaccount/ANALYTICS/PUBLIC?warehouse=W&role=R`,
  the account in place of a host) over Snowflake's SQL API, with komando's
  own small client (no driver library): `db query` with `?` placeholders,
  `schema`, `explain`, `info`, `activity` (running queries from
  `QUERY_HISTORY`), `sizes`, `kill` (`SYSTEM$CANCEL_QUERY`; `--session`
  ends the session), `db user ls` and `db grants` (read only), `db shell`
  and `conn test`, through `--via` and VPNs, always HTTPS with the
  certificate checked, and `?ca=secret:NAME` for a proxy's CA. Login is a
  private key from the vault (komando signs the key-pair token itself) or a
  programmatic access token; the SQL API takes no passwords, and browser
  SSO is not supported. Snowflake has no read-only mode, so komando's
  check is the guard: without `--write` only reads are sent, each request
  runs exactly one statement, and a statement that is not a read needs
  `--write`, goes alone, and a dry run only reports it; the docs give the
  SQL for a read-only role. `CREATE OR REPLACE`, `SYSTEM$` functions that
  change things, stage files, `CALL` and `EXECUTE IMMEDIATE` need
  `--allow-dangerous`; `//` comments, `$$` text and `\'` are read as
  Snowflake reads them. A run that times out cancels the statement on the
  server. `db dump`, `restore`, `locks`, `user add`/`passwd`/`rm` and
  `grant`/`revoke` say `NOT_SUPPORTED`. Not yet run against a real
  account: see docs/design/snowflake.md.
- **BigQuery conns** (`bigquery://my-project/analytics?location=EU`, the
  project jobs run in and a default dataset) over BigQuery's REST API, with
  komando's own small client (not the Google Cloud SDK): `db query` with `?`
  placeholders, `schema` (datasets, tables and columns from the API),
  `explain` (the dry run), `info`, `activity` (jobs that are not done, from
  `INFORMATION_SCHEMA.JOBS`), `sizes`, `kill` (`jobs.cancel`), `db shell`
  and `conn test`, through `--via` and VPNs, HTTPS with the certificate
  checked and `?ca=secret:NAME` for a proxy's CA. The login is the same as
  for `gs://` conns: gcloud's application default credentials (sent only to
  `*.googleapis.com`), or a service account key in `--password-ref`. Every
  statement goes to BigQuery as a dry run first: without `--write` only
  what BigQuery itself calls a `SELECT` runs, and a query that would read
  more than the new `--max-bytes` (default 10GB) stops with the new error
  `DB_BYTES_LIMIT`; each job also carries that cap (`maximumBytesBilled`),
  and each result says `bytes_processed`. `--dry-run` is BigQuery's own dry
  run, for reads too. A write needs `--write` and goes alone; `EXPORT DATA`,
  `EXTERNAL_QUERY`, remote functions, `CREATE OR REPLACE`, `LOAD DATA
  OVERWRITE`, row access policies, reservations, `CALL` and `EXECUTE
  IMMEDIATE` need `--allow-dangerous`. Scripts are refused; `#` comments,
  triple-quoted and raw strings and `` `names` `` are read as BigQuery reads
  them. A run that times out cancels its job. `db dump`, `restore`, `locks`,
  `db user` and `grant`/`revoke`/`grants` say `NOT_SUPPORTED`. Not yet run
  against a real project: see docs/design/bigquery.md.

### Changed

- The menu's Add asks one question at a time instead of one line
  (`web1 deploy@10.0.0.5`), and the main menu has **All features** in place
  of Audit (Audit is under All features, Safety and audit).
- Every JSON error now has an `error.hint`: an error without a hint of its
  own gets a general next step for its exit code.
- `komando schema` lists 16 more error codes (among them `CERT_PROBLEMS`,
  `NXDOMAIN` and `SECRET_DESTINATION`), and each code's example and hint now
  come from the same place in the code, so the hint fits the code.
- The `sql-remote` rule's reason names what it covers now (dblink, an
  Oracle database link, ClickHouse `url()` or `s3()`), not only dblink.

### Fixed

- The docs no longer claim more than the code does: secrets are hidden from
  agents komando recognises, and several design docs named flags, commands
  and error codes that do not exist.

### Security

- Windows forms of the destructive rules: a recursive delete of the system
  drive or a system folder, formatting disks, `Stop-Computer`,
  `Restart-Computer`, stopping SSH or WinRM, blocking all incoming traffic,
  deleting users, hidden (`-EncodedCommand`) or downloaded scripts,
  deleting shadow copies, and deleting a registry hive need
  `--allow-dangerous`. `exec --read-only` and `script --read-only` on
  Windows servers fail closed: they accept only a small subset of
  PowerShell that komando reads exactly (pipelines of listed read cmdlets
  with literal arguments and safe parameters, and simple `Where-Object`
  and `ForEach-Object` blocks) and refuse everything else, such as `$`,
  backticks, `@`, `&`, redirection, comments, .NET calls, keywords and
  characters outside ASCII. See docs/features/windows.md.
- A command komando cannot run on Windows is refused for every Windows
  server, so a sh script is never sent to PowerShell.
- WinRM refuses Basic login over plain HTTP (the password would travel
  unencrypted) and warns about `tls=off` and `tls=skip-verify`.

## [0.8.0] - 2026-11-09

### Highlights

- **SSH logins ask a person, as `ssh` does:** at a terminal, komando asks
  for a missing password and for the one-time code of a two-factor login,
  so `komando shell`, the menu and every other command reach two-factor
  servers. AI agents are never asked; they send the user to their own
  terminal.
- **New database and cache conns check TLS by default:** a conn that
  crosses the network gets `sslmode=verify-full` (Postgres) or `tls=true`
  (MySQL), and a plain `redis://` there is refused unless you say
  `?insecure=1`. Saved conns keep their URL.
- **Fewer ways for an AI agent to reach a secret:** `secret set` and
  `--ask-password` from an agent stop with `NEEDS_PERSON`, `vpn add` no
  longer overwrites another entry's secret, a VPN password or a new VPN
  address needs a person's yes, and `docker exec --read-only` and `cluster
  exec --read-only` are checked like `exec --read-only`.
- **Easier first steps:** `--ask-password` stores a password in one step,
  `host add`, `conn add` and `vpn add` say what to run next, the menu grows
  with your inventory, and more hints now name a whole command you can run.
- **Easier to move and to leave:** a whole `export` carries your deny rules
  and settings and names the keys it needs, `import` keeps servers whose
  key is not here yet, and `komando guide uninstall` takes komando out of
  your AI agents again.
- **For AI agents and their people:** `komando schema` lists every error
  code with its next step, `doctor` checks each agent's skill, and `audit
  --actor NAME` shows what one person or agent did.
- **A new vault keeps its key in the OS keychain**, so a backup or a synced
  copy of `~/.komando` no longer opens it. Vaults you have keep their key
  where it is; `komando secret keychain` moves it.
- **`komando ssh-gate` gives a phone's SSH key komando and nothing else:**
  no shell, one komando command at a time, run as for an AI agent, and
  read-only if you choose.
- **`komando login HOST` lets an AI agent reach a two-factor server:** a
  person answers the code once, and komando keeps that login for 8 hours.

### Added

- **`komando ssh-gate`: an SSH key that runs komando and nothing else.**
  For a phone (the Komando app) or another computer that reaches komando
  over SSH: `komando ssh-gate line --name phone KEY` prints the line for
  `~/.ssh/authorized_keys` (`restrict,command="/full/path/komando ssh-gate
  --name phone" ...`). For that key, sshd runs ssh-gate, which takes only
  one komando command: split into words like a shell, but with no shell and
  no expansion, so `;`, `|`, `$(...)` and other programs are refused
  (`SSH_GATE_SYNTAX`, `SSH_GATE_REFUSED`). komando then runs as for an AI
  agent, whatever the client says it is: secrets stay hidden, `--reveal`,
  `--allow-dangerous` and commands for a person at a terminal are refused,
  and `--yes` on a protected target needs a person on the komando computer.
  `--read-only` keys run only what `komando schema` counts as a read
  (`SSH_GATE_READ_ONLY`). No key writes on the komando computer: downloads,
  dumps and copies to a folder here, changes to komando's own setup, and
  every command on a target that is this computer (a sqlite conn,
  `localhost`, loopback) or not in the inventory (`u@HOST`) are refused;
  a change komando adds later is refused until it is known to act on
  servers only. Every command a key runs or is refused is in
  `komando audit`, with the key's name, the address it came from and why,
  even with the audit setting off; what the key sent is shown escaped.
  See [Safety](docs/features/safety.md#a-key-that-runs-komando-and-nothing-else).
- `KOMANDO_KEYCHAIN=off` keeps komando away from the keychain (CI runners,
  containers, test runs): a new vault then keeps its key in `vault.key`.
- `komando login HOST`: a person logs in to a server once, answering its
  password and two-factor code, and komando keeps that login in the
  background for the new `login_for` setting (8h). Every command to that
  server, an AI agent's too, uses it without a code; rules, approvals and
  audit stay the same. A login to a jump host serves every server behind
  it. `komando logout HOST` (or `--all`) ends it, and `komando status`
  lists kept logins. Making `login_for` longer needs a person's yes.
- `audit --actor NAME`: what one person, AI agent or computer account did
  (`komando audit --actor budi --since 30d`). A new page, [Rotate keys and
  passwords](docs/features/rotate.md), gives the steps in order for an SSH
  key, a server or database password, and for when someone leaves.
- `komando schema` lists every error code (`error_codes`, over 200): its
  exit code, an example message and the usual next step. It is made from the
  source, and a test keeps it in step. The troubleshooting table names the
  common codes that were missing (`HOSTKEY_UNKNOWN`, `DNS_ERROR`,
  `HOST_NOT_FOUND`, `VAULT_*`, `IMPORT_INCOMPLETE`).
- `komando guide uninstall` takes the skill and komando's guard entries out
  of Claude Code, Codex, Cursor and Gemini CLI, keeping everything else in
  those files (a changed file is kept as `.bak`). An AI agent needs a
  person's yes to remove its own guard.
- A whole `export` carries your own deny rules and settings. `import
  komando` adds the deny rules and lists the settings that differ with the
  `komando config set` command for each; it changes none.
- `doctor` checks AI agents: whether they have komando's skill, whether it
  is this version's (after an update, `komando guide install` again), and
  whether Claude Code runs with komando's guard.
- `--ask-password` on `host add`, `host edit`, `conn add` and `conn edit`: a
  person types the password once (hidden) and it is stored as
  `secret:NAME-pass` and used as the reference, in one step instead of
  three. It never replaces a secret something else uses, asks first on a
  protected entry, and takes back a new secret when the add fails. An AI
  agent gets `NEEDS_PERSON`.
- `host add`, `conn add` and `vpn add` end with `next:` (`komando test
  web1`, `komando vpn up office`). A `--password-ref secret:NAME` whose
  secret is not in the vault yet is a warning at once, with the command
  that stores it. `host rm`, `conn rm` and `vpn rm` name the secrets nothing
  uses any more (`secrets_unused`) with the `secret rm` command; komando
  does not remove them by itself.
- The installer says when another komando earlier in your PATH would run
  instead, tells an update to run `komando guide install` again, and shows
  how to turn on tab completion; README has a Tab completion section.
- **The menu grows with you.** Add stays once there is a server (after the
  actions) and also adds a conn from a name and a URL (`app-db
  postgres://...`). VPN connects or disconnects: an up VPN says `up (Enter
  disconnects)` and the header counts the VPNs that are up. Import shows
  while `~/.ssh/config` names servers komando does not know, and AI agent
  (`komando guide install`) while no agent has komando's skill, when the
  number keys still reach them (9 rows at most). `?` shows what komando
  does, by task, instead of `komando --help`.
- `db shell`: `\write` allows changes for the rest of the shell after a
  yes, and connects again read-write (`\write` again goes back); a
  destructive statement asks for the conn's name instead of refusing.
- **SSH logins ask a person, as `ssh` does.** At a terminal, komando asks
  for a server's password when none is stored, and for the one-time code
  of a two-factor login, with the server's name (`web1: Verification
  code:`), hidden unless the server lets the answer show; servers that log
  in at once ask one at a time, and Ctrl-C stops the login (`CANCELLED`).
  `komando shell`, the menu and every other command now reach two-factor
  servers. A stored password still goes out once, only to a hidden password
  question. AI agents, scripts and background processes are never asked:
  the `AUTH_FAILED` hint sends a person to run the command in their own
  terminal, no longer to `ssh`.
- `export` names the keychain keys its servers use (`keys_needed`) and
  their files (`key_files`), which an export file never holds.

### Changed

- **A new vault keeps its key in the OS keychain** (the macOS keychain, or
  the Secret Service through `secret-tool` on Linux), no longer in
  `vault.key` beside the vault, so a backup or a synced copy of
  `~/.komando` does not open it. komando makes the key at the first secret
  and counts on it only once it reads back. A key the keychain already
  holds for that folder (a vault moved aside) is used, never replaced.
  Where the keychain cannot keep it (no `secret-tool`, no desktop session,
  a locked keychain over SSH), the key goes into `vault.key` as before and
  `komando doctor` warns. Existing vaults keep their key where it is: move
  it with `komando secret keychain`.
- `AUTH_FAILED` and `NO_AUTH` for an AI agent or a script now name
  `komando login HOST` as the way a person lets it reach a two-factor
  server.
- Hints name whole commands: `komando fs ls TARGET FOLDER`, `komando
  cluster history CONN deployment/NAME`, `komando net check web1
  HOST:443` instead of a bare command that fails as typed. `DNS_ERROR`,
  `CONNECT_TIMEOUT`, `CONNECT_FAILED`, `WAIT_TIMEOUT` and `JOB_LOST` name
  the command to run next. A typo's hint never shows an example with
  `--yes`, `--allow-dangerous` or `--reveal`; SQLite `db restore` keeps its
  own hint.
- A vault that cannot be opened says why, with the step: `VAULT_LOCKED`
  (no passphrase given), `VAULT_KEY` (key file missing or broken),
  `VAULT_DECRYPT` (wrong passphrase), instead of `REMOTE_ERROR`. A server's
  unreadable password reference names the exact `secret set` (or what the
  reference needs). `test` on one target ends with that target's own hint.
- An import that refuses some servers still brings the rest in, but ends
  with `IMPORT_INCOMPLETE` (exit 1) instead of `ok`; names that exist
  already are still skipped quietly, so importing again is safe.
- Docs: one story for moving to another computer (export without
  passwords, or the whole folder once the vault has a passphrase), uninstall
  with `guide uninstall` and the keychain item, and "Undo a change" for files.
- For AI agents, the approval hint says "komando asks the user in a
  window" only where a flag opens one: not for `--write` or leaving out
  `--read-only` (komando does not ask; the agent asks the user first), and
  not for stops no flag lifts (komando's own folder, an unsafe backup line,
  an `.ovpn` script line). `READ_ONLY_VIOLATION` no longer says to add
  `--yes` on a server that is not protected.
- `VPN_DOWN` and `TUNNEL_TIMEOUT` put the last lines of the log in the
  message and name a command to try, instead of sending an agent to a file
  in `~/.komando` it may not read.
- Text for people says what happened first: `stored app-db-pass`, `added
  the deny rule "rm -rf /srv" (2 custom rules now)`, `removed app-db`,
  `saved 2 servers, 1 conn to FILE (no passwords)`; `false` fields after
  such a headline are left out. JSON is unchanged (fields were only added).
- `komando list` on an empty inventory also shows how to add a database,
  and `SECRET_NOT_FOUND` for a conn names the secret to set.
- A person at a terminal confirms `fs rm --recursive`, removing a top-level
  path, `sync --delete` and removing an essential package by typing the
  target's name, as `exec` and `db query` already ask, instead of being
  sent back to add `--allow-dangerous`. One typed name covers the same
  targets for the rest of the command, so a step two checks catch is asked
  once.
- An approval window nobody answers closes after 2 minutes and the agent is
  told nobody answered, no longer that the user clicked Deny.
- An AI agent that runs `secret set NAME` with no value gets `NEEDS_PERSON`:
  ask the user to run `komando secret set NAME` in their own terminal. It
  used to get a `USAGE` error whose hint was the same command. `komando
  guide` and the skill say never to ask for a password in the chat.
- `import komando` adds a server whose keychain key is not on this computer,
  leaves the key out and says how to bring it (`key add`, then `host edit
  --key`), as it does for an identity file. It used to leave the server out.
- `rename --prefix --notes` replaces only what clearly means an entry:
  server, conn, VPN and secret names, `@group`, and a pattern such as
  `shop-db-*` that matches the same entries afterwards (before, it did not
  follow). The old prefix without its `-`, group names without `@`, key
  names, and names that are also the user, host, bucket or database in a
  conn URL stay, and are listed under `kept` with the reason. Before, `db
  shop` and `bucket shop-dev` became `acme-shop…` too.
- `rename --prefix` lists every label value that names an old entry (such
  as a conn's `host=` label, which `doctor` reads), and `--labels` replaces
  them by the same rules. Without `--notes`, a warning counts the notes
  that still name old entries.

### Fixed

- Last gaps from the user-journey review: the features index no longer
  says SQLite restores; the tunnel page says how a person copies the
  database password; README says Codex asks once in `/hooks` and what
  `secret keychain` needs on Linux; `komando schema` describes every `meta`
  field; the proxy-command and credential-plugin stops name
  `--allow-dangerous`; `KEYCHAIN_FAILED` says a person unlocks the keychain.
- A flag a group gives all its sub-commands (`cron --user`, `cron --sudo`,
  `docker --sudo`, `pkg --no-sudo`) now shows in the sub-command's `--help`
  and in `komando schema <command>`, where agents look before using one.
- Docs: examples that broke the rules or skipped a step (`psql` and
  `pg_dump` over `exec`, a `policy check` example that is not blocked,
  `secret:` references with no `secret set`, conn names an import does not
  make, a key file from the cloud provider); the `tunnel start` usage line
  (`-L/-R/-D` are optional for a conn); "keychain" now means only the
  system keychain (komando's SSH keys are its key list); the env variable
  table, ID examples and the Go version.
- AI agents read komando's hints whole again. The secret masker hid the
  command after words such as "password:" (`save its password: [hidden]
  secret set web1-pass`) in `NO_AUTH`, `KEY_PASSPHRASE_REQUIRED`, `komando
  guide` itself and `guide install --help`. A value that starts with a
  `` `komando `` command is now kept, and a test runs the masker over every
  hint that names one, the guide and the skill. Kebab-case flags such as
  `--host-key-policy=strict` are no longer hidden, and a few messages (a
  locked vault, a missing `secret-tool`, a registry CA reference, a failing
  credential helper) were reworded so they arrive whole.
- `db dump` and `db restore` of an archive failed for a conn with a
  private CA (`?ca=secret:NAME`) when `pg_dump` or `pg_restore` ran on a
  server (`--on HOST` or `--via`): libpq refused the `ca` option. The tools
  now get the CA in a file on that server, removed when they end, and
  check the certificate fully against it, as komando does: libpq with
  `sslrootcert=` and `sslmode=verify-full`, `mysqldump` with `--ssl-ca`.

### Security

- With `host_key_policy strict`, an AI agent's first pin (`host trust`)
  needs a person's yes; the window shows each fingerprint to compare.
  `HOSTKEY_UNKNOWN` now says which fingerprint the server shows.
- **New conns check TLS by default.** `conn add` and `conn edit --url` of a
  conn that crosses the network on its own (no `--via`, not this computer)
  add `sslmode=verify-full` (Postgres) or `tls=true` (MySQL) when the URL
  says nothing, and say so in `warnings`. A plain `redis://` or
  `memcached://` there is refused (`INSECURE_PROTOCOL`) unless the URL
  has `?insecure=1`, which an AI agent needs a person's yes for. Saved
  conns keep their URL. `pg_dump` and `pg_restore` 16 or newer get
  `sslrootcert=system` for such a URL, so `db dump --on` checks the
  certificate against the system's CAs as komando does; an older one
  needs the CA in `~/.postgresql/root.crt` and stops with a hint
  (`DB_CONNECT`).
- An AI agent that adds a VPN with a password or pre-shared key reference,
  or points a VPN at another server or address, needs `--yes` and a
  person's yes (`SECRET_DESTINATION`); the window names the references and
  the server (for OpenVPN, its profile's `remote` lines). `vpn add` now
  takes `--legacy-crypto` and `--allow-pap` (a person's yes, as on
  `vpn edit`) and shows an OpenVPN profile's warnings.
- `vpn up` hands `KOMANDO_VAULT_PASS` to its background `vpn serve` on
  stdin instead of in its environment, as `tunnel start` does.
- `docker exec --read-only` and `cluster exec --read-only` are checked as
  `exec --read-only` is: a command that clearly changes something is
  refused (`READ_ONLY_VIOLATION`), and on a protected target only commands
  komando knows read skip `--yes`. Before, the flag alone skipped it.
- JSON answers list the SSH host keys a command trusted for the first time
  in `meta.host_keys_pinned`, so an agent can show the fingerprints.
- `vpn add NAME wireguard` and `vpn add NAME openvpn` no longer replace a
  vault secret named `NAME-key`, `NAME-psk` or `NAME-config` that is not
  that VPN's own (`SECRET_EXISTS`, nothing saved). Before, `vpn add prod
  ...` silently overwrote a secret `prod-key` that a server used, and an
  AI agent could put a value it chose there. `--overwrite` still reuses
  the secrets of the VPN it replaces when nothing else uses them.

## [0.7.0] - 2026-11-09

### Highlights

- **Rename a whole project in one step:** `komando rename --prefix shop-
  acme-shop-` renames every server, conn, VPN, secret, key and group that
  starts with `shop-`, and every reference follows. It needs one `--yes`
  (one approval window) for all the protected ones, and it changes
  everything or nothing.
- **`komando update` updates komando itself:** it installs the newest
  release (`sudo komando update` for /usr/local/bin), checked like the
  install line; `komando update --dry-run` says whether there is one.
- **An encrypted key in ssh-agent logs in, as with `ssh`:** a server whose
  `--identity` (from `import ssh-config`) or `--key` is encrypted now uses
  the agent's copy of that key, so a usual macOS setup works with
  `komando test` as it does with `ssh`.
- **The stored password is never sent as a two-factor code.** Before, every
  question the server asked got the password, and each try could count as
  a failed login and lock the account.
- **A person decides where an AI agent sends a secret:** `{{secret:NAME}}`,
  `--env K=secret:NAME` and a password on a new or moved server or conn
  need `--yes` and a yes in komando's window, which names the secret and
  the place (`SECRET_DESTINATION`). Agents that use `fs replace ...
  {{secret:NAME}}` now ask first.
- **Safer connections by default:** vault values for `-e` stay off the
  remote command line, the first trusted SSH host key is shown with its
  fingerprint, IKEv1 no longer offers 3DES or small DH groups, L2TP never
  sends the password with PAP, and `komando doctor` prints the fix for
  every database or cache without checked TLS.
- **Customer data stays out of the AI model:** on protected servers and
  conns, an AI agent sees email addresses, phone numbers, card numbers and
  IBANs as `[hidden: email]` and so on, and columns you name as
  `[hidden: column]`.
- **More places to reach:** MongoDB, Redis Cluster and Sentinel, databases
  and caches with a private CA (`?ca=secret:NAME`), and Google Cloud
  Storage, Azure Blob and WebDAV storage, all also through `--via`.
- **Many clusters at once, Helm without helm:** `cluster status`, `ls`,
  `events` and `helm ls` read every cluster a selector picks, and
  `cluster helm` reads Helm releases straight from Kubernetes.
- **Company proxies:** kube, registry and SSL VPN traffic follows
  `HTTPS_PROXY`, and an HTTP proxy can be a `--via` path (VPN kind
  `proxy`).

### Added

- **`komando secret passphrase`** re-encrypts every secret under a new
  passphrase, so `KOMANDO_VAULT_PASS` can change without losing the vault.
  It also gives a passphrase to a vault whose key is in `vault.key` or the
  keychain (the old key is removed once the new vault is saved and read
  back), and `--off --yes` goes back to a random key in `vault.key`. Every
  secret is decrypted first; when one cannot be, nothing changes. A person
  at a terminal only (`NEEDS_PERSON` for AI agents and scripts).
  `komando doctor` now fails when `KOMANDO_VAULT_PASS` does not open the
  vault and warns about a leftover `vault.key`.
- **`komando rename --prefix OLD NEW`** renames every server, conn, VPN,
  secret, key and group whose name starts with OLD. When OLD ends in `-`,
  the name without it is renamed too (group `shop` for `--prefix shop-`).
  Every reference follows: `--via` paths (also a server in the middle of
  one), password, sudo, key, preshared key and passphrase references,
  `secret:NAME` options in conn URLs, the key a server uses, group
  membership, jobs and tunnels. A key komando made moves its files. The
  protected mark, labels, notes and creation time stay, and names inside
  URLs (a bucket, a database user) do not change. The inventory and the
  vault are each written once; a name that is taken, or two old names with
  one new name, stops it before anything changes (`NAME_TAKEN` lists every
  clash). Protected servers and conns need `--yes` once, and an AI agent's
  window says how many it covers. `--dry-run` shows the old and new names
  per kind and every reference that would change. `--kind` renames only
  some kinds, and `--notes` also replaces the old names in notes, as whole
  words. When the new prefix starts with the old one, a second run changes
  nothing.
- **`komando key mv OLD NEW`** renames a key; the servers that use it follow,
  and a key komando made moves its private and `.pub` files in
  `~/.komando/keys`.
- **`komando group mv OLD NEW`** renames a group on every server, conn and
  VPN in it; with a protected member it needs `--yes` once. A name that is
  another group already is refused (`GROUP_EXISTS`).
- `komando audit --since` and `--until` pick a time window: how long ago
  (`2h`, `7d`), `today`, `yesterday`, or a time (`2026-11-07`,
  `'2026-11-07 14:30'`, `2026-11-07T14:30:00Z`; without a zone, this
  computer's). With either, every match is shown, not only the newest 50,
  unless `-n` is given. They work with `--target`, `--command` and
  `--failed`.
- A company HTTP proxy is a VPN of kind `proxy`
  (`komando vpn add office proxy --address proxy.corp:3128`, its login with
  `--user` and `--password-ref`): `--via office` tunnels servers (SSH),
  databases, caches and file servers through it (CONNECT), as `socks` VPNs
  do for SOCKS proxies. `host ssh-command` gives OpenSSH the same path.
- Personal data is hidden from AI agents in what they read from protected
  servers and conns: `[hidden: email]`, `[hidden: phone]` (international
  form), `[hidden: card]` (card network prefix, length and check digit) and
  `[hidden: iban]` (check digits). It covers `db query`, `cache get` and
  `run`, `storage cat` and `ls`, `fs cat`, `exec`, `logs` and the other
  commands that show data from a target; komando's own inventory is never
  hidden. `komando config set mask_personal all` hides it everywhere, `off`
  nowhere (showing more needs `--yes`). A conn can ask for it with
  `--option mask_personal=on`, and a database conn hides whole columns with
  `--option 'mask_columns=name address'`. `--reveal`, which a person
  allows, shows the values. A `db query --write`, `cache set` or
  `cache run --write` that still holds a hidden value stops with
  `HIDDEN_VALUE`, as file writes already did.

- `komando cluster status`, `cluster ls`, `cluster events` and
  `cluster helm ls` read every cluster a selector picks (`@prod`,
  `kind:k8s`, `all`) at the same time: one row per cluster in
  `data.results` with `data.summary`, and a cluster that cannot be read
  fails alone (`PARTIAL_FAILURE`). One cluster gives the same output as
  before; commands that change a cluster stay on one.
- `komando cluster helm ls|status|history|values` read the Helm releases
  stored in a Kubernetes cluster, without the `helm` program: name,
  revision, status, chart and app version, the notes, every stored
  revision, and the values (`--all` with the chart's defaults,
  `--revision N` for an older one). It only reads; install and upgrade
  stay with helm.
- Storage conns for **Google Cloud Storage** (`gs://bucket/folder`, logged
  in like gcloud or with a service account key), **Azure Blob Storage**
  (`azblob://ACCOUNT@container/folder`, with the account key or a SAS
  token) and **WebDAV** (`webdavs://user@host/path`: Nextcloud, ownCloud, a
  NAS). `storage ls`, `cat`, `upload`, `download`, `rm`, `sync` and
  `conn test` work on them as on S3, also through `--via`. `storage link`
  makes a signed link for Google Cloud (with a service account key) and
  Azure (with the account key). Big Azure uploads go up in blocks, with no
  temporary file; WebDAV makes missing folders. Emulators take
  `?endpoint=URL`.
- **MongoDB** conns (`mongodb://`, `mongodb+srv://`, replica sets, Atlas):
  `db query` takes a command document in JSON (`{"find": ...}`,
  `{"aggregate": ...}`, `{"update": ...}`), rated before it is sent like
  SQL, so changes need `--write`, and an empty-filter delete, `drop`, user
  changes and `shutdown` need `--allow-dangerous`. `db schema` lists
  collections, or the fields of a sample with their types; `db info` gives
  version, role and sizes; `conn test` logs in. Every member is reached
  through `--via`, and `?ca=` checks a private CA.
- Redis Cluster and Sentinel: a `redis://` or `rediss://` conn with
  `?cluster=1` works on the whole cluster from one node's address
  (`cache keys` scans every master, `cache info` adds them up with the
  cluster's state), and one with `?sentinel=MASTER` reaches the master the
  Sentinels name (more Sentinels with `sentinels=`, their login with
  `sentinel_auth=same`). Valkey, ElastiCache and MemoryDB clusters work
  the same way.
- Databases and caches whose certificate comes from a private CA (a
  company CA, Amazon RDS, Azure, ElastiCache) are checked against it:
  `?ca=secret:NAME` on a `postgres://`, `mysql://`, `rediss://` or
  `memcacheds://` conn names the vault secret that holds the CA (PEM), as
  registries already allowed. The check is a full one (signed by that CA,
  naming the server), also with `sslmode=require`, and a Postgres conn then
  never goes on without TLS.
- `komando` alone opens a menu for a person at a terminal: choose Shell,
  Test, Facts, Database, VPN, List, Audit or Doctor with the arrow keys and
  Enter (`?` for help), then a server, conn or VPN from a list you can
  filter by typing. Only what has something to act on is shown; with no
  server yet, Add (and Import, when there is a `~/.ssh/config`) comes
  first. It runs the same command you could type and shows it first. AI
  agents, scripts and `komando` with any flag still get the first steps
  (or, when piped, a `USAGE` error).
- **`komando update`** replaces komando with the newest release, checked
  against the release's `checksums.txt` like the install line, and tried
  once before it takes the old program's place. `komando update --dry-run`
  says whether there is a newer version; `komando update v0.6.0` installs
  that version (going back needs a person's yes, since an older komando may
  lack safety checks; without a VERSION it never goes back). In a folder
  only root may change it stops with `NOT_WRITABLE` and gives the `sudo`
  command to run. Run as you, the update goes into the audit log; as root
  it writes nothing in `~/.komando`, so no file there ends up belonging to
  root. It tries again when GitHub answers 5xx. A komando built from source
  is not replaced (`SOURCE_BUILD`).

### Changed

- `komando import` says `nothing to import from FILE` first when it adds
  nothing, and a note about a server it did add (such as a missing
  identity file) no longer reads `not imported:`. `import ssh-config` on a
  computer with no `~/.ssh/config` says so and shows how to add a server.
- The README, Settings, Safety and SECURITY.md now agree on how to protect
  the vault: `komando secret keychain` is the recommended setup (before or
  after the first secret), and `KOMANDO_VAULT_PASS` is optional. A new
  vault takes the passphrase at its first secret; setting the variable later
  does nothing to an existing vault (`komando secret passphrase` does), which
  the docs did not say.

### Fixed

- Behind a company proxy, Kubernetes clusters, registries and the
  AnyConnect, Fortinet, GlobalProtect, F5 and Pulse VPNs could not be
  reached: they ignored `HTTPS_PROXY`, while `kubectl` and `docker` use
  it. They now go through `HTTPS_PROXY` (`HTTP_PROXY` for `http://`)
  except what `NO_PROXY` names, like storage and the secret stores already
  did. That includes `cluster exec`, `cluster forward` and `cluster shell`,
  and a kubeconfig's `proxy-url` wins for its cluster. A target reached
  with `--via` still goes out through its path. See "Behind a company
  proxy" in [Private servers and tunnels](docs/features/tunnels.md).
- `komando db query --csv` and `--tsv` printed values an AI agent should
  not see: unlike the JSON and text output, they skipped the masking of
  secrets and vault values. They are masked the same way now.
- A `rediss://` conn reached through `--via` could not connect: the Redis
  client leaves TLS out when it is given its own dialer, so it spoke plain
  Redis to the TLS port. komando's dialer now adds TLS itself, checking
  each server's own name.
- `komando host import --overwrite` deleted an existing server when the
  imported copy with the same name was refused (for example, its `--via`
  host does not exist). The server it would have replaced now stays.
- `komando import dbeaver` told you to set a password with the conn's
  name from DBeaver, even when that name was taken and the conn was added
  as `shop-2`: following it pointed your existing `shop` conn at the new
  password. The note now names the conn as it was added, and only a
  connection that was added gets one.
- An encrypted `--identity` or `--key` with no passphrase ref failed with
  `KEY_PASSPHRASE_REQUIRED` even when ssh-agent (or the macOS Keychain)
  held it. komando now finds the agent's copy by its public key (from the
  key file, `PATH.pub` or the keychain) and offers it first, as OpenSSH
  does. The error stays (`KEY_PASSPHRASE_REQUIRED`, exit 2) when the agent
  does not hold the key, and its hint names commands that work:
  `ssh-add PATH`, or `komando secret set`, `komando key add ... --passphrase-ref`,
  then `komando host edit HOST --key NAME --unset identity` (for a `--key`
  key, `komando key edit` with its real name). Before, it named
  `komando key edit <name>`, which fails for an identity file.
- The stored password goes out at most once per login, and only to a
  hidden question that asks for a password. A question about a one-time
  code, token, OTP, passcode or verification, a shown question, or the
  password asked a second time gets no answer: the login stops with
  `AUTH_FAILED` (exit 4), and the message quotes the server's question,
  cleaned, for example `web1 asks "Verification code:" (two-factor login)`.
  The hint says to log in once at a terminal with the command
  `komando host ssh-command web1` prints. `komando shell` uses the same
  login.
- Clearer login hints; codes, exit codes and JSON fields are unchanged.
  `NO_AUTH` says `ssh-add ~/.ssh/id_ed25519` when that key is encrypted and
  the agent is empty, `ssh-add` when the agent is empty, and otherwise how
  to save a password (`komando secret set web1-pass`, then
  `komando host edit web1 --password-ref secret:web1-pass`); it says
  "start ssh-agent" only when `SSH_AUTH_SOCK` is not set. `AUTH_FAILED`
  no longer suggests `komando key deploy`, which logs in the same way and
  fails too; a password-only server is told how to store a changed
  password. The sudo hint names the server instead of a literal `<host>`.
- `HOSTKEY_MISMATCH` shows the full SHA256 fingerprint the server offers
  now, next to the pinned one. A person at a terminal gets a hint worded
  for them: if you rebuilt the server, compare the fingerprint with the one
  on its console, then run `komando host trust NAME --reset`. AI agents
  and scripts keep the hint that tells them to report it.
- Ctrl-C at a question ends it. Before, a `[y/N]` question or a hidden
  prompt went on waiting and Ctrl-C showed nothing. Now Ctrl-C at a
  `[y/N]` question or a typed name is a no (`cancelled: ...`, `nothing was
  changed`, exit 6), and at a hidden prompt (`secret set`, `secret check`,
  a VPN password) the command stops with `CANCELLED`, exit 1, with echo on
  again. Later questions in the same command are not asked. Ctrl-D at a
  `[y/N]` question is a no and ends the line.
- A paste of more than one line at a hidden prompt stores nothing. Before,
  only the first line was read and the shell ran the others as commands
  once komando ended, showing the secret and saving it in the shell's
  history. Now the other lines are thrown away and komando stops with a
  `USAGE` error (exit 2) that points to `komando secret set NAME < FILE`.
- VPN logins with komando's own clients (AnyConnect, Fortinet,
  GlobalProtect, F5, Pulse, OpenVPN, IPsec) ask the same way: Ctrl-C
  works, a paste of more than one line is refused, and the prompt text a
  VPN server sends keeps its lines but loses control characters. A Pulse
  realm or region choice shows numbered lines, takes the number or the
  name, and asks again after a typo (up to 3 times) instead of ending the
  login. The Pulse sign-in notice asks `Accept the sign-in notice? [y/N]`
  and takes y or yes in any case.

### Security

- **`--read-only` on a protected server or conn is now an allowlist, not a
  denylist.** Before, a protected target let any command komando did not
  recognise skip `--yes`, so an unknown program that changes things could
  pass. Now `--read-only` skips the confirmation only for commands komando
  knows read (`cat`, `ls`, `tail`, `df`, `ps`, `grep`, `journalctl` and
  `systemctl status`, `docker ps`/`logs`, `kubectl get`/`describe`, `find`
  without `-delete`/`-exec`, and the like); anything else takes the normal
  `--yes` path with a person's approval. Unprotected targets are unchanged.
  Affects `exec`, `script`, `job start` and read-only recipes.
- **An `--os-mode` OpenVPN profile is now rewritten into a canonical form
  and handed to `openvpn` on its input, never written to a file.** komando
  parses the `.ovpn`, refuses anything its checker and OpenVPN could read
  differently (backslash escapes, stray quotes, over-long lines, odd inline
  tags, control characters), and passes `openvpn` only the directives it
  checked, with `--script-security 1` on the command line so the root
  process runs no user programs. A profile komando accepted before may now
  be refused if it relies on one of those tricks.
- **`komando update` follows release redirects only while they stay on
  HTTPS**, so the download can never be pulled over plain HTTP.
- An AI agent that sends a secret somewhere needs `--yes`, and komando's
  window names the secret and the place (`SECRET_DESTINATION`, exit 6):
  `{{secret:NAME}}` in `fs write` and `fs replace`, `exec --env
  K=secret:NAME` and `job start --env`, `db user add` and `db user passwd`,
  and a password reference (`secret:`, `env:`, `file:`, ...) that `host
  add`, `host edit`, `conn add`, `conn edit`, `import csv` or another import
  attaches to a server or conn, or a server or conn with one that moves to
  another address, port, `--via` path or proxy command. Before, an agent
  could put a vault value on a server it controls, where it can come back
  in a form masking does not know. People and scripts are not asked. An
  agent's dry run reads no secret: it keeps `{{secret:NAME}}` as written.
- No password reference and no `{{secret:NAME}}` reads the approval code's
  key (`RESERVED_SECRET`), for anyone. Before, only the `secret` commands
  refused it.
- An AI agent that adds a conn whose URL turns its network protection down
  (`sslmode=disable`, `allow` or `prefer`; MySQL `tls=false`, `preferred`
  or `skip-verify`; `tls=false` or `tls=skip-verify` for a registry or
  FTPS; FTP `insecure=1`), or edits a conn so that it does (also
  `rediss://` to `redis://`), needs `--yes` and a person's yes
  (`SAFETY_SETTING`).
- An AI agent's command with a `KOMANDO_HOME` other than `~/.komando`
  needs `--yes` and a person's yes, every time (`SAFETY_SETTING`): in a new
  folder komando knew none of the protected servers, deny rules or host
  keys, and wrote the audit log elsewhere. A link to `~/.komando` counts as
  the usual folder. The guard (`komando guide install`) now also stops
  shell lines that set, export or unset `KOMANDO_HOME`.
- The vault key in the OS keychain is read with `/usr/bin/security` on
  macOS and with `secret-tool` from `/usr/bin`, `/bin` or `/usr/local/bin`
  on Linux, never through `PATH`, as the approval window's tools already
  were.
- `tunnel start` hands `KOMANDO_VAULT_PASS` to its background process on
  stdin instead of in its environment, where any program of the user could
  read it for as long as the tunnel runs.
- For an AI agent, audit records add `os_user` (the computer account, read
  from the system) and `actor_claimed: true` when the name comes from
  `KOMANDO_ACTOR`, which the agent's environment can set to anything.
  `komando audit -o text` shows such a line as `Claude Code (as NAME)`.
- `fs replace --regex` with `{{secret:NAME}}` writes a `$` in the secret
  as it is; before, `$1` in a password was read as a group.
- A vault value given to a remote command (`-e DB_PASS=secret:NAME`, or a
  server's `--env` with `secret:`) reaches the command on its input, not
  on its command line. Before, every user of the server could read it in
  `ps` while the command ran, and with `--sudo` it was written to sudo's
  log. Other values are unchanged. A vault value longer than 4000
  characters cannot go through `--pty` and is refused there. `job start`
  now writes the job's environment file from its input too; before, the
  values were on the command line while the job was set up.
- The first time komando trusts a server's SSH host key
  (`host_key_policy accept-new`, the default), it says so on stderr with
  the SHA256 fingerprint and how to compare it with the server's own, and
  writes it to the audit log (`host.key-pinned`). The servers page shows
  how to check keys before the first connection.
- IKEv1 (`l2tp`, `ipsec`) offers only AES with SHA-256 or SHA-1 and DH
  groups 14 and 19, and the server may only choose what was offered.
  Before, komando also offered 3DES and DH groups 2 and 5, and accepted a
  suite it had not offered. A server that only speaks those old ciphers
  now stops with an error whose hint names
  `komando vpn edit NAME --legacy-crypto`, which allows them for that VPN
  again (after the strong ones) and needs a person's yes. Cisco-style
  IPsec with a group name (aggressive mode) gets a warning in the session
  log and in `komando doctor`: anyone who sees that login can guess the
  group password offline.
- L2TP no longer sends your password with PAP when the server asks for
  it: komando asks for MS-CHAPv2 instead, and a server that insists on
  PAP stops with an error that says why.
  `komando vpn edit NAME --allow-pap` allows PAP for that VPN; it needs a
  person's yes.
  `komando doctor` lists VPNs with either setting on.
- komando's OpenVPN client wants the server's certificate to be marked for
  a server (serverAuth, or nsCertType server) even when the profile has no
  `remote-cert-tls server`, so another user's certificate from the same CA
  cannot pretend to be the server. A profile can name the server with
  `verify-x509-name` instead; the error shows the line to add. A profile
  without either check gets a warning in the session log.
- `komando doctor` explains why each database or cache conn without
  checked TLS is at risk (for example, the MySQL 8 login over a plain
  connection can be tricked into giving away the password) and prints the
  `komando conn edit NAME --url ...` line that adds `sslmode=verify-full`,
  `tls=true`, `rediss://` or `memcacheds://`. Saved conns keep working as
  they are. When TLS stops a connection, the hint names what to do and
  the weaker setting with its cost.

## [0.6.0] - 2026-11-08

### Highlights

- **Lists are sorted by name, as one list:** servers, conns and VPNs share
  one A-Z order in `list` and `test`, and lists a server sends (`fs ls`,
  `docker ps`, `registry ls` and more) are sorted too. Scripts that relied
  on servers coming first see a new order.

### Changed

- Lists are sorted by name, as one list. `list` (and `host`, `conn` and
  `vpn list`) and `test` put servers, conns and VPNs in one A-Z order
  instead of all servers first; the KIND column tells them apart.
  `recipe list` puts your saved recipes among the built-in ones (the
  category still says `saved`), `group list` shows groups and tags
  together, and `policy list` sorts the rules of each kind by ID. Lists a
  server sends in its own order are sorted too: `fs ls`, `storage ls` on
  SFTP and FTP, `user list`, `svc list`, `docker ps`, `docker stats`,
  `docker images` (docker puts the newest first) and `registry ls`. Lists
  without names keep their order: `job list` and `tunnel list` by start
  time, `cron list` as in the crontab.

## [0.5.0] - 2026-11-08

### Highlights

- **`?resolve=IP` for registry and S3 conns**, like `curl --resolve`: reach
  a registry whose public DNS is wrong or missing straight from your
  computer, without `--via` a server that has the right `/etc/hosts`.
- **Secrets named in a conn URL count as used** (`?ca=secret:NAME`):
  `secret rm` no longer deletes them, and `secret mv` and `export` follow.
- **`doctor` finds untidy conns:** a shared protected password, duplicate
  conns, and an unprotected conn of a protected server.
- **`sudo sh install.sh` installs komando owned by root.**

### Added

- Registry and S3 conns take `?resolve=IP` (or `IP:PORT`), like
  `curl --resolve`: komando connects to that address instead of the one DNS
  gives for the name. TLS keeps using the name in the URL, so
  `?ca=secret:NAME` and `?tls=skip-verify` work as they do without it. This
  helps when a registry's public DNS is wrong or missing: before, the only
  way was `--via` a server whose `/etc/hosts` had the right address. With
  `--via`, the last server connects to the IP. `komando test` and `tunnel`
  use it too, and so does `cert check` for an S3 conn. A value that is not
  an IP address is refused with `USAGE`.

### Changed

- `doctor` warns about conns worth a look: an unprotected conn that shares
  its password secret with a protected server or conn, two conns with the
  same kind, URL and `--via`, and an unprotected conn with the label
  `host=SERVER` of a protected server. Each warning says the command that
  fixes it.
- `host show @group` (or another selector where one name is expected) says
  that the command takes one name and points at `komando list @group` and
  `komando export @group`, instead of a bare "not found".

### Fixed

- A secret that only a conn URL names, such as a registry's
  `?ca=secret:NAME`, counts as used: `secret list` shows the conn under
  `used_by`, `secret rm` refuses it (`SECRET_IN_USE`), `secret mv` changes
  the URL too, `export` lists it in `secrets_needed`, and `doctor` warns
  when it is not in the vault. Before, `secret rm` deleted it and broke the
  conn, and `secret mv` left the URL on the old name.
- A database that times out in the checks right after connecting (a slow
  VPN) said `connecting to  timed out`, without the address. The message
  names the address, and the `--via` path when there is one:
  `connecting to 10.0.0.5:5432 via office-vpn timed out`.
- `sudo sh install.sh` installed komando owned by uid 1001, the user that
  built the release, instead of root. It now extracts with
  `--no-same-owner`. If you installed with sudo, fix the owner once:
  `sudo chown root:wheel /usr/local/bin/komando` (Linux: `root:root`).

## [0.4.0] - 2026-11-07

### Highlights

- **Clearer for people at a terminal:** `komando` alone shows three first
  steps instead of the full help, typos get "did you mean", and results
  of a change say what happened ("added web2") instead of a list of fields.
- **FTP and FTPS keep going** when the server drops a connection in the
  middle of a command: komando logs in again once and repeats it.
- **For scripts and agents:** piped `komando` alone, or a group such as
  `komando db` without its sub-command, now fails with `USAGE` (exit 2),
  and `komando test` on one target gives that target's own error code.
- **BREAKING exit codes:** `NO_AUTH` exits 4 (was 2) and
  `SECRET_UNRESOLVED` exits 3 everywhere; scripts that check them must be
  updated.

### Added

- Release archives include `THIRD_PARTY_LICENSES`: the license texts and
  NOTICE files of the Go modules and the Go standard library built into
  komando (`make licenses` writes it alone).
- `install.sh` installs one version with `KOMANDO_VERSION=vX.Y.Z`.
- The README has Update, Uninstall and "Something wrong?" sections, and
  says how to protect the vault key (`komando secret keychain`).
- The docs say how to get the AI agent seatbelts (secrets hidden in output,
  a person allows `--yes`) for agents komando does not know by name: set
  `KOMANDO_AGENT=1` in the agent's environment.

### Changed

- **BREAKING: exit codes.** Scripts and agents that check komando's exit
  codes must be updated. `NO_AUTH` (a server with no key, identity or password) now
  exits 4 like `AUTH_FAILED`, not 2. `SECRET_UNRESOLVED` (a password
  reference that cannot be read) exits 3 everywhere; it was 2 for servers
  and 1 for conns and registry CAs. The agent guide's error table now says
  `PARTIAL_FAILURE` exits with the worst code among the failed servers.
- `komando` with no arguments prints the first steps; `komando --help`
  still lists every command.
- A mistyped command or flag says what was meant, on one line:
  `unknown command "exce"; did you mean exec?`,
  `unknown flag: --tiemout; did you mean --timeout?`. The hint points at
  the help of the command meant.
- A usage error without its own hint now shows the command's example and
  its `--help`, instead of the same hint for every command.
- Text output of a change starts with what happened (`added web2`,
  `changed web2`, `web2: nothing to change`, `would add web2 (dry run)`),
  then the record without its timestamps. Records show `name` first, and
  times in local time with the zone instead of UTC RFC3339. JSON is
  unchanged.
- Counts read as words: "1 server", "3 servers", "both failed",
  "all 5 failed", instead of "server(s)" and "2 of 2 failed".
- `komando test` on one target fails with that target's own error code
  (for example `CONNECTION_REFUSED`), as `exec` already did, instead of
  `PARTIAL_FAILURE`.
- `komando list` shows `yes` or `-` under PROTECTED instead of
  `true`/`false`.
- Every command has at least one example in `--help`; a test checks that
  each example uses commands and flags that exist.
- `komando --help` fits 80 columns: shorter one-line descriptions (the
  full sentence stays in the command's own `--help`) and shorter global
  flag texts.
- A sub-command's `--help` lists the four global flags that matter
  (`--dry-run`, `-o`, `--timeout`, `--yes`) instead of all eleven;
  `komando --help` still lists every one.
- `config set` says what changed: `parallel: 10 → 5`, or
  `parallel: already 5`. JSON is unchanged.
- `policy list -o text` is a table of what each rule stops, with the note
  that the rules are guardrails, not a security boundary; the regular
  expressions stay in `-o json`.
- Piped (JSON) output for `komando` alone, or a group such as `komando db`
  without its sub-command, is a `USAGE` envelope (exit 2) that names the
  sub-commands, instead of help text. In a terminal nothing changed.
- Hints that were questions now say what to do: a refused SSH connection
  suggests checking sshd and `komando host show NAME`.

### Fixed

- `komando export -o text` showed `secrets_needed: [hidden]` for an empty
  list: names of secrets and `-` are not secret values.
- FTP and FTPS (`storage`, `upload`, `download`, `sync` on an `ftp://` or
  `ftps://` conn): when the server drops a connection in the middle of a
  command (EOF, reset), komando logs in again once and repeats the command,
  instead of stopping with `STORAGE_CONNECT`. It never repeats after an FTP
  error reply, a TLS error or a timeout, nor a download that already wrote
  bytes, nor an upload from a source that cannot start over (a pipe). A
  `rm` whose repeat finds the file gone counts as done.
- `install.sh` no longer installs into `~/.local/bin` when
  `KOMANDO_INSTALL_DIR` is set but cannot be written: it creates the
  folder, or stops with a message.

### Security

- Downloads by an AI agent (`download`, `sync`, `storage download`, also
  to stdout) save text files the way `fs cat` shows them, with secret
  values as `[hidden]`. Before, they gave the agent the real file.
- `upload` and `sync` refuse a file that still holds `[hidden]` or
  `[secret:NAME]`, as `fs write` does, so a masked copy never replaces the
  real values.
- `fs cat` and `fs replace` now hide Redis passwords (`requirepass`,
  `masterauth`, ACL rules) as other output does. Before, `fs replace`
  could confirm a guessed password and `fs cat` returned the file's hash.
- `exec --read-only` checks the SQL in `psql -c`, `mysql -e` and SQL fed in
  with `--stdin-file` (the same rules as `db query`), and the commands in
  `redis-cli`, `valkey-cli` and `keydb-cli` (the same as `cache run`). It
  also catches `sort -o`, `uniq IN OUT`, `split`, `openssl -out`, `date -s`,
  `hostname NAME`, `dmesg -C` and `less +CMD`.
- The danger check now stops `bash --rcfile FILE -c ...`, `ufw --force
  reset`, `iptables -P INPUT DROP`, `cp`, `mv`, `tee`, `truncate` or `dd`
  onto `/etc/passwd`, `/etc/shadow` or `/etc/sudoers`, `echo '...' | sh`
  (the text is checked like `sh -c`) and `base64 -d | sh`.
- `secret set` checks that `KOMANDO_VAULT_PASS` opens the secrets already
  stored; a mistyped passphrase no longer saves a secret under a second key.
  A missing `vault.key` is no longer replaced by a new one while secrets
  need it: komando asks you to restore it.

## [0.3.1] - 2026-11-07

### Highlights

- **Rebuilt a group of servers?** `komando host trust @group --reset --yes`
  accepts all their new keys after one yes, instead of one per server.
- **New servers that are still starting:** `komando test @new --wait 5m`
  waits until they answer, instead of a sleep loop.
- **AI agents read output more simply:** the guide tells them to use `-o
  text` when they only want to read what a command printed.

### Added

- `komando host trust TARGET` takes many servers (`@group`, `tag:`,
  `'web*'`, `a,b`): after a rebuild of a whole group, `--reset` replaces
  every changed key after ONE yes that names each server with its new
  fingerprint, instead of one yes per server. `data.results` has each
  server's `fingerprint` and `old_fingerprints`. A changed key is still
  refused without `--reset`; `host trust NAME` answers as before.

- `komando test TARGET --wait 5m` waits for new servers: it tests again
  every few seconds until every target passes or the time is up (right
  after creating or rebuilding cloud servers, instead of a sleep loop).
  It does not wait out a changed host key or a refused login: those fail at
  once. `data.waited_ms` says how long it waited.

### Changed

- `komando host rm` says which servers' pinned host keys it keeps
  (`host_keys_kept`, `note`): a server added again at the same address must
  show the same key, so `rm` plus `add` is no way around
  `HOSTKEY_MISMATCH`.

- The agent guide (`komando guide`), the skill and the output docs say
  when to use `-o text`: to read a command's output, instead of pulling
  `stdout` out of the JSON. JSON stays the default for branching on each
  server's exit code or error.

### Fixed

- `--help` examples for `cluster` commands now use `--namespace`; `-n` is
  `--limit` in komando, so the old examples failed when copied. `import
  --help` no longer shows "(default -)", and `komando --help` and `conn
  --help` now say that clusters and registries are conns too.

## [0.3.0] - 2026-11-07

### Highlights

- **New license.** komando is now under the AGPL-3.0, with a commercial
  license for closed-source use. It stays free to use for any purpose.
- **More VPNs built in.** L2TP/IPsec, Cisco-style IPsec (XAUTH) and IKEv2
  work without strongSwan, OS VPN settings or admin rights.
- **Patch rounds.** `pkg security` installs only security updates, one
  server at a time, and checks each server before and after. `cert check`
  shows when certificates expire, `docker prune` previews what it would
  delete, and `reboot` restarts servers one at a time and waits for them.
- **Safer for AI agents.** A full security review brought fixes for SQL,
  database restores, Redis passwords, clusters and `--read-only`.
- **Easier inventory.** Rename servers, conns, VPNs and secrets (`mv`),
  import servers from a spreadsheet (`import csv`) and edit many at once.

### Changed

- **License: komando is now under the GNU Affero General Public License
  v3.0 (AGPL-3.0)** instead of MIT. You can still use it for free, for any
  purpose. If you change komando and give it to others, or let them use it
  over a network, you must share your version's source code under the same
  license. A [commercial license](COMMERCIAL-LICENSE.md) is available for
  closed-source use. Contributors now sign a short
  [Contributor License Agreement](CLA.md) once. v0.1.0 and v0.2.0 stay
  under MIT.

- The built-in recipes `cert-expiry`, `certbot-certs` and `docker-prune`
  are gone: `komando cert check` and `komando docker prune` do the same
  better (`docker-prune` skipped the preview and the `--allow-dangerous`
  question). Running one of those names says which command to use; a
  saved recipe of the same name still works.

- `komando facts` and `komando pkg security` read the server's state with
  the same check, so they agree: `facts` now also sees a newer kernel that
  needrestart reports (`reboot_required`, `reboot_packages: ["kernel"]`)
  and, on dnf/yum servers, the services that need a restart (from
  `needs-restarting -s`). `pkg security` now has `os_support` and warns on
  an OS past end of life, where an empty list does not mean the server is
  safe.

- `komando vpn status`: `last_end` now says when the session ended and how
  long it ran. When an L2TP server ends the session, it also says how long
  the link had no traffic (a server idle timeout?), and the log shows the
  server's own reason (StopCCN/CDN result, LCP Terminate text).

- Servers behind the same jump hosts share one connection to them within a
  command: `exec -P 10` through a bastion logs in to it once (OpenSSH's
  ControlMaster), staying under its `MaxStartups`. A broken shared path is
  opened again once.

- A protected server stays protected under another name: before any
  change, komando also compares the IP addresses names resolve to on this
  computer, so `db.internal` is the protected `10.0.0.5` (hosts and conns,
  same port). Names only a jump host knows are compared as text.

- A person is asked about a safety change (for example a recipe replaced by
  a read-only one) before komando locks its state file, so other komando
  commands do not wait for the answer.

- `cache run` text output shows map entries as `name: value` (was `name =>
  value`). For agents, a RESP2 `HGETALL` reply is shown as a map, so
  secret-named fields are hidden as over RESP3.

- When a script command times out, the hint no longer says to raise
  `--timeout`; it says the script may still be running and names `SCRIPT
  KILL` or `FUNCTION KILL`.

- Approval window: line breaks, tabs, control characters, long runs of
  spaces, blank-drawing letters (U+3164 ...) and combining marks show as
  $'...' escapes, so multi-line `fs replace` edits on protected hosts can be
  approved; bidi and zero-width characters are still refused.

- Error and hint lines show colour/conceal escapes and carriage returns as
  \e and \r.

- A saved read-only recipe that no longer passes the read-only check runs as
  a change (protected servers ask for --yes) instead of being blocked.

- `--backup` copies add up next to the file; clean them up with `fs rm`.

- An SSH connection that stops answering (for example a VPN that dropped
  silently) is closed after about a minute without an answer, so commands
  report the loss instead of waiting until `--timeout`.

- `host edit --rename` and `conn edit --rename` are deprecated in favour of
  `host mv` / `conn mv`.

- The approval window for protected changes says which protected entries the
  command touches.

- Imports refuse a server whose `key` is not in komando's keychain.

- The hidden `secret set` prompt drops text typed or pasted before it
  appeared, and says so; it strips bracketed-paste marks.

- `komando facts` reports values it cannot read as `null` instead of
  `0`/`false`: `reboot_required` is `null` where it cannot be checked, and
  an unsupported OS shows `updates.security: null` with a warning.

### Added

- `komando schema` says what each command does: `kind` is `read`,
  `change` or `depends`, and `kind_note` says on what for `depends`
  (`exec` changes things unless `--read-only`, `db query` only reads
  unless `--write`). Agents can see it before they run a command.

- `make e2e` also runs `facts`, `pkg security` (with a real `--apply`) and
  `pkg` against Rocky Linux 9 (dnf) and Amazon Linux 2 (yum) servers, and
  compares every answer with the native `dnf`/`yum`/`rpm` on the same
  server (`test/e2e/rhel`, `test/e2e/checks/rhel.sh`).

- Registry conns (`registry://`, `oci://`) take TLS options:
  `?ca=secret:NAME` trusts a private CA (PEM in the vault), or pins the
  registry's own certificate when the CA is not at hand, and keeps the
  certificate check on; `?tls=skip-verify` uses HTTPS without the check
  (like Docker's `insecure-registries`; `komando doctor` warns about it,
  also with `--via`). A refused certificate is now `REGISTRY_TLS` (not
  `REGISTRY_UNREACHABLE`), with a hint that names `ca=` first. Unknown
  registry URL options and `tls=` values are refused instead of ignored.
  With `--via`, the last server looks the registry's name up (its
  `/etc/hosts` applies); the certificate check and `Host` stay on the name.

- L2TP/IPsec (`l2tp`), Cisco-style IPsec with a group name and XAUTH login
  (`ipsec`, also `cisco`) and IKEv2 (`ikev2`, pre-shared key or EAP-MSCHAPv2
  login with the server's certificate checked) are built into komando:
  komando's own IKEv1, IKEv2, ESP-in-UDP, L2TP and PPP, so they need no
  strongSwan, no OS VPN settings and no admin rights, and the computer's
  network stays as it is. New `vpn add`/`vpn edit` flags: `--server`,
  `--psk-ref`, `--id`, `--remote-id`, `--ca`. Tested against strongSwan 5.9
  and xl2tpd, rekeys included (`make e2e-ipsec`). Before, these kinds were
  only a name for `system`.

- `komando vpn status` shows why a VPN's last session ended (`last_end`),
  and for `l2tp`, `ipsec` and `ikev2` the last lines of its log
  (`last_log`), so an agent can tell why without reading `~/.komando`.

- `db dump --on HOST` runs pg_dump or mysqldump on a server you choose,
  whatever the conn's own path (for example a conn through a VPN), so
  `--format custom` works there too. It runs at low priority (nice, ionice),
  keeps the password in the tool's environment and streams the backup back
  over SSH; `runs_on` and `low_priority` in the answer and the audit say
  where and how. `db restore --on HOST` loads a PostgreSQL archive with
  pg_restore there, behind the same `--allow-dangerous` gate.

- New errors with hints: `TOOL_TOO_OLD` (pg_dump older than the database
  server, or pg_restore older than the archive) and `CONN_UNREACHABLE` (the
  tool cannot reach the database from that server, with how to add a
  127.0.0.1 conn through it).

- `komando reboot TARGET`: reboots servers one at a time, waits for each to
  answer again and checks it really started anew (boot id). A server that
  does not come back stops the rest. Destructive: needs `--allow-dangerous`.

- `komando registry prune CONN REPO --keep N [--older-than 30d] [--match RE]`:
  deletes old images, never one a kept tag points at (`latest` always
  stays). `registry inspect` now gives a multi-platform image's build date.

- `komando import aws`: one S3 storage conn per bucket of each profile in
  `~/.aws/config` (and the credentials file). The conns use the profile, so
  no key is copied and SSO or roles keep working.

- memcached conns (`memcached://`, `memcacheds://` for TLS, the text
  protocol's login): `cache get`, `set`, `rm`, `keys`, `info` and `run` work
  like they do for Redis, with the same safety rules (`flush_all` needs
  `--allow-dangerous`). komando speaks the protocol itself.

- `komando db user ls|add|passwd|rm`, `db grant`, `db revoke` and `db grants`
  for PostgreSQL and MySQL/MariaDB. Passwords come from a secret reference
  and are never shown or audited; PostgreSQL gets a SCRAM-SHA-256 verifier
  computed by komando, so the password never reaches the server.

- `komando config set audit_syslog tls://HOST:6514` (or `udp://`, `tcp://`):
  each audit record also goes to a log server or SIEM, as RFC 5424 syslog.
  Changing it needs `--yes`.

- `komando secret keychain`: the vault key moves from `vault.key` into the
  OS keychain (macOS keychain, Linux Secret Service), so a backup of
  `~/.komando` no longer opens the vault. `--off --yes` moves it back.
  `doctor` names it.

- `komando config approval-code`: komando's "Allow once" window then also
  asks for the 6-digit code from your authenticator app (TOTP), a second
  factor for an AI agent's `--yes`, `--allow-dangerous` and `--reveal`. Only a
  person at a terminal can turn it on; turning it off needs that code too.

- The guard that keeps AI agents away from secret files on this computer now
  also works for Cursor, Gemini CLI and Codex: `komando guide install` adds
  it to `.cursor/hooks.json`, `.gemini/settings.json` and `.codex/hooks.json`
  when those folders exist (Codex asks you to approve it once in `/hooks`).

- `komando svc daemon-reload TARGET`: reloads unit files after you write
  one, and names units that still need a reload.

- `komando job wait` takes several job IDs and waits for all of them, with
  one result per job and a summary; the exit code is the worst one.

- `komando job start --sudo` works on servers whose sudo needs a password
  (`--sudo-ref`). The password is sent as input, never on a command line,
  and the job deletes it as soon as it starts.

- `komando host mv OLD NEW`, `conn mv` and `vpn mv` rename an entry and
  update every reference to it (`--via` paths, jobs, tunnels) in one step;
  renaming a protected entry needs `--yes`.

- `komando host edit` takes several names and targets (`host edit @ubuntu
  --sudo-ref secret:ubuntu-sudo`); one `--yes` and one approval window,
  which lists every server and which are protected, cover the whole command.

- `komando import csv FILE` adds servers from a spreadsheet; every row is
  checked before anything is written.

- `komando secret mv OLD NEW` renames a secret and every server, conn, key
  and VPN reference to it, without showing the value. `secret cp OLD NEW`
  copies one inside the vault.

- `komando secret check NAME`: a person compares a value with the stored one
  without seeing either; refused for AI agents (`NEEDS_PERSON`).

- `secret set` and `secret get` warn when a value starts or ends with a
  space or tab, ends with a line break, or holds control characters.

- `komando facts` reports whether the OS still gets security updates
  (`os_support`: supported, extended through Ubuntu Pro ESM or Debian LTS,
  unsupported, unknown), pending and security updates with the package index
  age, reboot-required packages, services needing a restart, passwordless
  sudo, Docker version, Swarm role and running containers, PM2 daemons and
  apps, listening ports with their programs, hand-made systemd units, and
  `warnings`. It also has a short text view.

- `komando pkg security TARGET` lists pending security updates with each
  server's state (running containers, failed units, pending updates, reboot
  required, services needing a restart). `--apply` installs only security
  updates, one server at a time, compares each server before and after and
  stops the round on an unexpected change (`UNEXPECTED_CHANGE`;
  `--keep-going` to continue). It never reboots.

- `komando cert check TARGET...` shows when TLS certificates expire: on
  servers (certbot, nginx, haproxy, apache, `--path`; only the certificate
  part of a file is read) and for websites and TLS conns (directly or
  through `--via`, with a trust check), plus certbot renewal state. `--warn`
  (default 30d) flags certificates expiring soon; problems exit 1 with
  `CERT_PROBLEMS`.

- `komando docker prune TARGET` with `--older-than`, `--all` and
  `--volumes`. `--dry-run` lists the stopped containers, images, volumes and
  build cache that would be removed, with sizes and a total. The real run
  needs `--allow-dangerous`.

- komando's own restore of plain SQL skips pg_dump 17's `SET
  transaction_timeout` on PostgreSQL servers older than 17, so such backups
  restore there.

### Security

- Updated `github.com/klauspost/compress` to v1.20.2 (GO-2026-6865: a
  crafted compressed frame could crash komando during a VPN session).

Fixes from the full security review of 2026-11-04.

- komando db refuses SET NAMES, SET CHARACTER SET, client_encoding and
  character_set_client changes (SQL_STRING_RULES), and refuses a connection
  whose client character set can hide a backslash (SJIS, GBK, BIG5, GB18030,
  UHC, JOHAB, cp932).

- MySQL `--` before 0x7f is read as a comment the way the server reads it;
  `--` before a non-ASCII byte is refused (SQL_HIDDEN_CODE).

- In MySQL only known transactional statements (SELECT, INSERT, UPDATE,
  DELETE, REPLACE, WITH, VALUES, TABLE, SHOW, DESCRIBE, EXPLAIN, HELP, USE,
  DO, HANDLER, SET) run inside komando's transaction; everything else,
  including CHECK TABLE, CACHE INDEX, replication START/STOP/CHANGE, IMPORT
  TABLE, CLONE, BACKUP STAGE and XA, must be sent alone, needs --write, and
  a dry run reports it without running it.

- A dry run no longer executes statements a rollback does not undo (ending
  sessions, COPY ... PROGRAM, server files, dblink, server config,
  set_config with a computed name, DO, CALL, EXECUTE, setval); they are
  reported as skipped.

- `db query --write --dry-run` runs nothing when the real run would be
  blocked (destructive SQL without --allow-dangerous, or a protected conn
  without --yes); it shows the plan and meta.would_be_blocked.

- Postgres COMMIT AND CHAIN hidden from the classifier is now caught
  (SQL_TX_CONTROL) before the next statement runs.

- `db dump --table` refuses values that start with `-`; mysqldump read them
  as options on the --via server (e.g. --result-file could overwrite files).

- `db restore` names SQL that runs programs, touches server files, changes
  server config or privileges, or cannot be inspected (sql-program,
  sql-server-file, sql-server-config, sql-privileges, sql-opaque,
  sql-remote, sql-kill) next to db-restore in the approval and
  POLICY_BLOCKED, with the line where each first appears.

- `cache run` now needs `--write --allow-dangerous` for read-only scripts
  (`EVAL_RO`, `EVALSHA_RO`, `FCALL_RO`) and for module code (`TFCALL`,
  `TFCALLASYNC`, `RG.PYEXECUTE`, `RG.TRIGGER`, `RG.TRIGGERONKEY`), because
  each can block the server or run code komando cannot inspect.

- `FUNCTION LOAD REPLACE`, `TFUNCTION LOAD REPLACE`, `TFUNCTION DELETE` and
  `RG.UNREGISTER` count as `redis-scripts` (destructive).

- AI agents no longer see Redis passwords: `CONFIG GET` and `SENTINEL CONFIG
  GET` values of requirepass, masterauth, primaryauth, tls-*-pass and
  sentinel-pass, and the password hashes in `ACL LIST` and `ACL GETUSER`,
  show as `[hidden]`, also when the password is a word like `yes`.

- Output masking now also hides Redis passwords written the Redis way
  (`requirepass pw`, `sentinel auth-pass mymaster pw`, ACL `>pw` and
  `#hash`), as seen through `fs read` of redis.conf or users.acl, grep, or
  redis-cli `CONFIG GET` over `exec`.

- Cluster run: an AI agent's `get secret -o yaml|json` is a read, since the
  values show as hidden; it no longer asks the person for --allow-dangerous.

- Cluster run / cluster apply: a file that still holds a value komando hid
  ([hidden], (hidden)) is refused with HIDDEN_VALUE before anything is sent,
  so a get-edit-apply round trip cannot overwrite a password with the
  marker.

- Cluster run: an AI agent cannot send komando's own folder, or files that
  are secrets by name (unless --reveal), to the cluster through -f,
  --from-file or cp (SENSITIVE_FILE).

- Cluster run: an empty object name (delete pod/, delete pod "",
  metadata.name: "") is refused instead of deleting the whole collection.

- Cluster run cp: never writes into a .git folder; copied files keep their
  exec bit like kubectl cp, never setuid, setgid or world-write.

- Swarm: --mount read as CSV, host-folder volumes (volume-opt device, volume
  create --opt device=), --volumes-from, --network/--net host, --cgroupns
  host, --pid container:, --device-cgroup-rule, credential folders even
  read-only (/root, /home/USER, .ssh, /etc/kubernetes, /var/lib/kubelet,
  shadow, etcd, rancher), /opt and /var/spool, and plugin create|enable|set
  now need --allow-dangerous.

- Kubeconfig login programs: a kubeconfig a person imported (or allowed) is
  trusted for its program and server, so agents no longer get a window on
  every read; a change in the vault asks again.

- Approval window: names the program a kubeconfig login runs, and a yes
  given for something else does not cover it.

- Cluster exec/shell/forward --dry-run report the login-program stop the
  real run would meet.

- komando counts an AI agent's variable as present even when it is empty,
  and the agent guard now also stops env flag clusters, GNU long-option
  prefixes and env -S, exec -c, read/printf -v/mapfile/for loops that set
  the variables, brace/glob/$-computed names, statements that start with a
  keyword, more wrappers (timeout, setsid, stdbuf, chrt, busybox, ...),
  `sudo komando` without -E, `bash -lc`/`sh -ec` scripts and quoted heredocs
  fed to a shell.

- An AI agent's local reads, file: references and the guard catch
  ~/.KOMANDO-style case variants on macOS and Windows, hard links to
  komando's data or private keys, and any /proc/.../environ path (refused
  even with --reveal).

- `komando sync` of a folder checks each file for an AI agent, as `cp -r`
  does; komando's own data is never uploaded, even with --reveal.

- The agent guard stops recursive reads and archives of a folder that holds
  komando's data (grep -r ~, rg, tar -C ~, zip -r, cp -r, find -exec, the
  Grep tool in the home folder), follows tar/git -C, sees through $(echo
  ...) substitutions and expands ~user.

- `--read-only` now reads shell scripts the way bash does: options after
  `-c` (`bash -c -- '...'`), arguments a script gets (`sh -c '...' "$0"`),
  comments, here-documents, `case` inside `$( )` and brace expansion
  (`{rm,-rf,/x}`). A command it cannot read (an unclosed quote) is refused.

- Under `--read-only`, an argument that is only known when the command runs
  (`find /data $X`, `xargs find`) is refused for commands whose arguments
  decide what they do. `-e` values are filled in first.

- Under `--read-only`, setting a variable that runs code (BASH_ENV, PS4,
  PROMPT_COMMAND, LD_PRELOAD, PAGER, GIT_SSH_COMMAND, BASH_FUNC_*) is
  refused, whether inline, through env or sudo, through export, or with -e.

- `--read-only` now catches more commands that write or run commands: git
  -c, sed e/w, gawk --source and @f(), tar --checkpoint-action and extract,
  psql \! and \o, mysql system and tee, vim, script, sg, hash -p,
  gzip/xz/unzip/patch on files, curl -o/-O/-d/-X POST, wget saving a file,
  sqlite3, crontab FILE, docker/kubectl exec, and git branch/tag/config
  changes. Subcommands are now found after global options (`kubectl -n prod
  delete`, `iptables -t nat -A`). New wrappers: chrt, taskset, numactl,
  prlimit, fakeroot, faketime.

- `pkg rm` now treats openssh-server.x86_64, sudo.noarch and other name.arch
  spellings (also after a version) as essential, and apt patterns such as
  `openssh.server` that would pick an essential package. All need
  --allow-dangerous.

- Package names may no longer end in '-' (apt reads it as 'remove this
  package', even for `pkg install` and `pkg upgrade`) or '.'; a local
  package file gets a message pointing to `komando upload` + `komando exec`.

- On apt servers, `pkg rm` of a package whose removal would take an
  essential package with it (libssl3 takes openssh-server) now stops with
  POLICY_BLOCKED before anything is removed. Other package managers are not
  checked this way yet (known gap).

- An AI agent's `--dry-run --reveal` no longer shows hidden values; a dry
  run always keeps masking on and reports `REVEAL_NEEDS_PERSON` in
  `meta.would_be_blocked`.

- `fs replace` refuses (HIDDEN_VALUE) an agent's edit that would uncover a
  hidden value, such as renaming `DB_PASSWORD=` or cutting off `postgres://`
  or `Bearer `.

- For AI agents, `fs replace`, `fs write --if-changed` and `would_change` no
  longer reveal whether new text equals a hidden value, and `fs cat`/`fs
  replace`/`fs write` leave out the sha256 of a file with hidden values.

- `fs cat --head/--tail` masks the whole file before cutting it; the end of
  a private key without its BEGIN line is hidden too.

- VPN (OpenVPN): verify-x509-name now compares the server certificate's
  subject attribute by attribute. A crafted value such as O="Corp, CN=vpn"
  or CN="vpn " can no longer pass as the pinned server.

- VPN (OpenVPN): remote-cert-ku accepts the 0x prefix, as OpenVPN does.
  remote-cert-eku accepts the IPsec usage names (IPSec End System, IPSec
  Tunnel, IPSec User).

- VPN (OpenVPN): a client-side rekey no longer cuts off a renegotiation the
  server already started, which could drop the session.

- VPN: only SOCKS clients that log in keep a VPN session from going idle.
  Running out of file descriptors no longer ends the session.

### Removed

- `op://` no longer falls back to the closed-source `op` CLI, as announced
  in 0.2.0: it reads 1Password Connect only. Without Connect it says so and
  names the alternatives (`bw://`, `kdbx:`, a komando secret).

### Fixed

- `komando vpn up` printed the session's local SOCKS password; it now shows
  `[hidden]`.

- `komando db dump` works again on PostgreSQL 12 and 13: it no longer reads
  catalog columns that only newer servers have (`prosqlbody`, `tgparentid`).

- The Bitwarden device id file (`bitwarden-device`) is kept in
  `KOMANDO_HOME`, like every other state file, instead of always in
  `~/.komando`.

- The Postgres read-only session setting falls back for any pooler that
  rejects the startup parameter (SQLSTATE 08P01), not only PgBouncer's
  wording.

- `db restore` no longer hangs (PostgreSQL) or fails with 'Query was empty'
  (MySQL) when the last statement has no trailing `;`.

- `db restore` no longer refuses backups whose data or comments mention
  NO_BACKSLASH_ESCAPES or standard_conforming_strings, MySQL routines with a
  line starting with a column such as `source`, names ending in a backslash
  in backticks, or non-Latin PostgreSQL dollar-quote tags.

- `db restore` refuses computed changes to standard_conforming_strings
  (set_config) and sql_mode (CONCAT, variables), and DELIMITER lines it
  cannot follow; the check and the restore now read DELIMITER the same way.

- MySQL restore no longer sends a comment-only chunk in front of the next
  statement on the same line.

- Dry-run and result `runs_on` say `local` when komando itself runs the dump
  or restore through the --via path.

- The agent guard no longer treats quoted regexes and sed scripts as file
  globs (`grep -o '.*' f`, `sed 's/.*//' f`), no longer checks find's -name
  patterns, and allows `du -sh ~/*/*`.

- `komando import kubeconfig|pgpass|mycnf|env|docker` works for AI agents
  again (the secrets go into the vault, which agents never see).

- `--dry-run --host-key-policy off` keeps the policy for people and scripts;
  only an AI agent's preview connects with identity checks on.

- Read-only shell scripts with a `#!` line now work with `script
  --read-only` and `exec --read-only --stdin-file ... -- 'bash -s'`. Script
  arguments (`--arg`, `bash -s -- ARGS`) are refused under --read-only.

- `exec --read-only --stdin-file` treats input as data unless the command is
  a shell reading its input (`bash -s`). SQL sent to `psql` with `n > 5`
  works again; `\!` and `system` in that SQL are refused.

- `awk '/systemd/'`, `awk '/a|b/'`, `node -v`, `php -v`, `perl -v`, `bash
  --version` and `exec 2>&1` are read-only again.

- A streamed line that only mentions a private key header no longer holds
  `logs --follow` or `exec --stream` output for 256 KiB. After 16 KiB the
  output is released with the header hidden.

- Connecting through a jump host that never answers the channel open (or
  waits for a firewalled target) now fails with CONNECT_TIMEOUT after
  --connect-timeout, where it used to hang.

- A slow SSM or proxy-command start no longer makes the ssh-agent's
  signature time out into a false AUTH_FAILED.

- `host import` and `komando import` resolve each name once, in parallel and
  outside the inventory lock, when checking imported hosts against protected
  servers.

- `host trust --dry-run` says how the key would be fetched (directly,
  through a VPN, a proxy command or jump hosts).

- Re-running a secret rotation (`--old 'NAME=[hidden]' --new
  'NAME={{secret:VAULT}}'`) on a host where it is already done returns
  changed:false again, not NO_MATCH.

- Writes work again on SFTP servers that do not allow setting file modes,
  when their new files are no more open than requested; the result reports
  the mode the file got.

- A broken or empty state file now fails with `STATE_CORRUPT` and a hint on
  how to recover.

- Moving the vault key to or from the keychain waits for other komando
  processes changing the vault.

- `komando exec` (and `script`, `logs`, module commands) no longer reports a
  bare exit -1 when the connection breaks mid-command: the server's result
  has error code `CONNECTION_LOST` (exit 4), keeps the output received so
  far, and says the command may still be running or may have finished.

- Renaming a protected host or conn with `--rename` no longer skips the
  `--yes` check, and renaming a conn updates the tunnels that point to it.

- `secret rm` and `used_by` count `secret:` references in a server's
  environment variables.

- The approval code's key can no longer be set, moved, copied or removed
  with `komando secret` (`RESERVED_SECRET`).

- `komando test` results carry `host`, like `facts` and `exec`. `name` stays
  for existing scripts; use `host`.

## [0.2.0] - 2026-11-04

### Highlights

- **More than servers.** One list now holds databases (PostgreSQL, MySQL,
  SQLite), caches (Redis, Valkey), storage (S3, FTPS, SFTP),
  Kubernetes and Docker Swarm clusters and container registries, each with
  its own safe command: `db`, `cache`, `storage`, `cluster`, `registry`.
- **VPNs built in.** WireGuard, OpenVPN, AnyConnect and Tailscale connect by
  themselves when a target needs them, several at once, with nothing else
  to install.
- **Passwords from where you keep them.** komando's own vault, or HashiCorp
  Vault, AWS and Google secret managers, Bitwarden, KeePass and 1Password.
- **Secrets stay away from AI agents.** Passwords, keys and tokens show as
  `[hidden]`, and changes that need a person open a window on their screen.
- **Know what is running.** `komando status` and `komando prompt` show the
  VPNs, tunnels and jobs that are still up.

### Built in: secret managers and AWS logins (no vault, aws or gcloud CLI)

- `vault:` references read HashiCorp Vault or OpenBao themselves (KV v1 and
  v2, namespaces, `VAULT_CACERT`, `~/.vault-token`).
- `aws-sm:` reads AWS Secrets Manager, and `gcp-sm:` Google Secret Manager,
  with the credentials already on the computer.
- Conns with `aws_profile` (S3, ECR) read `~/.aws` themselves: SSO,
  assumed roles, temporary keys. New `komando login aws [--profile]` does
  the SSO sign-in that `aws sso login` did, into the same cache.
- New error codes `AWS_PROFILE_NOT_FOUND` and `AWS_FAILED`;
  `AWS_CLI_MISSING` no longer happens.

### Built in: OpenVPN and AnyConnect (no Docker, openvpn or openconnect)

- `openvpn` VPNs (and Pritunl profiles) run on komando's own OpenVPN client
  in user space: UDP and TCP, tls-auth and tls-crypt, AES-128/256-GCM,
  ChaCha20-Poly1305 and AES-CBC with HMAC, TLS key export or the older PRF,
  pushed options, keepalive and key renegotiation. No Docker container,
  no openvpn program, no admin rights; the computer's routes stay as they
  are. Profiles with options it does not support, or with compression
  (VORACLE), are refused at `vpn add` (`OVPN_UNSUPPORTED`). `--os-mode` is
  deprecated.
- `anyconnect` VPNs (Cisco AnyConnect, ocserv) run on komando's own client:
  the XML login (with one-time codes asked at `vpn up`) and the CSTP tunnel.
  The login happens at the terminal; the session's process gets only the
  session cookie.
- Experimental: komando's own Fortinet (form login with token codes, PPP
  over TLS), GlobalProtect (gateway login with challenges, GPST tunnel) and
  F5 BIG-IP (APM login, PPP over TLS) clients. They are used when
  openconnect is not installed, or with
  `KOMANDO_EXPERIMENTAL_VPN=fortinet,globalprotect,f5`; they have not yet
  been tried against the vendors' own servers.
- Experimental: komando's own Pulse Secure / Ivanti Connect Secure client
  (IF-T/TLS with EAP: realm choice, password, one-time codes asked at
  `vpn up`, the DSID session cookie, packets over TLS). Same rule: used
  when openconnect is not installed, or with `KOMANDO_EXPERIMENTAL_VPN=pulse`.
  Client certificates (EAP-TTLS) and Host Checker are refused with a clear
  error.
- AnyConnect uses DTLS (UDP) when the server offers it, with the key taken
  from the TLS connection (ocserv's PSK-NEGOTIATE); packets move back to
  TLS when UDP stops answering. Tested against ocserv.
- Hosts added with `--ssm` reach EC2 through komando's own AWS Session
  Manager client when the aws CLI or its session-manager-plugin is missing
  (or with `KOMANDO_EXPERIMENTAL=ssm`). KMS-encrypted sessions work: komando
  asks KMS for the session's data key and encrypts the stream with it.
- Every VPN session's local SOCKS port now needs a random per-session login
  (WireGuard and Tailscale too), so other users of the computer cannot use
  it.

### Built in: komando's own dump and restore

- `db dump` and `db restore` work without pg_dump, psql, mysqldump or mysql
  for direct conns, VPN conns and servers without those tools: komando
  writes and reads plain SQL itself (PostgreSQL: extensions, schemas, types,
  functions, sequences, tables with identity, generated columns and
  partitions, data via COPY, constraints, indexes, views, materialized
  views, triggers, row-level security, comments; MySQL: tables, data,
  views, triggers, routines). Objects it cannot write stop the dump by name
  (`DUMP_UNSUPPORTED`). Through a server that has the tools, they are still
  used. `tool` in the answer says which ran.

### Built in: komando's own kubectl and SQL shell

- `cluster run` no longer needs kubectl: komando understands the kubectl
  commands itself and prints what kubectl prints (server-side tables, wide,
  name, json, yaml, jsonpath, custom-columns, watch) for get, describe,
  logs, events, top, explain, version, api-resources, api-versions,
  cluster-info, auth, wait, rollout, apply, diff, create, replace, delete,
  patch, label, annotate, scale, set image, cordon, uncordon, drain, taint,
  run, exec, cp, debug, certificate and config. The read-only default and
  the risk checks are unchanged; port-forward and `exec -it` point at
  `cluster forward` and `cluster shell`.
- `db shell` is komando's own SQL shell for PostgreSQL, MySQL/MariaDB and
  SQLite (no psql, mysql or sqlite3): each statement gets db query's checks
  and is audited; `\d`, `\l`, `\dn`, `\du`, `\x`, `\G`, `\timing`, `\i`.
  `TOOL_MISSING` and `TLS_THROUGH_FORWARD` no longer happen for it.

### Built in: Kubernetes exec, shell and port-forward (no kubectl)

- `cluster exec` and `cluster forward` speak Kubernetes' streaming
  protocols over WebSocket themselves, and over SPDY on clusters before
  Kubernetes 1.30 (tried when the WebSocket is refused, as kubectl does;
  tested against Kubernetes 1.29). `cluster forward svc/NAME` maps the
  service port to the pod's target port (by number or name), like kubectl.
- New `cluster shell TARGET POD|TYPE/NAME [-- COMMAND]`: an interactive
  terminal in a pod for people, with the status lines and the protected
  question of `komando shell`.
- EKS and GKE tokens (`aws eks get-token`, `aws-iam-authenticator`,
  `gke-gcloud-auth-plugin` in a kubeconfig) are made by komando.
- `cluster exec --dry-run` and `cluster forward --dry-run` describe the
  call without "kubectl" in `would_run`, and add `pod`, `command`, `local`.

### Built in: Bitwarden, KeePass, 1Password Connect

- New `bw://ITEM/FIELD` for Bitwarden and Vaultwarden: komando logs in,
  syncs once per run and decrypts on this computer (personal, item-key and
  organization items), like Bitwarden's own clients.
- New `kdbx:FILE#GROUP/ENTRY[#FIELD]` for KeePass and KeePassXC files.
- `op://` reads a 1Password Connect server (`OP_CONNECT_HOST`,
  `OP_CONNECT_TOKEN`). Without Connect it still calls the `op` CLI, which is
  deprecated: komando ships only open-source parts, and the 1Password SDK's
  core is a prebuilt WebAssembly module.

### Built in: Tailscale and Headscale (no tailscaled)

- `tailscale` VPNs run inside komando with Tailscale's own Go library
  (`tsnet`), in user-space: no `tailscale` or `tailscaled` to install, no
  admin rights, the computer's network unchanged. Without an auth key,
  `komando vpn up` opens the login page once; the node then stays logged in.

### `komando prompt`: VPNs and tunnels in your shell prompt

- `komando prompt` prints `vpn:office tun:2`, or nothing, for zsh (also
  oh-my-zsh), bash or starship; the docs have the line to add. It only
  reads the state file: no network, no writes, no other programs, never an
  error, and it does not keep an idle VPN alive.

### `komando status`: what is still running

- One command lists what komando left running: VPN sessions (with when
  they close if unused), tunnels and jobs. It contacts nothing, so it is
  quick and works offline; `job list --refresh` still asks the servers
  whether a job runs.

### Where am I? Status lines for people

- `shell`, `db shell`, `cluster forward` and `logs --follow` (servers,
  Kubernetes, Swarm) print one line before they connect: what, where, as
  whom, the way there (`via vpn office → bastion1`) and `PROTECTED`
  (red; `NO_COLOR` turns colour off). `shell` and `db shell` also say how
  the session ended: `left web1 (exit 0, 12m)` or `connection to web1 lost`.
- A command that connects a VPN by itself says the VPN stays up, for how
  long, and how to stop it.
- Only for a person at a terminal, on stderr: agents, scripts, pipes and
  JSON output are unchanged. Names and addresses are printed without
  control characters, so they cannot rewrite the terminal.
- `db shell`'s line moved before connecting and uses the same format
  (was `komando: psql session on app-db (read-only)`).

### Safer `komando shell` (`ssh`, `connect`)

- `--dry-run` no longer opens a real shell: it shows the host, address,
  user, `--via` path and whether it is protected, and connects nothing.
- A protected server asks `[y/N]` before the shell opens, like `db shell`
  on a protected conn; `--yes` skips the question.
- AI agents are refused even when they run in a pseudo-terminal, and the
  error code is now `NEEDS_TERMINAL` (was `NOT_A_TTY`), the same as
  `db shell`. Like `db shell`, it also needs stderr to be a terminal.
### Clearer errors

- Every error now has a hint with the next step; a test keeps it that way.
- A file missing on this computer reads "./x does not exist on this
  computer" instead of Go's "stat ./x: no such file or directory".
- `cp ./missing web1:/tmp/` no longer suggests renaming the destination; that
  hint is only for a target komando does not know.
- A failure on one server no longer names it twice ("web1: … for web1").
- In text, an error from many servers shows its code too
  (`error [PARTIAL_FAILURE]: …`), like any other error.
- An unexpected file error is `FILE_ERROR`, not `REMOTE_ERROR`.

### Feels like the native tools (an end-to-end round over every command)

- `--dry-run` is never stopped by a safety rule: it shows the plan, and
  `meta.would_be_blocked` (in text: "without --dry-run this stops here")
  names the stop the real run would hit. Text dry runs start with
  "dry run: nothing was changed".
- A typo in a subcommand (`komando host lst`) fails with exit 2 and "did you
  mean list?" instead of printing help and exiting 0. Missing or extra
  arguments show the usage line and an example, and `-o text` now applies
  to these errors too.
- A person who answers no at a `[y/N]` prompt sees "cancelled … nothing was
  changed" instead of advice to re-run with `--yes`.
- A protected server or conn stays protected under another spelling of its
  address (upper case, a trailing dot).
- Text output shows server and database content safely: colours stay, but
  other terminal escape sequences (window title, clipboard writes) and
  control characters are shown as `\e` and `\xNN`.
- Many skipped targets print as one line; `KOMANDO_OUTPUT` with a wrong
  value names the variable; negative `-P`, `--timeout`, `--max-output` are
  refused.
- Masking for AI agents no longer hides settings and plain values
  (`max_tokens: 4096`, `password_min_length=12`, URLs, paths, YAML
  structure such as `secretKeyRef: {...}`), and a token never runs into the
  next line.
- cron: IDs are matched exactly (an ID with a dot could delete other
  entries), a newline in COMMAND is refused, schedules are checked here,
  `%` is escaped, crontab read errors are reported instead of shown as an
  empty list, `--user` uses sudo, `cron rm` says how many it removed.
- pkg: package names that start with `-` or hold patterns are refused
  (option injection), removing essential packages (openssh-server, sudo,
  systemd, libc ...) needs `--allow-dangerous`, `pkg installed` returns
  rows with installed true/false, `upgradable --refresh`, dnf/yum
  `upgradable` no longer fails when nothing is pending, and output and the
  audit log show `pkg install tree` instead of a long script.
- user: `user list` works on Debian and Alpine, `user unlock`, `--pubkey` is
  checked, `--shell` applies to existing users.
- net: `net check` fails (exit 5) on a closed port like `nc -z`, accepts
  `[IPv6]:port` and checks the port range; `net http` reports no answer as
  NO_RESPONSE and takes `--expect 200` or `2xx`; `net dns` fails with
  NXDOMAIN (exit 3) when a name does not resolve.
- The agent guard no longer blocks setting komando's variables, quoted
  heredocs, or `|` inside quotes; reading through them still is.
- Servers and files: `fs write`/`replace` follow symlinks and write the
  target (`--no-follow` refuses); `fs mv` never overwrites without
  `--overwrite`; diffs are real unified diffs; `--read-only` is checked
  (a command that writes is READ_ONLY_VIOLATION); remote `~` and `host:`
  mean the home folder like scp; `SRC/` copies the contents and re-runs
  never nest; symlinks that are skipped are listed; sync keeps modes and
  times, refuses a missing source, and never deletes when the source is
  empty; recursive downloads go on past unreadable files and report them;
  `download --sudo`; `script --arg` works for perl, python, ruby and node.
- Text output for people: each failed server shows `[FAILED exit=3]` with
  its own error and hint, stderr stays inside its server's block,
  truncated output says so, streamed output is not printed twice, and a
  `--timeout` that ends a follow (`logs -f`, `cluster logs -f`,
  `cluster run -- get -w`, `cluster forward`) is a normal end. Tables for
  `fs ls`, jobs, recipes, tunnels, keys, secrets, audit, config, db
  activity/locks/sizes, cache info, cluster ls and docker ps.
- Jobs: `job kill` records the kill and is safe to repeat, `job rm` refuses
  a running job (`--kill` first), `job wait --timeout`.
- Inventory: protected entries need `--yes` for any change, an alias of a
  protected server is protected too, hosts are validated when saved (port,
  user, --via, identity file), `host rm @group` / `conn rm 'tmp-*'` take
  selectors, `group rm GROUP` deletes a group, `config get`, `doctor`
  checks the inventory, audit records every inventory and settings change,
  `host ssh-command` prints commands that work through jump hosts, `import`
  vets proxy commands, an empty inventory says how to start, and "did you
  mean" everywhere.
- Policy: `rm -rf //`, `find / -delete`, `chmod -R ... /`, `iptables
  --flush` are caught; `grep mkfs notes` is not; `policy check` exits 6
  when blocked; `policy allow` explains built-in rules.
- Databases, caches, storage: dates and times print as psql/mysql do (no
  invented `Z`, MySQL zero dates kept); MariaDB `explain --analyze`;
  placeholder count checked before sending; `db query --csv/--tsv`; cache
  output reads like redis-cli and `cache info` gives a summary; downloads
  never write in a dry run; a key ending in `/` means into that folder;
  `--to DIR/` and `--to -`; folder markers are skipped; missing databases
  and folders exit 3; `db shell` explains how to install the client on
  this computer.
- Clusters and docker: Swarm output has the same shape as Kubernetes
  (`items`, `healthy`, `problems`); TYPE NAME and TYPE/NAME work in every
  verb; `-A`; rollouts that time out name the stuck pods and why; rollback
  skips the revision that failed; `apply` diffs Secrets without showing
  them and says created/configured/unchanged; `docker exec` passes words as
  given and keeps the exit code; `docker raw`/`compose` can no longer slip
  past the policy with a leading flag; a missing container exits 3.
- System modules and VPNs: hosts without systemd say NO_SYSTEMD, unknown
  units UNIT_NOT_FOUND; `svc restart --wait`; pkg install/rm report what
  changed and PACKAGE_NOT_FOUND; `pkg upgrade --dry-run` lists what would
  change; `net dns --type MX`; `net ports` with process and pid; `vpn
  status` dials SOCKS and system VPNs; `vpn up` checks a WireGuard tunnel
  really answers; `vpn edit`; VPN errors keep their own code through SSH.
- `facts` knows containers (init, virt, IPs without /len).
- `job wait` survives a dropped SSH connection (a NAT or firewall closing
  an idle one): it connects again and keeps waiting until the job ends or
  the timeout passes. Before, a 25-minute install's wait could stop after
  ~10 minutes with the job still running.
- The agent guard no longer mistakes `.../environments` for a process
  environment or a jq filter `.key` for a key file, and reads `\"` the way
  the shell does (fuzzing found a way around it).
- `cluster forward TARGET svc/x :80` picks any free local port, like kubectl.
- `vpn rm` takes several names, like `host rm`; `svc logs` as a user who may
  not read the system journal says to add `--sudo`.
- e2e: WireGuard end to end (a user-space peer), and svc/logs against the
  real systemctl and journalctl on a server with systemd as PID 1.
- e2e: AWS SSM end to end with a stand-in `aws` CLI (login, commands and
  files through `aws ssm start-session`), and an expired SSO login.
- `storage link --endpoint https://PUBLIC-NAME` signs a link for the address
  people use when komando reaches the storage through `--via`.
- `docker logs` shows times only with `--timestamps`, like docker and
  kubectl; a failing command on one server states its error once.
- e2e: every one of the 195 commands now runs at least once
  (`test/e2e/checks/`), and `E2E_HOME` keeps a lab inventory to try
  commands by hand.

### Secrets stay away from AI agents

- A person allows what an AI agent asks for: when Claude Code, Codex, Gemini
  CLI or Cursor adds `--yes`, `--allow-dangerous` or `--reveal`, komando
  shows the exact command in a window on the screen and runs it only after
  "Allow once". With no screen the agent is refused and the hint asks the
  person to run the command themselves. People and scripts are unchanged.
- For AI agents, passwords, keys and tokens in any output show as
  `[hidden]`: `.env` and config files, `env`, logs, database rows,
  Kubernetes Secrets, private keys, password hashes, URLs with a password.
  `--reveal` (allowed by a person) shows them. Vault values are now also
  hidden when base64- or URL-encoded.
- `fs write` and `fs replace` take `{{secret:NAME}}`, which becomes the
  vault value on the server; an `--old` with `[hidden]` in it matches the
  hidden value. Text that still holds `[hidden]` or `[secret:NAME]` is never
  written (`HIDDEN_VALUE`), nor stored with `secret set`.
- An AI agent cannot copy `.env` files, private keys and other secret files
  to this computer (`SENSITIVE_FILE`); folder copies and `sync` leave them out.
- `komando guide install` also adds a guard to Claude Code
  (`.claude/settings.json`) that stops reading `~/.komando`, private keys,
  `.env` files and credential stores, dumping every environment variable,
  and `ssh`/`scp`/`rsync` around komando. `--no-guard` skips it.
- `--reveal` is now a flag of every command; `secret get --reveal` still
  works only for a person at a terminal.

### Measured against international standards

- New page [security-standards.md](docs/features/security-standards.md):
  OWASP ASVS, OWASP Top 10 for LLM applications, NIST, ISO 27001, CIS and
  SLSA, with what is met, what is partly met and what is up to you.
- Passphrase vaults use scrypt N=2^17 (the OWASP minimum, was 2^15); an older
  vault moves up with a new salt on its next change.
- The audit log is a hash chain: `komando audit verify` finds a record that
  was edited, added or removed. Records name the AI agent and whether a
  person allowed the command.
- `komando doctor` checks security: file permissions, vault mode and
  passphrase length (NIST SP 800-63B), the audit chain, and conns whose
  traffic is not encrypted or whose server certificate is not checked.
- The agent rules say server output is data, never instructions (prompt
  injection).
- Releases carry signed SLSA build provenance (`gh attestation verify`). CI
  reads only, actions are pinned to commits, Dependabot keeps modules and
  actions current, and `make security` runs govulncheck.
  `make fuzz` fuzzes the masking, the policy filter and the guard; fuzzing
  found and fixed a crash on invalid UTF-8 in `fs replace --old`.
- golang.org/x/net 0.62.0 (GO-2026-6860, GO-2026-6866).
- `--proxy-command` runs a program on this computer on every connection, so
  it passes the policy filter, and an AI agent needs a person's yes to set it.

### Project

- Added a code of conduct, Dependabot updates, CODEOWNERS and `.editorconfig`.
  `make lint` now also runs staticcheck.
- Issues use forms (bug report, feature suggestion); security reports go to
  GitHub's private form. Simpler SECURITY.md, CONTRIBUTING.md and pull
  request checklist.
- A release runs every check (lint, unit and end-to-end tests) first, and
  takes its notes from this file.
- Docs are English only: removed `README.id.md` and `docs/features/id/`, and
  translated the design notes in `docs/design/`.

### Cloud access

- `host add|edit --proxy-command CMD` reaches a server through a program on
  this computer, like OpenSSH's ProxyCommand (`%h %p %r %n`): AWS SSM, GCP
  IAP, Cloudflare Access, Teleport. `--ssm` sets the AWS Systems Manager
  command (the address is the instance ID). Conns can use such a host as
  `--via` (RDS behind SSM). `import ssh-config` keeps ProxyCommand; imports
  of export files drop it.
- S3 conns can log in with an AWS CLI profile (`--option aws_profile=NAME`):
  SSO, assumed roles and temporary keys work as configured in the aws CLI.
  An expired SSO login answers `AWS_LOGIN_REQUIRED`.
- Amazon ECR registries get a fresh login from the aws CLI each time
  (logins last 12 hours), with the same `aws_profile` option.

### Day-to-day database care

- `db info` (version, uptime, size, connections, primary or replica and
  replay lag), `db activity [--all]`, `db locks` (who waits on whom),
  `db sizes` (databases, biggest tables and indexes) for PostgreSQL and
  MySQL/MariaDB; `db info` and `db sizes` for SQLite too.
- `db kill CONN PID` cancels a running query; `--session` ends the
  connection and needs `--allow-dangerous`. `--dry-run` shows the session.
- `db schema TABLE` shows foreign keys, checks and unique constraints.
- `db dump --format custom` writes a PostgreSQL archive; `db restore`
  recognises it and uses pg_restore (in one transaction). `--table` and
  `--schema-only` narrow a dump (PostgreSQL and MySQL).

### Bulk transfer

- `komando sync SRC DST` keeps a folder in step between this computer and
  servers (many at once) or storage, sending only new and changed files.
  `--exclude` skips names and paths; `--delete` removes what the source no
  longer has (needs `--allow-dangerous`); `--dry-run` lists every file.
- Storage: `upload -r` sends a folder, `download -r` fetches a prefix
  (existing local files stay unless `--overwrite`), `storage cat` reads a
  text object (`--head`, `--tail`), and `storage rm --prefix [--older-than
  30d]` cleans up old objects with a list first and a `--limit`.
- Uploads to servers stream the file: a backup of any size no longer has to
  fit in memory.
- `key revoke KEY TARGET` removes a public key from authorized_keys on many
  servers (`--user` for another account); revoking the key komando logs in
  with needs `--allow-dangerous`.

### Cluster deploy cycle

- `cluster deploy TARGET TYPE/NAME --image IMAGE [--wait]` puts out a new
  image on Kubernetes (deployment, statefulset, daemonset) or Swarm.
- `cluster status TARGET TYPE/NAME [--wait]` tells whether a rollout has
  finished, and waits for it (`ROLLOUT_FAILED`, `ROLLOUT_TIMEOUT`).
- `cluster history` lists a deployment's revisions with their images;
  `cluster rollback [--to N] [--wait]` goes back (Swarm: to the previous
  version).
- `cluster status TARGET` names every problem: CrashLoopBackOff and other
  container waits, deployments short of replicas, nodes not ready or under
  pressure (`healthy`, `problems`).
- `cluster describe` (state, conditions, containers or pods, events) and
  `cluster events [--warnings] [--for TYPE/NAME]`.
- `cluster ls -l SELECTOR`, and useful columns for ingresses, volume claims
  and volumes, jobs, cron jobs, autoscalers, config maps, events and
  namespaces.
- `cluster logs` reads a workload (`deploy/api`) or a label (`-l app=api`)
  across its pods, and follows with `-f` (Kubernetes and Swarm).
- `cluster exec` runs a command in a pod with the destructive-command
  check (`--read-only` for looks); `cluster forward` reaches a pod or
  service port on 127.0.0.1.

### Secrets stay out of sight; dry runs show the change

- Vault secrets are hidden in everything komando prints: a remote `.env`,
  a log line or `env` output shows `[secret:NAME]` instead of the value
  (values of 6 characters or more). `secret get --reveal` still shows it
  to a person.
- `--env KEY=secret:NAME` (exec, script, job, host `--env`) fills the value
  in from the vault on the way to the server, so an agent never handles it.
  Jobs get their exports from a private file that is deleted at start, not
  on a command line other users can see.
- `cluster apply --dry-run` shows each object's change (`create`, `change`
  or `none`) as a diff; Secret values stay hidden.
- `registry rm` lists every tag that goes with the image, in the dry run
  too.

### Promises kept

- The audit log fails closed: when it cannot be written, commands that
  could change something are refused (`AUDIT_UNAVAILABLE`); `doctor`
  checks it.
- `komando test` logs in to databases, caches and registries (and reports
  the server version) instead of only opening the port.
- Shell completion fills in server, conn and VPN names, `@groups`, `tag:`
  and saved names from the inventory.
- `komando schema` lists every selector (`kind:`, servers and conns) and
  every secret reference form.
- `import ssh-config` reports what it did not carry over (Match blocks,
  ProxyCommand, ...) instead of dropping it silently.
- `conn edit --option statement_timeout=10s` is used by `db query` and
  `db schema`.
- docs/design/vision.md shows the real status of every family.

### Safer file edits, downloads and tunnels

- `fs write|replace --validate CMD` checks the new file before it goes
  into place (`%s` is its path, e.g. `visudo -cf %s`, `sshd -t -f %s`). If
  the check fails the old file stays (`VALIDATION_FAILED`).
- `fs write --dry-run` shows the change as a diff.
- Downloads from servers never replace a file on this computer
  (`FILE_EXISTS`; `--overwrite` to replace), are written under a temporary
  name first, and refuse server paths that lead outside the destination.
- `tunnel start` asks for `--yes` before listening on anything but
  loopback (`OPEN_BIND`), as docs/design/network.md promised.

### Secrets and risk ratings

- `secret get --reveal` works only for a person at a terminal
  (`REVEAL_NEEDS_HUMAN` for agents and scripts); commands refer to secrets
  as `secret:NAME` instead.
- `secret rm` refuses a secret that a server, conn, key or VPN still uses
  (`SECRET_IN_USE`) and is written to the audit log.
- `host add|edit --password-ref/--sudo-ref` refuse a password typed where a
  reference belongs; before, it was stored and printed as plain text.
- `cluster run -- get secret ... -o yaml|json|jsonpath` needs
  `--allow-dangerous`: those formats print the secret values. The default
  table (names and key counts) stays a read.
- `docker raw` and `docker rm` are rated like `cluster run` on a Swarm
  manager: reads stay reads, and `rm`, `volume rm`, `prune`, `run`, `exec`
  need `--allow-dangerous`; so does `docker compose down -v/--rmi`.
- `cache run`: `GETDEL`, `RENAME` and `EXPIRE` to zero or the past delete
  keys, so they need `--allow-dangerous` like `DEL`. Read commands of
  RedisJSON, RediSearch, RedisTimeSeries and RedisBloom count as reads;
  `ACL LOG RESET` is a write.
- `db query`: passwords in `CREATE/ALTER USER|ROLE ... PASSWORD`,
  `IDENTIFIED BY` and `SET PASSWORD` are replaced with `'***'` in the audit
  log.
- `svc logs -f` and `docker logs -f` stream like `logs -f` (they waited for
  the timeout before).
- `registry ls` follows every page of the repository list (it read only the
  first).

### Safety fixes from a full review

- `--dry-run` now changes nothing on every command. Inventory commands
  (`host`, `conn`, `group`, `key`, `policy`, `config`, `recipe`) show the
  result without saving it, and `job kill`, `job rm`, `tunnel stop`,
  `key gen`, `key rm --delete-file`, `secret set` and `secret rm` only
  report what they would do. Before, some of them made the change while
  the answer and the audit log said `dry_run: true`.
- `.ovpn` profiles may not use `setenv opt ...`: OpenVPN runs the rest of
  that line as an option, which got past the allowlist (for example
  `setenv opt up /bin/sh`).
- The destructive-command policy checks each line of a script, so a
  `reboot` on its own line is caught. It also catches `/sbin/reboot`,
  `nohup reboot`, `rm -rf "/"`, `rm -rf -- /`, `rm --recursive --force /`,
  `rm -rf /etc/*` and `rm -rf /var/lib`.
- `--env` names must be shell variable names (`A-Z`, `0-9`, `_`). A name
  like `X;reboot;Y` used to run as a command, past the policy check.
- `svc restart|start|reload` quotes unit names in its `journalctl` call.
- The sudo password (`--sudo-ref`) is sent only when sudo asks for it.
  When sudo did not ask (NOPASSWD, or a recent sudo), the password went to
  the command's stdin, and `script` printed it in its error output.
- `db query` on MySQL: `--` starts a comment only before white space, as
  in MySQL itself, so `SELECT 1 --1, LOAD_FILE(...)` is no longer rated a
  read. `SET TRANSACTION`, `SET SESSION CHARACTERISTICS`,
  `transaction_read_only` and `SET autocommit` are refused, because they
  switch off or end the read-only transaction.
- `fs write|replace|upload --sudo` reads the existing file mode as root.
  Before, a file the SSH user could not see (`/etc/sudoers.d`, `/root`)
  became 0644. The staged copy in `/tmp` is now private (0600) and is
  removed when the connection fails.
- `fs write --append` refuses files over 64 MiB (FILE_TOO_LARGE) instead
  of cutting them to 64 MiB.

### VPN clients tested against real servers

- `make e2e-vpnclients` runs, all in Docker: ocserv (the AnyConnect
  protocol, the path the whole openconnect family uses) and Headscale with
  a Tailscale node. komando connects on demand, `--mfa` VPNs ask for a
  person, the Tailscale auth key is on no command line, and `vpn down`
  stops the clients.
- Session checks read the process name from /proc on Linux (small images
  have no `ps`, which made every session look dead).

### Subnet clashes

- `vpn up` for VPNs that change the computer's routes (OpenVPN
  `--os-mode`, system VPNs with `--service`) compares the routing table
  before and after and warns when the new routes overlap ones another
  interface already had (two networks claiming the same addresses). The
  other kinds never touch the computer's routes, so they cannot clash.

### Output contract 1

- Every JSON answer carries `meta.contract: 1`, and `komando schema` says
  `contract: 1`. Within a contract, field names, error codes and exit codes
  are only added, never renamed or removed (docs/design/ux.md, section 13).

### Agent skill

- `komando guide install` adds the komando skill (`SKILL.md`, the Agent
  Skills format) to `~/.claude/skills` (Claude Code) and `~/.agents/skills`
  (Codex, Cursor, Gemini CLI). Agents then reach for komando by themselves
  on server, database, cache and storage tasks. `--project` installs into
  the current folder; a changed file is kept as `SKILL.md.bak`. The same
  skill lives in `skills/komando/` for `npx skills add sgnd/komando`.

### Logs and files

- `komando logs ... --follow` (`-f`) keeps printing new lines until Ctrl-C;
  in a terminal they show as plain lines (marked by server when there are
  several), for agents as NDJSON events.
- `fs rm --recursive` needs `--allow-dangerous`, like `storage rm`.

### More import sources

- `komando import filezilla` (SFTP sites, passwords to the vault), `rclone`
  (SFTP remotes) and `dbeaver` (PostgreSQL, MySQL/MariaDB and SQLite
  connections).

### Fixes from the second review

- OpenVPN container: the entrypoint parsed again (a comment had swallowed
  `fi`; a test now checks every embedded script), the SOCKS port listens
  only on the container's network and needs a random per-connection
  login, the container runs with only the capabilities it needs and
  no-new-privileges, and config/login files are removed also when
  connecting fails. Tested against a real OpenVPN server
  (`make e2e-openvpn`).
- .ovpn inline blocks end the way OpenVPN ends them, so text after `</ca>`
  can no longer smuggle in directives; an unclosed block is refused.
- `cluster run` refuses flags that would send the conn's credentials to
  another cluster or identity (`--server`, `--kubeconfig`, `--token`,
  `--context`, `--as` ...) and user `--dry-run` values; `config view` (it
  can print credentials), `edit`, `apply --prune`, scaling to 0, role
  bindings, privileged `run`, and docker `exec`/`run`/`cp`, `--prune` and
  node drains are rated dangerous.
- VPN sessions: stops take the VPN's lock and check it is still the same
  session; sessions in use (a long `logs --follow`) stay fresh; containers
  are tracked by ID and labelled with their komando home; OS-mode OpenVPN
  writes its pid to /var/run and logs to syslog.
- Imports keep a secret reference only when that secret really does not
  exist (not when the vault is locked).

### Fixes from review

- `cluster run` must start with the command (a leading flag could hide a
  delete behind a "get"); kubectl and docker commands are rated by verb and
  subcommand (`auth reconcile`, `service rm`, `system prune` ...), the
  destructive-command policy sees them unquoted, and `--dry-run=server` goes
  right after the verb (never into `exec ... --`).
- `import komando` drops references to secrets or files that already exist
  on this computer and imports recipes as changes, so a file from someone
  else cannot send your passwords to their server or skip `--yes`.
- OpenVPN configs pass only an allowlist of client settings, with keys
  inline; nothing that runs programs or reads/writes files by path.
- KOMANDO_VAULT_PASS is removed from the environment at start, so kubectl,
  credential plugins, VPN clients and docker never inherit it.
- VPN sessions: a reused pid is never signalled, a failed stop (sudo) is
  reported and the session kept, idle sessions close at the next komando
  command, two commands cannot start the same VPN twice, config and login
  files are deleted once connected, the Tailscale auth key no longer shows
  in `ps`, and `vpn up/down/rm --dry-run` change nothing.
- `label:KEY` without a value picks targets that have the label (it picked
  those without it). kubectl secrets are hidden in the audit log;
  `cluster rm`/`registry rm --dry-run` report what would be blocked.

### OpenVPN without touching your computer's network

- `openvpn` (and `pritunl`) VPNs run in a small Docker container, built
  once from files inside komando, and are reached through a local SOCKS
  port, like the other VPN kinds: several at once, no sudo, no route
  changes. `--os-mode` keeps the old way (sudo, system routes).

### Password managers

- `--password-ref` also takes `op://...` (1Password), `vault:PATH#FIELD`
  (HashiCorp Vault), `aws-sm:NAME[#KEY]` (AWS Secrets Manager) and
  `gcp-sm:NAME[@PROJECT]` (Google Secret Manager). komando runs that tool's
  CLI when it needs the value and never stores it.
### Registry copy

- `komando registry copy SRC:IMAGE DST:[IMAGE]` copies an image between
  registries or repositories with every platform, keeping the digest.
  Layers already at the destination are skipped, layers within one registry
  are mounted, credentials never go to another host (e.g. an upload
  redirect), and only the destination is guarded (`--yes` when protected).

### Database shell

- `komando db shell CONN` opens psql, mysql or sqlite3 on this computer,
  connected through the conn's `--via` path, with the password in the
  client's environment. Read-only unless `--write` (PostgreSQL
  default_transaction_read_only, MySQL session READ ONLY, sqlite3
  -readonly); protected conns need `--yes` for `--write`. PostgreSQL keeps
  verifying the certificate's host name through the forward (PGHOSTADDR).
  For people only: without a terminal it refuses with NEEDS_TERMINAL.

### File servers in storage

- `komando storage` also works with FTPS (`ftps://`, TLS on control and data
  connections), SFTP (`sftp://`, for shell-less accounts; host keys checked
  like SSH hosts) and FTP (`ftp://`, refused without `?insecure=1` because
  it sends the password unencrypted). ls, download, upload and rm behave as
  for buckets; uploads go to a temporary name and are renamed into place,
  creating missing folders; keys cannot leave the conn's folder. All of it
  works through `--via` bastions and VPNs.

### Container registries

- `komando registry ls|inspect|rm` for Docker Hub, GHCR, GitLab, Harbor,
  ECR and registry:2 over the OCI Distribution API (basic and token auth),
  through `--via` paths and VPNs. `rm` deletes by digest and needs
  `--allow-dangerous`. `komando import docker` reads
  `~/.docker/config.json`, including credential helpers.

### Clusters

- `komando cluster` for Kubernetes (a k8s conn) and Docker Swarm (a manager
  server) with the same verbs: `status`, `ls`, `get` (Secret values hidden),
  `logs`, `apply` (server-side; `--dry-run` asks the server), `restart`,
  `scale` (to 0 needs `--allow-dangerous`), `rm` (needs `--allow-dangerous`)
  and `run` for any kubectl or docker command (read-only unless `--write`).
  The Kubernetes API is called directly (no client-go), through `--via`
  paths and VPNs; `cluster run` gives kubectl a private kubeconfig and a
  local tunnel. `komando import kubeconfig` adds one conn per context and
  keeps each context's credentials in the vault.

### VPNs

- `komando vpn add NAME wireguard|socks|system`. A VPN goes first in a
  `--via` path (`--via office,bastion`) for servers, conns and tunnels.
  WireGuard runs inside komando for that command only: several VPNs at
  once, overlapping subnets, no admin rights, no change to the computer's
  network. Keys go to the vault. `system` checks an OS VPN is connected
  (`VPN_DOWN` if not). `list`, `test`, targets (`kind:vpn`), groups and
  `export`/`import` include VPNs; a VPN in use cannot be removed.

### One command per job

- `--via` for servers too: `host add db1 ... --via bastion` (chains like
  `--via bastion,db1`). `--jump` still works; state files move `jump` to
  `via` on load. Conns take `--via` chains as well, and a host on anyone's
  `--via` path cannot be removed (`HOST_IN_USE`).
- `komando upload` and `komando download` work for servers (SFTP, many at
  once) and storage conns. `cp` and `storage upload/download` are the same
  commands spelled the old way.
- `komando recipe` is one list of built-in and saved commands. `ops` and
  `snippet` are other names for it; saved recipes cannot reuse built-in
  names, and marking an existing recipe read-only needs `--yes`.
- `host list/test` and `conn list/test` are `komando list/test` limited to
  servers or conns (new selector `kind:conn`); `svc logs` and `docker logs`
  are `komando logs` with `--unit` or `--container`.
- `komando import SOURCE` brings in `ssh-config`, `pgpass`, `mycnf`, `env`
  (.env URLs) and `komando` export files; passwords go to the vault, re-imports
  change nothing, and what cannot be imported is listed. `komando export`
  saves servers, conns and recipes (no passwords) to move computers.
- `komando tunnel start CONN` opens a local port to a conn through its
  `--via` path, for apps like TablePlus or psql (`--port` to choose it).

- `komando conn`: an inventory of databases (PostgreSQL, MySQL, SQLite) next
  to hosts. Add, edit, list, show, remove and test them; reach private ones
  through a host with `--via`. Passwords are refused in URLs and live in the
  vault. First step toward `komando db` (see `docs/design/resources-and-db.md`).
- Hosts and conns share one name space. Removing a host that a conn uses
  with `--via` is refused (`HOST_IN_USE`); renaming a host updates its conns.
- `komando audit --host` also matches conn names.
- `komando db query/schema/explain` for PostgreSQL and SQLite. Read-only by
  default (the database enforces it); `--write` to change data, `--write
  --dry-run` to try it and roll back. Destructive SQL (DROP, TRUNCATE,
  DELETE/UPDATE without WHERE, ...) needs `--allow-dangerous`; protected
  conns need `--yes`. Results are structured rows, safe for JSON.
- `komando storage` (alias `s3`) for S3 and S3-compatible storage (MinIO, R2,
  Wasabi, Spaces, B2, Garage): `ls`, `download` (to a file, never
  overwriting), `upload`, `rm` (exact keys only, needs `--allow-dangerous`),
  and `link` for temporary download links. Keys stay inside the conn's folder.
- `komando policy list` shows the SQL and Redis rules; `komando policy check
  --for KIND` rates a SQL query or Redis command.
- MySQL and MariaDB conns for `komando db`.
- `komando db dump` and `db restore`: backups to and from a file on this
  computer, using pg_dump/psql or mysqldump/mysql on the `--via` server (or
  locally). The password never appears on a command line; files are 0600 and
  never overwritten; restores need `--allow-dangerous` and refuse files with
  client commands (`\!`, `system`). MySQL `tls=` settings carry over.
- `komando config set audit_sql full|hash|off` controls how SQL text is kept
  in the audit log.
- `komando cache` for Redis/Valkey: `get` (any type, with TTL), `keys` (SCAN,
  never KEYS), `info`, `set`, `rm`, and `run` for any command, read-only
  unless `--write`. Deleting, flushing, blocking, scripts and
  server-reconfiguring commands need `--allow-dangerous`.

### Everything in one place

- Targets pick servers and conns together: `@prod` is everything in the
  `prod` group. Each command uses what it can work with and lists the rest
  in `meta.skipped`; when nothing fits, `NO_MATCHING_TARGETS` names the right
  command. New selector `kind:` (`kind:host`, `kind:db`, `kind:postgres`, ...).
  Typos get a "did you mean" hint. Unknown names now report
  `TARGET_NOT_FOUND` from commands that take both kinds.
- `komando list [TARGET]` and `komando test TARGET` show and check servers
  and conns together. `group add/rm` and `group list` include conns.

### Safety

- Snippets count as changes, so protected servers need `--yes`, unless saved
  with `--read-only`. Snippets saved before this release are treated as
  changes too. `snippet add --mutating` is no longer needed.
- `komando secret set NAME VALUE` is refused (`SECRET_IN_ARGS`): a value on
  the command line lands in shell history. Type it, pipe it, or use
  `--from-env`.
- Removing, replacing (`add --overwrite`) or unprotecting a protected server
  or conn needs `--yes`.
- Protection follows the address: an ad-hoc `user@address`, a second host
  name for the same address and port, or a second conn to the same database
  server, file or bucket counts as protected too.
- Turning off the audit log or `audit_sql`, loosening host key checks
  (setting, or `--host-key-policy off`), and removing a deny rule need `--yes`
  (`SAFETY_SETTING`). `config set audit` accepts only on/off values.
- A person typing in a terminal is asked instead of getting an error: `[y/N]`
  for protected targets, and typing the target's name for dangerous
  commands. Agents and scripts still need `--yes` / `--allow-dangerous`.
- Names ignore upper and lower case (`Web1` and `web1` cannot both exist),
  and `all` cannot be a name. `host import` skips invalid names.

### One way to say each thing

Old names keep working for one release and print a note.

- `rm` everywhere: `group remove`, `pkg remove` and `user delete` are now
  `rm`; every `rm` also accepts `remove`, `delete` and `del`.
- `--overwrite` replaces `--force` (`host add`, `conn add`, `snippet add`).
- `--var` replaces `--param` (`ops run`).
- `--target` replaces `--host` (`audit`, `job list`) and takes any target.
- `-n, --limit` replaces `--lines` (`logs`, `svc logs`, `docker logs`).
  `fs cat -n` (line numbers) is now `--line-numbers`; `job logs --limit`
  (bytes) is now `--max-bytes`.
- `-r` is the only short flag for `--recursive` (`fs ls` used `-R`).
- `logs --file` and `--grep` lose their short flags: `-g` now means only
  `--group`, and `-f` in `logs` is kept free for a future `--follow`.
- `pkg` and `user` accept `--no-sudo`.
- Usage lines say `TARGET` everywhere (was `HOST` in `fs`, `shell`, `tunnel`).

## [0.1.0] - 2026-11-02

First release.

- Server list with groups, tags, labels, jump hosts and `~/.ssh/config` import
- SSH keys and an encrypted password vault
- Run commands and scripts on many servers in parallel; long-running jobs
- Safe file reading and editing, upload and download
- Background tunnels (local, remote, SOCKS)
- Health checks and 39 ready-made recipes; services, logs, Docker, packages, network, users, cron
- Safety: dangerous-command filter, protected servers, dry run, server identity check, audit log
- Readable text in a terminal, JSON for AI agents

[Unreleased]: https://github.com/sgnd/komando/compare/v0.11.0...HEAD
[0.11.0]: https://github.com/sgnd/komando/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/sgnd/komando/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/sgnd/komando/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/sgnd/komando/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/sgnd/komando/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/sgnd/komando/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/sgnd/komando/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sgnd/komando/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/sgnd/komando/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/sgnd/komando/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sgnd/komando/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sgnd/komando/releases/tag/v0.1.0
