# Glossary

The words used in these docs, in plain language. [All docs](README.md)

| Word | Meaning |
|------|---------|
| AI agent | An AI that runs tools by itself to finish a task, such as Claude Code, Codex, Cursor or Gemini CLI. |
| Approval window | The window komando opens on your screen when an AI agent asks to run something that needs your yes. It runs only after you click **Allow once**. See [Safety](safety.md). |
| Audit log | komando's history of every action: who, what, where and the result. See it with `komando audit`. |
| Bastion / jump host | A gateway server you go through to reach private servers. In komando you write it as `--via bastion`. |
| Bucket | A folder-like container for files in object storage (S3, MinIO, R2). |
| Cache | A fast, temporary store an app uses to speed things up, such as Redis or Valkey. |
| CLI / terminal | A command-line interface: a window where you type commands instead of clicking. |
| Cluster | A group of machines that run containers together, managed by Kubernetes or Docker Swarm. |
| Conn | komando's word for anything you connect to that is not a server: a database, cache, queue, storage bucket, cluster or registry. Add one with `komando conn add`. |
| Container | An app packed with everything it needs, so it runs the same everywhere (Docker). |
| Container image | The packed app a container starts from, such as `nginx:1.27`. |
| Container registry | A server that stores container images: Docker Hub, GHCR, Harbor, ECR. |
| Database | Where an app keeps its data in tables: PostgreSQL, MySQL, SQLite. |
| Dry run | Running a command with `--dry-run`: it shows what would happen, without changing anything. |
| Exit code | A program's result number: 0 means success, anything else means a problem. See [Results and errors](output.md). |
| Fingerprint / host key | A server's ID card. If it changes, komando does not connect (`HOSTKEY_MISMATCH`). |
| Flag | An option added to a command, such as `--yes` or `--dry-run`. |
| Group | A named set of servers and conns, used as a target with `@name` (for example `@web`). |
| Host | The command word for a server: `komando host add`, `komando host edit`. Results name each target in a field called `host`. |
| Job | A long task left running on a server, started with `komando job start`. |
| JSON | Structured text that programs read easily. komando answers agents and scripts in JSON. |
| Message queue | A service that passes messages from one app to another: Kafka, RabbitMQ, NATS, Amazon SQS, Google Cloud Pub/Sub. See [Queues](queues.md). |
| Namespace | A named section inside a Kubernetes cluster, used to keep apps apart. |
| Object storage | A service that stores files as objects in buckets, reached over the internet: S3, MinIO, R2. |
| Pod | The smallest unit Kubernetes runs: one or more containers together. |
| Protected | A server, conn or VPN marked with `--protected`, for production. Before a change there, komando asks you; an AI agent or a script needs `--yes`, which a person approves. See [Safety](safety.md). |
| Recipe | A ready-made or saved command, run with `komando recipe run NAME TARGET`. |
| Secret | A password, token or key kept in komando's encrypted vault, referred to as `secret:NAME`. |
| Selector / target | What a command works on: a name, a group (`@web`), a tag (`tag:prod`), a glob (`web-*`), or `all`. See [Targets](targets.md). |
| Server | A computer (often in the cloud) that runs your apps. |
| Service | A background program, such as nginx, managed by systemd (or by Windows). Managed with `komando svc`. |
| SSH | The secure way to log in to and control a Linux server remotely. |
| SSH key | A pair of files that proves who you are; safer than a password. |
| sudo | Running a command as the administrator (root). |
| Tag / label | A word (`prod`) or `key=value` pair (`env=prod`) you attach to servers and conns, so you can pick them as a target. |
| Tunnel | Makes a remote service, such as a database, appear on your own computer. |
| Vault | komando's encrypted storage for passwords and other secrets. |
| VPN | A private network link to a company or cloud network. komando can connect several at once, by itself, when a target needs one. |
| Your list | Everything you added to komando: servers, conns and VPNs. See it with `komando list`. |
