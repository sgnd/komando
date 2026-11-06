# Everything built in

Status: **approved, 2026-11-03**. The owner decided that every komando feature
must be built in (one binary, nothing else to install), that komando writes
its own implementation wherever no suitable library exists, and that komando
is fully open source. This document is the plan, stress-tested in
[Stress test](#stress-test).

## The rule

> A komando feature works with the komando binary alone. It does not need
> Docker or another program installed on this computer.

What the rule covers, and what it does not:

| | Covered? | Why |
|---|---|---|
| Programs komando starts for its own features (`openvpn`, `openconnect`, `tailscaled`, `kubectl`, `psql`, `pg_dump`, `aws`, `op`, ...) | **yes**: replace them | the rule |
| Docker for a feature | **yes**: replace it | the rule |
| Programs the operating system already has (`osascript`/`zenity` for the "Allow once" window, `scutil`/`nmcli`, `open`/`xdg-open` for a browser login, `sudo`) | no | nothing to install; they are part of the computer |
| Programs on a **server** that komando runs there (`pg_dump` on the database server through `--via`, `systemctl`, `docker` on a Swarm manager) | no | komando manages servers; what runs there is the server's own software |
| Programs the person wires in on purpose (`--proxy-command`, an `exec` plugin in their kubeconfig) | no, but the common ones get a built-in path | the person chose that program; komando must still work without it |

> **Own version** where nothing suitable exists: komando writes the client
> itself, as its own Go package.
>
> **Fully open source**: every line komando ships, including every library,
> has its source available under an open-source licence (MIT, BSD, Apache,
> MPL). No prebuilt blobs (for example a vendor's compiled WebAssembly
> core). komando may talk to proprietary services (AWS, a Fortinet
> appliance) through its own open code.

It must stay **pure Go** (`CGO_ENABLED=0`, vision rule 3). A library that
needs cgo (for example `misteriumnetwork/go-openvpn`, a binding to the C++
OpenVPN 3 library) does not qualify.

## Where komando uses other programs today

| Feature | Program today | Built-in path | Size of the work |
|---|---|---|---|
| Tailscale / Headscale VPN | `tailscaled` | `tailscale.com/tsnet` (official, pure Go, userspace) ✅ | S |
| Secrets `vault:` | `vault` CLI | HashiCorp Vault HTTP API (KV v1/v2): a small REST client  ✅ | S |
| Secrets `aws-sm:` | `aws` CLI | AWS SDK for Go v2 (`secretsmanager`)  ✅ | S |
| Secrets `gcp-sm:` | `gcloud` CLI | Secret Manager REST API with Google application-default credentials  ✅ | S |
| Secrets `op://` | `op` CLI | own client for the 1Password Connect REST API (documented, self-hosted). The 1Password Go SDK is **not** used: its core is a prebuilt WebAssembly module, not open source. A personal 1Password account has no documented open API, so `op://` without Connect is removed | M |
| New: `bw://` (Bitwarden, Vaultwarden) and `kdbx:` (KeePass, KeePassXC files) | — | own clients: Bitwarden's documented API, the open KDBX file format | M |
| Conns with `aws_profile` (RDS IAM tokens, S3 profiles) | `aws` CLI | AWS SDK for Go v2: profiles, SSO cache, assume-role  ✅ | S |
| EKS / GKE tokens in a kubeconfig | `aws eks get-token`, `gke-gcloud-auth-plugin` | built in for these two; other `exec` plugins still run as configured  ✅ | M |
| `cluster exec`, `cluster cp` | `kubectl` | Kubernetes exec over WebSocket (`v5.channel.k8s.io`), SPDY for older clusters  ✅ | M |
| `cluster forward`, `tunnel` to a pod | `kubectl` | port-forward over WebSocket where the cluster allows it, SPDY otherwise  ✅ | M |
| `cluster run` (any kubectl verb) | `kubectl` | own implementation of the kubectl verbs that work on any resource, through API discovery: get, describe, apply (server-side), delete, patch, label, annotate, explain, api-resources, auth can-i, top, wait, events, rollout. kubectl plugins (krew) are not covered ✅ | L |
| `db shell` | `psql`, `mysql`, `sqlite3` | komando's own SQL shell on the drivers it already has ✅ | L |
| `db dump` / `db restore` on this computer | `pg_dump`, `pg_restore`, `mysqldump`, `mysql` | built-in dump and restore (plain SQL); through `--via` the server's own tools stay the first choice ✅ | L (PostgreSQL), M (MySQL), S (SQLite) |
| AWS SSM as a proxy | `aws ssm start-session` + session-manager-plugin | SSM Session Manager protocol over WebSocket, via the AWS SDK, KMS-encrypted sessions included 🧪 | M |
| OpenVPN / Pritunl | Docker, or `openvpn` with sudo | komando's own OpenVPN client in Go, on the same userspace network stack WireGuard uses ✅ | XL |
| AnyConnect / ocserv | `openconnect` + `ocproxy` | own client (CSTP over TLS, DTLS) on the userspace stack ✅ | L |
| Fortinet SSL VPN | `openconnect` + `ocproxy` | own client (HTTPS login, PPP over TLS) 🧪 | L |
| GlobalProtect | `openconnect` + `ocproxy` | own client (HTTPS login, GPST over TLS, ESP over UDP) 🧪 | XL |
| F5 BIG-IP | `openconnect` + `ocproxy` | own client (HTTPS login, PPP over TLS) 🧪 | L |
| Pulse / Ivanti | `openconnect` + `ocproxy` | own client (IF-T/TLS, EAP) 🧪 | XL |
| Docker credential helpers (registry logins saved by `docker login`) | `docker-credential-*` | read the person's saved Docker logins directly where the store is a file; OS keychain stores stay through their helper (the keychain needs cgo or the OS tool) ✅ | S |
| Approval window, `system` VPN, route check | OS tools | no change: part of the OS | — |

S = days, M = a week or two, L = several weeks, XL = a month or more,
including tests against real servers. ✅ built in and tested against the
real server software; 🧪 built in, experimental (no vendor server to test
against yet).

## Phases

Easiest and most used first. Each phase is released on its own, and each
built-in path replaces the old one only when it passes the same e2e tests.

**Phase 1: open libraries that exist (S–M)**
Tailscale through `tsnet`; `vault:`, `aws-sm:`, `gcp-sm:` secrets; conns with
`aws_profile`. `op://` through 1Password Connect; new `bw://` and `kdbx:`.
The CLIs are no longer needed.

**Phase 2: Kubernetes without kubectl (L)**
`cluster exec`, `cluster cp`, `cluster forward` and pod tunnels speak the
Kubernetes protocols themselves. EKS and GKE tokens are made in komando.
`cluster run` becomes komando's own implementation of the generic kubectl
verbs, keeping its read-only default and risk checks.

**Phase 3: databases without client programs (L)**
`db shell` becomes komando's own SQL shell. `db dump` and `db restore` gain
a built-in engine: SQLite (the driver's backup API), MySQL (`SHOW CREATE`
plus rows), then PostgreSQL (DDL from the catalog, data with `COPY`).
Through `--via`, the server's `pg_dump`/`mysqldump` stays the default when it
is there, because it is the reference.

**Phase 4: OpenVPN in Go (XL)**
OpenVPN and Pritunl without Docker and without sudo, on the userspace
network stack. `--os-mode` and the Docker mode are removed one release
after the built-in client passes `make e2e-openvpn` and the extra cases
below.

**Phase 5: corporate VPNs in Go (XL, one protocol per release)**
In order of use: AnyConnect/ocserv, Fortinet, GlobalProtect, F5,
Pulse/Ivanti. `openconnect` stays the fallback for a protocol until its
built-in client is released.

**Phase 6: the rest (S–M)**
AWS SSM sessions as a built-in proxy; Docker credential files.

## Stress test

### The rule itself

| Case | Risk | Decision |
|---|---|---|
| Vision says komando does not replace `psql`/`kubectl` | The rule contradicts the vision | Vision updated: komando has its own version of what its features need from them, `cluster run` included |
| A library is open source but ships a compiled core (1Password SDK) | Not fully open source | Not used; komando writes its own client against a documented API, or drops the feature where no open API exists (personal 1Password accounts), and says so in the changelog |
| Removing `op://` for personal 1Password accounts | People who use it lose it | Announced one release ahead with the error hint naming the alternatives: 1Password Connect, `bw://`, `kdbx:`, or komando's own vault |
| A library needs cgo | Breaks the pure-Go build and cross-compiling | Not allowed. Checked by building with `CGO_ENABLED=0` for all four platforms in CI |
| The OS keychain (macOS Keychain, Secret Service) | Reading it from Go needs cgo or the OS tool | The OS tool counts as part of the OS; Docker logins in a keychain keep their helper |
| Browser logins (SAML/SSO for VPNs, AWS SSO, GKE) | Need a browser | komando opens the system browser (OS tool) and listens on 127.0.0.1 for the answer, like `gcloud` and `aws sso login` do. MFA stays with a person |
| A program on the server | Is `pg_dump` over `--via` "not built in"? | No: it runs on the server. komando must also work when the server has no `pg_dump` (Phase 3 engine) |

### Size and speed

| Case | Risk | Decision |
|---|---|---|
| Binary grows (tsnet, AWS SDK, Kubernetes protocols) | Bigger download | Accepted: no size limit (vision decision 4). Measured per phase and noted |
| Package start-up (`init`) of big SDKs | Every command gets slower, also `komando prompt` (30 ms today, 20 ms of that start-up) | Prefer small REST clients over full SDKs (GCP: REST, not gRPC; Vault: REST). Measure `GODEBUG=inittrace=1` per phase; budget: `komando prompt` stays under 50 ms |
| Memory of a userspace VPN | A long session holds a network stack | Same as WireGuard today; measured in the VPN e2e |

### Security

| Case | Risk | Decision |
|---|---|---|
| Writing VPN clients ourselves | Mistakes in a security protocol | Only Go's standard crypto and `x/crypto`; no own primitives. Every parser fuzzed. Each VPN client reviewed against the protocol spec and tested against the real server software; it is marked experimental until a security review |
| `ooni/minivpn` | Its README says it is not a secure, complete implementation | Not used as is. Its code may be read as a reference; komando's client is written and tested on its own |
| OpenVPN options (tls-auth, tls-crypt, tls-crypt-v2, ciphers, compression, renegotiation) | A profile that half works is worse than one that refuses | Unsupported options are refused at `vpn add` with the option's name, never ignored. `comp-lzo`/`compress` with real compression is refused (compression over encryption is unsafe, VORACLE) |
| Licences | openconnect is LGPL, openfortivpn GPLv3. komando is AGPL-3.0 and is also sold under a commercial license, so every line must be its own or under a permissive licence | No code is copied or translated from them. Clients are written from protocol documentation and packet captures. Libraries used must be MIT/BSD/ISC/Apache (MPL only unchanged, as a library) |
| Secret SDKs | A token in a log or error | Same rule as today: errors name the tool, never the value; tests check no secret reaches output or audit |

### Compatibility

| Case | Risk | Decision |
|---|---|---|
| Kubernetes before 1.30 | No WebSocket exec; port-forward over WebSocket is newer still | SPDY fallback for both, chosen by trying WebSocket first (what kubectl does) |
| `db shell` users expect psql commands | Muscle memory: `\d`, `\dt`, `\x`, `\timing`, `\G` | Common ones built in; an unknown `\` command says what to use instead. Never silently ignored |
| `db dump` fidelity | A PostgreSQL dump that misses an object loses data | The built-in dump lists what it covers; an object it cannot dump (for example a custom access method) stops the dump with its name. Round-trip e2e: dump, restore into a new database, compare with `pg_dump --schema-only` of both |
| Existing VPN sessions | A person upgrades while an OpenVPN container runs | `vpn down` keeps stopping old containers; new sessions use the built-in client |
| Pritunl | Adds its own login (PIN, OTP) on top of OpenVPN | Tested against a Pritunl server, not only plain OpenVPN |
| Each corporate VPN vendor changes things | A server update breaks the client | Each protocol has its own e2e (real server where one exists, openconnect's fake servers for the logins otherwise) and its own error codes, so a break is reported clearly |

### Testing

| Case | Risk | Decision |
|---|---|---|
| No open-source server for GlobalProtect, Fortinet, F5, Pulse | Cannot run a full e2e | Logins tested against fake servers written from the protocol (openconnect's test suite has such fakes; komando writes its own). The tunnel tested against a real appliance before a protocol leaves experimental |
| OpenVPN | — | `make e2e-openvpn` already runs a real OpenVPN server; extended with tls-crypt, tls-crypt-v2, UDP and TCP, and a Pritunl server |
| AnyConnect | — | `make e2e-vpnclients` runs ocserv with UDP: TLS, then DTLS |
| Kubernetes | — | `make e2e` runs k3s 1.33 (WebSocket) and k3s 1.29 (SPDY) |

## Where it stands (2026-11-03)

Built in and tested against the real server software (✅ in the table):
Vault/OpenBao, AWS Secrets Manager (moto), Bitwarden (Vaultwarden), KeePass
files, 1Password Connect (a fake server), AWS profiles and SSO login,
Tailscale (Headscale), Kubernetes exec/shell/port-forward and `cluster run`
(k3s), the SQL shell (PostgreSQL), dump and restore (PostgreSQL compared
with pg_dump, MariaDB), OpenVPN (OpenVPN 2.6: TCP, UDP, tls-auth, tls-crypt,
GCM, ChaCha20, CBC, PRF, user name and password, renegotiation),
AnyConnect over TLS and DTLS (ocserv; DTLS 1.2 with the PSK-NEGOTIATE key,
packets checked to go over UDP) and Kubernetes exec, terminal and
port-forward over SPDY (k3s 1.29, which refuses the WebSocket).

Built in, experimental (🧪): Fortinet, GlobalProtect, F5 and Pulse/Ivanti
(tested only against fake servers written from the protocols), AWS SSM
sessions (fake agent; the KMS data key against moto's KMS). Each is used only where nothing worked before (its old program is
missing) or when asked for with `KOMANDO_EXPERIMENTAL_VPN` /
`KOMANDO_EXPERIMENTAL`.

Still to do:

- Fortinet, GlobalProtect, F5, Pulse/Ivanti: try them against real
  appliances, then make them the default. Pulse's vendor parts (the
  Juniper EAP attributes and configuration layout) have no public
  specification, so its client is the most likely to need fixes there.
- Pulse/Ivanti: client certificate logins (EAP-TTLS) and Host Checker are
  refused with a clear error; ESP over UDP is not used (packets stay on
  TLS).
- AWS SSM: try a session, with and without KMS, against a real EC2
  instance, then make it the default.
- Pritunl: test against a Pritunl server (its PIN/OTP login); plain
  OpenVPN profiles from it already work.
- A Google login without gcloud (`komando login gcp`) needs an OAuth client
  registered for komando; until then `gcp-sm:` and GKE use a key file
  (`GOOGLE_APPLICATION_CREDENTIALS`) or run on Google Cloud.

## Decisions

1. **Own version** (2026-11-03): where no suitable open library exists,
   komando writes its own, `cluster run` included.
2. **Fully open source** (2026-11-03): no closed or prebuilt components.
   Hence no 1Password SDK; `op://` only through 1Password Connect.
