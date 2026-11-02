# Extra coverage: areas not yet compared in the five gap reports

The five reports in this folder compare komando (`feat/v0.3`, commit 4784fc9)
with the tools in each field. This document looks for **what was
missed**: tools and daily devops work that do not appear in any
report.

How it works:

1. The candidate list comes from daily devops work (other host types,
   out-of-band, virtualization, cloud, DNS/CDN, certificates, deploy, backup,
   observability, disks, host security, identity, mail, CI, config management).
2. Each candidate is `grep`-ed in `docs/design/gap/*.md`. Those already present go
   into the [Already covered](#already-covered) list and are not repeated here.
3. Those not present are checked against the code (`internal/`), `komando schema --compact`,
   `komando recipe list` (39 recipes), and `--help`. Their status uses the same
   legend as the [README](README.md#how-to-read).

Priority is measured against [vision.md](../vision.md): P1 = security or
agent blocker, P2 = useful and fits the vision/candidates after v1.0,
P3 = rare, or `exec`/`script`/`job` is enough.


## Summary

| Status | Row count |
|---|---|
| PRESENT | 6 |
| PARTIAL | 3 |
| MISSING | 57 |
| NON-GOAL | 1 |
| **Total new rows** | **67** |

| Priority | Count |
|---|---|
| P1 | 1 |
| P2 | 14 |
| P3 | 45 |
| – (PRESENT/NON-GOAL) | 7 |

The six PRESENT rows (area T) are basic inventory commands that have no
row of their own in the other reports; they were found while matching 178
komando commands against all reports. Almost every row here can still be done through `exec`
or `job start` on the host; what is missing is a structured command, an honest
risk, and dry-run.

Most important finding: **remote command output is never filtered for
secrets** (row J1). The other reports only cover secrets in arguments, audit,
`cluster run`, `docker inspect`, and `compose config`. But `fs cat .env`,
`exec -- env`, and `logs` can all show passwords to the agent.

## A. Host types other than Linux

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| A1 | macOS host (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt | PARTIAL | `exec`/`fs`/`upload` work over SSH. `facts` falls back to `uname -s` (`ops.go:21`) and reads `/proc`, which does not exist, so memory, load, and uptime are empty. `svc` is systemd only, `pkg` has no `brew` | P3 — the host model in the vision = "SSH (Linux)"; rarely used as a server |
| A2 | FreeBSD/OpenBSD host (`service`, `sysrc`, `pkg`, `rc.conf`) | Ansible (`sysrc`, `pkgng`), Salt | PARTIAL | same as A1: `exec` works, system modules (`svc`, `pkg`, `facts`) assume Linux | P3 — few users (pfSense/OPNsense firewalls, see A3) |
| A3 | Routers, switches, firewalls: run `show ...` and get the result (Cisco IOS/NX-OS, Juniper Junos, MikroTik RouterOS, Arista EOS, FortiGate, pfSense) | netmiko, scrapli, Ansible `network_cli`, NAPALM | MISSING | `komando test` runs `id -un`, `hostname`, `sudo -n true` (`host.go:637`), which fail on a device CLI. `exec` without `--env`/`--dir`/`--sudo` (and without `--env` on the host) sends the command as is (`sshx/run.go:68-96` `BuildCommand`), so a single command might work, but it is not tested. Policy only knows Linux shell commands (`reload`, `write erase` are not recognized) | P2 — "universal client"; network devices are part of daily work on-prem and in offices |
| A4 | Back up network device config and diff between versions | Oxidized, RANCID, NAPALM `get_config` | MISSING | no code for network devices | P3 — needs A3 first |
| A5 | SNMP get/walk (interface status, UPS, printers, old devices) | `snmpwalk`, `snmpget` | MISSING | no `snmp` kind in `internal/driver` | P3 — continuous monitoring is a NON-GOAL; a one-off read is rarely needed |

## B. Out-of-band and virtualization

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| B1 | Status and power on/off/cycle of physical servers through the BMC (iDRAC, iLO, XClarity, Supermicro) | `ipmitool chassis power`, Redfish API, `racadm`, `hponcfg` | MISSING | no `ipmi`/`redfish` code in `internal/` | P2 — the only way in when SSH is dead (complements the P1 "controlled reboot" in the README); Redfish = HTTP API, fits the conn model; power off = destructive |
| B2 | Serial console / Serial-over-LAN | `ipmitool sol activate`, conserver, `screen /dev/ttyUSB0` | MISSING | interactive like `shell` (for humans only) | P3 |
| B3 | Proxmox VE: list VMs/LXC, start/stop/shutdown, snapshot and rollback | `pvesh`, `qm`, `pct`, proxmoxer, Terraform provider | MISSING | no `proxmox` kind; only through `exec -- qm ...` on a Proxmox node | P2 — very common on-prem/in small businesses; REST API + token fits the family contract; snapshot before risky changes |
| B4 | libvirt/KVM: `virsh list/start/shutdown/snapshot-create` | `virsh`, `virt-manager` | MISSING | through `exec -- virsh ...` | P3 |
| B5 | LXD/Incus: containers and VMs | `lxc`, `incus` | MISSING | through `exec` | P3 |
| B6 | VMware vSphere: list VMs, power, snapshot | `govc`, PowerCLI | MISSING | no code | P3 — needs vCenter SOAP/REST; binary size |

## C. Cloud CLI as a client (beyond dynamic inventory)

Dynamic inventory from EC2/GCP/DO/Hetzner is already in the report
[ssh-files-system.md](ssh-files-system.md) §4 and
[vpn-secrets-platform.md](vpn-secrets-platform.md) C6. The rows below are
other operations used day to day.

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| C1 | Status, start, stop, reboot of cloud VMs | `aws ec2 start-instances/reboot-instances`, `gcloud compute instances`, `az vm`, `doctl compute droplet-action`, `hcloud server` | MISSING | no `ec2`/`hcloud`/`doctl` code in `internal/` | P2 — vision candidate "cloud VMs"; recovery path when SSH is locked out (not provisioning) |
| C2 | Snapshot a VM disk/volume before a risky change | `aws ec2 create-snapshot`, `hcloud server create-image`, `doctl compute droplet-action snapshot`, `gcloud compute disks snapshot` | MISSING | none | P2 — a way back for patching and OS upgrades; fits the "dry-run and rollback" rule |
| C3 | VM console/serial output when SSH is dead | `aws ec2 get-console-output`, `gcloud compute instances get-serial-port-output`, `hcloud server request-console` | MISSING | none | P3 |
| C4 | Managed container services as a `cluster` kind (ECS, Cloud Run, Azure Container Apps, Fly Machines) | `aws ecs`, `gcloud run`, `az containerapp`, `flyctl` | MISSING | `cluster` is k8s and swarm only (vision: "later: nomad") | P3 |
| C5 | Managed DB operations: snapshot, reboot, failover, view parameters | `aws rds`, `gcloud sql`, `az postgres` | MISSING | DB provisioning is already a NON-GOAL ([database-cache.md](database-cache.md):362); snapshot/failover are operations, not yet covered | P3 |
| C6 | Cloud logs: tail and search (CloudWatch Logs, Cloud Logging, Azure Monitor) | `aws logs tail`, `gcloud logging read`, `az monitor log-analytics query` | MISSING | none | P3 — API per cloud, binary size |
| C7 | Serverless functions: invoke, view logs/versions | `aws lambda`, `gcloud functions` | MISSING | none | P3 |

## D. DNS, CDN, load balancers, web servers

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| D1 | Manage DNS records at the provider (list/set/rm A, CNAME, TXT) with dry-run | dnscontrol, octoDNS, `flarectl`/Cloudflare API, `aws route53`, `doctl compute domain` | MISSING | no DNS kind; `net dns` only resolves from the server | P2 — vision candidate "DNS (Cloudflare, Route 53)"; small HTTP API; clear risk (`rm` = destructive) |
| D2 | Purge CDN cache, maintenance mode, block IPs in the WAF | Cloudflare API, `aws cloudfront create-invalidation`, `fastly purge` | MISSING | none | P3 |
| D3 | Take a node out of / put it back into the load balancer during maintenance | HAProxy runtime API (`disable server`), `aws elbv2 deregister-targets`, Traefik/nginx upstream | MISSING | through `exec` + `socat` to the HAProxy socket | P3 — supports rolling updates (`serial`, P2 in [ssh-files-system.md](ssh-files-system.md) §5) |
| D4 | Enable/disable a vhost + test + reload in one step | `a2ensite`/`a2dissite`, `sites-enabled` symlink, Caddy admin API `/load` | MISSING | recipes `nginx-test`, `nginx-sites`, `apache-test` only read; Caddy has no recipe | P3 |

## E. Certificates and PKI

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| E1 | Scan certificate files on servers (`/etc/ssl`, `/etc/letsencrypt`, `/etc/nginx`, keystores) and their remaining days, across a fleet | `openssl x509 -enddate`, ssl-cert-check, `certbot certificates` | PARTIAL | recipe `certbot-certs` covers certbot certificates only; `cert-expiry` works over the network (s_client), not from files; internal certs (mTLS, DB, kubelet) are not visible | P2 — expired certificates are a common cause of outages; vision candidate "certificates/ACME" |
| E2 | Issue/renew certificates from an internal CA | `step ca certificate`, cfssl, Vault PKI | MISSING | none | P3 |
| E3 | Check cert/key/CSR files: key matches cert, full chain, SAN | `openssl`, `step certificate inspect` | MISSING | through `exec -- openssl ...` | P3 |

## F. App deploy to VMs and app runtimes

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| F1 | Release deploy: release folder + `current` symlink + rollback to the previous release | Capistrano, Deployer (PHP), Ansistrano | MISSING | the `deploy-app` example in the `recipe add` help is only `git pull` + restart (`ops.go:265`); not a built-in recipe | P3 — close to a playbook (NON-GOAL); `script` is enough |
| F2 | Zero-downtime container deploy to a VM without an orchestrator | Kamal, docker-rollout | MISSING | only `docker compose up -d` | P3 |
| F3 | Self-hosted PaaS: list apps, logs, restart, config | `dokku`, Coolify CLI, CapRover | MISSING | through `exec -- dokku ...` | P3 |
| F4 | Non-systemd process managers: status, restart, logs (pm2, Supervisor, Laravel queue workers) | `pm2 list/restart/logs`, `supervisorctl status/restart` | MISSING | `svc` is systemd only; no pm2/supervisor recipe | P2 — very common on Node/PHP/Python VPSes; restarting workers after a deploy is daily work |
| F5 | App framework commands (`artisan`, `manage.py`, `rails runner`), PHP-FPM status/reload | artisan, Django, Rails, `php-fpm -t` | MISSING | through `exec`/`recipe add` | P3 |

## G. Server file backup

`db dump` already exists for databases, and `storage` for uploading files. What
is missing: backup of server folders.

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| G1 | Back up server folders to storage (snapshots, dedup, encryption, retention) | restic, borg, kopia, duplicity | MISSING | `download -r` is only server → laptop (`transfer.go:106-110`); storage rejects `-r` and accepts one file per command (`transfer.go:62-66`, `:96-99`); no direct server → storage path, snapshots, dedup, or retention | P2 — vision goal 2 "back up and restore" for every family; hosts do not have it yet |
| G2 | View snapshots, check the age of the last backup, restore one file | `restic snapshots/restore`, `borg list/extract` | MISSING | through `exec` if restic/borg is installed | P3 |

## H. Observability (one-off, not monitoring)

Prometheus queries are already covered in [database-cache.md](database-cache.md):349,
Elasticsearch/OpenSearch in §20 of the same report.

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| H1 | Silence alerts during maintenance, view active alerts | `amtool silence add/alert query`, Grafana API | MISSING | none | P3 — a one-off command, does not break the monitoring NON-GOAL |
| H2 | Query centralized logs (Loki LogQL, Graylog) | `logcli query`, Graylog API | MISSING | none | P3 |
| H3 | Ack incidents / view app errors | PagerDuty CLI, Sentry CLI | MISSING | none | P3 — outside the vision's "devops client" |

## I. Disks, RAID, and filesystems

The full list of mounts and disks in `facts` is already covered
([ssh-files-system.md](ssh-files-system.md) §16), and so are mount/fstab and
swap (§18).

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| I1 | SMART and NVMe disk health | `smartctl -H -A`, `nvme smart-log` | MISSING | no `smartctl` recipe or code | P2 — a broken disk = data loss; a one-off read command, easy to make a recipe |
| I2 | Software RAID and pool status, detect degraded | `mdadm --detail`, `/proc/mdstat`, `zpool status`, `btrfs device stats` | MISSING | none | P2 — same as I1 |
| I3 | Grow the disk after the cloud volume was enlarged | `growpart`, `pvresize`, `lvextend -r`, `resize2fs`, `xfs_growfs` | MISSING | through `exec`; the agent has to guess the step order and the filesystem type | P2 — "disk full" is a daily incident; the wrong order can cause damage |
| I4 | LVM/ZFS/Btrfs snapshot before an upgrade, and rollback | `lvcreate -s`, `zfs snapshot/rollback`, snapper | MISSING | none | P3 |
| I5 | Stuck (stale) NFS/SMB mounts | `findmnt`, `showmount`, `umount -l` | MISSING | recipes `disk`, `inodes`, `health` use `df` over all mounts (without `-l`/`-x nfs`), so they can hang on a stuck NFS mount (`facts` only `df /`); the only thing present is a per-host `--timeout` for the whole command (default 5m), not a per-step limit, and there is no recipe to detect stuck mounts | P3 |

## J. Host security and compliance

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| J1 | Redact secrets in the **output** of remote commands (`fs cat .env`, `exec -- env`, `logs`, `docker exec ... env`, app config files) | gitleaks/trufflehog rules, Teleport (session redaction) | MISSING | redaction exists only in `cluster get` (`cluster.go:327`) and in `cluster run` audit arguments (`redactArgs`, `cluster.go:1110`). Output of `exec`/`fs cat`/`logs`/`storage` is sent to the agent in full | **P1** — vision: "passwords are never visible to the AI"; agents routinely read `.env`, `wp-config.php`, `application.yml` |
| J2 | fail2ban/CrowdSec: jail status, blocked IPs, unban | `fail2ban-client status/set ... unbanip`, `cscli decisions` | MISSING | no recipe | P2 — admin/CI IPs are often blocked; parallel `exec` through one bastion can also trigger a ban (see O1) |
| J3 | One-off hardening/compliance audit (CIS) | Lynis, OpenSCAP `oscap`, kube-bench | MISSING | only recipes `sshd-config`, `sudoers`, `auth-failures` | P3 — `job start -- lynis audit system` is already enough |
| J4 | Read auditd logs | `ausearch`, `aureport` | MISSING | through `exec`/`logs --file /var/log/audit/audit.log` | P3 |
| J5 | File integrity, rootkits, malware | AIDE, rkhunter, debsums, ClamAV | MISSING | none | P3 |
| J6 | Scan for leaked secrets on servers (`.git` in the webroot, keys in public folders) | gitleaks, trufflehog `filesystem` | MISSING | none | P3 |
| J7 | Kernel live patch status | `canonical-livepatch status`, `kpatch list` | MISSING | `facts` only `reboot_required` | P3 |

## K. Identity and directories

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| K1 | Search users/groups in LDAP/Active Directory | `ldapsearch`, `adcli`, `realm list` | MISSING | no `ldap` kind | P3 |
| K2 | Domain-joined hosts (SSSD/FreeIPA): check a directory user can log in, clear the cache | `id`, `getent passwd`, `sss_cache -E`, `ipa` | MISSING | no command for a single directory user or the SSSD cache; through `exec -- id USER`. `user list` uses `getent passwd` (`modules.go:615`) through NSS, so directory users only show up if SSSD is set to `enumerate=true` (the default is off); no check whether a directory user can log in or whether the SSSD cache is healthy | P3 |

## L. Mail

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| L1 | Mail queue: view, flush, delete | `mailq`, `postqueue -p/-f`, `postsuper -d`, `exim -bp` | MISSING | no recipe | P3 |
| L2 | Test SMTP sending from the server (auth, STARTTLS) | swaks, `openssl s_client -starttls smtp` | MISSING | `net check` is TCP only | P3 |

## M. Container runtime on nodes

Podman is already covered in [cluster-docker.md](cluster-docker.md):70.

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| M1 | Containers on a k8s node when the API/kubelet has problems (containerd/CRI-O) | `crictl ps/logs/images`, `nerdctl`, `ctr` | MISSING | the `docker` command is hardcoded; the `komando ctr` alias (`modules.go:288`) is an alias for `docker`, not containerd `ctr`; through `exec -- crictl ...` | P3 |

## N. CI/CD, config management, IaC

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| N1 | Trigger and watch pipelines | `gh workflow run/watch`, `glab ci run`, Jenkins CLI | MISSING | `gh workflow` is only mentioned as a scheduling comparison ([vpn-secrets-platform.md](vpn-secrets-platform.md) C7) | P3 — not a family in the vision; `gh`/`glab` are already good |
| N2 | Run a config management agent once (check mode) and view the last run result | `puppet agent -t --noop`, `chef-client --why-run`, `salt-call state.apply test=True` | MISSING | through `exec`; Ansible playbooks themselves are already a NON-GOAL | P3 |
| N3 | Read Terraform/Pulumi output/state as an inventory source | `terraform output -json`, `pulumi stack output` | MISSING | `komando import` has no `terraform`/`pulumi` source (`importSources`, `importer.go:48`) | P3 — goal 4 (migration); IaC itself is a NON-GOAL (N4) |
| N4 | Declarative infrastructure: plan/apply/destroy and state (VMs, networks, DNS, managed DBs) | Terraform, OpenTofu, Pulumi | NON-GOAL | vision.md "Non-goals": "Infrastructure as Code, cloud provisioning, or GitOps"; no IaC code in `internal/`. Use the original tool; komando only operates its results | – |

## O. Fleet reliability

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| O1 | One bastion connection shared by all hosts in **one** command | OpenSSH ControlMaster, Ansible (persistent connections), pssh | MISSING | `sshx.Dial` (`sshx/client.go:56`) builds a new `--via` chain per host. `exec @prod -P 10` through one bastion opens 10 logins to the bastion at once, close to the default `MaxStartups` limit (10:30:100), and can trigger fail2ban. Different from the NON-GOAL row "multiplexing across commands" ([ssh-files-system.md](ssh-files-system.md):53) | P2 — a fleet behind a bastion is the main pattern; random failures are hard to explain to an agent |

## S. Advanced system diagnostics

| # | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| S1 | Core dumps and crashes | `coredumpctl list/info`, kdump | MISSING | only the `oom` recipe | P3 |
| S2 | Diagnostic bundle for vendors | `sosreport`, `supportconfig` | MISSING | through `job start` + `download` | P3 |
| S3 | Process tracing/profiling | `strace`, `perf`, `py-spy` | MISSING | through `exec`/`job` | P3 |
| S4 | Change server network config with automatic rollback | `netplan try`, `nmcli`, Ansible `nmcli` | MISSING | `facts` reads IPs; routes partly in §17 of the SSH report. A wrong change = the server is cut off | P3 |

## T. Inventory lifecycle without its own row

Found while matching 178 komando commands against the five reports: these
commands are only mentioned in passing, not yet compared as a capability of their own.

| ID | Capability | Comparison tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|---|
| T1 | List supported resource kinds with example URLs | `rclone help backends`, usql `\drivers` | PRESENT | `conn kinds` (`conn.go:325`) | – |
| T2 | View and remove conns (secret stays a ref, protected conns are guarded) | DBeaver, `rclone config show/delete` | PRESENT | `conn show` (`connShowCmd`, `conn.go:268`), `conn rm` rejects protected conns through `guardProtection` (`conn.go`, `connRmCmd`) | – |
| T3 | Removing a host that is still a `--via` path for another host/conn is rejected | Termius (no check), Ansible (no check) | PRESENT | `host rm` → `HOST_IN_USE` (`hostRmCmd`, `viaChain`) | – |
| T4 | View and remove VPNs; removal is rejected if still used by `--via` | `nmcli con show/delete`, `tailscale logout` | PRESENT | `vpn show` (`vpnShowCmd`, `vpn.go:331`), `vpn rm` → `VPN_IN_USE` (`vpn.go:366`); the key stays in the vault until `secret rm` (on purpose) | – |
| T5 | Remove your own recipes; built-in recipes cannot be removed | Termius snippets, Fabric | PRESENT | `recipe rm` rejects built-in recipes (`builtinRecipe`, `ops.go`) | – |
| T6 | Per-family aliases: `host list`, `conn list`, `vpn list`, `host test`, `conn test`, `vpn test`, `svc logs`, `docker logs`, `storage download`, `storage upload` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` | PRESENT | all call the same `list`/`test`/`logs`/`download`/`upload` (one need, one command; ux.md §11). Note: the `docker logs -f` alias (`modules.go:323`) and `svc logs -f` (`modules.go:158`) use `runOne`, not `followLogs` like `logs` (`modules.go:273`), so output is held until the timeout (bug; the README only notes `docker logs`) | – |

## Already covered

Areas that were checked and turned out to be covered already, so they are not repeated. Each area
(27 rows) was matched to a table row in the referenced report section: that
row must compare the same capability with the named tools.
25 areas matched. Two were fixed: image build (the `storage-registry.md` §I reference
turned out not to be a build row, removed) and Terraform/IaC (no
comparison row, only README §5 prose; now row N4).

| Area | Report |
|---|---|
| Windows hosts, WinRM, PowerShell | [ssh-files-system.md](ssh-files-system.md) §1 |
| Windows build, Homebrew, MCP server | [vpn-secrets-platform.md](vpn-secrets-platform.md) C5, C8 |
| Dynamic cloud inventory (EC2, GCP, DO, Hetzner) | [ssh-files-system.md](ssh-files-system.md) §4, [vpn-secrets-platform.md](vpn-secrets-platform.md) C6 |
| AWS SSM, GCP IAP, cloudflared, `ProxyCommand` | [vpn-secrets-platform.md](vpn-secrets-platform.md) A7, [ssh-files-system.md](ssh-files-system.md) §1 |
| RDS/Cloud SQL IAM login, managed DB provisioning (NON-GOAL) | [database-cache.md](database-cache.md) §1, §20 |
| Nomad, Podman | [cluster-docker.md](cluster-docker.md) §1 |
| Image build (`docker build`, buildx) | [cluster-docker.md](cluster-docker.md) §10 (row "Build image on host"). The old reference to [storage-registry.md](storage-registry.md) §I was removed: §I only compares copy/retag/index with `buildx imagetools`, not builds |
| systemd timers, journald, `logs --follow`, lnav/multitail, logrotate | [ssh-files-system.md](ssh-files-system.md) §11, §14, §15 |
| certbot/ACME, TLS check from the network (`openssl s_client`) | [ssh-files-system.md](ssh-files-system.md) §17, §18 |
| DNS resolve from the server (`dig`, record types) | [ssh-files-system.md](ssh-files-system.md) §17 |
| Git pull on the server | [ssh-files-system.md](ssh-files-system.md) §18 |
| rclone, SMB/CIFS as storage | [storage-registry.md](storage-registry.md) §F, §G |
| Prometheus/promtool, InfluxDB | [database-cache.md](database-cache.md) §20 |
| Kafka, RabbitMQ, NATS, Elasticsearch/OpenSearch, etcd, Consul, MongoDB, Memcached | [database-cache.md](database-cache.md) §19, §20 |
| Terraform/IaC, Ansible playbooks, GitOps, helm install (NON-GOAL) | [ssh-files-system.md](ssh-files-system.md) §5 (playbooks), [cluster-docker.md](cluster-docker.md) §5 (`apply --prune`, GitOps) and §8 (helm install/upgrade); Terraform/IaC: row N4 above (previously only prose in [README.md](README.md) §5, with no comparison row); reading Terraform state: row N3 |
| Ansible Vault, vault rekey | [vpn-secrets-platform.md](vpn-secrets-platform.md) B1 |
| Search files/content across a fleet (`find`, `grep -r`) | [ssh-files-system.md](ssh-files-system.md) §10 |
| Processes: structured list, kill, lsof | [ssh-files-system.md](ssh-files-system.md) §16 |
| nginx/apache test before reload, file validation | [ssh-files-system.md](ssh-files-system.md) §10, §11 |
| NTP/chrony, timezone, locale, swap, hostname, sysctl, mount/fstab, kernel modules | [ssh-files-system.md](ssh-files-system.md) §18 |
| SELinux/AppArmor, firewall, sshd hardening | [ssh-files-system.md](ssh-files-system.md) §13, §18 |
| tcpdump, iperf3, nmap, mtr | [ssh-files-system.md](ssh-files-system.md) §17 |
| Send audit to SIEM/syslog (auditd as comparison) | [ssh-files-system.md](ssh-files-system.md) §20, [vpn-secrets-platform.md](vpn-secrets-platform.md) C7 |
| Slack/webhook notifications | [vpn-secrets-platform.md](vpn-secrets-platform.md) C7 |
| Non-systemd init (OpenRC, sysvinit) | [ssh-files-system.md](ssh-files-system.md) §11 |
| Connection multiplexing across commands (NON-GOAL) | [ssh-files-system.md](ssh-files-system.md) §1 |
| Juniper Network Connect as a VPN | [vpn-secrets-platform.md](vpn-secrets-platform.md) A4 |

## Per-row verification

Each row was re-checked by **reading** the code that should
run that capability (not just grepping keywords): `internal/cli/`
(`modules.go` for `svc`/`pkg`/`user`/`logs`/`docker`/`net`, `ops.go`
for `facts` and the 39 recipes, `host.go`, `exec.go`, `common.go`,
`transfer.go`, `cluster.go`, `conn.go`, `vpn.go`, `importer.go`),
`internal/sshx`, `internal/policy` and `internal/driver`. The binary's output
was checked with `komando recipe list -o json`, `komando conn kinds`,
`komando schema --compact` and `--help` (without connecting to any server).
Indirect support (`exec`, `job`, recipes, aliases) was also assessed; per the
README legend, "can be done through `exec`" is still MISSING.

Facts used repeatedly:
`svc` always calls `systemctl` (`modules.go:82`, `:100`, `:121`);
`pkg` is only apt/dnf/yum/apk/zypper/pacman (`modules.go:415-420`);
the only known kinds are ftp, ftps, k8s, mysql, postgres, redis, registry,
s3, sftp, sqlite (`conn kinds`); the only `import` sources are ssh-config, pgpass,
mycnf, env, kubeconfig, docker, filezilla, rclone, dbeaver, komando
(`importer.go:48-58`); the 39 built-in recipes are in `ops.go:106-144`. "No
recipe" means it is not in that list of 39.

| # | ID | Capability | Final status | Check result | Evidence in code |
|---|---|---|---|---|---|
| 1 | A1 | macOS host (launchd, Homebrew, `sw_vers`) | PARTIAL | Correct | `ops.go:21` `factsScript` falls back to `uname -s` when there is no `/etc/os-release`; `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime` (`ops.go:24-26`) do not exist on macOS, nor do `hostname -I`/`ip`, so memory, load, uptime, IP are empty. `svc` = `systemctl`, `pkg` has no `brew` (exit 3 "no supported package manager"), `user list` = `getent` (not on macOS). `exec`/`fs`/`upload` work over plain SSH/SFTP |
| 2 | A2 | FreeBSD/OpenBSD host (`service`, `sysrc`, `pkg`, `rc.conf`) | PARTIAL | Correct | same as A1: `pkgShell` (`modules.go:415-420`) does not know `pkg`/`pkg_add`, `svc` is `systemctl` only, `facts` reads `/proc`. `exec` does not assume Linux (`BuildCommand` is only `export`/`cd`/`sudo sh -c`) |
| 3 | A3 | Routers, switches, firewalls: run `show ...` and get the result | MISSING | Correct (evidence fixed: flag `--dir`, not `--cwd`) | `testHost` (`host.go:637`) runs `id -un`, `hostname`, `sudo -n true` through a POSIX shell; `BuildCommand` (`sshx/run.go:68-96`) sends `r.Command` as is when there is no env/dir/sudo; `policy.go:26-27` only has Linux shell patterns (`reboot`, `shutdown`, `systemctl poweroff`), `reload`/`write erase` get through |
| 4 | A4 | Back up network device config and diff between versions | MISSING | Correct | no network device code (see A3); no version diff command |
| 5 | A5 | SNMP get/walk | MISSING | Correct | `conn kinds` does not include `snmp`; `internal/driver` has only SQL drivers |
| 6 | B1 | Physical server power through the BMC (IPMI/Redfish) | MISSING | Correct | no BMC kind or command; the only "power" path is `reboot` through `exec`, which is blocked by `policy.go:26` |
| 7 | B2 | Serial console / Serial-over-LAN | MISSING | Correct | `shell` only opens an SSH login shell; no serial/IPMI transport |
| 8 | B3 | Proxmox VE: VMs/LXC, start/stop, snapshot | MISSING | Correct | no `proxmox` kind in `conn kinds`; only `exec -- qm/pct ...` on a node |
| 9 | B4 | libvirt/KVM | MISSING | Correct | no `virsh` recipe/command; through `exec` |
| 10 | B5 | LXD/Incus | MISSING | Correct | no `lxc`/`incus` recipe/command; through `exec` |
| 11 | B6 | VMware vSphere | MISSING | Correct | no vCenter kind or code |
| 12 | C1 | Status, start, stop, reboot of cloud VMs | MISSING | Correct | no cloud kind; the only AWS code is the `aws-sm:` secret ref and SigV4 for S3 |
| 13 | C2 | VM disk/volume snapshot | MISSING | Correct | same as C1 |
| 14 | C3 | VM console/serial output | MISSING | Correct | same as C1 |
| 15 | C4 | Managed container services as a `cluster` kind | MISSING | Correct | `cluster` uses the `k8s` kind or a Swarm manager server (`resolveCluster`, `cluster.go`); no ECS/Cloud Run/Fly |
| 16 | C5 | Managed DB operations (snapshot, failover) | MISSING | Correct | `db` only speaks the SQL protocol to the server; `FAILOVER` in `cachex.go:101` is a Redis command, unrelated |
| 17 | C6 | Cloud logs | MISSING | Correct | `logs` is only journald/file/docker on the host (`logOpts.build`, `modules.go:190-256`) |
| 18 | C7 | Serverless functions | MISSING | Correct | no code |
| 19 | D1 | Manage DNS records at the provider | MISSING | Correct | `net dns` = `getent ahosts` from the server (`modules.go:594`), resolve only; no DNS kind |
| 20 | D2 | CDN purge, maintenance, WAF | MISSING | Correct | no code; `PURGE` in `driver/sql.go:393` is an SQL keyword, unrelated |
| 21 | D3 | Take a node out of / put it back into the load balancer | MISSING | Correct | `haproxy` only appears in the `facts` binary detection list (`ops.go:32`) |
| 22 | D4 | Enable/disable vhost + test + reload | MISSING | Correct | recipes `nginx-test` (`nginx -t`), `nginx-sites` (`nginx -T \| grep`), `apache-test` only read; no Caddy recipe; `caddy` is only binary detection (`ops.go:32`); `svc reload` does not validate |
| 23 | E1 | Scan certificate files on servers and their remaining days | PARTIAL | Correct | recipe `certbot-certs` = `certbot certificates` (certbot certs only); `cert-expiry` (`ops.go:128`) = `openssl s_client` to host:port, not files; no scanning of `/etc/ssl` etc. |
| 24 | E2 | Issue certificates from an internal CA | MISSING | Correct | no CA code |
| 25 | E3 | Check cert/key/CSR files | MISSING | Correct | the only `openssl x509` is in `cert-expiry` (`ops.go:128`), over the network |
| 26 | F1 | Release deploy + `current` symlink + rollback | MISSING | Correct (evidence clarified) | `ops.go:265` is an example in the `recipe add` help (`cd /srv/{{app}} && git pull && systemctl restart`), not a built-in recipe; no `fs` symlink (see SSH report §10) |
| 27 | F2 | Zero-downtime container deploy to a VM | MISSING | Correct | `docker compose` only passes arguments through (`modules.go:377`); no rollout logic |
| 28 | F3 | Self-hosted PaaS (dokku, Coolify, CapRover) | MISSING | Correct | no recipe/command; through `exec` |
| 29 | F4 | Non-systemd process managers (pm2, Supervisor) | MISSING | Correct | `svc` is `systemctl` only; no `pm2`/`supervisorctl` recipe among the 39 recipes |
| 30 | F5 | App framework commands, PHP-FPM | MISSING | Correct | no recipe; `meta.go:457` is only policy note text |
| 31 | G1 | Back up server folders to storage | MISSING | Correct (evidence corrected) | `download -r` exists but is only server → laptop (`transfer.go:106-110`); storage rejects `-r` and takes only one file (`transfer.go:62-66`, `:96-99`); no server → storage path, snapshots, dedup, encryption, retention |
| 32 | G2 | View snapshots, backup age, restore one file | MISSING | Correct | no restic/borg recipe |
| 33 | H1 | Silence alerts, view active alerts | MISSING | Correct | no Alertmanager/Grafana code; `SilenceUsage` (`root.go:130`) is a cobra flag |
| 34 | H2 | Query centralized logs (Loki, Graylog) | MISSING | Correct | `logs` only has sources on the host (`modules.go:190-256`) |
| 35 | H3 | Ack incidents / view app errors | MISSING | Correct | no code |
| 36 | I1 | SMART and NVMe disk health | MISSING | Correct | no `smartctl` recipe; `facts` does not read SMART |
| 37 | I2 | Software RAID and pool status | MISSING | Correct | no `mdadm`/`zpool` recipe; `health` is only `uptime`/`free`/`df`/`systemctl --failed` |
| 38 | I3 | Grow the disk after the volume was enlarged | MISSING | Correct | no command; through `exec` |
| 39 | I4 | LVM/ZFS/Btrfs snapshot and rollback | MISSING | Correct | no command |
| 40 | I5 | Stuck NFS/SMB mounts | MISSING | Correct (evidence corrected) | recipes `disk`, `inodes`, `health` use `df` over all mounts without `-l`/`-x nfs`; `facts` only `df -P -k /` (`ops.go:27`); `--timeout` exists but is per host for the whole command (`probe`, `exec.go:347` `cmdTimeout`), not per step |
| 41 | J1 | Redact secrets in remote command output | MISSING | Correct | `redact` (`cluster.go:327`, used by `cluster get` at `:453`) and `redactArgs` (`cluster.go:1110`, only `cluster run` audit arguments); `runFleet`/`probe` (`exec.go`) and `limitedBuf` (`sshx/run.go:121`) pass stdout through in full for `exec`, `fs cat`, `logs`, `docker exec` |
| 42 | J2 | fail2ban/CrowdSec | MISSING | Correct | no recipe; `auth-failures` only reads failed login logs |
| 43 | J3 | Hardening/compliance audit (CIS) | MISSING | Correct | only read recipes `sshd-config`, `sudoers`, `auth-failures` |
| 44 | J4 | Read auditd logs | MISSING | Correct | `logs --file /var/log/audit/audit.log --sudo` reads raw text (`modules.go:232-236`); no `ausearch`/`aureport` |
| 45 | J5 | File integrity, rootkits, malware | MISSING | Correct | no recipe/command |
| 46 | J6 | Scan for leaked secrets on servers | MISSING | Correct | no recipe/command |
| 47 | J7 | Kernel live patch status | MISSING | Correct | `facts` only `reboot_required` from `/var/run/reboot-required` (`ops.go:33`) |
| 48 | K1 | Search users/groups in LDAP/AD | MISSING | Correct | no `ldap` kind |
| 49 | K2 | Domain-joined hosts (SSSD/FreeIPA): check directory user login, clear the cache | MISSING | Corrected: PARTIAL → MISSING | `user list` (`modules.go:615`) = `getent passwd`, then filters by UID; does not take a user name, does not check login, does not touch the SSSD cache. No part of this capability is done by komando, so it is not "present but lacking" |
| 50 | L1 | Mail queue | MISSING | Correct | no `mailq`/`postqueue` recipe |
| 51 | L2 | Test SMTP sending | MISSING | Correct | `net check` is only `nc -z` or `/dev/tcp` (`modules.go:526`), without SMTP/STARTTLS |
| 52 | M1 | Containers on a k8s node (containerd/CRI-O) | MISSING | Correct (note added) | all `docker` subcommands build `"docker "+...` (`modules.go:298-387`); the `ctr` alias (`modules.go:288`) points to `docker`, not containerd |
| 53 | N1 | Trigger and watch pipelines | MISSING | Correct | no CI code; `registry.go:2` only mentions the GitLab registry |
| 54 | N2 | Run a config management agent once | MISSING | Correct | no puppet/chef/salt recipe/command |
| 55 | N3 | Read Terraform/Pulumi output/state for inventory | MISSING | Correct | `importSources` (`importer.go:48-58`) without `terraform`/`pulumi` |
| 56 | N4 | Declarative infrastructure (Terraform, OpenTofu, Pulumi) | NON-GOAL | New row (an "Already covered" area that had no comparison row) | vision.md "Non-goals": "Infrastructure as Code, cloud provisioning, or GitOps"; no IaC code in `internal/` |
| 57 | O1 | One bastion connection shared within one command | MISSING | Correct | `fanout` (`common.go:135-158`) calls `sshx.Dial` per host; `Dial` (`sshx/client.go:56-96`) builds a new `--via` chain every time (`resolveChain`, `dialDirect`/`dialVia`), without a bastion client cache |
| 58 | S1 | Core dumps and crashes | MISSING | Correct | only the `oom` recipe (kernel journal/dmesg) |
| 59 | S2 | Diagnostic bundle for vendors | MISSING | Correct | through `job start` + `download` |
| 60 | S3 | Process tracing/profiling | MISSING | Correct | through `exec`/`job` |
| 61 | S4 | Change network config with automatic rollback | MISSING | Correct | `facts` only reads `ips` (`ops.go:28`); no command to change the network |
| 62 | T1 | List resource kinds and example URLs | PRESENT | Correct | `connKindsCmd` (`conn.go:322-330`) prints `driver.Kinds()` with scheme, default port, example URL |
| 63 | T2 | View and remove conns | PRESENT | Correct (row fixed: `conn.go:268`) | `connShowCmd` (`conn.go:268`); `connRmCmd` (`conn.go:288`) calls `guardProtection("conn", "removing", prot)` at `:304` |
| 64 | T3 | Removing a host that is still a `--via` path is rejected | PRESENT | Correct | `hostRmCmd` (`host.go:315`): `viaChain(o.Via)` for other hosts (`:331`) and conns (`:338`) → `HOST_IN_USE` |
| 65 | T4 | View and remove VPNs | PRESENT | Correct (row fixed: `vpn.go:331`) | `vpnShowCmd` (`vpn.go:331`) prints `used_by`; `vpnRmCmd` → `VPN_IN_USE` (`vpn.go:366`); the key stays in the vault (`Short` text in `vpn.go:354`) |
| 66 | T5 | Remove your own recipes; built-in ones cannot be removed | PRESENT | Correct | `recipeRmCmd` (`ops.go:309-315`): `builtinRecipe(args[0]) != nil` → `RECIPE_BUILTIN` |
| 67 | T6 | Per-family aliases | PRESENT | Correct (bug note expanded) | the `--help` of all ten aliases says "Same as ..."; `svc logs` (`modules.go:158`) and `docker logs` (`modules.go:323`) call `runOne` even though `-f` is available through `logOpts.bind`, while `logs -f` uses `followLogs` (`modules.go:273`) |
