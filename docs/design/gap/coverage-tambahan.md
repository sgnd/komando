# Cek cakupan: area yang belum dibandingkan di lima laporan gap

Lima laporan di folder ini membandingkan komando (`feat/v0.3`, commit 4784fc9)
dengan tools di bidangnya masing-masing. Dokumen ini mencari **apa yang
terlewat**: tools dan pekerjaan harian devops yang tidak muncul di laporan
mana pun.

Cara kerjanya:

1. Daftar kandidat dibuat dari pekerjaan harian devops (jenis host lain,
   out-of-band, virtualisasi, cloud, DNS/CDN, sertifikat, deploy, backup,
   observability, disk, keamanan host, identitas, mail, CI, config management).
2. Setiap kandidat di-`grep` di `docs/design/gap/*.md`. Yang sudah ada masuk
   daftar [Sudah tercakup](#sudah-tercakup) dan tidak diulang di sini.
3. Yang belum ada dicek ke kode (`internal/`), ke `komando schema --compact`,
   `komando recipe list` (39 recipe), dan `--help`. Statusnya memakai legenda
   yang sama dengan [README](README.md#cara-membaca).

Prioritas diukur dengan [vision.md](../vision.md): P1 = keamanan atau
penghambat agent, P2 = berguna dan cocok dengan visi/kandidat setelah v1.0,
P3 = jarang atau cukup lewat `exec`/`script`/`job`.


## Ringkasan

| Status | Jumlah baris |
|---|---|
| ADA | 6 |
| SEBAGIAN | 3 |
| TIDAK ADA | 57 |
| NON-GOAL | 1 |
| **Total baris baru** | **67** |

| Prioritas | Jumlah |
|---|---|
| P1 | 1 |
| P2 | 14 |
| P3 | 45 |
| – (ADA/NON-GOAL) | 7 |

Enam baris ADA (area T) adalah perintah inventaris dasar yang belum punya
baris sendiri di laporan lain; ditemukan saat mencocokkan 178 perintah
komando dengan semua laporan. Hampir semua baris di sini masih bisa dikerjakan lewat `exec`
atau `job start` di host; yang kurang adalah perintah terstruktur, risk yang
jujur, dan dry-run.

Temuan paling penting: **output perintah remote tidak pernah disaring dari
secret** (baris J1). Laporan lain hanya membahas secret di argumen, audit,
`cluster run`, `docker inspect`, dan `compose config`. Padahal `fs cat .env`,
`exec -- env`, dan `logs` sama-sama bisa memperlihatkan password ke agent.

## A. Jenis host selain Linux

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| A1 | Host macOS (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt | SEBAGIAN | `exec`/`fs`/`upload` jalan lewat SSH. `facts` jatuh ke `uname -s` (`ops.go:21`) dan membaca `/proc` yang tidak ada, jadi memori, load, dan uptime kosong. `svc` hanya systemd, `pkg` tanpa `brew` | P3 — model host di vision = "SSH (Linux)"; jarang jadi server |
| A2 | Host FreeBSD/OpenBSD (`service`, `sysrc`, `pkg`, `rc.conf`) | Ansible (`sysrc`, `pkgng`), Salt | SEBAGIAN | sama dengan A1: `exec` jalan, modul sistem (`svc`, `pkg`, `facts`) mengasumsikan Linux | P3 — pengguna sedikit (firewall pfSense/OPNsense lihat A3) |
| A3 | Router, switch, firewall: jalankan `show ...` dan ambil hasilnya (Cisco IOS/NX-OS, Juniper Junos, MikroTik RouterOS, Arista EOS, FortiGate, pfSense) | netmiko, scrapli, Ansible `network_cli`, NAPALM | TIDAK ADA | `komando test` menjalankan `id -un`, `hostname`, `sudo -n true` (`host.go:637`) yang gagal di CLI perangkat. `exec` tanpa `--env`/`--dir`/`--sudo` (dan tanpa `--env` di host) mengirim perintah apa adanya (`sshx/run.go:68-96` `BuildCommand`), jadi satu perintah mungkin jalan, tapi tidak dites. Policy hanya mengenal perintah shell Linux (`reload`, `write erase` tidak dikenali) | P2 — "client universal"; perangkat jaringan bagian kerja harian di on-prem dan kantor |
| A4 | Backup konfigurasi perangkat jaringan dan diff antar versi | Oxidized, RANCID, NAPALM `get_config` | TIDAK ADA | tidak ada kode untuk perangkat jaringan | P3 — butuh A3 dulu |
| A5 | SNMP get/walk (status interface, UPS, printer, perangkat lama) | `snmpwalk`, `snmpget` | TIDAK ADA | tidak ada kind `snmp` di `internal/driver` | P3 — monitoring terus-menerus NON-GOAL; baca sekali jarang dibutuhkan |

## B. Out-of-band dan virtualisasi

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| B1 | Status dan power on/off/cycle server fisik lewat BMC (iDRAC, iLO, XClarity, Supermicro) | `ipmitool chassis power`, Redfish API, `racadm`, `hponcfg` | TIDAK ADA | tidak ada kode `ipmi`/`redfish` di `internal/` | P2 — satu-satunya jalan saat SSH mati (melengkapi "reboot terkendali" P1 di README); Redfish = HTTP API, cocok model conn; power off = destructive |
| B2 | Konsol serial / Serial-over-LAN | `ipmitool sol activate`, conserver, `screen /dev/ttyUSB0` | TIDAK ADA | interaktif seperti `shell` (khusus manusia) | P3 |
| B3 | Proxmox VE: daftar VM/LXC, start/stop/shutdown, snapshot dan rollback | `pvesh`, `qm`, `pct`, proxmoxer, Terraform provider | TIDAK ADA | tidak ada kind `proxmox`; hanya lewat `exec -- qm ...` di node Proxmox | P2 — sangat umum di on-prem/UMKM; REST API + token cocok kontrak family; snapshot sebelum perubahan berisiko |
| B4 | libvirt/KVM: `virsh list/start/shutdown/snapshot-create` | `virsh`, `virt-manager` | TIDAK ADA | lewat `exec -- virsh ...` | P3 |
| B5 | LXD/Incus: container dan VM | `lxc`, `incus` | TIDAK ADA | lewat `exec` | P3 |
| B6 | VMware vSphere: daftar VM, power, snapshot | `govc`, PowerCLI | TIDAK ADA | tidak ada kode | P3 — butuh SOAP/REST vCenter; ukuran biner |

## C. Cloud CLI sebagai client (di luar inventaris dinamis)

Inventaris dinamis dari EC2/GCP/DO/Hetzner sudah ada di laporan
[ssh-files-system.md](ssh-files-system.md) §4 dan
[vpn-secrets-platform.md](vpn-secrets-platform.md) C6. Baris di bawah adalah
operasi lain yang dipakai sehari-hari.

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| C1 | Status, start, stop, reboot VM cloud | `aws ec2 start-instances/reboot-instances`, `gcloud compute instances`, `az vm`, `doctl compute droplet-action`, `hcloud server` | TIDAK ADA | tidak ada kode `ec2`/`hcloud`/`doctl` di `internal/` | P2 — kandidat vision "VM cloud"; jalan pemulihan saat SSH terkunci (bukan provisioning) |
| C2 | Snapshot disk/volume VM sebelum perubahan berisiko | `aws ec2 create-snapshot`, `hcloud server create-image`, `doctl compute droplet-action snapshot`, `gcloud compute disks snapshot` | TIDAK ADA | tidak ada | P2 — jalan mundur untuk patching dan upgrade OS; cocok dengan aturan "dry-run dan rollback" |
| C3 | Konsol/serial output VM saat SSH mati | `aws ec2 get-console-output`, `gcloud compute instances get-serial-port-output`, `hcloud server request-console` | TIDAK ADA | tidak ada | P3 |
| C4 | Layanan container terkelola sebagai kind `cluster` (ECS, Cloud Run, Azure Container Apps, Fly Machines) | `aws ecs`, `gcloud run`, `az containerapp`, `flyctl` | TIDAK ADA | `cluster` hanya k8s dan swarm (vision: "nanti: nomad") | P3 |
| C5 | Operasi DB terkelola: snapshot, reboot, failover, lihat parameter | `aws rds`, `gcloud sql`, `az postgres` | TIDAK ADA | provisioning DB sudah NON-GOAL ([database-cache.md](database-cache.md):362); snapshot/failover adalah operasi, belum dibahas | P3 |
| C6 | Log cloud: tail dan cari (CloudWatch Logs, Cloud Logging, Azure Monitor) | `aws logs tail`, `gcloud logging read`, `az monitor log-analytics query` | TIDAK ADA | tidak ada | P3 — API per cloud, ukuran biner |
| C7 | Fungsi serverless: invoke, lihat log/versi | `aws lambda`, `gcloud functions` | TIDAK ADA | tidak ada | P3 |

## D. DNS, CDN, load balancer, web server

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| D1 | Kelola record DNS di provider (list/set/rm A, CNAME, TXT) dengan dry-run | dnscontrol, octoDNS, `flarectl`/Cloudflare API, `aws route53`, `doctl compute domain` | TIDAK ADA | tidak ada kind DNS; `net dns` hanya resolve dari server | P2 — kandidat vision "DNS (Cloudflare, Route 53)"; API HTTP kecil; risk jelas (`rm` = destructive) |
| D2 | Purge cache CDN, mode maintenance, blok IP di WAF | Cloudflare API, `aws cloudfront create-invalidation`, `fastly purge` | TIDAK ADA | tidak ada | P3 |
| D3 | Keluarkan/masukkan node dari load balancer saat maintenance | HAProxy runtime API (`disable server`), `aws elbv2 deregister-targets`, Traefik/nginx upstream | TIDAK ADA | lewat `exec` + `socat` ke socket HAProxy | P3 — pendukung rolling update (`serial`, P2 di [ssh-files-system.md](ssh-files-system.md) §5) |
| D4 | Aktif/nonaktif vhost + test + reload dalam satu langkah | `a2ensite`/`a2dissite`, symlink `sites-enabled`, Caddy admin API `/load` | TIDAK ADA | recipe `nginx-test`, `nginx-sites`, `apache-test` hanya membaca; Caddy tidak punya recipe | P3 |

## E. Sertifikat dan PKI

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| E1 | Pindai file sertifikat di server (`/etc/ssl`, `/etc/letsencrypt`, `/etc/nginx`, keystore) dan sisa harinya, untuk satu fleet | `openssl x509 -enddate`, ssl-cert-check, `certbot certificates` | SEBAGIAN | recipe `certbot-certs` hanya sertifikat certbot; `cert-expiry` lewat jaringan (s_client), bukan dari file; cert internal (mTLS, DB, kubelet) tidak terlihat | P2 — sertifikat kedaluwarsa penyebab outage umum; kandidat vision "sertifikat/ACME" |
| E2 | Terbitkan/perpanjang sertifikat dari CA internal | `step ca certificate`, cfssl, Vault PKI | TIDAK ADA | tidak ada | P3 |
| E3 | Periksa file cert/key/CSR: key cocok dengan cert, rantai lengkap, SAN | `openssl`, `step certificate inspect` | TIDAK ADA | lewat `exec -- openssl ...` | P3 |

## F. Deploy aplikasi ke VM dan runtime aplikasi

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| F1 | Deploy rilis: folder rilis + symlink `current` + rollback ke rilis sebelumnya | Capistrano, Deployer (PHP), Ansistrano | TIDAK ADA | contoh `deploy-app` di bantuan `recipe add` hanya `git pull` + restart (`ops.go:265`); bukan recipe bawaan | P3 — mendekati playbook (NON-GOAL); `script` cukup |
| F2 | Deploy container tanpa downtime ke VM tanpa orkestrator | Kamal, docker-rollout | TIDAK ADA | `docker compose up -d` saja | P3 |
| F3 | PaaS self-hosted: daftar app, logs, restart, config | `dokku`, Coolify CLI, CapRover | TIDAK ADA | lewat `exec -- dokku ...` | P3 |
| F4 | Process manager non-systemd: status, restart, logs (pm2, Supervisor, worker antrian Laravel) | `pm2 list/restart/logs`, `supervisorctl status/restart` | TIDAK ADA | `svc` hanya systemd; tidak ada recipe pm2/supervisor | P2 — sangat umum di VPS Node/PHP/Python; restart worker setelah deploy adalah kerja harian |
| F5 | Perintah framework aplikasi (`artisan`, `manage.py`, `rails runner`), status/reload PHP-FPM | artisan, Django, Rails, `php-fpm -t` | TIDAK ADA | lewat `exec`/`recipe add` | P3 |

## G. Backup file server

`db dump` sudah ada untuk database, dan `storage` untuk mengunggah file. Yang
belum ada: backup folder server.

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| G1 | Backup folder server ke storage (snapshot, dedup, enkripsi, retensi) | restic, borg, kopia, duplicity | TIDAK ADA | `download -r` hanya server → laptop (`transfer.go:106-110`); storage menolak `-r` dan menerima satu file per perintah (`transfer.go:62-66`, `:96-99`); tidak ada jalur server → storage langsung, snapshot, dedup, atau retensi | P2 — tujuan 2 vision "backup dan pulihkan" untuk setiap family; host belum punya |
| G2 | Lihat snapshot, cek umur backup terakhir, restore satu file | `restic snapshots/restore`, `borg list/extract` | TIDAK ADA | lewat `exec` bila restic/borg terpasang | P3 |

## H. Observability (sekali jalan, bukan monitoring)

Query Prometheus sudah dibahas di [database-cache.md](database-cache.md):349,
Elasticsearch/OpenSearch di §20 laporan yang sama.

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| H1 | Silence alert selama maintenance, lihat alert yang aktif | `amtool silence add/alert query`, Grafana API | TIDAK ADA | tidak ada | P3 — perintah sekali jalan, tidak melanggar NON-GOAL monitoring |
| H2 | Query log terpusat (Loki LogQL, Graylog) | `logcli query`, Graylog API | TIDAK ADA | tidak ada | P3 |
| H3 | Ack insiden / lihat error aplikasi | PagerDuty CLI, Sentry CLI | TIDAK ADA | tidak ada | P3 — di luar "client devops" vision |

## I. Disk, RAID, dan filesystem

Daftar mount dan disk lengkap di `facts` sudah dibahas
([ssh-files-system.md](ssh-files-system.md) §16), begitu juga mount/fstab dan
swap (§18).

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| I1 | Kesehatan disk SMART dan NVMe | `smartctl -H -A`, `nvme smart-log` | TIDAK ADA | tidak ada recipe atau kode `smartctl` | P2 — disk rusak = kehilangan data; perintah baca sekali jalan, mudah dibuat recipe |
| I2 | Status RAID software dan pool, deteksi degraded | `mdadm --detail`, `/proc/mdstat`, `zpool status`, `btrfs device stats` | TIDAK ADA | tidak ada | P2 — sama dengan I1 |
| I3 | Perbesar disk setelah volume cloud diperbesar | `growpart`, `pvresize`, `lvextend -r`, `resize2fs`, `xfs_growfs` | TIDAK ADA | lewat `exec`; urutan langkah dan jenis filesystem harus ditebak agent | P2 — "disk penuh" insiden harian; salah urutan bisa merusak |
| I4 | Snapshot LVM/ZFS/Btrfs sebelum upgrade, dan rollback | `lvcreate -s`, `zfs snapshot/rollback`, snapper | TIDAK ADA | tidak ada | P3 |
| I5 | Mount NFS/SMB yang macet (stale) | `findmnt`, `showmount`, `umount -l` | TIDAK ADA | recipe `disk`, `inodes`, `health` memakai `df` atas semua mount (tanpa `-l`/`-x nfs`), jadi bisa menggantung di mount NFS macet (`facts` hanya `df /`); yang ada hanya `--timeout` per host untuk seluruh perintah (default 5m), bukan batas per langkah, dan tidak ada recipe untuk mendeteksi mount macet | P3 |

## J. Keamanan host dan kepatuhan

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| J1 | Redaksi secret di **output** perintah remote (`fs cat .env`, `exec -- env`, `logs`, `docker exec ... env`, file config aplikasi) | aturan gitleaks/trufflehog, Teleport (redaksi sesi) | TIDAK ADA | redaksi hanya di `cluster get` (`cluster.go:327`) dan argumen audit `cluster run` (`redactArgs`, `cluster.go:1110`). Output `exec`/`fs cat`/`logs`/`storage` dikirim utuh ke agent | **P1** — vision: "password tidak pernah terlihat oleh AI"; agent rutin membaca `.env`, `wp-config.php`, `application.yml` |
| J2 | fail2ban/CrowdSec: status jail, IP yang diblok, unban | `fail2ban-client status/set ... unbanip`, `cscli decisions` | TIDAK ADA | tidak ada recipe | P2 — IP admin/CI sering terblokir; `exec` paralel lewat satu bastion bisa ikut memicu ban (lihat O1) |
| J3 | Audit hardening/kepatuhan sekali jalan (CIS) | Lynis, OpenSCAP `oscap`, kube-bench | TIDAK ADA | hanya recipe `sshd-config`, `sudoers`, `auth-failures` | P3 — `job start -- lynis audit system` sudah cukup |
| J4 | Baca log auditd | `ausearch`, `aureport` | TIDAK ADA | lewat `exec`/`logs --file /var/log/audit/audit.log` | P3 |
| J5 | Integritas file, rootkit, malware | AIDE, rkhunter, debsums, ClamAV | TIDAK ADA | tidak ada | P3 |
| J6 | Scan secret yang bocor di server (`.git` di webroot, key di folder publik) | gitleaks, trufflehog `filesystem` | TIDAK ADA | tidak ada | P3 |
| J7 | Status kernel live patch | `canonical-livepatch status`, `kpatch list` | TIDAK ADA | `facts` hanya `reboot_required` | P3 |

## K. Identitas dan direktori

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| K1 | Cari user/grup di LDAP/Active Directory | `ldapsearch`, `adcli`, `realm list` | TIDAK ADA | tidak ada kind `ldap` | P3 |
| K2 | Host yang join domain (SSSD/FreeIPA): cek user direktori bisa login, bersihkan cache | `id`, `getent passwd`, `sss_cache -E`, `ipa` | TIDAK ADA | tidak ada perintah untuk satu user direktori atau cache SSSD; lewat `exec -- id USER`. `user list` memakai `getent passwd` (`modules.go:615`) lewat NSS, jadi user direktori hanya muncul kalau SSSD diset `enumerate=true` (defaultnya tidak); tidak ada cek apakah user direktori bisa login atau cache SSSD sehat | P3 |

## L. Mail

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| L1 | Antrian mail: lihat, flush, hapus | `mailq`, `postqueue -p/-f`, `postsuper -d`, `exim -bp` | TIDAK ADA | tidak ada recipe | P3 |
| L2 | Uji kirim SMTP dari server (auth, STARTTLS) | swaks, `openssl s_client -starttls smtp` | TIDAK ADA | `net check` hanya TCP | P3 |

## M. Container runtime di node

Podman sudah dibahas di [cluster-docker.md](cluster-docker.md):70.

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| M1 | Container di node k8s saat API/kubelet bermasalah (containerd/CRI-O) | `crictl ps/logs/images`, `nerdctl`, `ctr` | TIDAK ADA | perintah `docker` di-hardcode; alias `komando ctr` (`modules.go:288`) adalah alias `docker`, bukan containerd `ctr`; lewat `exec -- crictl ...` | P3 |

## N. CI/CD, config management, IaC

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| N1 | Picu dan pantau pipeline | `gh workflow run/watch`, `glab ci run`, Jenkins CLI | TIDAK ADA | `gh workflow` hanya disebut sebagai pembanding penjadwalan ([vpn-secrets-platform.md](vpn-secrets-platform.md) C7) | P3 — bukan family di vision; `gh`/`glab` sudah baik |
| N2 | Jalankan agen config management sekali (mode cek) dan lihat hasil run terakhir | `puppet agent -t --noop`, `chef-client --why-run`, `salt-call state.apply test=True` | TIDAK ADA | lewat `exec`; Ansible playbook sendiri sudah NON-GOAL | P3 |
| N3 | Baca output/state Terraform/Pulumi sebagai sumber inventaris | `terraform output -json`, `pulumi stack output` | TIDAK ADA | `komando import` tidak punya sumber `terraform`/`pulumi` (`importSources`, `importer.go:48`) | P3 — tujuan 4 (migrasi); IaC sendiri NON-GOAL (N4) |
| N4 | Infrastruktur deklaratif: plan/apply/destroy dan state (VM, jaringan, DNS, DB terkelola) | Terraform, OpenTofu, Pulumi | NON-GOAL | vision.md "Bukan tujuan": "Infrastructure as Code, provisioning cloud, atau GitOps"; tidak ada kode IaC di `internal/`. Pakai alat aslinya; komando hanya mengoperasikan hasilnya | – |

## O. Keandalan fleet

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| O1 | Satu koneksi bastion dipakai bersama oleh semua host dalam **satu** perintah | OpenSSH ControlMaster, Ansible (koneksi persisten), pssh | TIDAK ADA | `sshx.Dial` (`sshx/client.go:56`) membangun rantai `--via` baru per host. `exec @prod -P 10` lewat satu bastion membuka 10 login ke bastion sekaligus, dekat batas `MaxStartups` default (10:30:100) dan bisa memicu fail2ban. Berbeda dengan baris NON-GOAL "multiplexing antar-perintah" ([ssh-files-system.md](ssh-files-system.md):53) | P2 — fleet di balik bastion adalah pola utama; gagal acak sulit dijelaskan ke agent |

## S. Diagnosa sistem lanjutan

| # | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| S1 | Core dump dan crash | `coredumpctl list/info`, kdump | TIDAK ADA | recipe `oom` saja | P3 |
| S2 | Bundel diagnosa untuk vendor | `sosreport`, `supportconfig` | TIDAK ADA | lewat `job start` + `download` | P3 |
| S3 | Tracing/profiling proses | `strace`, `perf`, `py-spy` | TIDAK ADA | lewat `exec`/`job` | P3 |
| S4 | Ubah konfigurasi jaringan server dengan rollback otomatis | `netplan try`, `nmcli`, Ansible `nmcli` | TIDAK ADA | `facts` membaca IP; route sebagian di §17 laporan SSH. Salah ubah = server terputus | P3 |

## T. Siklus inventaris yang belum punya baris sendiri

Ditemukan saat mencocokkan 178 perintah komando dengan kelima laporan: perintah
ini hanya disebut sambil lalu, belum dibandingkan sebagai kemampuan sendiri.

| ID | Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|---|
| T1 | Daftar jenis resource yang didukung beserta contoh URL | `rclone help backends`, usql `\drivers` | ADA | `conn kinds` (`conn.go:325`) | – |
| T2 | Lihat dan hapus conn (secret tetap ref, conn protected dijaga) | DBeaver, `rclone config show/delete` | ADA | `conn show` (`connShowCmd`, `conn.go:268`), `conn rm` menolak conn protected lewat `guardProtection` (`conn.go`, `connRmCmd`) | – |
| T3 | Hapus host yang masih jadi jalur `--via` host/conn lain ditolak | Termius (tanpa cek), Ansible (tanpa cek) | ADA | `host rm` → `HOST_IN_USE` (`hostRmCmd`, `viaChain`) | – |
| T4 | Lihat dan hapus VPN; hapus ditolak bila masih dipakai `--via` | `nmcli con show/delete`, `tailscale logout` | ADA | `vpn show` (`vpnShowCmd`, `vpn.go:331`), `vpn rm` → `VPN_IN_USE` (`vpn.go:366`); kunci tetap di vault sampai `secret rm` (disengaja) | – |
| T5 | Hapus recipe sendiri; recipe bawaan tidak bisa dihapus | Termius snippets, Fabric | ADA | `recipe rm` menolak recipe bawaan (`builtinRecipe`, `ops.go`) | – |
| T6 | Alias per family: `host list`, `conn list`, `vpn list`, `host test`, `conn test`, `vpn test`, `svc logs`, `docker logs`, `storage download`, `storage upload` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` | ADA | semuanya memanggil `list`/`test`/`logs`/`download`/`upload` yang sama (satu kebutuhan, satu perintah; ux.md §11). Catatan: alias `docker logs -f` (`modules.go:323`) dan `svc logs -f` (`modules.go:158`) memakai `runOne`, bukan `followLogs` seperti `logs` (`modules.go:273`), jadi output ditahan sampai timeout (bug; README hanya mencatat `docker logs`) | – |

## Sudah tercakup

Area yang dicek dan ternyata sudah dibahas, jadi tidak diulang. Setiap area
(27 baris) dicocokkan ke baris tabel di bagian laporan yang dirujuk: baris
itu harus membandingkan kemampuan yang sama dengan tools yang disebut.
25 area cocok. Dua diperbaiki: build image (rujukan `storage-registry.md` §I
ternyata bukan baris build, dihapus) dan Terraform/IaC (tidak ada baris
pembanding, hanya prosa README §5; sekarang baris N4).

| Area | Laporan |
|---|---|
| Host Windows, WinRM, PowerShell | [ssh-files-system.md](ssh-files-system.md) §1 |
| Build Windows, Homebrew, MCP server | [vpn-secrets-platform.md](vpn-secrets-platform.md) C5, C8 |
| Inventaris dinamis cloud (EC2, GCP, DO, Hetzner) | [ssh-files-system.md](ssh-files-system.md) §4, [vpn-secrets-platform.md](vpn-secrets-platform.md) C6 |
| AWS SSM, GCP IAP, cloudflared, `ProxyCommand` | [vpn-secrets-platform.md](vpn-secrets-platform.md) A7, [ssh-files-system.md](ssh-files-system.md) §1 |
| Login IAM RDS/Cloud SQL, provisioning DB terkelola (NON-GOAL) | [database-cache.md](database-cache.md) §1, §20 |
| Nomad, Podman | [cluster-docker.md](cluster-docker.md) §1 |
| Build image (`docker build`, buildx) | [cluster-docker.md](cluster-docker.md) §10 (baris "Build image di host"). Rujukan lama ke [storage-registry.md](storage-registry.md) §I dihapus: §I hanya membandingkan copy/retag/index dengan `buildx imagetools`, bukan build |
| systemd timer, journald, `logs --follow`, lnav/multitail, logrotate | [ssh-files-system.md](ssh-files-system.md) §11, §14, §15 |
| certbot/ACME, cek TLS dari jaringan (`openssl s_client`) | [ssh-files-system.md](ssh-files-system.md) §17, §18 |
| DNS resolve dari server (`dig`, tipe record) | [ssh-files-system.md](ssh-files-system.md) §17 |
| Git pull di server | [ssh-files-system.md](ssh-files-system.md) §18 |
| rclone, SMB/CIFS sebagai storage | [storage-registry.md](storage-registry.md) §F, §G |
| Prometheus/promtool, InfluxDB | [database-cache.md](database-cache.md) §20 |
| Kafka, RabbitMQ, NATS, Elasticsearch/OpenSearch, etcd, Consul, MongoDB, Memcached | [database-cache.md](database-cache.md) §19, §20 |
| Terraform/IaC, Ansible playbook, GitOps, helm install (NON-GOAL) | [ssh-files-system.md](ssh-files-system.md) §5 (playbook), [cluster-docker.md](cluster-docker.md) §5 (`apply --prune`, GitOps) dan §8 (helm install/upgrade); Terraform/IaC: baris N4 di atas (sebelumnya hanya prosa di [README.md](README.md) §5, tanpa baris pembanding); membaca state Terraform: baris N3 |
| Ansible Vault, rekey vault | [vpn-secrets-platform.md](vpn-secrets-platform.md) B1 |
| Cari file/isi di fleet (`find`, `grep -r`) | [ssh-files-system.md](ssh-files-system.md) §10 |
| Proses: daftar terstruktur, kill, lsof | [ssh-files-system.md](ssh-files-system.md) §16 |
| nginx/apache test sebelum reload, validasi file | [ssh-files-system.md](ssh-files-system.md) §10, §11 |
| NTP/chrony, timezone, locale, swap, hostname, sysctl, mount/fstab, kernel module | [ssh-files-system.md](ssh-files-system.md) §18 |
| SELinux/AppArmor, firewall, hardening sshd | [ssh-files-system.md](ssh-files-system.md) §13, §18 |
| tcpdump, iperf3, nmap, mtr | [ssh-files-system.md](ssh-files-system.md) §17 |
| Kirim audit ke SIEM/syslog (auditd sebagai pembanding) | [ssh-files-system.md](ssh-files-system.md) §20, [vpn-secrets-platform.md](vpn-secrets-platform.md) C7 |
| Notifikasi Slack/webhook | [vpn-secrets-platform.md](vpn-secrets-platform.md) C7 |
| Init non-systemd (OpenRC, sysvinit) | [ssh-files-system.md](ssh-files-system.md) §11 |
| Multiplexing koneksi antar-perintah (NON-GOAL) | [ssh-files-system.md](ssh-files-system.md) §1 |
| Juniper Network Connect sebagai VPN | [vpn-secrets-platform.md](vpn-secrets-platform.md) A4 |

## Verifikasi per baris

Setiap baris dicek ulang dengan **membaca** kode yang semestinya
menjalankan kemampuan itu (bukan hanya grep kata kunci): `internal/cli/`
(`modules.go` untuk `svc`/`pkg`/`user`/`logs`/`docker`/`net`, `ops.go`
untuk `facts` dan 39 recipe, `host.go`, `exec.go`, `common.go`,
`transfer.go`, `cluster.go`, `conn.go`, `vpn.go`, `importer.go`),
`internal/sshx`, `internal/policy` dan `internal/driver`. Hasil biner
dicek dengan `komando recipe list -o json`, `komando conn kinds`,
`komando schema --compact` dan `--help` (tanpa koneksi ke server).
Dukungan tidak langsung (`exec`, `job`, recipe, alias) ikut dinilai; sesuai
legenda README, "bisa lewat `exec`" tetap TIDAK ADA.

Fakta yang dipakai berulang:
`svc` selalu memanggil `systemctl` (`modules.go:82`, `:100`, `:121`);
`pkg` hanya apt/dnf/yum/apk/zypper/pacman (`modules.go:415-420`);
kind yang dikenal hanya ftp, ftps, k8s, mysql, postgres, redis, registry,
s3, sftp, sqlite (`conn kinds`); sumber `import` hanya ssh-config, pgpass,
mycnf, env, kubeconfig, docker, filezilla, rclone, dbeaver, komando
(`importer.go:48-58`); 39 recipe bawaan ada di `ops.go:106-144`. "Tidak ada
recipe" berarti tidak ada di daftar 39 itu.

| # | ID | Kemampuan | Status akhir | Hasil cek | Bukti di kode |
|---|---|---|---|---|---|
| 1 | A1 | Host macOS (launchd, Homebrew, `sw_vers`) | SEBAGIAN | Benar | `ops.go:21` `factsScript` jatuh ke `uname -s` bila tidak ada `/etc/os-release`; `/proc/meminfo`, `/proc/loadavg`, `/proc/uptime` (`ops.go:24-26`) tidak ada di macOS, `hostname -I`/`ip` juga tidak, jadi memori, load, uptime, IP kosong. `svc` = `systemctl`, `pkg` tanpa `brew` (exit 3 "no supported package manager"), `user list` = `getent` (tidak ada di macOS). `exec`/`fs`/`upload` jalan lewat SSH/SFTP biasa |
| 2 | A2 | Host FreeBSD/OpenBSD (`service`, `sysrc`, `pkg`, `rc.conf`) | SEBAGIAN | Benar | sama dengan A1: `pkgShell` (`modules.go:415-420`) tidak mengenal `pkg`/`pkg_add`, `svc` hanya `systemctl`, `facts` membaca `/proc`. `exec` tidak mengasumsikan Linux (`BuildCommand` hanya `export`/`cd`/`sudo sh -c`) |
| 3 | A3 | Router, switch, firewall: jalankan `show ...` dan ambil hasilnya | TIDAK ADA | Benar (bukti diperbaiki: flag `--dir`, bukan `--cwd`) | `testHost` (`host.go:637`) menjalankan `id -un`, `hostname`, `sudo -n true` lewat shell POSIX; `BuildCommand` (`sshx/run.go:68-96`) mengirim `r.Command` apa adanya bila tanpa env/dir/sudo; `policy.go:26-27` hanya pola shell Linux (`reboot`, `shutdown`, `systemctl poweroff`), `reload`/`write erase` lolos |
| 4 | A4 | Backup konfigurasi perangkat jaringan dan diff antar versi | TIDAK ADA | Benar | tidak ada kode perangkat jaringan (lihat A3); tidak ada perintah diff versi |
| 5 | A5 | SNMP get/walk | TIDAK ADA | Benar | `conn kinds` tidak memuat `snmp`; `internal/driver` hanya driver SQL |
| 6 | B1 | Power server fisik lewat BMC (IPMI/Redfish) | TIDAK ADA | Benar | tidak ada kind atau perintah BMC; satu-satunya jalur "power" adalah `reboot` lewat `exec`, yang diblok `policy.go:26` |
| 7 | B2 | Konsol serial / Serial-over-LAN | TIDAK ADA | Benar | `shell` hanya membuka login shell SSH; tidak ada transport serial/IPMI |
| 8 | B3 | Proxmox VE: VM/LXC, start/stop, snapshot | TIDAK ADA | Benar | tidak ada kind `proxmox` di `conn kinds`; hanya `exec -- qm/pct ...` di node |
| 9 | B4 | libvirt/KVM | TIDAK ADA | Benar | tidak ada recipe/perintah `virsh`; lewat `exec` |
| 10 | B5 | LXD/Incus | TIDAK ADA | Benar | tidak ada recipe/perintah `lxc`/`incus`; lewat `exec` |
| 11 | B6 | VMware vSphere | TIDAK ADA | Benar | tidak ada kind atau kode vCenter |
| 12 | C1 | Status, start, stop, reboot VM cloud | TIDAK ADA | Benar | tidak ada kind cloud; satu-satunya kode AWS adalah ref secret `aws-sm:` dan SigV4 untuk S3 |
| 13 | C2 | Snapshot disk/volume VM | TIDAK ADA | Benar | sama dengan C1 |
| 14 | C3 | Konsol/serial output VM | TIDAK ADA | Benar | sama dengan C1 |
| 15 | C4 | Layanan container terkelola sebagai kind `cluster` | TIDAK ADA | Benar | `cluster` memakai kind `k8s` atau server manager Swarm (`resolveCluster`, `cluster.go`); tidak ada ECS/Cloud Run/Fly |
| 16 | C5 | Operasi DB terkelola (snapshot, failover) | TIDAK ADA | Benar | `db` hanya bicara protokol SQL ke server; `FAILOVER` di `cachex.go:101` adalah perintah Redis, tidak terkait |
| 17 | C6 | Log cloud | TIDAK ADA | Benar | `logs` hanya journald/file/docker di host (`logOpts.build`, `modules.go:190-256`) |
| 18 | C7 | Fungsi serverless | TIDAK ADA | Benar | tidak ada kode |
| 19 | D1 | Kelola record DNS di provider | TIDAK ADA | Benar | `net dns` = `getent ahosts` dari server (`modules.go:594`), hanya resolve; tidak ada kind DNS |
| 20 | D2 | Purge CDN, maintenance, WAF | TIDAK ADA | Benar | tidak ada kode; `PURGE` di `driver/sql.go:393` kata kunci SQL, tidak terkait |
| 21 | D3 | Keluarkan/masukkan node dari load balancer | TIDAK ADA | Benar | `haproxy` hanya di daftar deteksi biner `facts` (`ops.go:32`) |
| 22 | D4 | Aktif/nonaktif vhost + test + reload | TIDAK ADA | Benar | recipe `nginx-test` (`nginx -t`), `nginx-sites` (`nginx -T \| grep`), `apache-test` hanya membaca; tidak ada recipe Caddy; `caddy` hanya deteksi biner (`ops.go:32`); `svc reload` tidak memvalidasi |
| 23 | E1 | Pindai file sertifikat di server dan sisa harinya | SEBAGIAN | Benar | recipe `certbot-certs` = `certbot certificates` (hanya cert certbot); `cert-expiry` (`ops.go:128`) = `openssl s_client` ke host:port, bukan file; tidak ada pemindaian `/etc/ssl` dll. |
| 24 | E2 | Terbitkan sertifikat dari CA internal | TIDAK ADA | Benar | tidak ada kode CA |
| 25 | E3 | Periksa file cert/key/CSR | TIDAK ADA | Benar | satu-satunya `openssl x509` ada di `cert-expiry` (`ops.go:128`), lewat jaringan |
| 26 | F1 | Deploy rilis + symlink `current` + rollback | TIDAK ADA | Benar (bukti diperjelas) | `ops.go:265` adalah contoh di bantuan `recipe add` (`cd /srv/{{app}} && git pull && systemctl restart`), bukan recipe bawaan; tidak ada `fs` symlink (lihat laporan SSH §10) |
| 27 | F2 | Deploy container tanpa downtime ke VM | TIDAK ADA | Benar | `docker compose` hanya meneruskan argumen (`modules.go:377`); tidak ada logika rollout |
| 28 | F3 | PaaS self-hosted (dokku, Coolify, CapRover) | TIDAK ADA | Benar | tidak ada recipe/perintah; lewat `exec` |
| 29 | F4 | Process manager non-systemd (pm2, Supervisor) | TIDAK ADA | Benar | `svc` hanya `systemctl`; tidak ada recipe `pm2`/`supervisorctl` di 39 recipe |
| 30 | F5 | Perintah framework aplikasi, PHP-FPM | TIDAK ADA | Benar | tidak ada recipe; `meta.go:457` hanya teks catatan policy |
| 31 | G1 | Backup folder server ke storage | TIDAK ADA | Benar (bukti dikoreksi) | `download -r` ada tapi hanya server → laptop (`transfer.go:106-110`); storage menolak `-r` dan hanya satu file (`transfer.go:62-66`, `:96-99`); tidak ada jalur server → storage, snapshot, dedup, enkripsi, retensi |
| 32 | G2 | Lihat snapshot, umur backup, restore satu file | TIDAK ADA | Benar | tidak ada recipe restic/borg |
| 33 | H1 | Silence alert, lihat alert aktif | TIDAK ADA | Benar | tidak ada kode Alertmanager/Grafana; `SilenceUsage` (`root.go:130`) adalah flag cobra |
| 34 | H2 | Query log terpusat (Loki, Graylog) | TIDAK ADA | Benar | `logs` hanya sumber di host (`modules.go:190-256`) |
| 35 | H3 | Ack insiden / lihat error aplikasi | TIDAK ADA | Benar | tidak ada kode |
| 36 | I1 | Kesehatan disk SMART dan NVMe | TIDAK ADA | Benar | tidak ada recipe `smartctl`; `facts` tidak membaca SMART |
| 37 | I2 | Status RAID software dan pool | TIDAK ADA | Benar | tidak ada recipe `mdadm`/`zpool`; `health` hanya `uptime`/`free`/`df`/`systemctl --failed` |
| 38 | I3 | Perbesar disk setelah volume diperbesar | TIDAK ADA | Benar | tidak ada perintah; lewat `exec` |
| 39 | I4 | Snapshot LVM/ZFS/Btrfs dan rollback | TIDAK ADA | Benar | tidak ada perintah |
| 40 | I5 | Mount NFS/SMB yang macet | TIDAK ADA | Benar (bukti dikoreksi) | recipe `disk`, `inodes`, `health` memakai `df` atas semua mount tanpa `-l`/`-x nfs`; `facts` hanya `df -P -k /` (`ops.go:27`); `--timeout` ada tapi per host untuk seluruh perintah (`probe`, `exec.go:347` `cmdTimeout`), bukan per langkah |
| 41 | J1 | Redaksi secret di output perintah remote | TIDAK ADA | Benar | `redact` (`cluster.go:327`, dipakai `cluster get` di `:453`) dan `redactArgs` (`cluster.go:1110`, hanya argumen audit `cluster run`); `runFleet`/`probe` (`exec.go`) dan `limitedBuf` (`sshx/run.go:121`) meneruskan stdout utuh untuk `exec`, `fs cat`, `logs`, `docker exec` |
| 42 | J2 | fail2ban/CrowdSec | TIDAK ADA | Benar | tidak ada recipe; `auth-failures` hanya membaca log gagal login |
| 43 | J3 | Audit hardening/kepatuhan (CIS) | TIDAK ADA | Benar | hanya recipe baca `sshd-config`, `sudoers`, `auth-failures` |
| 44 | J4 | Baca log auditd | TIDAK ADA | Benar | `logs --file /var/log/audit/audit.log --sudo` membaca teks mentah (`modules.go:232-236`); tidak ada `ausearch`/`aureport` |
| 45 | J5 | Integritas file, rootkit, malware | TIDAK ADA | Benar | tidak ada recipe/perintah |
| 46 | J6 | Scan secret yang bocor di server | TIDAK ADA | Benar | tidak ada recipe/perintah |
| 47 | J7 | Status kernel live patch | TIDAK ADA | Benar | `facts` hanya `reboot_required` dari `/var/run/reboot-required` (`ops.go:33`) |
| 48 | K1 | Cari user/grup di LDAP/AD | TIDAK ADA | Benar | tidak ada kind `ldap` |
| 49 | K2 | Host join domain (SSSD/FreeIPA): cek login user direktori, bersihkan cache | TIDAK ADA | Dikoreksi: SEBAGIAN → TIDAK ADA | `user list` (`modules.go:615`) = `getent passwd` lalu menyaring UID; tidak menerima nama user, tidak cek login, tidak menyentuh cache SSSD. Tidak ada bagian dari kemampuan ini yang dikerjakan komando, jadi bukan "ada tapi kurang" |
| 50 | L1 | Antrian mail | TIDAK ADA | Benar | tidak ada recipe `mailq`/`postqueue` |
| 51 | L2 | Uji kirim SMTP | TIDAK ADA | Benar | `net check` hanya `nc -z` atau `/dev/tcp` (`modules.go:526`), tanpa SMTP/STARTTLS |
| 52 | M1 | Container di node k8s (containerd/CRI-O) | TIDAK ADA | Benar (catatan ditambah) | semua subperintah `docker` membentuk `"docker "+...` (`modules.go:298-387`); alias `ctr` (`modules.go:288`) menunjuk ke `docker`, bukan containerd |
| 53 | N1 | Picu dan pantau pipeline | TIDAK ADA | Benar | tidak ada kode CI; `registry.go:2` hanya menyebut registry GitLab |
| 54 | N2 | Jalankan agen config management sekali | TIDAK ADA | Benar | tidak ada recipe/perintah puppet/chef/salt |
| 55 | N3 | Baca output/state Terraform/Pulumi untuk inventaris | TIDAK ADA | Benar | `importSources` (`importer.go:48-58`) tanpa `terraform`/`pulumi` |
| 56 | N4 | Infrastruktur deklaratif (Terraform, OpenTofu, Pulumi) | NON-GOAL | Baris baru (area "Sudah tercakup" yang tidak punya baris pembanding) | vision.md "Bukan tujuan": "Infrastructure as Code, provisioning cloud, atau GitOps"; tidak ada kode IaC di `internal/` |
| 57 | O1 | Satu koneksi bastion dipakai bersama dalam satu perintah | TIDAK ADA | Benar | `fanout` (`common.go:135-158`) memanggil `sshx.Dial` per host; `Dial` (`sshx/client.go:56-96`) membangun rantai `--via` baru setiap kali (`resolveChain`, `dialDirect`/`dialVia`), tanpa cache klien bastion |
| 58 | S1 | Core dump dan crash | TIDAK ADA | Benar | hanya recipe `oom` (journal kernel/dmesg) |
| 59 | S2 | Bundel diagnosa untuk vendor | TIDAK ADA | Benar | lewat `job start` + `download` |
| 60 | S3 | Tracing/profiling proses | TIDAK ADA | Benar | lewat `exec`/`job` |
| 61 | S4 | Ubah konfigurasi jaringan dengan rollback otomatis | TIDAK ADA | Benar | `facts` hanya membaca `ips` (`ops.go:28`); tidak ada perintah ubah jaringan |
| 62 | T1 | Daftar jenis resource dan contoh URL | ADA | Benar | `connKindsCmd` (`conn.go:322-330`) mencetak `driver.Kinds()` dengan skema, port default, contoh URL |
| 63 | T2 | Lihat dan hapus conn | ADA | Benar (baris diperbaiki: `conn.go:268`) | `connShowCmd` (`conn.go:268`); `connRmCmd` (`conn.go:288`) memanggil `guardProtection("conn", "removing", prot)` di `:304` |
| 64 | T3 | Hapus host yang masih jadi jalur `--via` ditolak | ADA | Benar | `hostRmCmd` (`host.go:315`): `viaChain(o.Via)` untuk host lain (`:331`) dan conn (`:338`) → `HOST_IN_USE` |
| 65 | T4 | Lihat dan hapus VPN | ADA | Benar (baris diperbaiki: `vpn.go:331`) | `vpnShowCmd` (`vpn.go:331`) mencetak `used_by`; `vpnRmCmd` → `VPN_IN_USE` (`vpn.go:366`); kunci tetap di vault (teks `Short` di `vpn.go:354`) |
| 66 | T5 | Hapus recipe sendiri; bawaan tidak bisa | ADA | Benar | `recipeRmCmd` (`ops.go:309-315`): `builtinRecipe(args[0]) != nil` → `RECIPE_BUILTIN` |
| 67 | T6 | Alias per family | ADA | Benar (catatan bug diperluas) | `--help` kesepuluh alias berbunyi "Same as ..."; `svc logs` (`modules.go:158`) dan `docker logs` (`modules.go:323`) memanggil `runOne` walau `-f` tersedia lewat `logOpts.bind`, sedangkan `logs -f` memakai `followLogs` (`modules.go:273`) |
