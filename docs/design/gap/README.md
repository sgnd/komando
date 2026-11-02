# Analisis gap fitur komando vs tools CLI populer

Dokumen ini membandingkan semua fitur komando (`feat/v0.3`, commit 4784fc9,
178 perintah) dengan tools CLI populer di tiap bidang. Tujuannya: tahu apa
yang masih kurang, dan mana yang harus dikerjakan dulu.

## Cara membaca

Setiap kemampuan diberi status:

| Status | Arti |
|---|---|
| **ADA** | komando sudah punya, dengan perintah atau flag yang disebut |
| **SEBAGIAN** | ada, tapi kurang (yang kurang ditulis) |
| **TIDAK ADA** | belum ada (sering masih bisa lewat `exec`, `db query`, `cache run`, `cluster run`) |
| **NON-GOAL** | sengaja tidak dibuat, menurut [vision.md](../vision.md#bukan-tujuan) |

Prioritas gap: **P1** kebutuhan harian, masalah keamanan, atau penghambat agent ·
**P2** berguna · **P3** jarang dipakai.

Setiap status sudah dicek ke kode (`internal/`), dokumen, dan
`komando --help`, bukan dari ingatan. Setelah itu **setiap baris di kelima
laporan (1.010 baris, semua status dan prioritas) dicek ulang satu per satu**
langsung di kode. Hasilnya ada di bagian "Verifikasi per baris" di akhir
tiap laporan. Semua 178 perintah komando juga dicocokkan ke laporan:
setiap perintah tercakup di minimal satu baris. Satu audit lagi mencari tools dan bidang yang sama sekali belum
dibandingkan; hasilnya [coverage-tambahan.md](coverage-tambahan.md).

## Hasil per bidang

| Bidang | Dibandingkan dengan | ADA | SEBAGIAN | TIDAK ADA | NON-GOAL | P1 |
|---|---|---|---|---|---|---|
| [SSH, file, fleet, modul sistem](ssh-files-system.md) | OpenSSH, rsync, pssh, Ansible, Fabric, pyinfra, Salt, Teleport, tmux, systemctl, apt/dnf, certbot, ufw | 104 | 41 | 115 | 13 | 13 |
| [Database dan cache](database-cache.md) | psql, pgcli, mysql, mycli, sqlite3, usql, pg_dump, pg_activity, migrate/Atlas, redis-cli, mongosh, sqlcmd, clickhouse, kcat | 66 | 71 | 67 | 15 | 12 |
| [Storage dan registry](storage-registry.md) | aws s3, mc, rclone, s3cmd, gsutil, azcopy, lftp, crane, skopeo, regctl, oras, cosign, trivy | 26 | 19 | 81 | 12 | 10 |
| [Kubernetes, Swarm, Docker](cluster-docker.md) | kubectl, k9s, stern, helm, kustomize, docker, compose, lazydocker, Swarm CLI | 46 | 83 | 43 | 11 | 23 |
| [VPN, secret, UX platform](vpn-secrets-platform.md) | wg, openvpn, openconnect, tailscale, SSM, cloudflared, op, Vault, sops, gh, aws, kubectl, gcloud | 68 | 40 | 81 | 8 | 10 |
| [Bidang tambahan](coverage-tambahan.md) | macOS/BSD host, perangkat jaringan, IPMI/Redfish, Proxmox, cloud VM, DNS provider, pm2/supervisor, restic/borg, SMART/RAID/ZFS, fail2ban, redaksi output, siklus inventaris dasar, Terraform/IaC | 6 | 3 | 57 | 1 | 1 |
| **Total** | | **316** | **257** | **444** | **60** | **69** |

Total 1.077 kemampuan. Setelah verifikasi per baris, 59 baris dikoreksi
(status, bukti, atau prioritas); tidak ada temuan P1 yang ternyata salah.

Kesimpulan singkat: fondasi komando (inventaris, `exec`, `fs`, keamanan, VPN,
format output) sudah setara atau lebih baik dari tools sejenis untuk kerja
yang aman. Gap terbesar ada di tiga tempat: **siklus deploy di cluster**
(rollout, rollback, ganti image, diff), **transfer massal** (sync, folder,
file besar), dan **pekerjaan DBA harian** (aktivitas, lock, ukuran, backup
format custom).

## Status Fase 1 (selesai)

Fase 1 menutup janji dokumen dan celah keamanan di bagian 1 dan 2, dalam tiga
commit (`fa38148`, `0c3eb85`, `23d1f97`), masing-masing lolos gofmt, vet,
staticcheck, `go test -race` dan e2e Docker (100, 108, 120 cek).

- **Bagian 1:** nomor 1–8 dan 12 selesai. Nomor 9 (`sync`) pindah ke Fase 3,
  nomor 10 (ECR) ke Fase 5, nomor 11 (import termius/tableplus/aws,
  memcached) ke fase berikutnya.
- **Bagian 2:** semua 12 selesai. Upload ke server tetap menimpa file
  (seperti `storage upload` dan `fs write`); yang tidak menimpa tanpa
  `--overwrite` adalah download ke komputer ini.
- **Bug yang ditemukan di jalan:** catalog registry, `docker logs -f`,
  `svc logs -f` dan opsi `statement_timeout` selesai. Fan-out login ke
  bastion (`exec -P 10`) belum.

## Status Fase 2 (selesai)

Siklus deploy cluster dari bagian 3: `cluster deploy` (ganti image),
`cluster status TYPE/NAME --wait` (status rollout), `cluster history` dan
`cluster rollback`, `cluster status` yang menyebut CrashLoopBackOff, replika
kurang dan node bermasalah, `cluster describe`, `cluster events`,
`cluster ls -l` dengan kolom untuk lebih banyak kind, `cluster logs` per
workload, per label dan `-f`, `cluster exec` (dengan cek policy dan
`--read-only`) dan `cluster forward`. Diff sebelum apply sudah ada sejak
Fase 1. Lolos e2e 140/140 di k3s dan Docker Swarm.

## Status Fase 3 (selesai)

Transfer massal dari bagian 3: `komando sync` (server banyak sekaligus,
storage, dan komputer ini; hanya file baru dan berubah; `--exclude`,
`--delete`, dry-run per file), `upload -r` dan `download -r` untuk storage,
`storage cat`, `storage rm --prefix --older-than` dengan `--limit`, upload
ke server secara streaming (file sebesar apa pun), dan `key revoke`. Verb
`sync` yang dijanjikan vision.md (bagian 1 nomor 9) sekarang ada. Lolos
e2e 161/161.

## Status Fase 4 (selesai)

DBA harian dari bagian 3: `db info`, `db activity`, `db locks` (MySQL tanpa
hak PROCESS mendapat `DB_PRIVILEGE` dengan petunjuk), `db sizes`,
`db kill` (batalkan query; `--session` butuh `--allow-dangerous`), foreign
key dan constraint di `db schema`, `db dump --format custom` dengan
`pg_restore` otomatis, serta `--table` dan `--schema-only`. Kelola user dan
role masih lewat `db query --write`. Lolos e2e 177/177.

Tabel di bawah ini adalah keadaan **sebelum** Fase 1.

## 1. Janji di dokumen yang belum dipenuhi kode (kerjakan dulu)

Ini bukan fitur baru. Dokumen komando sudah menjanjikannya, tapi kodenya
belum mengikuti. Ini yang paling membingungkan pengguna dan agent.

| # | Janji | Di mana dijanjikan | Kenyataan |
|---|---|---|---|
| 1 | Perubahan ditolak kalau audit tidak bisa ditulis | ux.md §6 | `audit()` diam saja kalau gagal menulis (gagal terbuka) |
| 2 | File tujuan tidak ditimpa tanpa `--overwrite`, download atomik | ux.md (file transfer) | download dari **server** menulis langsung dengan `O_TRUNC` (`cp.go:284`), upload ke server juga menimpa (`cp.go:210`). Download dari storage sudah benar (tidak menimpa) |
| 3 | Tunnel ke alamat selain 127.0.0.1 butuh `--yes` | network.md | `parseTunnel` menerima `-L 0.0.0.0:...` apa adanya, tanpa konfirmasi (`tunnel.go:68`) |
| 4 | `komando test` mengecek login | help `test`, resources-and-db.md | db dan cache hanya dicek TCP |
| 5 | Completion nama host/conn/grup | ux.md §10 | belum ada `ValidArgsFunction` sama sekali |
| 6 | `komando schema` jadi sumber kebenaran untuk agent | guide, SKILL.md | selector dan ref secret di schema sudah usang (tanpa `kind:`, tanpa `op://`, `vault:`, ...) |
| 7 | Directive ssh_config yang tidak didukung dilaporkan | ux.md §9 | `ProxyCommand`, `Match` dibuang diam-diam saat import |
| 8 | `cluster apply` menampilkan diff | ux.md | `--dry-run` hanya menyebut nama objek |
| 9 | Verb `sync` untuk storage | vision.md | belum ada |
| 10 | Registry ECR didukung | vision.md | credential helper Docker hanya dibaca sekali saat `import docker`; token ECR (berlaku 12 jam) tidak diperbarui |
| 11 | Import `termius`, `tableplus`, `aws`; kind memcached | vision.md | belum dibuat |
| 12 | Tabel status di vision.md | vision.md "Review kondisi sekarang" | masih menulis cluster, registry, ftp, VPN "❌ belum ada", padahal v0.4–v0.7 sudah selesai |

Bug yang ditemukan di jalan:
- `registry ls` (catalog) hanya membaca satu halaman, padahal `Tags` sudah
  mengikuti header `Link`. Daftar repository bisa terpotong tanpa peringatan.
- `docker logs -f` dan `svc logs -f` memakai `runOne`, bukan `followLogs`
  (`modules.go:323`, `modules.go:158`), jadi output ditahan sampai timeout.
  `logs --container -f` dan `logs --unit -f` sudah benar.
- `conn edit --option statement_timeout=10s` (contoh di help `conn edit`)
  diterima tapi tidak dipakai; hanya `cluster` yang membaca opsi conn.
- `exec -P 10` lewat satu bastion membuka 10 login sekaligus ke bastion
  (`sshx.Dial` membuat rantai `--via` per host), dekat batas `MaxStartups`
  default dan bisa memicu fail2ban.

## 2. Celah keamanan dan secret (P1)

| # | Masalah | Bidang |
|---|---|---|
| 1 | `cluster run -- get secret X -o yaml` dinilai read dan mencetak nilai secret (`cluster get` sudah menyembunyikannya) | cluster |
| 2 | Docker di host lebih longgar dari `cluster`: `docker rm -f -v`, `docker raw volume rm`, `compose down -v`, `run --privileged` cukup sebagai perubahan biasa; `docker raw` tidak memakai `classifyDocker` | docker |
| 3 | `secret get --reveal` jalan tanpa terminal dan tanpa `--yes`, jadi agent bisa membaca password, padahal visinya "AI tidak pernah melihat password" | secret |
| 4 | Tidak ada cara memberi secret ke perintah remote tanpa terlihat agent (`--env DB_PASS=secret:x`), sehingga agent terdorong memakai `--reveal` | secret |
| 5 | `secret rm` tidak mengecek apakah secret masih dipakai host/conn/VPN, tanpa konfirmasi, tanpa audit | secret |
| 6 | Password di `CREATE USER ... PASSWORD '...'` tersimpan polos di `audit.jsonl` (default `audit_sql=full`) | db |
| 7 | `registry rm` tidak menyebut tag lain (mis. `latest`, `prod`) yang ikut terhapus | registry |
| 8 | `fs write` tidak bisa memvalidasi file sebelum dipasang (`visudo -cf`, `sshd -t`, `nginx -t`); salah edit sudoers/sshd bisa mengunci semua orang | fs |
| 9 | `fs write --dry-run` tidak menampilkan diff (padahal `fs replace` sudah punya) | fs |
| 10 | Klasifikasi cache tidak rata: `GETDEL`, `RENAME` menimpa, `EXPIRE 0` cukup `--write`, sedangkan `DEL` butuh `--allow-dangerous`; perintah baca modul (`JSON.GET`, `FT.SEARCH`) dinilai write | cache |
| 11 | `host add/edit --password-ref` tidak memvalidasi bentuk ref: `--password-ref hunter2` diterima, password polos tersimpan di `state.json` dan dicetak di output (`conn` dan `vpn` sudah memakai `vault.ValidRef`) | host |
| 12 | Tidak ada redaksi secret di output perintah remote: `fs cat .env`, `exec -- env`, `logs`, `docker exec ... env` mengirim nilai secret apa adanya ke agent | semua |

## 3. Fitur harian yang belum ada (P1)

**Server dan file**
- Cabut public key dari `authorized_keys` di banyak server (offboarding, rotasi key). Sekarang hanya bisa menambah.
- Sinkronisasi folder: hanya yang berubah, `--delete`, `--exclude`, dry-run yang menyebut file apa saja.
- Upload/download file besar tanpa memuat seluruh file ke memori (sekarang `os.ReadFile`).
- Reboot terkendali: reboot → tunggu server kembali → verifikasi. Policy memblokir `reboot`, tapi belum ada jalan amannya, jadi patching tidak bisa selesai.
- `svc daemon-reload` setelah mengubah unit file.

**Database dan cache**
- `db info`: versi, ukuran, koneksi, primary/replica (cache sudah punya `cache info`).
- Aktivitas yang sedang jalan, lock dan siapa memblok siapa, `db kill` dengan dry-run.
- Ukuran database, tabel, dan index terbesar.
  (Recipe `postgres-status` dan `mysql-status` sudah menampilkan sebagian aktivitas dan ukuran, tapi hanya lewat SSH ke server DB dengan `psql`/`mysql` terpasang, bukan lewat conn.)
- Foreign key dan constraint di `db schema`.
- `db dump` format custom/directory (`pg_dump -Fc`) dan restore-nya (`pg_restore`).
- Kelola user/role/grant dengan password dari vault.

**Storage dan registry**
- Upload dan download folder (prefix) untuk storage; sekarang ditolak.
- `storage cat` dengan `--head`/`--tail`, supaya agent tidak perlu download dulu.
- Hapus berdasarkan prefix atau umur (`--older-than`) dengan pratinjau dan batas, untuk membersihkan backup lama.
- Kredensial AWS sementara: session token, profile/SSO, AssumeRole.
- Bersihkan tag registry massal: simpan N terbaru, hapus yang lebih tua dari X.

**Kubernetes dan Swarm**
- Siklus deploy lengkap: ganti image, status rollout/tunggu, rollback (k8s dan Swarm).
- Diff sebelum apply.
- Logs: `--follow` (ux.md sudah mencatatnya sebagai "belum ada"), per workload (`deploy/api`), banyak pod lewat label selector.
- `describe` dan events (Warning saja, urut waktu); filter `-l`; kolom yang berarti untuk ingress, pvc, job, hpa.
- `cluster status` yang menangkap CrashLoopBackOff, ImagePullBackOff, replika kurang, node pressure. (`cluster ls pods` sudah menampilkan alasan `waiting`. `cluster status` hanya menyaring `phase`: pod ImagePullBackOff (Pending) muncul tanpa alasan, dan pod CrashLoopBackOff (berstatus `Running`) tidak muncul sama sekali.)
- Exec read-only ke pod tanpa `--allow-dangerous`; port-forward ke service lewat `tunnel start`.

**Akses dan platform**
- AWS SSM Session Manager (shell dan port forwarding) sebagai langkah `--via`.
- `ProxyCommand` generik sebagai jalan keluar untuk SSM, GCP IAP, cloudflared, tsh.

## 4. Tema P2 terbesar

- **Akses**: sertifikat SSH (user cert, `@cert-authority`), agent forwarding, SAML/SSO untuk openconnect, `HTTPS_PROXY` untuk klien kube dan registry, `vpn edit`.
- **Fleet**: eksekusi bertahap (`serial` gaya Ansible), `lineinfile`/`blockinfile` yang idempoten, `user unlock` dan grup, `download --sudo`, import inventaris Ansible.
- **Secret**: `vault.key` di keyring OS, ref Azure Key Vault/Bitwarden/pass/sops/SSM Parameter Store, kredensial dinamis Vault, export terenkripsi beserta secret.
- **Cluster**: perintah ke banyak cluster sekaligus (`@group`), helm read-only (list/status/history), `kubectl top`/kapasitas, redaksi `docker inspect` dan `compose config`.
- **Database**: engine baru (MongoDB paling diminta; HTTP-based seperti Elasticsearch/OpenSearch, RabbitMQ, Consul paling murah untuk ukuran biner), Redis Cluster/Sentinel, TLS dengan CA sendiri, migrasi schema.
- **Storage**: GCS, Azure Blob, WebDAV; TLS self-signed untuk S3/registry; import filezilla/rclone untuk FTP/FTPS/S3.
- **Platform**: `--debug`/verbose, output CSV, Homebrew, rilis bertanda tangan + SBOM, build Windows, MCP server, inventaris dinamis dari cloud (EC2, GCP, DO, Hetzner), kirim audit ke syslog/SIEM, filter waktu di `audit`.

## 5. Yang sengaja tidak dibuat (NON-GOAL)

Sesuai [vision.md](../vision.md#bukan-tujuan), dan tetap benar setelah
perbandingan ini: TUI/dashboard (k9s, Lens, lazydocker, Portainer,
RedisInsight), helm install/upgrade/template, kustomize, GitOps, Terraform/IaC,
mount/serve storage, monitoring terus-menerus (`MONITOR`, watch), image
mutate/sign, scan kerentanan sendiri, plugin system, daemon. Untuk semua ini,
jawabannya tetap "pakai alat aslinya, atau `exec`".

## 6. Batas teknis yang perlu diputuskan

- **Ukuran biner**: tidak dibatasi (keputusan pemilik; batas 40 MB di
  vision.md dihapus). Build rilis sekarang 35–37 MB. Driver besar seperti
  MongoDB, MSSQL, Azure SDK atau Sigstore tidak lagi terhalang ukuran;
  yang tetap berlaku hanya pure Go (tanpa cgo) dan kebutuhan harian.

## Verifikasi

Dua putaran. Putaran pertama: semua baris P1 dan 12 janji di bagian 1 dicek
langsung di kode. Putaran kedua: **setiap baris** di kelima laporan dicek
ulang (bukti per baris ada di bagian "Verifikasi per baris" tiap laporan),
dengan 59 koreksi: SSH 15, database 10, storage 4, cluster 15, platform 15.
Koreksi status yang penting: login password di SSH turun ke SEBAGIAN (P1,
`--password-ref` tidak divalidasi), file besar naik ke SEBAGIAN (download
dan `upload -r` sudah streaming), beberapa NON-GOAL yang ternyata tidak
disebut di vision.md diubah jadi TIDAK ADA P3.

Di putaran pertama tidak ada P1 yang salah; tiga diperjelas
(download yang menimpa hanya dari server; `cluster ls` vs `cluster status`;
recipe DB), dan satu dikeluarkan dari daftar janji (`logs -f`, karena ux.md
sendiri mencatatnya "belum ada").

| Bidang | Bukti utama di kode |
|---|---|
| SSH/file | tidak ada perintah atau kode yang menghapus baris `authorized_keys`; `cp.go:173` `os.ReadFile` untuk upload; `cp.go:210,284` `O_TRUNC`; `fs write --dry-run` hanya mencetak jumlah byte (`unifiedDiff` hanya dipakai `fs replace`); tidak ada `validate`, `daemon-reload`, atau perintah reboot (hanya recipe yang membaca `reboot-required`) |
| Database | `testConn` hanya `r.Check = "tcp"` (`conn.go:491`); `dbx/schema.go` tanpa foreign key; `dbdump.go` tanpa `-Fc`/`pg_restore`; tidak ada perintah activity/lock/kill/size/role; `db.go` tanpa redaksi password |
| Storage/registry | `transfer.go:64` "storage takes one file"; perintah storage hanya `ls/download/upload/rm/link`; `storex.go:79` `NewStaticV4`; `registry.go` `Catalog` satu kali `getJSON` tanpa `Link`; `registry rm` hanya `would_delete: repo@digest` |
| Cluster/Docker | `cluster ls` tanpa flag selector; tidak ada perintah describe/events/rollout/rollback/set image; Swarm memakai `--detach` (`cluster.go:562,631,684`); `classifyKubectl` menilai `get` read (secret bocor lewat `cluster run`) dan `exec` destructive; `docker rm/raw` lewat `runOne(..., true)` tanpa `classifyDocker` (`modules.go:311,387`); `tunnel.go` tanpa k8s |
| Platform | tidak ada kode SSM/IAP/cloudflared; `ProxyCommand` dan blok `Match` diabaikan diam-diam (`host.go:509`); `secret get --reveal` tanpa cek terminal (`key.go:449`); `secret rm` tanpa cek pemakaian/audit; `audit()` `return` saat gagal; 0 `ValidArgsFunction`; `schema` `secret_refs` hanya `secret:\|env:\|file:` |

### Putaran ketiga: kelengkapan

- **Jumlah baris dicocokkan ulang** dengan parser yang memahami `\|`. Kelima
  laporan cocok persis: 1.010 baris di tabel utama, 1.010 baris di
  "Verifikasi per baris", dan status di keduanya sama untuk setiap baris.
  Lima baris yang memakai `|` di dalam backtick (misalnya
  `--type ed25519|rsa`) merusak tabel di GitHub; sudah di-escape.
- **[coverage-tambahan.md](coverage-tambahan.md) dicek ulang oleh pemeriksa
  independen yang membaca kode langsung** (bukan grep), untuk 67 barisnya.
  Hasilnya: K2 (SSSD/FreeIPA) turun ke TIDAK ADA, baris N4 (Terraform/IaC,
  NON-GOAL) ditambahkan karena belum ada baris pembandingnya, dan bukti di 10
  baris diperbaiki. Dari 27 area "Sudah tercakup", 25 benar-benar punya baris
  pembanding dan 2 diperbaiki (build image, Terraform/IaC).
- **Semua 178 perintah komando dipetakan secara ketat** ke baris perbandingan:
  baris yang menyebut perintah itu di dalam backtick **dan** punya tool
  pembanding (lihat [lampiran](#lampiran-peta-178-perintah-ke-baris-perbandingan)).
  Pencocokan longgar sebelumnya (kata yang sama di satu baris) tidak dipakai.
  Perintah yang belum punya baris sendiri ditambahkan: `conn kinds/rm/show`,
  `vpn show/rm`, `recipe rm` dan semua alias (area T), lalu `guide install`,
  `secret list` dan `storage download` disebut eksplisit di baris yang sudah
  ada, lengkap dengan tool pembandingnya.

## Urutan yang disarankan

1. **Penuhi janji di bagian 1 dan tutup celah di bagian 2.** Kecil-kecil, dan
   langsung menaikkan kepercayaan pada kontrak keamanan komando.
2. **Siklus deploy cluster** (rollout, rollback, ganti image, diff, logs -f).
   Ini kerja harian paling sering di bidang yang gap P1-nya paling banyak.
3. **Transfer massal** (sync, folder di storage, file besar, cabut key).
4. **DBA harian** (`db info`, aktivitas, lock, ukuran, dump format custom).
5. **Akses cloud** (SSM, `ProxyCommand`, kredensial AWS sementara).

## Lampiran: peta 178 perintah ke baris perbandingan

Setiap perintah komando dicocokkan secara ketat: baris yang **menyebut perintah itu di dalam backtick** (termasuk bentuk gabungan seperti `svc start/stop/restart`) **dan** punya tool pembanding. Kolom "Baris" menyebut jumlah baris yang cocok; satu contoh ditampilkan.

| Perintah | Baris | Contoh: laporan § kemampuan | Tool pembanding (contoh) |
|---|---|---|---|
| `audit` | 5 | [Cluster](cluster-docker.md) §7 Audit setiap perubahan | kubectl (tidak), Lens (tidak) |
| `cache` | 43 | [DB](database-cache.md) §7 Ringkasan server: versi, uptime, ukuran DB, koneksi/max_connections, r | `\conninfo`, `SELECT version()`, `mysqladmin status`, pg_activity head |
| `cache get` | 5 | [DB](database-cache.md) §13 Baca key tipe apa pun + TTL + ukuran | redis-cli `GET/HGETALL/...`, RedisInsight browser |
| `cache info` | 8 | [DB](database-cache.md) §7 Ringkasan server: versi, uptime, ukuran DB, koneksi/max_connections, r | `\conninfo`, `SELECT version()`, `mysqladmin status`, pg_activity head |
| `cache keys` | 7 | [DB](database-cache.md) §12 Redis Cluster (MOVED/ASK, ElastiCache cluster mode, `redis-cli -c`) | redis-cli `-c` |
| `cache rm` | 3 | [DB](database-cache.md) §14 Hapus key tepat | redis-cli `DEL/UNLINK` |
| `cache run` | 24 | [DB](database-cache.md) §12 Sentinel (temukan master) | redis-cli `-p 26379`, `SENTINEL get-master-addr-by-name` |
| `cache set` | 4 | [DB](database-cache.md) §14 Set string + TTL | redis-cli `SET ... EX` |
| `cluster` | 98 | [Cluster](cluster-docker.md) §1 Pindah cluster/context | kubectx, `kubectl config use-context` |
| `cluster apply` | 6 | [Cluster](cluster-docker.md) §5 Apply YAML multi-dokumen, server-side apply | `kubectl apply --server-side` |
| `cluster get` | 11 | [Cluster](cluster-docker.md) §2 Objek lengkap (YAML/JSON) | `kubectl get -o yaml` |
| `cluster logs` | 5 | [Cluster](cluster-docker.md) §3 Log satu pod, tail N, since, timestamps | `kubectl logs --tail --since --timestamps` |
| `cluster ls` | 13 | [Cluster](cluster-docker.md) §1 Pindah cluster/context | kubectx, `kubectl config use-context` |
| `cluster restart` | 3 | [Cluster](cluster-docker.md) §5 Status rollout / tunggu sampai selesai | `kubectl rollout status`, `kubectl wait` |
| `cluster rm` | 5 | [Cluster](cluster-docker.md) §5 Hapus objek | `kubectl delete` |
| `cluster run` | 64 | [Cluster](cluster-docker.md) §1 Daftar context | `kubectl config get-contexts` |
| `cluster scale` | 2 | [Cluster](cluster-docker.md) §5 Scale | `kubectl scale` |
| `cluster status` | 8 | [Cluster](cluster-docker.md) §1 Cek koneksi cluster | `kubectl cluster-info`, `kubectl version` |
| `config` | 7 | [Cluster](cluster-docker.md) §1 Daftar context | `kubectl config get-contexts` |
| `config set` | 6 | [SSH](ssh-files-system.md) §1 Connect timeout | ssh `ConnectTimeout` |
| `config show` | 1 | [Platform](vpn-secrets-platform.md) §C1 Satu file konfigurasi + `config show/set` | `aws configure`, `gh config` |
| `conn` | 12 | [Cluster](cluster-docker.md) §1 Daftar context | `kubectl config get-contexts` |
| `conn add` | 4 | [DB](database-cache.md) §1 Daftarkan DB dengan URL, password di vault | psql (`PG*` env, `.pgpass`), mysql (`.my.cnf`), usql, DBeaver |
| `conn edit` | 3 | [Cluster](cluster-docker.md) §1 Namespace default per cluster (ganti) | kubens, `kubectl config set-context --namespace` |
| `conn kinds` | 1 | [Tambahan](coverage-tambahan.md) §T Daftar jenis resource yang didukung beserta contoh URL | `rclone help backends`, usql `\drivers` |
| `conn list` | 2 | [Cluster](cluster-docker.md) §1 Daftar context | `kubectl config get-contexts` |
| `conn rm` | 1 | [Tambahan](coverage-tambahan.md) §T Lihat dan hapus conn (secret tetap ref, conn protected dijaga) | DBeaver, `rclone config show/delete` |
| `conn show` | 1 | [Tambahan](coverage-tambahan.md) §T Lihat dan hapus conn (secret tetap ref, conn protected dijaga) | DBeaver, `rclone config show/delete` |
| `conn test` | 2 | [Tambahan](coverage-tambahan.md) §T Alias per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `cp` | 9 | [Cluster](cluster-docker.md) §4 Copy file ke/dari pod | `kubectl cp` |
| `cron` | 10 | [DB](database-cache.md) §6 Backup terjadwal + retensi | pgBackRest, cron |
| `cron list` | 2 | [SSH](ssh-files-system.md) §14 Daftar entri (dengan ID) | crontab -l |
| `cron rm` | 3 | [SSH](ssh-files-system.md) §14 Hapus entri | Ansible `cron state=absent` |
| `cron set` | 7 | [DB](database-cache.md) §6 Backup terjadwal + retensi | pgBackRest, cron |
| `db` | 65 | [DB](database-cache.md) §1 TLS Postgres (sslmode, sslrootcert, client cert) | psql `sslmode`/`sslrootcert`/`sslcert` |
| `db dump` | 9 | [DB](database-cache.md) §1 TLS Postgres (sslmode, sslrootcert, client cert) | psql `sslmode`/`sslrootcert`/`sslcert` |
| `db explain` | 1 | [DB](database-cache.md) §2 EXPLAIN / EXPLAIN ANALYZE | psql, pgcli, DataGrip |
| `db query` | 40 | [DB](database-cache.md) §1 Query ke banyak DB sekaligus (`db query @prod`) | usql (tidak), skrip loop, DataGrip "run on multiple" |
| `db restore` | 2 | [DB](database-cache.md) §3 Salin data antar DB (tabel A di prod → staging) | DBeaver data transfer, pg_dump `-t` \| psql |
| `db schema` | 10 | [DB](database-cache.md) §1 Postgres-wire lain: CockroachDB, YugabyteDB, Neon, Supabase, Timescale | cockroach sql, psql |
| `db shell` | 9 | [DB](database-cache.md) §1 TLS Postgres (sslmode, sslrootcert, client cert) | psql `sslmode`/`sslrootcert`/`sslcert` |
| `docker` | 47 | [Cluster](cluster-docker.md) §1 Docker host remote | `docker context`, `DOCKER_HOST=ssh://` |
| `docker compose` | 3 | [Cluster](cluster-docker.md) §3 Log compose project (semua service) | `docker compose logs --tail -f` |
| `docker exec` | 7 | [Cluster](cluster-docker.md) §4 Exec perintah di pod (non-interaktif) | `kubectl exec POD -- cmd` |
| `docker images` | 2 | [Cluster](cluster-docker.md) §10 Images terstruktur | `docker images` |
| `docker inspect` | 1 | [Cluster](cluster-docker.md) §10 Inspect | `docker inspect` |
| `docker logs` | 2 | [Cluster](cluster-docker.md) §3 Log container di host (tail/since/until/grep/follow) | `docker logs`, lazydocker |
| `docker ps` | 3 | [Cluster](cluster-docker.md) §10 ps terstruktur (semua container) | `docker ps -a`, lazydocker, ctop |
| `docker pull` | 4 | [Cluster](cluster-docker.md) §10 Pull image | `docker pull` |
| `docker raw` | 17 | [Cluster](cluster-docker.md) §4 Copy file host<->container | `docker cp` |
| `docker restart` | 1 | [Cluster](cluster-docker.md) §10 Start/stop/restart | `docker start/stop/restart` |
| `docker rm` | 1 | [Cluster](cluster-docker.md) §10 Hapus container | `docker rm` |
| `docker start` | 1 | [Cluster](cluster-docker.md) §10 Start/stop/restart | `docker start/stop/restart` |
| `docker stats` | 2 | [Cluster](cluster-docker.md) §10 Stats CPU/mem terstruktur | `docker stats --no-stream`, ctop |
| `docker stop` | 1 | [Cluster](cluster-docker.md) §10 Start/stop/restart | `docker start/stop/restart` |
| `doctor` | 2 | [SSH](ssh-files-system.md) §1 Pakai ssh-agent (termasuk 1Password/Secretive agent lewat `SSH_AUTH_SO | ssh-agent, `IdentityAgent` |
| `download` | 12 | [Tambahan](coverage-tambahan.md) §G Backup folder server ke storage (snapshot, dedup, enkripsi, retensi) | restic, borg, kopia, duplicity |
| `exec` | 41 | [Cluster](cluster-docker.md) §1 Podman sebagai engine | podman CLI, podman-remote |
| `export` | 5 | [SSH](ssh-files-system.md) §4 Export / pindah komputer | Termius sync |
| `facts` | 12 | [Tambahan](coverage-tambahan.md) §A Host macOS (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt |
| `fs` | 41 | [Cluster](cluster-docker.md) §11 Edit compose file/env di host | editor + ssh |
| `fs cat` | 7 | [Tambahan](coverage-tambahan.md) §J Redaksi secret di **output** perintah remote (`fs cat .env`, `exec --  | aturan gitleaks/trufflehog, Teleport (redaksi sesi) |
| `fs chmod` | 2 | [SSH](ssh-files-system.md) §10 mkdir -p, mv, chmod (rekursif), rm (rekursif) | Ansible `file` |
| `fs ls` | 3 | [SSH](ssh-files-system.md) §9 Browsing interaktif ala sftp shell | sftp, Cyberduck |
| `fs mkdir` | 1 | [SSH](ssh-files-system.md) §10 mkdir -p, mv, chmod (rekursif), rm (rekursif) | Ansible `file` |
| `fs mv` | 3 | [SSH](ssh-files-system.md) §9 Salin file di dalam satu server | Ansible `copy remote_src` |
| `fs replace` | 9 | [Cluster](cluster-docker.md) §11 Edit compose file/env di host | editor + ssh |
| `fs rm` | 1 | [SSH](ssh-files-system.md) §10 mkdir -p, mv, chmod (rekursif), rm (rekursif) | Ansible `file` |
| `fs stat` | 4 | [SSH](ssh-files-system.md) §9 Browsing interaktif ala sftp shell | sftp, Cyberduck |
| `fs write` | 19 | [SSH](ssh-files-system.md) §9 Upload dengan mode, buat folder induk, pasang via sudo | Ansible `copy mode/become` |
| `group` | 1 | [SSH](ssh-files-system.md) §4 Grup, tag, label key=value, catatan | Termius tags, Ansible groups/vars |
| `group add` | 1 | [SSH](ssh-files-system.md) §4 Grup, tag, label key=value, catatan | Termius tags, Ansible groups/vars |
| `group list` | 1 | [SSH](ssh-files-system.md) §4 Grup, tag, label key=value, catatan | Termius tags, Ansible groups/vars |
| `group rm` | 1 | [SSH](ssh-files-system.md) §4 Grup, tag, label key=value, catatan | Termius tags, Ansible groups/vars |
| `guide` | 2 | [Platform](vpn-secrets-platform.md) §C3 Dokumen offline | `gh help`, `az find` |
| `guide install` | 1 | [Platform](vpn-secrets-platform.md) §C8 Skill untuk Claude Code, Codex, Cursor, Gemini CLI | `claude mcp add`, `npx skills add`, aturan Cursor (`.cursor/rules`) |
| `host` | 22 | [Tambahan](coverage-tambahan.md) §T Hapus host yang masih jadi jalur `--via` host/conn lain ditolak | Termius (tanpa cek), Ansible (tanpa cek) |
| `host add` | 4 | [SSH](ssh-files-system.md) §1 Login dengan private key file | ssh `-i`, `IdentityFile` |
| `host edit` | 4 | [SSH](ssh-files-system.md) §1 Login dengan private key file | ssh `-i`, `IdentityFile` |
| `host export` | 2 | [SSH](ssh-files-system.md) §1 Ekspor inventaris ke `ssh_config` (supaya ssh/scp/VS Code Remote memak | Termius, Teleport `tsh config` |
| `host import` | 3 | [SSH](ssh-files-system.md) §1 `Match` blok di ssh_config (Match host/user/exec) | ssh_config |
| `host list` | 1 | [Tambahan](coverage-tambahan.md) §T Alias per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `host rm` | 2 | [Tambahan](coverage-tambahan.md) §T Hapus host yang masih jadi jalur `--via` host/conn lain ditolak | Termius (tanpa cek), Ansible (tanpa cek) |
| `host show` | 1 | [SSH](ssh-files-system.md) §4 Tambah/ubah/hapus/lihat host | Termius, Ansible inventory |
| `host ssh-command` | 1 | [SSH](ssh-files-system.md) §1 Ekspor inventaris ke `ssh_config` (supaya ssh/scp/VS Code Remote memak | Termius, Teleport `tsh config` |
| `host test` | 1 | [Tambahan](coverage-tambahan.md) §T Alias per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `host trust` | 4 | [SSH](ssh-files-system.md) §3 Ambil & pin host key (keyscan), juga di balik bastion | ssh-keyscan |
| `import` | 16 | [Cluster](cluster-docker.md) §1 Impor kubeconfig, satu conn per context | kubectl config, Lens |
| `job` | 20 | [Cluster](cluster-docker.md) §5 Jalankan Job dari CronJob sekarang | `kubectl create job --from=cronjob/x` |
| `job kill` | 2 | [SSH](ssh-files-system.md) §7 Hentikan (sinyal ke process group) | kill |
| `job list` | 1 | [SSH](ssh-files-system.md) §7 Status, exit code, runtime, tail log | `jobs`, tmux |
| `job logs` | 2 | [SSH](ssh-files-system.md) §7 Baca log inkremental | `tail -f` |
| `job rm` | 1 | [Platform](vpn-secrets-platform.md) §C9 Job panjang terlepas | `nohup`, Ansible async |
| `job start` | 10 | [Tambahan](coverage-tambahan.md) §S Bundel diagnosa untuk vendor | `sosreport`, `supportconfig` |
| `job status` | 2 | [SSH](ssh-files-system.md) §7 Status, exit code, runtime, tail log | `jobs`, tmux |
| `job wait` | 4 | [SSH](ssh-files-system.md) §7 Tunggu selesai dengan batas waktu | Ansible `async_status`, `wait` |
| `key` | 14 | [SSH](ssh-files-system.md) §1 Key terenkripsi (passphrase dari vault) | ssh + ssh-agent |
| `key add` | 4 | [SSH](ssh-files-system.md) §1 Key terenkripsi (passphrase dari vault) | ssh + ssh-agent |
| `key deploy` | 6 | [SSH](ssh-files-system.md) §2 Pasang public key ke server (idempoten) | ssh-copy-id, Ansible `authorized_key` |
| `key edit` | 2 | [SSH](ssh-files-system.md) §1 Key terenkripsi (passphrase dari vault) | ssh + ssh-agent |
| `key gen` | 5 | [SSH](ssh-files-system.md) §2 Buat key pair ed25519 / RSA | ssh-keygen |
| `key list` | 2 | [SSH](ssh-files-system.md) §2 Lihat public key dan fingerprint | ssh-keygen `-y`, `-l` |
| `key rm` | 1 | [Platform](vpn-secrets-platform.md) §B3 Generate/register/deploy kunci SSH | `ssh-keygen`, `ssh-copy-id` |
| `key show` | 2 | [SSH](ssh-files-system.md) §2 Lihat public key dan fingerprint | ssh-keygen `-y`, `-l` |
| `list` | 9 | [Cluster](cluster-docker.md) §1 Daftar context | `kubectl config get-contexts` |
| `logs` | 23 | [Cluster](cluster-docker.md) §2 Watch perubahan (`-w`) | `kubectl get -w`, k9s |
| `net` | 10 | [Tambahan](coverage-tambahan.md) §D Kelola record DNS di provider (list/set/rm A, CNAME, TXT) dengan dry-r | dnscontrol, octoDNS, `flarectl`/Cloudflare API, `aws route53`, `doctl  |
| `net check` | 3 | [Tambahan](coverage-tambahan.md) §L Uji kirim SMTP dari server (auth, STARTTLS) | swaks, `openssl s_client -starttls smtp` |
| `net dns` | 2 | [Tambahan](coverage-tambahan.md) §D Kelola record DNS di provider (list/set/rm A, CNAME, TXT) dengan dry-r | dnscontrol, octoDNS, `flarectl`/Cloudflare API, `aws route53`, `doctl  |
| `net http` | 2 | [SSH](ssh-files-system.md) §17 HTTP dari server (status, timing, IP) | curl -w |
| `net ports` | 2 | [SSH](ssh-files-system.md) §16 File terbuka / siapa memegang file/port | lsof, fuser |
| `pkg` | 10 | [Tambahan](coverage-tambahan.md) §A Host macOS (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt |
| `pkg install` | 1 | [SSH](ssh-files-system.md) §12 Install / remove / update index / upgrade (semua manajer, auto-detect) | apt, dnf, Ansible `package` |
| `pkg installed` | 1 | [SSH](ssh-files-system.md) §12 Versi terinstal | dpkg-query, rpm -q |
| `pkg rm` | 1 | [SSH](ssh-files-system.md) §12 Install / remove / update index / upgrade (semua manajer, auto-detect) | apt, dnf, Ansible `package` |
| `pkg update` | 1 | [SSH](ssh-files-system.md) §12 Install / remove / update index / upgrade (semua manajer, auto-detect) | apt, dnf, Ansible `package` |
| `pkg upgradable` | 1 | [SSH](ssh-files-system.md) §12 Daftar upgrade tertunda | apt list --upgradable |
| `pkg upgrade` | 5 | [SSH](ssh-files-system.md) §7 Modul lambat otomatis jadi job (`pkg upgrade`, `db dump` di server) | Ansible async per task |
| `policy` | 2 | [DB](database-cache.md) §2 Klasifikasi risiko sebelum kirim | (tidak ada) |
| `policy allow` | 1 | [SSH](ssh-files-system.md) §5 Guardrail perintah berbahaya | — (Teleport hanya RBAC) |
| `policy check` | 2 | [DB](database-cache.md) §2 Klasifikasi risiko sebelum kirim | (tidak ada) |
| `policy deny` | 1 | [SSH](ssh-files-system.md) §5 Guardrail perintah berbahaya | — (Teleport hanya RBAC) |
| `policy list` | 1 | [SSH](ssh-files-system.md) §5 Guardrail perintah berbahaya | — (Teleport hanya RBAC) |
| `recipe` | 9 | [Tambahan](coverage-tambahan.md) §F Perintah framework aplikasi (`artisan`, `manage.py`, `rails runner`),  | artisan, Django, Rails, `php-fpm -t` |
| `recipe add` | 3 | [Tambahan](coverage-tambahan.md) §F Perintah framework aplikasi (`artisan`, `manage.py`, `rails runner`),  | artisan, Django, Rails, `php-fpm -t` |
| `recipe list` | 1 | [SSH](ssh-files-system.md) §19 39 recipe bawaan (health, disk, certs, security, network, db, web) | Termius snippets, Salt modules |
| `recipe rm` | 1 | [Tambahan](coverage-tambahan.md) §T Hapus recipe sendiri; recipe bawaan tidak bisa dihapus | Termius snippets, Fabric |
| `recipe run` | 3 | [SSH](ssh-files-system.md) §4 Variabel per host untuk recipe/template (`{{app}}` per host) | Ansible host_vars |
| `registry` | 15 | [Cluster](cluster-docker.md) §9 Stack deploy dengan auth registry | `docker stack deploy --with-registry-auth` |
| `registry copy` | 4 | [Cluster](cluster-docker.md) §10 Tag/push image | `docker tag/push` |
| `registry inspect` | 2 | [Cluster](cluster-docker.md) §10 Analisis layer image | dive |
| `registry ls` | 4 | [Storage](storage-registry.md) §H Daftar repository (catalog) | `crane catalog`, `regctl repo ls`, `skopeo` (tidak), Harbor API |
| `registry rm` | 2 | [Cluster](cluster-docker.md) §10 Hapus image (rmi) | `docker rmi`, `image rm` |
| `schema` | 5 | [DB](database-cache.md) §4 Daftar tabel/view + perkiraan baris (`\dt`, `.tables`, `SHOW TABLES`) | psql, sqlite3, mysql |
| `script` | 2 | [SSH](ssh-files-system.md) §5 Jalankan skrip lokal di remote tanpa menyalin | Ansible `script`, pyinfra, `ssh 'bash -s' < x` |
| `secret` | 13 | [Cluster](cluster-docker.md) §5 Buat Secret/ConfigMap dari file/literal | `kubectl create secret generic --from-literal`, `create configmap` |
| `secret get` | 3 | [Cluster](cluster-docker.md) §7 Lihat satu nilai Secret atas permintaan manusia | `kubectl get secret -o jsonpath \| base64 -d` |
| `secret list` | 1 | [Platform](vpn-secrets-platform.md) §B1 Vault terenkripsi (AES-256-GCM, scrypt), daftar nama secret tanpa nila | `pass`/`pass ls`, `gopass ls`, ansible-vault, `vault kv list` |
| `secret rm` | 2 | [Tambahan](coverage-tambahan.md) §T Lihat dan hapus VPN; hapus ditolak bila masih dipakai `--via` | `nmcli con show/delete`, `tailscale logout` |
| `secret set` | 3 | [Platform](vpn-secrets-platform.md) §B1 Input secret tanpa argumen (prompt tersembunyi, `--from-env`, stdin) | `gh secret set` |
| `shell` | 6 | [Tambahan](coverage-tambahan.md) §B Konsol serial / Serial-over-LAN | `ipmitool sol activate`, conserver, `screen /dev/ttyUSB0` |
| `storage` | 14 | [Tambahan](coverage-tambahan.md) §G Backup folder server ke storage (snapshot, dedup, enkripsi, retensi) | restic, borg, kopia, duplicity |
| `storage download` | 2 | [Tambahan](coverage-tambahan.md) §T Alias per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `storage link` | 1 | [Storage](storage-registry.md) §C Presigned download URL | `aws s3 presign`, `mc share download`, `rclone link`, `gsutil signurl` |
| `storage ls` | 3 | [Storage](storage-registry.md) §A List satu level (folder sebagai prefix) | `aws s3 ls`, `mc ls`, `rclone lsf`, `s3cmd ls`, `gsutil ls`, `lftp ls` |
| `storage rm` | 1 | [Storage](storage-registry.md) §A Hapus objek tepat | `aws s3 rm`, `mc rm`, `rclone deletefile`, `s3cmd del`, `lftp rm` |
| `storage upload` | 3 | [Tambahan](coverage-tambahan.md) §G Backup folder server ke storage (snapshot, dedup, enkripsi, retensi) | restic, borg, kopia, duplicity |
| `svc` | 12 | [Tambahan](coverage-tambahan.md) §A Host macOS (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt |
| `svc disable` | 1 | [SSH](ssh-files-system.md) §11 enable/disable | systemctl |
| `svc enable` | 1 | [SSH](ssh-files-system.md) §11 enable/disable | systemctl |
| `svc list` | 1 | [SSH](ssh-files-system.md) §11 Daftar unit + filter failed/state | systemctl list-units |
| `svc logs` | 1 | [Tambahan](coverage-tambahan.md) §T Alias per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `svc reload` | 2 | [SSH](ssh-files-system.md) §11 start/stop/restart/reload + laporan state + journal saat gagal | systemctl, Ansible `systemd` |
| `svc restart` | 1 | [SSH](ssh-files-system.md) §11 start/stop/restart/reload + laporan state + journal saat gagal | systemctl, Ansible `systemd` |
| `svc start` | 1 | [SSH](ssh-files-system.md) §11 start/stop/restart/reload + laporan state + journal saat gagal | systemctl, Ansible `systemd` |
| `svc status` | 1 | [SSH](ssh-files-system.md) §11 Status terstruktur | systemctl show |
| `svc stop` | 1 | [SSH](ssh-files-system.md) §11 start/stop/restart/reload + laporan state + journal saat gagal | systemctl, Ansible `systemd` |
| `test` | 16 | [Cluster](cluster-docker.md) §1 Cek koneksi cluster | `kubectl cluster-info`, `kubectl version` |
| `tunnel` | 14 | [Cluster](cluster-docker.md) §4 Port-forward ke pod/service | `kubectl port-forward`, k9s, Lens |
| `tunnel list` | 2 | [SSH](ssh-files-system.md) §8 Tunnel di latar, list, stop | autossh `-f`, Termius |
| `tunnel start` | 9 | [Cluster](cluster-docker.md) §4 Port-forward ke pod/service | `kubectl port-forward`, k9s, Lens |
| `tunnel stop` | 2 | [SSH](ssh-files-system.md) §8 Tunnel di latar, list, stop | autossh `-f`, Termius |
| `upload` | 16 | [Tambahan](coverage-tambahan.md) §A Host macOS (launchd, Homebrew, `sw_vers`) | Ansible (`community.general.launchd`, `homebrew`), Salt |
| `user` | 11 | [Tambahan](coverage-tambahan.md) §K Host yang join domain (SSSD/FreeIPA): cek user direktori bisa login, b | `id`, `getent passwd`, `sss_cache -E`, `ipa` |
| `user add` | 4 | [SSH](ssh-files-system.md) §2 Cabut / hapus public key dari `authorized_keys` di banyak server (offb | Ansible `authorized_key state=absent`, Teleport |
| `user list` | 2 | [Tambahan](coverage-tambahan.md) §K Host yang join domain (SSSD/FreeIPA): cek user direktori bisa login, b | `id`, `getent passwd`, `sss_cache -E`, `ipa` |
| `user lock` | 1 | [SSH](ssh-files-system.md) §13 Kunci akun | usermod -L |
| `user rm` | 1 | [SSH](ssh-files-system.md) §13 Hapus user (dangerous) | userdel |
| `version` | 1 | [Platform](vpn-secrets-platform.md) §C5 Cek versi / self-update | `gh` (notifikasi), `flyctl version upgrade` |
| `vpn` | 16 | [Tambahan](coverage-tambahan.md) §T Lihat dan hapus VPN; hapus ditolak bila masih dipakai `--via` | `nmcli con show/delete`, `tailscale logout` |
| `vpn add` | 6 | [SSH](ssh-files-system.md) §1 Password login (tersimpan aman) | ssh + sshpass |
| `vpn down` | 1 | [Platform](vpn-secrets-platform.md) §A1 Sesi latar per VPN dipakai ulang + putus saat idle | `tailscale up`, `nmcli` |
| `vpn list` | 1 | [Tambahan](coverage-tambahan.md) §T Alias per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `vpn rm` | 1 | [Tambahan](coverage-tambahan.md) §T Lihat dan hapus VPN; hapus ditolak bila masih dipakai `--via` | `nmcli con show/delete`, `tailscale logout` |
| `vpn show` | 1 | [Tambahan](coverage-tambahan.md) §T Lihat dan hapus VPN; hapus ditolak bila masih dipakai `--via` | `nmcli con show/delete`, `tailscale logout` |
| `vpn status` | 4 | [Platform](vpn-secrets-platform.md) §A1 Sesi latar per VPN dipakai ulang + putus saat idle | `tailscale up`, `nmcli` |
| `vpn test` | 1 | [Tambahan](coverage-tambahan.md) §T Alias per family: `host list`, `conn list`, `vpn list`, `host test`, ` | `kubectl get` per resource, `gh repo list`/`gh pr list`, `aws s3 ls` |
| `vpn up` | 4 | [Platform](vpn-secrets-platform.md) §A1 Sesi latar per VPN dipakai ulang + putus saat idle | `tailscale up`, `nmcli` |
