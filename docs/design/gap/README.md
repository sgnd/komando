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

Setiap status "TIDAK ADA" sudah dicek ke kode (`internal/`), dokumen, dan
`komando --help`, bukan dari ingatan. Lalu **semua 66 baris P1 dan semua
janji di bagian 1 dicek ulang satu per satu langsung di kode** (lihat
[Verifikasi](#verifikasi)).

## Hasil per bidang

| Bidang | Dibandingkan dengan | ADA | SEBAGIAN | TIDAK ADA | NON-GOAL | P1 |
|---|---|---|---|---|---|---|
| [SSH, file, fleet, modul sistem](ssh-files-system.md) | OpenSSH, rsync, pssh, Ansible, Fabric, pyinfra, Salt, Teleport, tmux, systemctl, apt/dnf, certbot, ufw | 106 | 36 | 117 | 14 | 11 |
| [Database dan cache](database-cache.md) | psql, pgcli, mysql, mycli, sqlite3, usql, pg_dump, pg_activity, migrate/Atlas, redis-cli, mongosh, sqlcmd, clickhouse, kcat | 66 | 63 | 72 | 15 | 12 |
| [Storage dan registry](storage-registry.md) | aws s3, mc, rclone, s3cmd, gsutil, azcopy, lftp, crane, skopeo, regctl, oras, cosign, trivy | 27 | 18 | 80 | 13 | 10 |
| [Kubernetes, Swarm, Docker](cluster-docker.md) | kubectl, k9s, stern, helm, kustomize, docker, compose, lazydocker, Swarm CLI | 46 | 83 | 41 | 12 | 23 |
| [VPN, secret, UX platform](vpn-secrets-platform.md) | wg, openvpn, openconnect, tailscale, SSM, cloudflared, op, Vault, sops, gh, aws, kubectl, gcloud | 68 | 40 | 78 | 11 | 10 |
| **Total** | | **313** | **240** | **388** | **65** | **66** |

Kesimpulan singkat: fondasi komando (inventaris, `exec`, `fs`, keamanan, VPN,
format output) sudah setara atau lebih baik dari tools sejenis untuk kerja
yang aman. Gap terbesar ada di tiga tempat: **siklus deploy di cluster**
(rollout, rollback, ganti image, diff), **transfer massal** (sync, folder,
file besar), dan **pekerjaan DBA harian** (aktivitas, lock, ukuran, backup
format custom).

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

Bug yang ditemukan di jalan: `registry ls` (catalog) hanya membaca satu
halaman, padahal `Tags` sudah mengikuti header `Link`. Daftar repository
bisa terpotong tanpa peringatan.

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
- `cluster status` yang menangkap CrashLoopBackOff, ImagePullBackOff, replika kurang, node pressure. (`cluster ls pods` sudah menampilkan alasan `waiting`, tapi `cluster status` hanya menyaring `phase`, padahal pod CrashLoopBackOff berstatus `Running`.)
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

- **Ukuran biner**: build rilis (`-s -w -trimpath`, `CGO_ENABLED=0`) sekarang
  34,7 MB dari anggaran 40 MB. Sisa ~5 MB tidak cukup untuk beberapa driver
  besar sekaligus (Mongo +6–8 MB). Engine baru perlu dipilih dengan hati-hati,
  atau anggarannya diputuskan ulang. (`bin/komando` 51 MB di folder kerja
  adalah build dev tanpa strip.)

## Verifikasi

Semua 66 baris P1 dan 12 janji di bagian 1 dicek langsung di kode setelah
laporan per bidang selesai. Tidak ada yang salah; tiga diperjelas
(download yang menimpa hanya dari server; `cluster ls` vs `cluster status`;
recipe DB), dan satu dikeluarkan dari daftar janji (`logs -f`, karena ux.md
sendiri mencatatnya "belum ada").

| Bidang | Bukti utama di kode |
|---|---|
| SSH/file | tidak ada perintah atau kode yang menghapus baris `authorized_keys`; `cp.go:173` `os.ReadFile` untuk upload; `cp.go:210,284` `O_TRUNC`; `fs write --dry-run` hanya mencetak jumlah byte (`unifiedDiff` hanya dipakai `fs replace`); tidak ada `validate`, `daemon-reload`, atau perintah reboot (hanya recipe yang membaca `reboot-required`) |
| Database | `testConn` hanya `r.Check = "tcp"` (`conn.go:491`); `dbx/schema.go` tanpa foreign key; `dbdump.go` tanpa `-Fc`/`pg_restore`; tidak ada perintah activity/lock/kill/size/role; `db.go` tanpa redaksi password |
| Storage/registry | `transfer.go:64` "storage takes one file"; perintah storage hanya `ls/download/upload/rm/link`; `storex.go:79` `NewStaticV4`; `registry.go` `Catalog` satu kali `getJSON` tanpa `Link`; `registry rm` hanya `would_delete: repo@digest` |
| Cluster/Docker | `cluster ls` tanpa flag selector; tidak ada perintah describe/events/rollout/rollback/set image; Swarm memakai `--detach` (`cluster.go:562,631,684`); `classifyKubectl` menilai `get` read (secret bocor lewat `cluster run`) dan `exec` destructive; `docker rm/raw` lewat `runOne(..., true)` tanpa `classifyDocker` (`modules.go:311,387`); `tunnel.go` tanpa k8s |
| Platform | tidak ada kode SSM/IAP/cloudflared; `ProxyCommand` dan blok `Match` diabaikan diam-diam (`host.go:509`); `secret get --reveal` tanpa cek terminal (`key.go:449`); `secret rm` tanpa cek pemakaian/audit; `audit()` `return` saat gagal; 0 `ValidArgsFunction`; `schema` `secret_refs` hanya `secret:|env:|file:` |

## Urutan yang disarankan

1. **Penuhi janji di bagian 1 dan tutup celah di bagian 2.** Kecil-kecil, dan
   langsung menaikkan kepercayaan pada kontrak keamanan komando.
2. **Siklus deploy cluster** (rollout, rollback, ganti image, diff, logs -f).
   Ini kerja harian paling sering di bidang yang gap P1-nya paling banyak.
3. **Transfer massal** (sync, folder di storage, file besar, cabut key).
4. **DBA harian** (`db info`, aktivitas, lock, ukuran, dump format custom).
5. **Akses cloud** (SSM, `ProxyCommand`, kredensial AWS sementara).
