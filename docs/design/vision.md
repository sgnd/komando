# Visi dan roadmap komando

Status: **disetujui, 2026-11-02** (lihat [Keputusan](#keputusan-dan-pertanyaan-terbuka)). Dokumen ini menggantikan tujuan lama ("CLI SSH
untuk AI agent") dengan tujuan baru. Rancangan per fitur tetap di dokumen
masing-masing, misalnya [resources-and-db.md](resources-and-db.md).

## Visi

> **komando adalah satu client universal untuk semua pekerjaan devops:
> server, database, cache, object storage, cluster, registry, secrets, dan
> file. Satu inventaris, satu cara pakai, satu lapisan aman. Bisa dipakai
> manusia dan AI agent.**

Bayangkan Termius + TablePlus + Lens + Cyberduck + `docker`/`kubectl`/`aws s3`
digabung jadi satu CLI. Semua perintahnya mengikuti aturan yang sama, dan
password tidak pernah terlihat oleh AI.

## Empat tujuan

| # | Tujuan | Artinya, dan cara mengukurnya |
|---|---|---|
| 1 | **Client universal** | Satu inventaris (`host` + `conn`) untuk semua jenis target. Bisa diukur: kind baru cukup didaftarkan di `internal/driver`, tanpa membuat model atau flag baru. |
| 2 | **Fitur devops yang kaya** | Setiap family punya perintah yang benar-benar dipakai sehari-hari: lihat, cari, baca, ubah, backup, dan pulihkan. Fitur yang jarang dipakai tidak ditambahkan. |
| 3 | **Mengelola banyak hal** | Server, database, cache, object storage, cluster (k8s/k3s/swarm), secrets, ftp/sftp, container registry, dan kind lain yang lolos [kriteria](#kriteria-menambah-family). |
| 4 | **Berguna, mudah dipakai, mudah migrasi** | Lima menit pertama langsung berguna. Semua perintah memakai pola yang sama, dan konfigurasi yang sudah ada bisa diimpor sekali jalan. Tidak ada lock-in: state berupa JSON biasa yang bisa diekspor. |

Dua prinsip tambahan dari pemilik (2026-11-02): **tidak ada fitur yang
tumpang tindih**, dan **semua fitur CLI asli tetap bisa dipakai** lewat
komando. Aturannya ada di [ux.md](ux.md) bagian 11 dan 12.

Prinsip desain (KISS, secure by default, tanpa flag yang membingungkan, ramah
pemula, dan seterusnya) tetap berlaku untuk semuanya.

## Review kondisi sekarang

Per commit `39d2e68` (± 11.500 baris Go, biner 26 MB):

| Area | Status |
|---|---|
| Server (SSH): inventaris, key, vault, exec paralel, job, fs aman, cp/SFTP, tunnel, shell | ✅ matang |
| Modul devops di atas SSH: svc, logs, docker, pkg, cron, user, net, facts, 39 recipe `ops` | ✅ matang |
| Lapisan aman: policy, protected, dry-run, cek host key, audit, JSON envelope + exit code | ✅ matang |
| `conn` + `db` (PostgreSQL, MySQL, SQLite; query/schema/explain/dump/restore; `audit_sql`) | ✅ selesai |
| `cache` (Redis, Valkey) | ✅ selesai |
| `storage` (S3: ls/get/put/rm/link) | ✅ selesai |
| Cluster, registry, ftp, VPN, secret backend eksternal | ❌ belum ada |
| Satu inventaris: selector universal, `komando list`, `komando test` | ✅ selesai |
| Migrasi | ✅ `import` (ssh-config, pgpass, mycnf, env, komando) dan `export` |

**Kekuatan.** Fondasinya sudah benar untuk tujuan universal. Kontrak output,
exit code, guard berbasis risiko (`read`/`write`/`destructive`), `--via HOST`
tanpa port lokal, dan referensi secret (`secret:`/`env:`/`file:`) semuanya
umum, bukan khusus SSH. Fase `db` membuktikan pola ini bisa dipakai di luar
SSH.

**Celah yang perlu ditutup sebelum menambah banyak family:**

1. **Positioning.** README dan `--help` masih bilang "manage fleets of servers"
   dan "like Termius". Itu terlalu sempit untuk tujuan baru.
2. **Nama perintah per family belum punya aturan.** `Families` memetakan
   `s3 → s3`, padahal family lain diberi nama kategori (`db`, `cache`). Kalau
   tidak diatur sekarang, top-level akan jadi campuran nama produk dan
   kategori.
3. **Verb belum seragam antar-family.** `db` punya `query/schema/dump`. Family
   lain perlu pola verb yang sama supaya pengguna tidak belajar ulang.
4. **Migrasi masih terpecah per perintah** (`host import`). Untuk banyak sumber
   (kubeconfig, pgpass, aws, filezilla, ...) perlu satu pintu.
5. **Ukuran biner.** Ukurannya sudah 26 MB. SDK berat (client-go, AWS SDK
   penuh) bisa menggandakannya. Perlu aturan dependensi.
6. ~~**Selector `@group` hanya memilih host.**~~ Selesai: selector memilih
   server dan conn sekaligus (lihat [ux.md](ux.md)).

## Model inti

Semua fitur harus masuk ke empat konsep ini. Kalau tidak bisa, berarti
fiturnya belum siap.

```
target   = host (SSH, bisa exec)  |  conn (semua yang lain, punya kind)
kind     = produk konkret: postgres, redis, s3, k8s, ftp, oci, ...
family   = kelompok kind dengan verb yang sama  →  satu perintah top-level
risk     = read | write | destructive  →  guard yang sama untuk semua
```

### Family dan perintahnya

Nama perintah selalu berupa **kategori**, bukan nama produk.

| Perintah | Family | Kind | Status |
|---|---|---|---|
| `exec`, `fs`, `cp`, `svc`, `docker`, ... | host | SSH (Linux) | ✅ |
| `db` | sql | postgres, mysql/mariadb, sqlite; nanti: mssql, clickhouse | ✅ |
| `cache` | kv | redis, valkey, keydb, dragonfly; nanti: memcached | ✅ |
| `storage` | object/file | s3 (AWS, MinIO, R2, Spaces, Wasabi, B2), ftp/ftps; nanti: gcs, azblob, webdav | ✅ s3, 📋 ftp |
| `cluster` | orchestrator | k8s (k3s, EKS, GKE, AKS, kind), swarm; nanti: nomad | 📋 |
| `registry` | oci | Docker Hub, GHCR, GitLab, Harbor, ECR, registry:2 | 📋 |
| `secret` | secret | vault lokal; ref eksternal: `op:`, `vault:`, `aws-sm:`, `gcp-sm:` | ✅ lokal, 📋 eksternal |
| `vpn` | jalur | wireguard, tailscale, socks, system (VPN di OS); dipakai lewat `--via` | 📋 ([network.md](network.md)) |

Keputusan (disetujui 2026-11-02):

- **Nama perintah memakai bahasa manusia**, bukan nama produk, supaya mudah
  diingat: `storage`, `cache`, `cluster`, `registry`. Nama produk boleh jadi
  alias (`s3`, `redis`, `sql`).

- **`s3` diganti jadi `storage`.** Nama ini mencakup S3 dan FTP dengan verb
  yang sama (`ls/get/put/rm/sync`). Pengguna tidak perlu tahu protokolnya.
- **SFTP tetap lewat host** (`cp`, `fs`). Akun yang hanya punya SFTP tanpa shell
  (misalnya hosting) didaftarkan sebagai conn `sftp://` di `storage`.
- **Swarm masuk `cluster`, bukan `docker`.** `docker` tetap untuk satu host.
  `cluster` untuk orkestrator. Verb yang ada di semua engine langsung di bawah
  `cluster` dan bekerja di cluster mana pun, karena conn sudah tahu kind-nya
  (`komando cluster status prod`, `komando cluster logs prod api`). Hal yang
  hanya ada di satu engine masuk sub-perintah engine itu
  (`komando cluster k8s ...`, `komando cluster swarm ...`).

### Verb yang sama di semua family

Daftar kata kerja dan flag yang berlaku ada di [ux.md](ux.md). Tabel di bawah
ini ringkasannya.

| Verb | Arti | Risk default |
|---|---|---|
| `list` / `ls` | daftar isi (tabel, key, objek, pod, tag) | read |
| `get` / `show` | baca satu item | read |
| `schema` / `info` / `status` | struktur dan kondisi | read |
| `logs` | log (pod, service) | read |
| `put` / `set` / `apply` | ubah, wajib `--dry-run` dulu | write |
| `rm` / `delete` | hapus | destructive |
| `dump` / `restore` / `sync` | backup, pindah data; lewat `job` kalau lama | write |
| `run` | perintah mentah family itu (SQL, redis cmd), diklasifikasi | sesuai klasifikasi |

Flag yang sama di semua family: `--write`, `--dry-run`, `--yes`,
`--allow-dangerous`, `--via`, `--limit`, `--timeout`, `-o`. Flag ini tidak
boleh berubah arti di family mana pun.

### Kontrak keamanan per family

Sebuah family baru dianggap selesai kalau semua poin ini terpenuhi:

- [ ] Terdaftar sebagai kind di `internal/driver` (skema URL, port, contoh)
- [ ] `conn add/test` jalan, termasuk `--via HOST`
- [ ] Password hanya lewat ref; ditolak kalau ada di URL
- [ ] Read-only default, sebaiknya **ditegakkan oleh servernya sendiri** (read-only
      transaction, token read-only, k8s `--dry-run=server`), bukan hanya oleh
      klasifikasi
- [ ] Klasifikasi risk sebelum apa pun dikirim; aturannya muncul di `komando policy`
- [ ] `--dry-run` yang nyata, atau laporan jujur kalau tidak bisa
- [ ] Protected → `--yes`; destructive → `--allow-dangerous`
- [ ] Satu baris audit per perintah, tanpa secret
- [ ] Output JSON terstruktur + teks yang mudah dibaca
- [ ] Bagian di `komando guide`, halaman sendiri di `docs/features/`, dan importer kalau ada sumber umum

## Migrasi: satu pintu masuk

```
komando import SOURCE [FILE] [--dry-run] [--group G]
komando export [--to FILE]          # semua inventaris, tanpa secret (atau terenkripsi)
```

| SOURCE | Membaca | Hasil |
|---|---|---|
| `ssh-config` | `~/.ssh/config` | host (sudah ada di `host import`) |
| `kubeconfig` | `~/.kube/config` | conn `k8s` per context |
| `pgpass`, `mycnf` | `~/.pgpass`, `~/.my.cnf` | conn `db` + password ke vault |
| `aws` | `~/.aws/config` + `credentials` | conn `storage` + key ke vault |
| `docker` | `~/.docker/config.json` | conn `registry` (memakai credential helper kalau ada) |
| `rclone` | `rclone.conf` | conn `storage` |
| `filezilla` | `sitemanager.xml` | conn `storage` (ftp/sftp) |
| `termius`, `tableplus`, `dbeaver` | file ekspor masing-masing | host/conn |
| `env` | file `.env` (`DATABASE_URL`, `REDIS_URL`, ...) | conn |
| `komando` | file `export` | semuanya (pindah mesin) |

Aturannya: secret yang diimpor **selalu masuk vault**, `--dry-run` menampilkan
apa yang akan dibuat, dan entri yang sudah ada tidak ditimpa kecuali dengan
`--overwrite`. `host import` tetap jalan sebagai alias.

## Aturan teknis

- **Pure Go, tanpa cgo, satu biner.** Ini sudah berlaku dan dipertahankan.
- **Bicara langsung ke API, bukan lewat SDK raksasa.** k8s: REST API +
  kubeconfig (tanpa client-go). Registry: OCI Distribution API. Swarm: Docker
  Engine API lewat socket di host SSH. S3: client ringan (`minio-go` atau
  signer SigV4 sendiri), bukan AWS SDK penuh.
- **Anggaran biner: ≤ 40 MB, satu biner untuk semua orang** (tanpa build
  `lite`/`full`; satu biner lebih mudah dipasang dan didukung). Kalau
  terlewati, kurangi dependensi dulu; build tag (`-tags nok8s`) hanya jalan
  terakhir, dan tidak memakai sistem plugin.
- **Tanpa pool dan tanpa daemon.** Satu koneksi per perintah. Tunnel dan job
  tetap jadi satu-satunya proses di latar belakang.
- Tes integrasi per family di CI memakai service container (postgres, redis,
  minio, k3s, registry:2).

## Roadmap

| Rilis | Isi | Tujuan yang dicapai |
|---|---|---|
| **v0.2** ✅ | `db`, `cache`, `storage` (S3), satu inventaris (`list`, `test`, selector untuk semua), aturan UX, positioning baru | 1, 3, 4 |
| **v0.3** | Hapus tumpang tindih ([ux.md](ux.md#11-tidak-ada-fitur-yang-tumpang-tindih)); `--via` untuk semua target, `tunnel start TARGET`; `komando import` (ssh-config, pgpass, mycnf, aws, env) dan `export` | 1, 4 |
| **v0.4** | `komando vpn`: WireGuard dan SOCKS di dalam proses, banyak VPN sekaligus tanpa pindah-pindah; kind `system` untuk VPN di OS ([network.md](network.md)) | 1, 3, 4 |
| **v0.5** | `cluster` untuk k8s: status, ls (pods/deploy/svc/nodes), logs, describe, `apply --dry-run` (server-side), rollout restart/scale, `run -- <kubectl>`; import `kubeconfig` | 2, 3 |
| **v0.6** | `registry` (ls repos/tags, inspect digest, rm tag, copy); `cluster` untuk swarm; import `docker` | 3 |
| **v0.7** | `storage` untuk ftp/ftps/sftp-only; ref secret eksternal (`op:`, `vault:`, `aws-sm:`); `db shell`; import filezilla/rclone/termius/tableplus | 3, 4 |
| **v1.0** | Kontrak dibekukan (`schema` versi 1), semua family lulus checklist, dokumentasi lengkap dua bahasa | semua |

Kandidat setelah v1.0, dinilai dengan kriteria di bawah: DNS (Cloudflare,
Route 53), message queue (RabbitMQ, Kafka, NATS), search (Elasticsearch,
OpenSearch), query metrics (Prometheus), sertifikat/ACME, VM cloud
(DigitalOcean, Hetzner, AWS EC2), dan mongodb.

## Kriteria menambah family

Family baru hanya ditambahkan kalau **semua** ini terpenuhi:

1. Masuk ke model `conn` + kind + verb yang sudah ada, tanpa konsep baru.
2. Bisa diberi read-only default dan klasifikasi risk yang jujur.
3. Bisa dibangun tanpa cgo dan tanpa SDK yang membuat biner melewati anggaran.
4. Ada kebutuhan nyata: dipakai sehari-hari, bukan hanya "ada baiknya".
5. Ada orang yang mau merawatnya: tes integrasi di CI dan dokumentasi.

## Bukan tujuan

- Mengganti alat lengkap (`psql`, `kubectl`, `terraform`, `helm`). komando
  menangani 80% pekerjaan harian dengan aman. Sisanya tetap bisa dikerjakan
  lewat `exec` di host atau alat aslinya.
- Infrastructure as Code, provisioning cloud, atau GitOps.
- GUI, TUI, sistem plugin, atau daemon/server. komando tetap CLI murni.
- Monitoring atau alerting yang berjalan terus-menerus.

## Keputusan dan pertanyaan terbuka

| # | Pertanyaan | Keputusan |
|---|---|---|
| 1 | `storage` atau `s3`? | ✅ `storage`. Semua nama perintah memakai bahasa manusia; nama produk jadi alias. |
| 2 | Satu `cluster`, atau `k8s`/`swarm` terpisah? | ✅ Satu `cluster`. Verb umum langsung di bawahnya; fitur khusus engine di `cluster k8s ...` / `cluster swarm ...`. |
| 3 | Apakah `@prod` memilih host dan conn sekaligus? | ✅ Ya, semuanya. Aturan lengkapnya di [ux.md](ux.md#2-target-dan-selector-berlaku-untuk-host-dan-conn). |
| 4 | Anggaran biner? | ✅ Ikuti best practice: satu biner, ≤ 40 MB, pure Go. |
| 5 | TUI? | ✅ Tidak. CLI murni. |

### Contoh nomor 3

```bash
komando host add web1 ubuntu@10.0.0.2 --group prod
komando conn add app-db postgres://app@10.0.0.5/app --group prod

komando list @prod                  # server dan conn di prod, dalam satu daftar
komando test @prod                  # cek semuanya bisa dihubungi
komando exec @prod -- uptime        # jalan di web1; app-db dilaporkan di "skipped"
komando db query @prod "select 1"   # jalan di app-db; web1 dilaporkan di "skipped"
```

Mulai sekarang, keputusan teknis dan UX diambil berdasarkan best practice dan
dicatat di [ux.md](ux.md). Pemilik produk menentukan arah (apa yang dikelola
komando dan untuk siapa).
