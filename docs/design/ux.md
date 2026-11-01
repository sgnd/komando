# Panduan UX komando

Status: **berlaku, 2026-11-02.** Dokumen ini adalah aturan main untuk setiap
perintah, flag, pesan, dan output. Fitur baru wajib mengikutinya. Kalau ada
perintah lama yang melanggar, perbaikannya ada di [Backlog](#backlog-perbaikan).
Tujuan besarnya ada di [vision.md](vision.md).

Ringkasnya: **satu cara untuk setiap hal, kata yang dipahami manusia, aman
kalau ragu, dan setiap error memberi tahu langkah berikutnya.**

## 1. Tata bahasa perintah

```
komando <kata-benda> <kata-kerja> <TARGET> [argumen] [flag]
komando db query app-db "select 1"
komando storage upload backups ./dump.sql.gz
```

- **Kata benda** = area kerja dalam bahasa manusia: `host`, `conn`, `db`,
  `cache`, `storage`, `cluster`, `registry`, `secret`. Nama produk hanya jadi
  alias (`s3`, `redis`, `sql`, `k8s`).
- **Kata kerja** berasal dari daftar baku di bawah. Kata kerja baru hanya
  boleh ditambah kalau tidak ada yang cocok, dan harus dicatat di sini.
- **TARGET selalu argumen pertama** setelah kata kerja, kecuali perintah yang
  tidak punya target (`host list`, `secret set`).
- Perintah lintas-area yang sering dipakai boleh ada di level atas (`exec`,
  `logs`, `cp`, `list`, `test`), tapi hanya sebagai jalan pintas yang
  bentuknya sama.

### Kata kerja baku

| Kata kerja | Arti | Alias yang diterima | Risk |
|---|---|---|---|
| `list` | daftar barang di **inventaris komando** (host, conn, secret, job) | `ls` | read |
| `ls` | daftar **isi di dalam** sebuah target (file, objek, key, pod) | `list` | read |
| `show` | detail satu barang inventaris | `info` | read |
| `get` | baca **nilai** satu item di dalam target (key, objek kecil, secret) | — | read |
| `status` / `info` | kondisi target (versi, kesehatan, memori) | — | read |
| `logs` | log | — | read |
| `test` | cek koneksi dan login | — | read |
| `add` | tambah ke inventaris | — | — |
| `edit` | ubah inventaris | — | — |
| `rm` | hapus | `remove`, `delete`, `del` | destructive kalau datanya hilang |
| `set` | tulis satu nilai | — | write |
| `upload` / `download` | pindah file antara komputer ini dan target | `put` / `get` | write / read |
| `run` | kirim perintah mentah milik area itu (SQL, Redis), tetap diklasifikasi | `query` untuk SQL | sesuai isi |
| `start` / `stop` / `restart` | hidupkan, matikan, mulai ulang | — | write |
| `dump` / `restore` | backup dan pulihkan | — | write / destructive |
| `import` / `export` | pindah konfigurasi masuk dan keluar | — | — |

Aturan: **`rm` selalu kata utamanya.** `remove`, `delete`, dan `del` hanya
alias, supaya siapa pun yang mengetiknya tetap berhasil.

## 2. Target dan selector (berlaku untuk host dan conn)

Keputusan pemilik (2026-11-02): **selector memilih semuanya**, server maupun
conn, karena komando sekarang universal.

| Selector | Memilih |
|---|---|
| `NAME` | satu host atau conn (nama unik di antara keduanya) |
| `web-*`, `db-?` | glob atas nama |
| `@GROUP` | semua anggota grup |
| `tag:T`, `label:K=V` | semua yang punya tag atau label itu |
| `kind:postgres`, `kind:host` | semua yang berjenis itu |
| `all` | semuanya |
| `a,b,!c` | gabungan; `!` mengecualikan |
| `user@addr:port` | host ad-hoc (hanya host; conn harus didaftarkan) |

Cara perintah memakai hasil selector:

1. **Perintah yang melihat** (`list`, `test`, `show`, `audit`) memakai semua
   yang terpilih.
2. **Perintah yang berbuat** memakai anggota yang bisa ia layani
   (`exec` → host; `db` → conn sql; `cache` → conn kv). Sisanya dilaporkan di
   `meta.skipped` beserta alasannya, bukan diam-diam diabaikan.
3. Kalau **tidak ada satu pun** yang bisa dilayani, perintah gagal dengan
   `NO_MATCHING_TARGETS` (exit 3) dan hint yang menyebut perintah yang cocok
   (mis. "app-db is a database; use `komando db query app-db`").
4. Selector yang tidak cocok dengan apa pun selalu error, tidak pernah sukses
   dengan nol hasil. Typo (`@prdo`) mendapat "did you mean `@prod`?".
5. Urutan hasil selalu menurut nama, supaya stabil untuk manusia dan agent.
6. **Pemeriksaan keamanan dilakukan untuk seluruh batch sebelum apa pun
   jalan.** Kalau satu target protected butuh `--yes`, seluruh batch berhenti
   dan menyebut target mana saja. Tidak ada "setengah jalan karena diblok".

## 3. Flag

### Flag global yang artinya tidak pernah berubah

| Flag | Arti |
|---|---|
| `-o, --output json\|text` | bentuk output (otomatis: text di terminal, json kalau di-pipe) |
| `--dry-run` | tunjukkan apa yang akan terjadi, tanpa mengubah apa pun |
| `--write` | izinkan perubahan pada perintah mentah (`db query`, `cache run`) |
| `--yes` | konfirmasi perubahan di target protected |
| `--allow-dangerous` | izinkan perintah yang diblok policy, hanya untuk perintah ini |
| `--timeout` | batas waktu per target |
| `--parallel` | berapa target sekaligus |

### Nama flag baku

| Kebutuhan | Flag | Catatan |
|---|---|---|
| berapa banyak | `-n, --limit` | baris log, item, key, baris SQL |
| rekursif | `-r, --recursive` | selalu `-r` kecil |
| ikuti terus (log) | `-f, --follow` | `-f` **hanya** untuk follow, seperti `tail -f` dan `kubectl logs -f` (belum ada; `-f` sudah dikosongkan untuknya) |
| file input | `--file` | `-f` hanya kalau alat aslinya memakainya (`db query -f`, `docker compose -f`); di `logs`, `-f` untuk follow |
| ke/dari file lokal | `--to` / `--from` | |
| ganti yang sudah ada | `--overwrite` | menggantikan `--force` |
| parameter bernama | `--var KEY=VALUE` | untuk recipe dan snippet |
| parameter berurutan | `--arg VALUE` | untuk `$1`/`?` di SQL dan argumen skrip |
| grup / tag | `-g, --group` / `-t, --tag` | |
| cari teks | `--grep` | tanpa huruf pendek, karena `-g` = group |
| saring inventaris | `--target SELECTOR` | menggantikan `--host` di `audit` dan `job list` |
| hak root | `--sudo` / `--no-sudo` | lihat aturan sudo di bawah |
| perintah mentah tidak mengubah apa pun | `--read-only` | lihat aturan polaritas |
| waktu | `--since`, `--until`, `--ttl`, `--expires` | format durasi Go (`10m`, `2h`) atau RFC3339 |

### Aturan polaritas (penting untuk keamanan)

- **Yang tidak diketahui dianggap mengubah.** Perintah mentah yang isinya
  tidak bisa dibuktikan aman (`exec`, `script`, `snippet`, `docker exec`)
  dianggap *write*, kecuali ditandai `--read-only`.
- **Kalau server bisa menegakkan read-only, default-nya read-only** dan butuh
  `--write` (`db query`, `cache run`).
- Perintah dengan kata kerja yang jelas (`storage upload`, `svc restart`)
  tidak butuh `--write`; kata kerjanya sudah menjadi pernyataan niat.

### Aturan sudo

Perintah tingkat sistem (`svc`, `pkg`, `user`, `ops`) otomatis memakai sudo
kalau perlu, dan bisa dimatikan dengan `--no-sudo`. Perintah lain (`exec`,
`fs`, `cp`, `logs`, `cron`, `docker`) tidak memakai sudo kecuali diberi
`--sudo`. Satu aturan, satu flag per perintah.

## 4. Output

- **Satu envelope JSON** di stdout kalau di-pipe. Teks yang rapi kalau di
  terminal. Progress dan prompt **selalu ke stderr**, tidak pernah ke stdout.
- Warna hanya di terminal, dan mematuhi `NO_COLOR`.
- Banyak target: `data.results[]` per target (diurutkan nama), ringkasan
  `data.summary` (`ok`, `failed`), dan target yang dilewati di
  `meta.skipped[]`. `ok` di level atas `false` kalau ada satu yang gagal; exit code
  memakai yang terburuk.
- Hasil besar dipotong dengan `truncated: true` dan hint yang menyarankan
  `--limit`, `WHERE`, atau prefix. Tidak pernah ada output tanpa batas.
- Waktu dalam JSON selalu UTC RFC3339. Teks untuk manusia menampilkan waktu
  lokal beserta zonanya.
- Nilai biner → `{"base64": "..."}`. Bilangan besar → string. `null` dan
  string kosong dibedakan.
- Teks untuk manusia muat di lebar 80 kolom; kolom panjang dipotong dengan `…`
  dan ditampilkan penuh di `-o json`.

## 5. Error

Setiap error punya `code` (stabil, HURUF_BESAR), `message` (apa yang
terjadi, dalam bahasa sederhana), dan `hint` (perintah persis yang perlu
dijalankan berikutnya).

- Typo pada perintah, nama, atau selector → "did you mean ...".
- Error dari server (SQL, Redis, S3, k8s) diteruskan apa adanya di
  `message`, dengan kode aslinya di `data` (`sqlstate`, kode HTTP).
- Kalau perintah tidak bisa dibatalkan atau dry-run tidak mungkin, katakan
  itu terang-terangan. Jangan berpura-pura.

## 6. Konfirmasi dan keamanan

- **Agent dan skrip**: perubahan di target protected gagal tanpa `--yes`
  (exit 6), dengan hint.
- **Manusia di terminal** (stdin dan stdout sama-sama terminal): komando
  bertanya `Change protected target prod-db? [y/N]`. Untuk perintah
  destructive di target protected, nama target harus diketik ulang. Jawaban
  dibaca dari terminal, bukan dari stdin yang di-pipe, jadi agent tidak bisa
  menjawabnya.
- `--allow-dangerous` dan `--yes` hanya berlaku untuk satu perintah dan
  tercatat di audit.
- **Tidak ada jalan memutar.** Menghapus, mengganti, atau mematikan protected
  pada target protected butuh `--yes`. Mematikan audit log, cek host key, atau
  menghapus aturan deny butuh `--yes` (`SAFETY_SETTING`).
- **Gagal tertutup**: kalau audit tidak bisa ditulis, perubahan ditolak.
- Ctrl-C di tengah jalan: transaksi di-rollback, file sementara dihapus,
  audit mencatat `interrupted`, exit 130.

## 7. Secret

- Secret tidak pernah ada di argumen perintah, URL, audit, atau output
  (kecuali `secret get --reveal` atas permintaan manusia).
- Cara memasukkan secret: prompt tersembunyi, `--from-env VAR`, atau stdin.
  **Nilai sebagai argumen posisional ditolak**, karena tersimpan di shell
  history dan terlihat di `ps`.
- Ref yang tidak bisa dibaca (`env:X` kosong, file tidak ada, izin file
  terlalu longgar) → error dengan nama ref-nya, tanpa nilainya.

## 8. Inventaris dan nama

- Nama: huruf, angka, `-`, `_`, `.`; 1–63 karakter; diawali huruf atau
  angka (sudah berlaku). Unik di antara host dan conn, tanpa membedakan huruf
  besar/kecil.
- Kata yang punya arti sebagai selector (`all`) ditolak sebagai nama.
- Rename memperbarui semua yang merujuknya (grup, `--via`, jump, snippet).
  Hapus ditolak (`IN_USE`) kalau masih dipakai, dengan daftar pemakainya.
- State ditulis atomik di bawah file lock, jadi dua komando yang jalan
  bersamaan tidak saling menimpa. Perubahan skema state membuat backup dulu.

## 9. Migrasi

- `komando import SOURCE` dengan `--dry-run` dan `--overwrite`. Import ulang
  aman (idempoten): yang sama dilewati, yang beda dilaporkan.
- Field yang tidak didukung **dilaporkan**, tidak dibuang diam-diam.
- Nama yang bentrok antar-sumber (mis. `web1` di ssh-config dan kubeconfig)
  diberi saran nama, tidak ditimpa.
- Secret dari sumber mana pun masuk vault, lalu dirujuk dengan `secret:`.

## 10. Bantuan dan kemudahan

- `komando` tanpa argumen: tiga langkah pertama, bukan dinding teks.
- Setiap perintah punya minimal satu contoh nyata di `--help`.
- Completion shell melengkapi nama host, conn, grup, dan tag dari inventaris.
- `komando guide` (untuk agent) dan `docs/features/` (untuk manusia, satu file per fitur) selalu
  diperbarui di commit yang sama dengan fiturnya.
- Perubahan nama perintah atau flag: yang lama tetap jalan sebagai alias
  selama satu rilis minor, dengan peringatan di stderr, lalu dihapus.

## 11. Tidak ada fitur yang tumpang tindih

Keputusan pemilik (2026-11-02). **Satu kebutuhan, satu perintah.** Sebelum
menambah perintah atau flag, cek dulu apakah sudah ada yang melakukannya.
Kalau sudah ada, perluas yang lama. Jangan buat yang baru.

- Satu konsep punya satu nama di semua area (mis. jalur = `--via`, bukan
  `--via` di sini dan `--jump` di sana).
- Versi "per area" dari perintah umum hanya boleh ada sebagai **alias** yang
  memanggil perintah umum. Tidak boleh ada dua implementasi.
- Yang berbeda karena **skala** (satu item vs banyak sekaligus) boleh ada,
  tapi keduanya memakai kode yang sama.

Tumpang tindih yang ada sekarang, dan keputusannya:

| Sekarang | Keputusan |
|---|---|
| `host --jump` dan `conn --via` | ✅ `--via` untuk semua; `--jump` jadi alias ([network.md](network.md)) |
| `host test`, `conn test`, `test` | ✅ `test` saja; `host test`/`conn test` = `test` untuk satu jenis |
| `host list`, `conn list`, `list` | ✅ `list` saja; `host list`/`conn list` = `list kind:host` / `list kind:conn` |
| `svc logs`, `docker logs`, `logs --unit/--container` | ✅ `logs` saja; `svc logs` dan `docker logs` jadi alias |
| `ops run` (resep bawaan) dan `snippet run` (resep sendiri) | ✅ satu `recipe` (kata yang lebih mudah dipahami); `ops` dan `snippet` jadi nama lain |
| `cp` (server) dan `storage upload/download` | ✅ `upload`/`download` untuk server (SFTP) dan storage; `cp` dan `storage upload/download` jadi alias |
| `group add/rm` dan `edit --add-group/--rm-group` | tetap keduanya (banyak vs satu), kode yang sama |

## 12. Semua fitur CLI asli bisa dipakai

Keputusan pemilik (2026-11-02): komando harus sekuat alat aslinya. Caranya
bukan menyalin semua fitur alat itu, tapi tiga jalur yang sama di semua area:

1. **Perintah yang dipahami** (`db schema`, `cache get`, `storage ls`): output
   terstruktur, aman, mudah dipakai. Untuk 80% pekerjaan harian.
2. **Jalur mentah dengan bahasa aslinya**, tetap diklasifikasi, read-only
   default, dan diaudit: `exec` (shell), `db query` (SQL apa pun), `cache run`
   (perintah Redis apa pun), nanti `cluster run -- <argumen kubectl>`. Apa pun
   yang bisa dilakukan alat aslinya bisa dilakukan lewat sini.
3. **Alat asli di laptop, lewat jalur komando**: `komando tunnel start
   app-db` memberi port lokal untuk TablePlus/`psql`, dan `komando shell`
   untuk SSH interaktif. Nanti `komando db shell app-db` membuka `psql`/`mysql`
   dengan password dari vault dan jalur `--via`, tanpa password di layar.

Jalur 2 dan 3 tidak dihitung tumpang tindih dengan jalur 1: itu pintu darurat
yang sengaja ada, dengan pengaman yang sama.

## Daftar edge case

Checklist ini dipakai untuk setiap fitur dan setiap review.

**Target dan jaringan**
- Host `--via` mati, lambat, atau host key-nya berubah (`HOSTKEY_MISMATCH`, tidak pernah dilewati otomatis)
- Alamat IPv6 (`[2001:db8::1]:22`), DNS gagal, port salah, firewall diam (timeout, bukan menggantung)
- Rantai bastion lebih dari satu lompatan; proxy perusahaan
- TLS dengan sertifikat self-signed: opsi eksplisit per conn, tidak pernah dimatikan diam-diam
- 500 target sekaligus: batas `--parallel`, output tetap terurut, satu yang gagal tidak menghentikan yang lain (kecuali `--fail-fast`)

**Kredensial**
- Ref secret tidak ada, env kosong, file tidak terbaca, vault terkunci di sesi non-interaktif
- Token kedaluwarsa (AWS session, kube exec plugin): error jelas dengan cara memperbaruinya
- Password di URL saat `conn add` atau `import`: ditolak, hint ke `secret set`

**Keamanan**
- Perintah berbahaya disamarkan: komentar, huruf besar-kecil, spasi aneh, multi-statement, `rename-command` di Redis
- Perintah yang tidak dikenal dianggap write
- Satu target protected di dalam batch: seluruh batch berhenti sebelum mulai
- `--yes` diberikan tapi tidak dibutuhkan: tetap jalan, tidak memberi izin tambahan
- Dry-run tidak mungkin (DDL MySQL, `VACUUM`): dilaporkan, tidak dieksekusi
- Audit gagal ditulis: perubahan ditolak

**Data dan output**
- Hasil sangat besar, nilai biner, teks non-UTF-8, `NULL`, bilangan > 2^53, zona waktu
- Terminal sempit, output di-pipe ke `less` atau `head` (SIGPIPE tidak dianggap error)
- Gagal sebagian di banyak target: exit code dan ringkasan yang jujur

**File dan transfer**
- File tujuan sudah ada: tidak ditimpa tanpa `--overwrite`
- Unduhan terputus: tulis ke file sementara lalu rename; tidak pernah meninggalkan file setengah jadi
- Garis miring di akhir path (`dir` vs `dir/`): artinya ditulis jelas di `--help`, sama untuk `cp` dan `storage`
- `~` di path lokal vs remote, spasi dan unicode di nama file, symlink, file sangat besar (progress di stderr)

**Proses**
- Lebih dari ~2 menit → `job`; koneksi putus saat job jalan; job yatim dibersihkan
- Ctrl-C: rollback, bersihkan, audit `interrupted`
- Dua komando berjalan bersamaan pada state yang sama

**Per area**
- **db**: lock lama (`lock_timeout`), replika read-only, batas koneksi, restore ke database yang salah (protected + ketik ulang nama)
- **cache**: `KEYS` di cache besar (pakai `SCAN`), Redis cluster (`MOVED`), sentinel, nomor database
- **storage**: bucket dengan versioning (delete marker), "folder" yang sebenarnya prefix, upload multipart, link dengan masa berlaku maksimal 7 hari
- **cluster**: namespace default, context kubeconfig, exec auth plugin yang butuh biner lain, `apply` selalu dengan diff dan `--dry-run=server` dulu
- **registry**: rate limit Docker Hub, tag vs digest (menghapus digest ikut menghapus tag lain)

**Migrasi dan versi**
- `~/.ssh/config` dengan `Include`, `Match`, dan wildcard; kubeconfig dengan banyak context
- Import ulang, nama bentrok, field tidak didukung
- Kontrak JSON berubah: field baru boleh, field lama tidak dihapus sebelum versi mayor

## Backlog perbaikan

Hasil audit 149 perintah pada commit `93f7268`. P0 = keamanan, P1 =
konsistensi yang sering mengenai pengguna, P2 = rapi-rapi. Nama lama tetap
diterima sebagai alias selama satu rilis. Aturan nama perintah dan flag
dijaga oleh `TestConventions` (`internal/cli/conventions_test.go`).

| # | Prio | Masalah | Status |
|---|---|---|---|
| 1 | P0 | Snippet bisa jalan di host protected tanpa `--yes` kecuali ditandai `--mutating` | ✅ Dianggap mengubah; `--read-only` untuk yang aman |
| 2 | P0 | `secret set NAME VALUE` (masuk shell history dan `ps`) | ✅ Ditolak (`SECRET_IN_ARGS`) |
| 3 | P0 | Selector hanya memilih host | ✅ Selector universal, `kind:`, `meta.skipped`, `NO_MATCHING_TARGETS`, "did you mean" |
| 4 | P1 | `logs -f` = file | ✅ `--file` tanpa huruf pendek. `--follow` belum dibuat |
| 5 | P1 | `rm`, `del`, `remove`, `delete` | ✅ `rm` di semua perintah, sisanya alias |
| 6 | P1 | `-n` punya tiga arti | ✅ `-n, --limit`; `fs cat --line-numbers`; `job logs --max-bytes` |
| 7 | P1 | `--host` vs `--target` | ✅ `--target` (menerima selector) |
| 8 | P1 | `--param` vs `--var` | ✅ `--var` |
| 9 | P1 | `--force` vs `--overwrite` | ✅ `--overwrite` |
| 10 | P1 | `-r` vs `-R` | ✅ `-r` |
| 11 | P1 | `storage get/put` | ✅ `download/upload` (dikerjakan session lain) |
| 12 | P1 | `-g` = group dan grep | ✅ `-g` hanya group |
| 13 | P1 | Sudo tidak konsisten | ✅ Aturan sudo di bagian 3; `pkg` dan `user` dapat `--no-sudo` |
| 14 | P1 | Tidak ada `list`/`test` untuk semuanya | ✅ `komando list`, `komando test` |
| 15 | P2 | `cache keys` tanpa alias `ls` | ✅ (session lain) |
| 16 | P2 | `HOST` vs `TARGET` di usage | ✅ `TARGET` |
| 17 | P2 | Manusia di terminal hanya dapat error | ✅ Prompt `[y/N]` dan ketik nama untuk yang berbahaya |
| 18 | P2 | Nama `all`, `Web1` vs `web1` | ✅ Ditolak |
| 19 | P2 | `komando import` belum ada | ⏳ Roadmap v0.3 |
| 20 | P0 | `host add --overwrite` diam-diam mencopot protected | ✅ Butuh `--yes` |
| 21 | P0 | `host rm` / `edit --protected=false` pada target protected tanpa `--yes` (jalan memutar) | ✅ Butuh `--yes` |
| 23 | P0 | Alias tanpa protected (`user@alamat`, nama kedua, conn kedua ke server yang sama) melewati protected | ✅ Protected mengikuti alamat |
| 24 | P1 | Satu jawaban "y" di terminal berlaku untuk pengecekan lain dalam perintah yang sama | ✅ Setiap jawaban hanya untuk satu pertanyaan; `rm` banyak target ditanya sekali |
| 25 | P1 | `tunnel start --host-key-policy off --yes` gagal di proses latar | ✅ |
| 22 | P0 | `config set audit off`, `host_key_policy off`, `--host-key-policy off`, `policy allow` tanpa konfirmasi; `audit tru` mematikan audit | ✅ Butuh `--yes`; nilai on/off ketat |

Berikutnya:
- `logs --follow` (`-f`) untuk log yang terus berjalan.
- Prompt di terminal muncul saat file lock state dipegang, jadi komando lain
  menunggu jawaban manusia. Tanya dulu sebelum mengambil lock, lalu cek ulang.
- `snippet add --read-only --overwrite` bisa mengganti snippet milik orang
  lain menjadi read-only. Mengganti snippet sebaiknya butuh `--yes`, dan
  `read_only` dicatat di audit.
- Protected yang mengikuti alamat membandingkan teks alamat, tanpa DNS:
  `db.internal` dan `10.0.0.5` dianggap berbeda.
- Perintah satu target menolak selector yang memilih banyak dengan pesan
  yang sama di semua tempat (sudah, lewat `singleHost`/`singleConn`).
- `fs rm --recursive` sebaiknya dianggap destructive (`--allow-dangerous`),
  sama seperti `storage rm` dan `cache rm`.
- `db query` ke banyak database sekaligus (`@prod` yang berisi beberapa
  database) belum didukung; sekarang ditolak dengan pesan jelas.
