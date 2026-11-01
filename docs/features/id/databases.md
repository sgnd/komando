# Database

Menambahkan database, lalu query, backup, dan restore dengan aman. [Semua fitur](README.md)

## Database (conn)

**Conn** adalah database, cache, atau bucket storage yang dikenal komando,
sama seperti host adalah server yang Anda kenal. Jenisnya ditentukan dari
awal URL:

| Jenis      | Contoh URL |
|------------|------------|
| PostgreSQL | `postgres://app@10.0.0.5:5432/app?sslmode=require` |
| MySQL / MariaDB | `mysql://shop@db.internal:3306/shop?tls=true` |
| SQLite     | `sqlite:///var/lib/app.db` (file di komputer ini) |
| Redis / Valkey | `redis://default@cache.internal:6379/0` (`rediss://` untuk TLS) |
| S3 dan yang kompatibel (MinIO, R2, Wasabi, ...) | `s3://ACCESS_KEY_ID@my-bucket/backups?endpoint=https://minio.internal:9000&region=us-east-1` |

Untuk S3, bagian user adalah access key ID; secret key masuk ke vault
seperti password (`--password-ref secret:NAME`). Kosongkan `endpoint` untuk
AWS.

Jalankan `komando conn kinds` untuk melihat semuanya.

Jangan pernah menaruh password di URL; komando menolaknya. Simpan di vault
saja:

```bash
komando secret set prod-db-pass
komando conn add prod-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:prod-db-pass --protected
```

`--via web1` artinya "database ini hanya bisa dijangkau dari web1". komando
terhubung lewat web1 melalui SSH dengan sendirinya: tidak perlu menyalakan
tunnel, tidak ada port yang dibuka di komputer Anda.

```bash
komando list kind:conn                     # semua conn
komando test kind:conn                 # bisa dijangkau? referensi password-nya jalan?
komando conn edit prod-db --add-tag critical
komando conn rm old-db                # hanya melupakannya; database-nya tidak disentuh
```

Conn memakai target yang sama dengan server (`@group`, `tag:prod`, `*-db`,
`all`) dan berbagi nama dengannya: host dan conn tidak bisa sama-sama
bernama `db1` (atau `DB1`: nama tidak membedakan huruf besar dan kecil).
Host yang dipakai conn lewat `--via` tidak bisa dihapus sampai conn-nya
diubah.

## Query database

`komando db` menjalankan SQL di sebuah conn. **Perintah ini tidak mengubah
data Anda kecuali Anda menambahkan `--write`**: tanpa itu, query berjalan
dalam transaksi read-only dan database itu sendiri yang menolak perubahan.
Beberapa fungsi admin yang tidak dihentikan oleh transaksi read-only
(mengakhiri sesi, membaca file server, `dblink`) diblokir oleh pengecekan
komando sendiri. Pengecekan ini menangkap kesalahan; untuk batas yang
sungguhan, beri komando user database yang hanya punya hak yang
dibutuhkannya.

```bash
komando db schema prod-db                     # ada tabel apa saja?
komando db schema prod-db users               # kolom, tipe, index dari satu tabel
komando db query prod-db "select id, email from users order by id desc limit 10"
komando db explain prod-db "select * from orders where user_id = 42"
```

Pakai `--arg` untuk nilai, alih-alih menempelkannya ke dalam SQL (`$1`, `$2`
di PostgreSQL; `?` di MySQL dan SQLite):

```bash
komando db query prod-db "select * from users where email = $1" --arg bob@example.com
```

**Mengubah data** butuh dua langkah. Pertama dry run: SQL-nya benar-benar
dijalankan, Anda melihat berapa baris yang terkena, lalu semuanya dibatalkan
(rollback).

```bash
komando db query prod-db --write --dry-run "update users set plan = 'pro' where id = 42"
komando db query prod-db --write "update users set plan = 'pro' where id = 42"
```

Sabuk pengaman:

- Conn yang protected juga butuh `--yes` untuk `--write`.
- SQL yang merusak butuh `--allow-dangerous`: `DROP`, `TRUNCATE`, `DELETE`
  atau `UPDATE` tanpa `WHERE`, perubahan hak akses, dan beberapa lainnya
  (`komando policy list` menampilkannya; `komando policy check --for postgres "..."`
  menguji sebuah query).
- `BEGIN`/`COMMIT` ditolak: komando menjalankan semuanya dalam satu transaksi.
- Beberapa statement tidak bisa di-rollback (`VACUUM`, `CREATE INDEX
  CONCURRENTLY`, DDL MySQL). Statement ini harus dikirim sendirian, dan dry
  run hanya melaporkannya.
- Query berhenti setelah 30 detik (`--timeout 2m` untuk lebih lama) dan
  mengembalikan paling banyak 500 baris (`--limit`).

SQL dari file: `komando db query prod-db --file report.sql` (`--file -`
membaca stdin).

### Shell interaktif (untuk manusia)

```bash
komando db shell staging-db           # psql / mysql / sqlite3, mulai dalam mode read-only
komando db shell staging-db --write   # izinkan perubahan
komando db shell prod-db --yes        # shell apa pun di conn protected butuh --yes
```

`db shell` membuka client bawaan database di komputer ini, sudah tersambung
(lewat jalur `--via` milik conn jika ada). Sesinya read-only kecuali Anda
menambahkan `--write`: database menolak perubahan, sama seperti `db query`.
Ini hanya melindungi dari kecelakaan: di dalam client, seseorang bisa
mematikan read-only (dan shell escape seperti `\!` bisa melihat password),
itulah sebabnya conn yang protected butuh `--yes` bahkan untuk shell
read-only. Password sampai ke client lewat environment-nya, tidak pernah
lewat command line-nya. Ctrl-C diteruskan ke client (untuk membatalkan
query), bukan ke komando.

Client-nya harus terpasang di sini: `psql` (paket `postgresql-client`),
`mysql` (`mysql-client` atau `mariadb-client`) atau `sqlite3`. Ini untuk
manusia di terminal; agent dan skrip mendapat `NEEDS_TERMINAL` dan memakai
`db query`, yang mengembalikan JSON dan mengecek setiap statement.

### Backup

```bash
komando db dump prod-db --to prod-2026-11-02.sql.gz      # backup ke file di komputer ini
komando db restore staging-db --from prod-2026-11-02.sql.gz --allow-dangerous
```

- File backup selalu disimpan di **komputer ini**, hanya bisa dibaca oleh
  Anda. File yang sudah ada tidak pernah ditimpa.
- komando memakai alat bawaan database: `pg_dump`/`psql` (paket
  `postgresql-client`) atau `mysqldump`/`mysql` (`mysql-client`). Alat itu
  berjalan di server `--via` milik conn jika ada, kalau tidak di sini. Jika
  belum terpasang, pesan error-nya memberi tahu apa yang perlu dipasang
  (`komando pkg install web1 postgresql-client`).
- Password dikirim ke alat itu lewat environment-nya, tidak pernah lewat
  command line-nya, jadi user lain di server tidak bisa melihatnya.
- Restore bisa menimpa data, jadi butuh `--allow-dangerous` (dan `--yes`
  pada conn yang protected). Restore PostgreSQL berjalan dalam satu
  transaksi: jika ada yang gagal, tidak ada yang berubah.
- Sebelum mengirim apa pun, komando membaca seluruh file. File yang berisi
  perintah client yang bisa menjalankan program atau membaca file (`\!`,
  `system`, `\i`) ditolak; dump yang asli tidak pernah berisi perintah itu.
- Untuk conn MySQL dengan `?tls=...`, pengaturan TLS yang sama diteruskan ke
  `mysqldump`/`mysql` (client MySQL dan MariaDB sama-sama bisa).
- SQLite: `dump` menyalin file database (`--to backup.db`). Untuk restore,
  hentikan aplikasinya lalu salin file itu kembali.
- Database besar butuh waktu: tidak ada batas waktu kecuali Anda memberi
  `--timeout`.
