# Gap analysis: database dan cache (komando `feat/v0.3`, commit 4784fc9)

Cakupan: `komando db` (postgres, mysql/mariadb, sqlite), `komando cache` (redis/valkey/keydb/dragonfly),
dan engine data yang belum didukung. Dibandingkan dengan psql, pgcli, mysql, mycli, sqlite3, usql,
DBeaver/DataGrip, pg_dump/pg_restore/pg_dumpall, mysqldump/mydumper, pg_activity/pg_top, pgbench,
golang-migrate/dbmate/Flyway/Atlas/sqitch, PgBouncer admin, redis-cli, RedisInsight, memcached tools,
mongosh, sqlcmd, sqlplus, clickhouse-client, cqlsh, curl ke Elasticsearch/OpenSearch, influx, cockroach,
aws dynamodb, kcat/kafka-topics, rabbitmqadmin, nats, etcdctl, consul.

Metode: membaca `internal/cli/db.go`, `dbdump.go`, `dbshell.go`, `cache.go`, `conn.go`, `everything.go`,
`meta.go`, `ops.go`, `internal/dbx/*`, `internal/cachex/cachex.go`, `internal/driver/*`, docs
(`vision.md`, `resources-and-db.md`, `ux.md`, `features/databases.md`, `features/caches.md`), plus
`bin/komando ... --help` dan `komando policy check --for ...` (offline, tanpa koneksi ke server mana pun).

## Legenda

- **ADA**: ada perintah/flag first-class yang aman dan terstruktur.
- **SEBAGIAN**: bisa, tapi lewat jalur mentah (`db query`, `cache run`, `exec`, `db shell`, `tunnel`) atau fiturnya kurang lengkap. Kolom catatan menyebut apa yang kurang.
- **TIDAK ADA**: tidak ada jalur yang wajar di komando (workaround di luar komando disebut kalau ada).
- **NON-GOAL**: sengaja tidak dibuat; alasan dikutip dari dokumen desain.
- Prioritas: **P1** kebutuhan harian / keamanan / penghambat agent; **P2** berguna; **P3** niche. Baris ADA dan NON-GOAL diberi `-`.

Kutipan non-goal yang dipakai berulang:

- **NG-1** (vision.md, Bukan tujuan): "Mengganti alat lengkap (`psql`, `kubectl`, `terraform`, `helm`). komando menangani 80% pekerjaan harian dengan aman. Sisanya tetap bisa dikerjakan lewat `exec` di host atau alat aslinya."
- **NG-2** (resources-and-db.md, Bukan tujuan): "Menjadi klien DB lengkap (REPL, migrasi, ORM). Untuk itu sudah ada `psql`/`usql`."
- **NG-3** (vision.md): "GUI, TUI, sistem plugin, atau daemon/server. komando tetap CLI murni."
- **NG-4** (vision.md): "Monitoring atau alerting yang berjalan terus-menerus."
- **NG-5** (vision.md, Aturan teknis): "Tanpa pool dan tanpa daemon. Satu koneksi per perintah."
- **NG-6** (vision.md): "Infrastructure as Code, provisioning cloud, atau GitOps."

Fakta teknis yang memengaruhi prioritas:

- Ukuran biner: build rilis (`-s -w -trimpath`, CGO_ENABLED=0) **34,7 MB** (`bin/komando` 51 MB di repo adalah build dev tanpa strip). Ukuran biner tidak lagi dibatasi (keputusan pemilik), jadi driver baru (Mongo, MSSQL, ClickHouse, Cassandra) dinilai dari kebutuhan harian, bukan ukuran.
- `db dump/restore` memakai `pg_dump`/`psql`/`mysqldump`/`mysql` eksternal (di laptop atau di host `--via`), bukan Go murni.

---

## 1. Koneksi dan inventaris database

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Daftarkan DB dengan URL, password di vault | psql (`PG*` env, `.pgpass`), mysql (`.my.cnf`), usql, DBeaver | ADA | `conn add NAME URL --password-ref secret:X`; URL berpassword ditolak (`URL_HAS_PASSWORD`, `driver.Parse`) | - |
| PostgreSQL | psql, pgcli | ADA | kind `postgres`/`postgresql` (pgx v5, Go murni) | - |
| MySQL / MariaDB | mysql, mycli, mariadb | ADA | kind `mysql`/`mariadb`; MariaDB `max_statement_time` fallback (`dbx.setTimeout`) | - |
| SQLite (file lokal) | sqlite3 | ADA | `sqlite:///path` (modernc, tanpa cgo); `mode=ro` + `query_only` tanpa `--write` | - |
| SQLite di server remote (file di host SSH) | sqlite3 via ssh | TIDAK ADA | `conn.go:94` "conns are local files; --via is not supported". Workaround: `exec host -- sqlite3 ...` (tanpa klasifikasi SQL) atau `download` lalu query lokal | P2 (SQLite di VPS kecil umum: app Rails/Django/PocketBase) |
| Jangkau DB lewat bastion (`--via`), tanpa port lokal | ssh -L + psql, DBeaver SSH tunnel | ADA | `conn add --via HOST`; dial di dalam proses (pgx `DialFunc`, mysql `RegisterDialContext`) | - |
| Jangkau DB lewat VPN | DBeaver + VPN OS | ADA | `--via office,bastion` (VPN kinds) | - |
| TLS Postgres (sslmode, sslrootcert, client cert) | psql `sslmode`/`sslrootcert`/`sslcert` | SEBAGIAN | pgx membaca semua parameter `ssl*` dari URL. Tapi `db shell` hanya meneruskan `PGSSLMODE` (`dbshell.go`), bukan `sslrootcert`/`sslcert`; `db dump` meneruskan URL utuh ke `pg_dump` (ok). Path cert berupa file lokal, tidak lewat vault | P2 |
| TLS MySQL dengan CA sendiri / client cert | mysql `--ssl-ca`, `--ssl-cert` | SEBAGIAN | Hanya `tls=` true, false, skip-verify, preferred (`dbx/mysql.go`); CA kustom butuh `mysql.RegisterTLSConfig` yang tidak dipakai. Edge case ux.md: "TLS dengan sertifikat self-signed: opsi eksplisit per conn" | P2 (RDS/Azure/self-hosted dengan CA privat) |
| Unix socket lokal (`/var/run/postgresql`, `mysql.sock`) | psql, mysql | TIDAK ADA | `driver.Parse` mewajibkan hostname. Workaround: TCP ke 127.0.0.1 lewat `--via` server itu | P3 |
| Login IAM / token cloud (RDS IAM, Cloud SQL IAM, Azure AD) | aws rds generate-db-auth-token + psql, cloud-sql-proxy | TIDAK ADA | Ref secret statis saja (`secret:`/`env:`/`file:`/`aws-sm:`...). Token 15 menit perlu dibuat per koneksi | P2 (makin umum di AWS/GCP; cocok dengan model ref `aws-rds-iam:`) |
| `pg_service.conf` / `~/.pgpass` / `~/.my.cnf` | psql, mysql | ADA | `komando import pgpass`, `import mycnf`, `import env`, `import dbeaver` (importer.go). `pg_service.conf` tidak diimpor | - (pg_service: P3) |
| Cek koneksi **dan login** + versi server | `pg_isready`, `psql -c 'select 1'`, `redis-cli ping` | SEBAGIAN | **Bug/celah**: `komando test` untuk conn hanya membuka TCP (`conn.go testConn`, `Check: "tcp"`) dan mengecek ref password bisa dibaca. Login, auth, nama DB salah, TLS, dan versi server tidak dicek, padahal `--help` bilang "reached and logged in to" dan resources-and-db.md menjanjikan "connect + ping + versi server" | **P1** (agent mengandalkan `test` sebelum bekerja; error auth baru muncul belakangan) |
| Query ke banyak DB sekaligus (`db query @prod`) | usql (tidak), skrip loop, DataGrip "run on multiple" | TIDAK ADA | Ditolak dengan pesan jelas (`singleConn`; ux.md "Berikutnya") | P2 (cek versi/ukuran di 20 DB tenant; selector universal sudah ada) |
| Pilih DB lain di server yang sama tanpa conn baru | psql `\c dbname`, mysql `USE` | SEBAGIAN | `USE` di mysql hanya untuk satu perintah; tidak ada `--database` override. Workaround: conn baru per DB | P3 |
| Replika baca / routing read-only ke replica | pgcli? (tidak), aplikasi | TIDAK ADA | Workaround: conn terpisah untuk replica (`--tag replica`) | P3 |
| Postgres-wire lain: CockroachDB, YugabyteDB, Neon, Supabase, Timescale, Redshift, AlloyDB | cockroach sql, psql | SEBAGIAN | Query lewat `postgres://` kemungkinan jalan (pgx, `SHOW standard_conforming_strings`, `BEGIN READ ONLY`). Belum diuji; `db schema` memakai `pg_class` (CockroachDB mendukung sebagian), `db dump` dengan `pg_dump` tidak didukung CockroachDB; Redshift tidak mendukung semua katalog | P2 (perlu tes + catatan kompatibilitas) |
| MySQL-wire lain: TiDB, Vitess/PlanetScale, Aurora, SingleStore | mysql | SEBAGIAN | Lewat `mysql://`; belum diuji (PlanetScale: `START TRANSACTION READ ONLY` didukung; `mysqldump` ke Vitess terbatas) | P3 |

## 2. Menjalankan query

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Jalankan SQL apa pun | psql `-c`, mysql `-e`, sqlite3, usql | ADA | `db query CONN "SQL"` | - |
| Read-only default, ditegakkan server | (tidak ada di psql; DBeaver "read-only connection") | ADA | `BEGIN READ ONLY` / `START TRANSACTION READ ONLY` / sqlite `mode=ro` (`dbx.Run`) | - |
| Klasifikasi risiko sebelum kirim | (tidak ada) | ADA | `driver.ClassifySQL`; aturan `sql-drop`, `sql-delete-no-where`, `sql-kill`, dll.; `policy check --for postgres "..."` | - |
| Dry-run tulis dengan rollback | (manual BEGIN/ROLLBACK) | ADA | `--write --dry-run` → `rows_affected` + `rolled_back` | - |
| SQL dari file / stdin | psql `-f`, `\i`, mysql `< file` | ADA | `--file FILE`, `--file -` | - |
| Parameter binding | psql `\bind` (16+), `-v` | ADA | `--arg` berurutan (`$1`/`?`), hanya untuk 1 statement | - |
| Variabel bernama / substitusi (`:var`, `\set`) | psql `-v`, `\set`, `\gset` | TIDAK ADA | Hanya `--arg` posisi; `\gset` (hasil → variabel) tidak ada | P3 |
| Multi-statement dalam satu transaksi atomik | psql `--single-transaction` | ADA | Satu `db query` = satu transaksi; `BEGIN/COMMIT` ditolak (`SQL_TX_CONTROL`) | - |
| Transaksi interaktif lintas perintah (BEGIN … periksa … COMMIT) | psql, mysql REPL | NON-GOAL | NG-5 "Satu koneksi per perintah"; desain sengaja (resources-and-db.md). Pengganti: `--write --dry-run` lalu `--write` | - |
| Savepoint | psql | NON-GOAL | `SAVEPOINT` ditolak (`txControl`); konsekuensi model satu transaksi | - |
| Statement non-transaksional (VACUUM, CREATE INDEX CONCURRENTLY, DDL MySQL) | psql | ADA | Harus dikirim sendirian; dry-run hanya melapor (`Statement.NoTx`) | - |
| Timeout query | psql `statement_timeout`, mysql `max_execution_time` | ADA | `--timeout` (default 30 detik), di-set di server | - |
| `lock_timeout` (jangan menunggu lock lama) | psql `SET lock_timeout` | SEBAGIAN | Tidak di-set; hanya `statement_timeout`. ux.md edge case "db: lock lama (`lock_timeout`)" belum ditutup. Bisa manual `SET lock_timeout` dalam query yang sama | P2 (DDL di produksi bisa antre di belakang lock dan memblok semua query lain selama 30 detik) |
| `idle_in_transaction_session_timeout`, `application_name` | psql | ADA | `application_name = komando/<actor>` (terlihat di `pg_stat_activity`); transaksi selalu ditutup per perintah | - |
| Batalkan query (Ctrl-C) | psql Ctrl-C | ADA | context cancel + timeout server | - |
| EXPLAIN / EXPLAIN ANALYZE | psql, pgcli, DataGrip | ADA | `db explain [--analyze]` (Postgres `ANALYZE, BUFFERS`; MySQL `EXPLAIN ANALYZE`; SQLite `QUERY PLAN`) | - |
| EXPLAIN format JSON / visualisasi (explain.dalibo, pev2) | psql, DataGrip | SEBAGIAN | Bisa `db query "explain (format json) ..."`; tidak ada flag `--format json` atau ringkasan node terlambat | P3 |
| `\gexec` (jalankan hasil query sebagai SQL) | psql | TIDAK ADA | Disengaja tidak ada (berbahaya untuk agent); bisa dua langkah manual | P3 |
| `\watch` (ulang query tiap N detik) | psql `\watch`, `watch` | TIDAK ADA | Tidak ada `--repeat/--interval`. Mode terus-menerus bertabrakan dengan NG-4; versi terbatas (`--repeat 5 --interval 2s`) masih cocok | P3 |
| `\timing` | psql, mysql | ADA | `meta.duration_ms` di setiap jawaban (total, bukan per statement) | - |
| Pengaman MySQL `--safe-updates` | mysql `--safe-updates` | ADA | Setara/lebih kuat: `sql-update-no-where`, `sql-delete-no-where` | - |
| Hasil per statement terstruktur | (tidak ada di psql) | ADA | `data.results[]` dengan `columns`, `rows`, `row_count`, `rows_affected` | - |
| Tipe data aman JSON (bigint, numeric, bytea, timestamp UTC) | — | ADA | `driver.JSONValue`; > 2^53 jadi string, biner → `{"base64":...}` | - |

## 3. Output, paging, ekspor, impor data

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Output tabel teks | psql aligned, mysql table | ADA | `-o text` (tabwriter, potong sel > 80 karakter) | - |
| Output JSON | usql `-J`, psql `\pset format json` (17+) | ADA | `-o json` (envelope stabil) | - |
| Mode expanded / vertikal (`\x`, `\G`) | psql `\x`, mysql `\G`, pgcli | TIDAK ADA | Tabel lebar terpotong di terminal; tidak ada `-o vertical` | P3 |
| Ekspor CSV/TSV/Markdown | psql `\copy ... csv`, `--csv`, sqlite3 `.mode csv`, DBeaver export, mycli `--csv` | TIDAK ADA | `-o` hanya `auto`, `json`, `text`. Workaround: `-o json` lalu jq `@csv` | P2 (permintaan "kirim data ini sebagai CSV" sangat umum) |
| Ekspor hasil besar ke file (streaming, tanpa batas 500 baris / 256 KiB) | psql `\copy (query) TO file`, `\o file`, DBeaver export | SEBAGIAN | `--limit 0` + `--max-output` besar; semua ditampung di memori dan dicetak sekali. `COPY ... TO STDOUT` tidak didukung lewat `database/sql` | P2 |
| Paging hasil (offset/cursor, "halaman berikutnya") | pgcli pager, DataGrip, psql `FETCH` | SEBAGIAN | `truncated: true` + hint; tidak ada `--offset`/cursor; agent harus menulis `LIMIT/OFFSET` sendiri | P3 |
| Pager untuk manusia (`less`) | psql/pgcli pager | SEBAGIAN | Pipe ke `less` aman (SIGPIPE ditangani, ux.md); tidak otomatis | P3 |
| Impor CSV ke tabel | psql `\copy FROM`, mysql `LOAD DATA LOCAL INFILE`, sqlite3 `.import`, DBeaver import | TIDAK ADA | `COPY FROM STDIN` tidak bisa lewat `db query`; `LOAD DATA LOCAL` tidak diaktifkan di driver. Workaround: generate INSERT lalu `--file --write` | P2 |
| Salin data antar DB (tabel A di prod → staging) | DBeaver data transfer, pg_dump `-t` \| psql | TIDAK ADA | Workaround: `db dump` (seluruh DB) lalu `db restore` | P3 |
| Simpan output ke file | psql `\o`, `-o file` | ADA | Redirect shell; JSON stabil | - |

## 4. Introspeksi schema (setara meta-command psql / sqlite3 / mysql)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Daftar tabel/view + perkiraan baris (`\dt`, `.tables`, `SHOW TABLES`) | psql, sqlite3, mysql | ADA | `db schema CONN` (tabel, view, matview, foreign table; `row_estimate`) | - |
| Kolom, tipe, null, default, PK (`\d tabel`, `.schema`, `DESCRIBE`) | psql, sqlite3, mysql | ADA | `db schema CONN TABLE...` | - |
| Index (definisi) | psql `\d`, `\di` | ADA | `indexes[].definition` | - |
| Foreign key / relasi | psql `\d`, DataGrip diagram | SEBAGIAN | `dbx.Table` tidak punya FK (`dbx/schema.go:14-21`). Hanya lewat jalur mentah: `db query` ke `information_schema.table_constraints`/`pg_constraint` (read) | **P1** (agent butuh relasi untuk JOIN yang benar dan untuk menilai dampak DELETE/ON DELETE CASCADE) |
| Constraint unique/check, exclusion | psql `\d` | SEBAGIAN | Unique hanya tersirat dari definisi index; CHECK/exclusion tidak ada di `db schema`, hanya lewat `db query` ke `pg_constraint` / `information_schema.check_constraints` | P2 |
| Trigger | psql `\d`, `SHOW TRIGGERS` | SEBAGIAN | Tidak ada di `db schema`; hanya lewat `db query` (`information_schema.triggers`, `SHOW TRIGGERS`, dinilai read). Penting saat menilai efek samping UPDATE/DELETE | P2 |
| Daftar schema/namespace (`\dn`) | psql | SEBAGIAN | Nama schema muncul per tabel; tidak ada daftar schema (yang kosong tidak terlihat) | P3 |
| Daftar database di server (`\l`, `SHOW DATABASES`) | psql, mysql | SEBAGIAN | Lewat `db query "select datname from pg_database"`; MySQL `db schema` hanya `DATABASE()` saat ini | P2 |
| Fungsi/prosedur (`\df`, `SHOW PROCEDURE STATUS`) | psql, mysql | SEBAGIAN | Lewat `db query` ke katalog | P3 |
| Sequence (`\ds`), tipe/enum (`\dT`), extension (`\dx`) | psql | SEBAGIAN | Lewat `db query`; enum penting untuk menulis INSERT yang valid | P3 |
| Definisi view (`\d+ view`, `SHOW CREATE VIEW`) | psql, mysql | SEBAGIAN | Lewat `db query "select pg_get_viewdef(...)"` / `SHOW CREATE VIEW` | P3 |
| DDL lengkap satu tabel (`SHOW CREATE TABLE`, `pg_dump -s -t`) | mysql, pg_dump | SEBAGIAN | MySQL: `db query "show create table x"` (read). Postgres: tidak ada fungsi bawaan; `db dump` tidak punya `--schema-only -t` | P2 |
| Ukuran tabel/index (`\dt+`, `\di+`) | psql | SEBAGIAN | Lewat `db query` (`pg_total_relation_size`, `information_schema.tables.data_length`). Tidak ada kolom ukuran di `db schema` | P2 |
| Komentar tabel/kolom (`\d+`, `COMMENT`) | psql, DataGrip | SEBAGIAN | Tidak ada di `db schema`; lewat `db query` (`obj_description`/`col_description`, `information_schema.columns.column_comment`). Komentar sering berisi arti kolom: berguna untuk agent | P3 |
| Partisi | psql `\d+` | SEBAGIAN | Tabel partisi (`relkind p`) tampil sebagai `table`; hubungan parent/child tidak | P3 |
| Hak akses per tabel (`\dp`, `SHOW GRANTS`) | psql, mysql | SEBAGIAN | Lewat `db query` | P3 |
| Cari tabel/kolom berdasarkan nama di semua schema | DataGrip search, pgcli completion | SEBAGIAN | `db schema` lalu filter jq; kolom hanya untuk tabel yang disebut | P3 |
| Diagram ER | DBeaver, DataGrip | NON-GOAL | NG-3 (bukan GUI) | - |

## 5. Kenyamanan klien interaktif

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| REPL interaktif | psql, mysql, sqlite3, pgcli, mycli, usql | ADA (lewat alat asli) | `db shell CONN` membuka psql/mysql/sqlite3 dengan password dari vault dan jalur `--via`, read-only default (`PGOPTIONS=-c default_transaction_read_only=on`, `--init-command=SET SESSION TRANSACTION READ ONLY`, `-readonly`). REPL buatan sendiri = NG-2 | - |
| REPL dengan pgcli/mycli/usql/litecli | pgcli, mycli, usql | SEBAGIAN | `db shell` hanya memanggil psql/mysql/sqlite3. Workaround: `tunnel start CONN` lalu pgcli ke port lokal (password harus dimasukkan manual) | P3 (`--client pgcli`) |
| Autocomplete SQL | pgcli, mycli, DataGrip | NON-GOAL | NG-2/NG-3; tersedia via `db shell` + pgcli | - |
| Riwayat query | psql `~/.psql_history`, pgcli history, DataGrip | SEBAGIAN | `komando audit --command db.query` mencatat SQL (kalau `audit_sql=full`), aktor, hasil. Tidak ada "jalankan ulang entri N" | P3 |
| Query tersimpan / favorit (named queries) | pgcli `\ns`/`\n`, mycli favorites, DBeaver scripts, usql | TIDAK ADA | `recipe` hanya untuk shell di host (ops.go), bukan SQL ke conn. Workaround: file `.sql` + `--file` | P2 (agent dan tim butuh "cek antrean", "user terbaru" yang aman dipakai ulang; `recipe` sudah ada sebagai konsep) |
| Edit query di `$EDITOR` (`\e`) | psql, pgcli | NON-GOAL | NG-2 (tersedia via `db shell`) | - |
| `\!` shell escape | psql | NON-GOAL | Sengaja diblok di restore; di `db shell` tercatat sebagai risiko (docs) | - |
| Bantuan sintaks (`\h`) | psql, mysql `help` | NON-GOAL | Alat asli via `db shell` | - |

## 6. Backup dan restore

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Dump satu DB ke file lokal (plain SQL, gzip) | pg_dump, mysqldump | ADA | `db dump CONN --to FILE[.gz]`; file 0600, tidak menimpa, atomik | - |
| Dump SQLite konsisten | sqlite3 `.backup`, `.dump` | ADA | `VACUUM INTO` (file DB, bukan teks SQL). `.dump` teks: tidak ada | - |
| Format custom/directory/tar (`pg_dump -Fc/-Fd/-Ft`) | pg_dump, pg_restore | TIDAK ADA | Hanya plain SQL (`toolsFor`). Format custom adalah praktik standar Postgres (restore selektif, paralel, kompresi) | **P1** (backup Postgres produksi hampir selalu `-Fc`; file dari tim lain tidak bisa dipulihkan) |
| Restore format custom (`pg_restore`) | pg_restore | TIDAK ADA | `db restore` hanya menjalankan SQL lewat `psql` | **P1** (pasangan dari baris di atas) |
| Dump paralel (`-j`), mydumper/myloader | pg_dump `-Fd -j`, mydumper | TIDAK ADA | | P3 |
| Schema saja / data saja (`-s`, `-a`, `--no-data`) | pg_dump, mysqldump | TIDAK ADA | | P2 (dump schema untuk review/diff sangat umum) |
| Pilih/kecualikan tabel atau schema (`-t`, `-T`, `-n`, `--ignore-table`) | pg_dump, mysqldump | TIDAK ADA | | P2 (kecualikan tabel log raksasa) |
| Globals/role (`pg_dumpall --globals-only`), semua DB | pg_dumpall, mysqldump `--all-databases` | TIDAK ADA | | P3 |
| Opsi restore: `--clean`, `--create`, `--no-owner`, `--no-acl` | pg_restore, psql | TIDAK ADA | Restore dari prod ke staging sering gagal karena owner/role berbeda; tidak ada `--no-owner` | P2 |
| Restore satu transaksi + cek file berbahaya | psql `--single-transaction` | ADA | `--single-transaction ON_ERROR_STOP=1` (hanya Postgres, `dbdump.go:64`; restore MySQL tidak atomik karena DDL auto-commit); file dengan `\!`, `\i`, `system` ditolak (`driver/restore.go`) | - |
| Pengaman restore (destructive + protected) | — | ADA | `--allow-dangerous`, `--yes` di conn protected | - |
| Kompresi zstd/lz4, level | pg_dump `-Z zstd`, gzip | SEBAGIAN | Hanya `.gz` | P3 |
| Dump langsung ke storage (S3) atau tetap di server | pg_dump \| aws s3 cp | SEBAGIAN | File selalu ke laptop; dua langkah `db dump` lalu `storage upload` (DB besar lewat laptop = lambat). Workaround: `job start host -- 'pg_dump ...'` (password harus diurus sendiri) | P2 |
| Dump/restore DB besar sebagai job di latar (progress, lanjut setelah putus) | `nohup pg_dump`, `komando job` | TIDAK ADA | `db dump` berjalan di depan, tanpa progress, tanpa detach; AGENTS.md aturan 6 menyuruh `job` untuk > 2 menit tapi `job` tidak bisa menjalankan `db dump` | P2 |
| Dump dengan klien Go murni (tanpa pg_dump terpasang) | — | TIDAK ADA | Butuh `postgresql-client`/`mysql-client` di laptop atau host `--via`; versi pg_dump < server → gagal (hint ada) | P3 |
| Backup terjadwal + retensi | pgBackRest, cron | NON-GOAL | NG-5 (tanpa daemon); bisa `cron set` di host | - |
| PITR / WAL archiving / base backup (pgBackRest, Barman, wal-g, xtrabackup) | pgBackRest, wal-g | NON-GOAL | NG-1 | - |
| Verifikasi backup (list isi, `pg_restore -l`) | pg_restore `-l` | TIDAK ADA | | P3 |

## 7. Operasional dan diagnosis (DBA harian)

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Ringkasan server: versi, uptime, ukuran DB, koneksi/max_connections, role primary/replica | `\conninfo`, `SELECT version()`, `mysqladmin status`, pg_activity header | SEBAGIAN | Tidak ada `db info`/`db status` (padahal `cache info` ada dan ux.md mendaftarkan verb `status`/`info`). Recipe `postgres-status`/`mysql-status` jalan di host via `sudo -u postgres psql`, bukan di conn. Workaround: `db query` | **P1** (langkah pertama setiap insiden; konsistensi verb antar family) |
| Aktivitas / query yang sedang jalan | pg_activity, pg_top, `SHOW PROCESSLIST`, mytop | SEBAGIAN | `db query "select ... from pg_stat_activity"` (read). Tidak ada perintah first-class yang menyaring query lama/idle in transaction | **P1** |
| Lock dan siapa memblok siapa | pg_activity (blocking), `pg_blocking_pids`, `sys.innodb_lock_waits` | SEBAGIAN | Lewat `db query`; query lock tree cukup rumit untuk ditulis ulang tiap kali | **P1** |
| Hentikan query / sesi | `pg_cancel_backend`, `pg_terminate_backend`, MySQL `KILL` | SEBAGIAN | `db query --write --allow-dangerous "select pg_terminate_backend(123)"` (aturan `sql-kill`). Tidak ada `db kill PID` dengan dry-run yang menampilkan query yang akan dihentikan dan beda cancel vs terminate | **P1** |
| Query lambat / statistik query (`pg_stat_statements`, slow log, `performance_schema`) | pg_stat_statements, pt-query-digest, PMM | SEBAGIAN | Lewat `db query` kalau extension terpasang | P2 |
| Ukuran DB / tabel / index terbesar | psql `\l+`, `\dt+`, pg_activity | SEBAGIAN | Lewat `db query` | **P1** (disk penuh adalah insiden harian; `db schema` sudah menampilkan baris tapi tidak ukuran) |
| Bloat, dead tuples, autovacuum terakhir | pgstattuple, check_postgres, pg_activity | SEBAGIAN | Lewat `db query` (`pg_stat_user_tables`) | P3 |
| Index tak terpakai / index hilang | pg_stat_user_indexes, pghero | SEBAGIAN | Lewat `db query` | P3 |
| Cache hit ratio, statistik IO | pghero, pg_activity | SEBAGIAN | Lewat `db query` | P3 |
| Status replikasi dan lag | `pg_stat_replication`, `SHOW REPLICA STATUS`, orchestrator | SEBAGIAN | Lewat `db query` (`SHOW REPLICA STATUS` dinilai read) | P2 |
| Slot replikasi (logical/physical) | psql | SEBAGIAN | Baca lewat `db query`; drop/create diblok `sql-server-config` (butuh `--allow-dangerous`) | P3 |
| Konfigurasi server (`SHOW ALL`, `pg_settings`, `SHOW VARIABLES`) | psql, mysql | SEBAGIAN | Baca lewat `db query`; ubah global = `sql-server-config` (destructive). Tidak ada ringkasan "setting yang beda dari default" | P3 |
| VACUUM / ANALYZE / REINDEX / OPTIMIZE TABLE | psql, mysqlcheck | ADA (lewat jalur mentah) | `db query --write "vacuum analyze t"` (noTx, harus sendirian); `VACUUM FULL` diblok `sql-vacuum-full` | - |
| Wraparound / umur XID | check_postgres | SEBAGIAN | Lewat `db query` | P3 |
| Benchmark (pgbench, sysbench, mysqlslap) | pgbench | TIDAK ADA | Tidak masuk 80% harian; bisa `exec host -- pgbench` | P3 |
| Monitoring berkelanjutan / dashboard (pg_activity live, PMM) | pg_activity, pg_top | NON-GOAL | NG-4 dan NG-3 (TUI) | - |
| Pemeriksaan kesehatan DB berisi saran (pghero-style "checks") | pghero, pg_doctor | TIDAK ADA | Bisa jadi `recipe` SQL bawaan (lihat bagian 5) | P2 |

## 8. User, role, dan hak akses

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Daftar user/role dan atributnya (`\du`, `mysql.user`) | psql, mysql | SEBAGIAN | Lewat `db query` | P2 |
| Buat user / ubah password / grant / revoke | psql, mysql, DataGrip | SEBAGIAN | `db query --write --allow-dangerous "create user ..."` (aturan `sql-privileges`). **Celah keamanan**: password di `CREATE USER ... PASSWORD '...'` / `ALTER ROLE ... PASSWORD` ikut tercatat utuh di `audit.jsonl` saat `audit_sql=full` (default), padahal `--arg` tidak bisa dipakai di DDL Postgres. Tidak ada redaksi literal password dan tidak ada cara mengambil password dari vault (`secret:`) | **P1** (keamanan: secret bocor ke audit log; "buat user read-only untuk aplikasi/komando" adalah tugas umum dan docs sendiri menyarankan user khusus berhak minimal) |
| Template "user read-only untuk komando/agent" | — | TIDAK ADA | docs/features/databases.md: "give komando a database user with only the rights it needs", tapi tidak ada bantuan membuatnya | P2 |
| Lihat grant efektif satu user (`SHOW GRANTS FOR`, `\dp`) | mysql, psql | SEBAGIAN | Lewat `db query` | P3 |
| Row-level security, policy | psql | SEBAGIAN | Lewat `db query`; `CREATE POLICY` dinilai write (bukan privileges) | P3 |

## 9. Migrasi schema dan schema diff

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Alat migrasi berversi (up/down, tabel versi) | golang-migrate, dbmate, Flyway, Liquibase, Atlas, sqitch, goose | NON-GOAL | NG-2 "Menjadi klien DB lengkap (REPL, migrasi, ORM)". Pengganti: `db query --file m.sql --write --dry-run` lalu `--write` (atomik di Postgres) | - |
| Jalankan berkas migrasi yang sudah ada dengan aman (dry-run per file, urutan) | dbmate `--dry-run`?, Atlas `migrate apply --dry-run` | SEBAGIAN | Satu file per perintah dengan `--file`; DDL MySQL tidak bisa dry-run. Tidak ada "jalankan folder" | P3 |
| Status migrasi (versi terpasang) | migrate `version`, Flyway `info` | SEBAGIAN | Lewat `db query "select * from schema_migrations"` | P3 |
| Schema diff dua DB (prod vs staging) | Atlas `schema diff`, migra, pgquarrel, mysqldiff, DataGrip compare | TIDAK ADA | Workaround: `db schema -o json` dua conn lalu `diff`/jq (hanya kolom/index tabel yang disebut) | P2 (deteksi drift sebelum deploy; `db schema` JSON sudah 70% jalan) |
| Generate migrasi dari diff | Atlas, migra | NON-GOAL | NG-2/NG-6 | - |
| Lint migrasi (operasi yang mengunci tabel) | squawk, Atlas lint | SEBAGIAN | Klasifikasi risiko menangkap DROP/TRUNCATE/ALTER DROP, tidak menangkap `ALTER TABLE ... ADD COLUMN ... DEFAULT volatile`, index tanpa CONCURRENTLY, dll. | P3 |

## 10. Connection pooler dan proxy

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Konsol admin PgBouncer (`SHOW POOLS`, `SHOW STATS`, `PAUSE`, `RELOAD`) | psql ke db `pgbouncer` | TIDAK ADA | Konsol PgBouncer tidak menerima `BEGIN READ ONLY` dan pemeriksaan `SHOW standard_conforming_strings` saat `dbx.Open`, jadi `db query` hampir pasti gagal. Workaround: `exec host -- psql -p 6432 pgbouncer -c 'show pools'` | P3 |
| Query lewat PgBouncer mode transaction (aplikasi DB biasa) | psql | SEBAGIAN | Kemungkinan jalan (satu transaksi per perintah cocok); pgx stdlib memakai prepared statement yang bermasalah di PgBouncer < 1.21 mode transaction. Belum diuji/didokumentasikan | P2 |
| ProxySQL admin, pgpool, Odyssey | mysql ke port admin | TIDAK ADA | | P3 |
| Pool koneksi di sisi komando | — | NON-GOAL | NG-5 "Tanpa pool dan tanpa daemon" | - |

## 11. Keamanan dan audit khusus DB

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Audit setiap query (siapa, apa, hasil) | pgaudit (sisi server), DataGrip log | ADA | `audit_sql`: full, hash, off; `--arg` hanya dicatat jumlahnya | - |
| Redaksi data sensitif di SQL audit (literal password, PII) | — | TIDAK ADA | Hanya pilihan semua/hash/tidak ada. Lihat bagian 8 | **P1** (gabung dengan baris CREATE USER) |
| Blok fungsi berbahaya di read-only (dblink, pg_read_file, COPY PROGRAM, lo_export) | — | ADA | `sql-remote`, `sql-server-file`, `sql-program` | - |
| Tolak setting parsing string non-default (bypass klasifikasi) | — | ADA | `checkStringRules`, `SQL_STRING_RULES` | - |
| Konfirmasi ketik nama saat restore/drop di terminal | DataGrip "production" warning | ADA | `confirmDangerous` (`common.go:334`): di terminal tanpa `--allow-dangerous` diminta mengetik nama conn; conn protected minta `[y/N]` (`confirmProtected`) | - |
| Batas jumlah baris yang diubah (`--max-rows-affected`) | (tidak umum; Atlas/ pt-archiver) | TIDAK ADA | `--dry-run` menunjukkan jumlahnya, tapi `--write` tanpa dry-run tidak punya batas pengaman (mis. UPDATE dengan WHERE yang salah menyentuh 1 juta baris) | P2 (lapisan aman murah untuk agent) |
| Masking kolom sensitif di output | DataGrip, Satori, pg_anonymizer | TIDAK ADA | `conn --option` sudah ada tapi tidak dipakai kind db | P3 |
| Opsi per conn yang dijanjikan (`statement_timeout`, `row_limit`) | — | TIDAK ADA | resources-and-db.md: "Options ... per-kind: statement_timeout, row_limit"; `conn --option` hanya dipakai `cluster` (namespace, `cluster.go:78`). Contoh di `conn edit --help` (`--option statement_timeout=10s`, `conn.go:186`) menyesatkan: diterima tapi diabaikan | P3 |

---

## 12. Cache: koneksi dan topologi

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Redis/Valkey/KeyDB/Dragonfly standalone | redis-cli, valkey-cli | ADA | kind `redis` (`redis://`, `rediss://`), go-redis v9 | - |
| Garnet, Upstash, ElastiCache/Memorystore non-cluster | redis-cli | ADA (kemungkinan) | Protokol sama; belum diuji | - |
| Redis Cluster (MOVED/ASK, ElastiCache cluster mode, `redis-cli -c`) | redis-cli `-c` | TIDAK ADA | `redis.NewClient` tunggal; perintah ke slot lain mendapat `MOVED` (ux.md edge case "Redis cluster (`MOVED`)"). `cache keys` hanya men-scan satu node | P2 (umum di ElastiCache/Azure besar) |
| Sentinel (temukan master) | redis-cli `-p 26379`, `SENTINEL get-master-addr-by-name` | SEBAGIAN | Hanya jalur mentah: conn ke port sentinel lalu `cache run --write -- SENTINEL get-master-addr-by-name X` (`SENTINEL` tidak dikenal `cachex.Classify`, jadi dinilai write). Tidak ada conn yang sadar sentinel (cari master otomatis, ikut failover); ux.md edge case "sentinel" belum ditutup | P2 |
| ACL user + password | redis-cli `--user`, `--pass` | ADA | user di URL, password via ref | - |
| TLS default (rediss) | redis-cli `--tls` | ADA | `MinVersion TLS1.2`, SNI | - |
| TLS CA sendiri / skip-verify / client cert (`--cacert`, `--insecure`, `--cert`) | redis-cli | TIDAK ADA | `cachex.Open` hanya `ServerName`; tidak ada opsi URL. Redis self-hosted dengan sertifikat privat tidak bisa dipakai | P2 |
| Pilih DB (`-n`, `SELECT`) | redis-cli `-n` | SEBAGIAN | Nomor DB dari path URL; `SELECT` lewat `cache run` dinilai write dan tidak berguna (satu perintah per koneksi). Tidak ada `--db N` per perintah | P3 |
| Lewat bastion/VPN (`--via`) | ssh -L + redis-cli | ADA | `a.Dial` | - |
| Unix socket | redis-cli `-s` | TIDAK ADA | | P3 |
| Cek login (bukan hanya TCP) | `redis-cli ping` | SEBAGIAN | Sama dengan bagian 1: `komando test` hanya TCP; `cache info` melakukan PING+AUTH | **P1** (gabung dengan baris test di bagian 1) |
| REPL interaktif | redis-cli | TIDAK ADA | `db shell` tidak punya padanan `cache shell`. Workaround: `tunnel start CONN` + `redis-cli` (password manual). ux.md bagian 12 jalur 3 ("alat asli di laptop lewat jalur komando") belum ada untuk cache | P3 |

## 13. Cache: membaca dan menjelajah

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Baca key tipe apa pun + TTL + ukuran | redis-cli `GET/HGETALL/...`, RedisInsight browser | ADA | `cache get` (string/hash/list/set/zset/stream, batas `--limit`, biner → base64) | - |
| Tipe modul (RedisJSON, TimeSeries, Bloom) | RedisInsight | SEBAGIAN | `cache get` mengembalikan `value: null`; `cache run -- JSON.GET k` **dinilai write** (perintah tak dikenal) jadi butuh `--write` untuk sekadar membaca | P2 (aturan baca modul umum: `JSON.GET/MGET`, `FT.SEARCH/INFO`, `TS.RANGE/GET`, `BF.EXISTS`) |
| Daftar key dengan pola (SCAN, aman) | redis-cli `--scan --pattern` | ADA | `cache keys CONN 'pat*' --limit` (SCAN, tidak pernah KEYS) | - |
| Filter key per tipe (`SCAN TYPE`) | redis-cli `--scan --type` (7+) | SEBAGIAN | `cache keys` tidak punya `--type` (`cachex.Keys`); lewat jalur mentah `cache run -- SCAN 0 MATCH 'x:*' TYPE hash COUNT 1000` (read), kursor diulang manual | P3 |
| Hitung key yang cocok pola / per prefix | RedisInsight "tree view", redis-rdb-tools | TIDAK ADA | `cache keys` berhenti di `--limit`; jumlah total tidak diketahui | P3 |
| Jumlah key per DB | redis-cli `INFO keyspace`, `DBSIZE` | ADA | `cache info` (bagian keyspace) / `cache run -- DBSIZE` | - |
| INFO server terstruktur per section | redis-cli `INFO` | ADA | `cache info CONN [SECTION]` → map per section | - |
| TTL / PTTL / OBJECT / MEMORY USAGE | redis-cli | ADA | TTL di `cache get`; lainnya lewat `cache run` (dinilai read) | - |
| Baca stream (XRANGE, XINFO, XPENDING) | redis-cli | ADA | `cache get` (stream) dan `cache run` (read) | - |
| `XREAD` non-blocking | redis-cli | SEBAGIAN | Dinilai write (tidak ada di daftar read) karena bisa `BLOCK`; `XREAD` tanpa BLOCK seharusnya read | P3 |

## 14. Cache: menulis per tipe data

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Set string + TTL | redis-cli `SET ... EX` | ADA | `cache set CONN KEY VALUE --ttl` | - |
| Set dengan NX/XX/KEEPTTL/GET | redis-cli | SEBAGIAN | Lewat `cache run --write -- SET k v NX` | P3 |
| Nilai dari file/stdin (biner, JSON besar) | redis-cli `-x` | TIDAK ADA | `cache set` hanya argumen; tidak ada `--file`/stdin | P3 |
| Ubah TTL / persist (`EXPIRE`, `PERSIST`) | redis-cli | SEBAGIAN | `cache run --write -- EXPIRE k 3600`; tidak ada `cache expire`/`cache set --ttl` untuk key yang sudah ada | P3 |
| Hash/list/set/zset/stream (HSET, LPUSH, SADD, ZADD, XADD, HDEL, SREM ...) | redis-cli, RedisInsight editor | SEBAGIAN | Semua lewat `cache run --write`; first-class hanya string | P3 |
| Rename/copy key | redis-cli `RENAME`, `COPY` | SEBAGIAN | `cache run --write`. `RENAME` diam-diam menimpa key tujuan tapi hanya dinilai write (lihat bagian 17) | P3 |
| Hapus key tepat | redis-cli `DEL/UNLINK` | ADA | `cache rm` (`--allow-dangerous`) | - |
| Hapus berdasarkan pola (invalidasi prefix: `--scan --pattern 'x:*' \| xargs DEL`) | redis-cli pipeline | TIDAK ADA | `cache rm` sengaja tanpa pola. Workaround: `cache keys` lalu `cache rm k1 k2 ...` (dibatasi `--limit`, panjang argv). Bisa dibuat aman: `--dry-run` menunjukkan jumlah + contoh, `--allow-dangerous`, UNLINK bertahap | P2 (invalidasi cache per prefix adalah pekerjaan harian setelah deploy) |
| Flush DB | redis-cli `FLUSHDB` | ADA (lewat jalur mentah) | `cache run --write --allow-dangerous -- FLUSHDB` (aturan `redis-flush`) | - |
| Dry-run tulis | — | SEBAGIAN | Jujur dilaporkan: Redis tidak bisa rollback, `--dry-run` hanya mengecek izin (`withCache`). Tidak menampilkan nilai lama / apakah key ada | P3 |

## 15. Cache: diagnosis dan operasi server

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Key terbesar (`--bigkeys`) | redis-cli `--bigkeys` | TIDAK ADA | Workaround: `cache keys` + `cache run -- MEMORY USAGE` per key (lambat, dibatasi). Masuk akal sebagai `cache keys --sort size` / `cache big` dengan SCAN | P2 (insiden memori penuh/eviction umum) |
| Memori per key (`--memkeys`, `--memkeys-samples`) | redis-cli | TIDAK ADA | Sama dengan di atas | P2 |
| Hot keys (`--hotkeys`, LFU) | redis-cli `--hotkeys` | TIDAK ADA | `OBJECT FREQ` per key lewat `cache run` | P3 |
| Latensi (`--latency`, `--latency-history`, `--intrinsic-latency`) | redis-cli | SEBAGIAN | `LATENCY LATEST/HISTORY/DOCTOR` lewat `cache run` (read). Latensi sisi klien tidak ada (`test` hanya TCP) | P3 |
| Statistik bergulir (`--stat`) | redis-cli `--stat` | NON-GOAL | NG-4 (pemantauan terus-menerus); snapshot ada di `cache info` | - |
| Slowlog | redis-cli `SLOWLOG GET` | ADA (lewat jalur mentah) | `cache run -- SLOWLOG GET 20` (read); `SLOWLOG RESET` = write | - |
| MONITOR (lihat semua perintah) | redis-cli `MONITOR` | TIDAK ADA | `cache run -- MONITOR` dinilai write dan `Do()` hanya membaca satu balasan. Versi terbatas waktu (`--duration 5s`) berguna untuk debug; versi terus-menerus = NG-4. Perhatian: MONITOR membocorkan nilai (PII/secret) | P3 |
| Daftar klien | redis-cli `CLIENT LIST` | ADA (lewat jalur mentah) | `cache run -- CLIENT LIST` (read; teks mentah, tidak diparse jadi tabel) | - |
| Kill klien | redis-cli `CLIENT KILL` | ADA (lewat jalur mentah) | `cache run --write --allow-dangerous -- CLIENT KILL ...` (`redis-kill`) | - |
| Lihat config (`CONFIG GET`) | redis-cli | ADA (lewat jalur mentah) | read | - |
| Ubah config (`CONFIG SET maxmemory`) | redis-cli | ADA (lewat jalur mentah) | `redis-server-config` (destructive) | - |
| Replikasi (role, lag, `INFO replication`) | redis-cli | ADA | `cache info CONN replication` | - |
| Memory doctor / stats | redis-cli `MEMORY DOCTOR` | ADA (lewat jalur mentah) | read | - |
| Persistensi: BGSAVE, LASTSAVE, BGREWRITEAOF | redis-cli | ADA (lewat jalur mentah) | `BGSAVE` dinilai write; `SAVE` diblok (`redis-blocking`) | - |
| `DEBUG` (sleep, object, reload) | redis-cli | ADA (lewat jalur mentah) | `redis-blocking`, butuh `--allow-dangerous` | - |
| Ulangi perintah (`-r N -i S`) | redis-cli `-r`, `-i` | TIDAK ADA | | P3 |
| Cek kesehatan dengan saran (eviction, fragmentasi, maxmemory tidak diset, persistence mati) | RedisInsight "Database analysis" | TIDAK ADA | `cache info` hanya angka mentah; tidak ada ringkasan `warnings[]` | P2 (agent perlu interpretasi; murah dari INFO) |

## 16. Cache: pub/sub, scripting, cluster admin

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| PUBLISH | redis-cli | ADA (lewat jalur mentah) | `cache run --write -- PUBLISH ch msg` | - |
| SUBSCRIBE / PSUBSCRIBE (dengar N pesan atau N detik) | redis-cli `SUBSCRIBE` | TIDAK ADA | Butuh mode streaming; versi terbatas (`--count`, `--duration`) cocok dengan CLI, versi terus-menerus = NG-4 | P3 |
| `PUBSUB CHANNELS/NUMSUB` | redis-cli | ADA (lewat jalur mentah) | read | - |
| EVAL / EVALSHA / FCALL | redis-cli `--eval` | ADA (lewat jalur mentah) | `redis-script-run` (destructive: tidak bisa diinspeksi); `EVAL_RO` read | - |
| `--eval file.lua` | redis-cli | TIDAK ADA | Skrip harus inline di argv | P3 |
| Admin cluster (`CLUSTER NODES/INFO`, `--cluster check/fix/rebalance/reshard`) | redis-cli `--cluster` | SEBAGIAN | `CLUSTER INFO/NODES` read lewat `cache run` ke satu node; `--cluster fix/reshard` tidak ada (NG-1) | P3 |
| Sentinel admin (`SENTINEL masters`, failover) | redis-cli | SEBAGIAN | Lewat `cache run --write -- SENTINEL ...` ke conn port sentinel. Membaca pun butuh `--write`, dan `SENTINEL FAILOVER/REMOVE/SET` hanya dinilai write (tidak butuh `--allow-dangerous`) | P3 |

## 17. Cache: backup, bulk, migrasi data

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Backup RDB ke laptop (`redis-cli --rdb`) | redis-cli `--rdb` | TIDAK ADA | vision.md tujuan 2: setiap family punya "backup, dan pulihkan"; `cache` tidak punya `dump`/`restore` | P2 |
| Ekspor/impor key (DUMP/RESTORE, JSON) per pola | redis-dump, RIOT, RedisInsight bulk | TIDAK ADA | `DUMP` read & `RESTORE` write ada lewat `cache run`, satu per satu | P3 |
| Mass insert (`--pipe`) | redis-cli `--pipe` | TIDAK ADA | | P3 |
| Salin antar instance (`MIGRATE`, RIOT, redis-shake) | redis-cli, redis-shake | SEBAGIAN | `MIGRATE` diblok sebagai `redis-flush` (destructive) lewat `cache run` | P3 |

## 18. Temuan keamanan/konsistensi pada klasifikasi cache

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Perintah yang menghapus data diperlakukan sama dengan `DEL` | — | SEBAGIAN | `GETDEL`, `HDEL`, `SREM`, `ZREMRANGEBY*`, `LTRIM`, `EXPIRE k 0`, `RESTORE ... REPLACE`, `RENAME` (menimpa tujuan), `SET` di atas key lain tipe dinilai **write**, sedangkan `DEL/UNLINK` dan `cache rm` butuh `--allow-dangerous` (`cachex.Classify`). Minimal `GETDEL`, `RENAME` ke key yang ada, dan `EXPIRE/PEXPIRE` ≤ 0 setara `data-delete` | P2 |
| `policy check --for redis "CLIENT LIST"` (satu argumen berkutip) | — | SEBAGIAN | Bug kecil: tanpa dipecah per kata dinilai `write`; `-- CLIENT LIST` dinilai `read` (`meta.go` memberi `args` mentah ke `cachex.Classify`). Untuk SQL argumen digabung, jadi dua jalur berbeda | P3 |
| Perintah baca modul dan baca biasa yang belum terdaftar (`XREAD`, `JSON.GET`, `FT.SEARCH`, `TS.RANGE`, `HELLO`, `CLIENT NO-TOUCH`) | — | SEBAGIAN | Dinilai write sehingga agent harus memakai `--write` untuk membaca; ini melemahkan makna `--write` di audit | P2 |

## 19. Memcached

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| get/set/delete, stats, stats items/slabs, flush_all | telnet, memcached-tool, memcdump, mcrouter | TIDAK ADA | vision.md tabel family: `cache` "nanti: memcached". Protokol teks sederhana, client Go murni kecil (`gomemcache`), cocok dengan `cache get/set/rm/info`; tidak ada SCAN (`keys` terbatas lewat `lru_crawler metadump`) | P2 (masih umum di WordPress/PHP/legacy; biaya biner kecil) |

---

## 20. Engine data yang belum didukung

Penilaian memakai kriteria vision.md "Kriteria menambah family" (masuk model conn+kind+verb, read-only default jujur, Go murni, kebutuhan harian, ada perawat). Ukuran biner tidak lagi dibatasi.

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| MongoDB (find, aggregate, count, indexes, stats, currentOp, killOp, mongodump/restore) | mongosh, mongodump, Compass | TIDAK ADA | vision.md: kandidat setelah v1.0 ("dan mongodb"). Driver resmi Go murni tapi besar (+~6-8 MB); read-only bisa lewat `readPreference` + user read, tidak ada transaksi read-only setara, jadi klasifikasi (`find`/`aggregate` tanpa `$out/$merge`) jadi lapisan utama. Workaround: `exec host -- mongosh --eval` | P2 (DB non-SQL paling populer) |
| Microsoft SQL Server / Azure SQL | sqlcmd, Azure Data Studio | TIDAK ADA | vision.md: `db` "nanti: mssql". `go-mssqldb` Go murni; read-only: `SET TRANSACTION ISOLATION ... ` tidak memblok tulis, perlu `ApplicationIntent=ReadOnly`/user read + klasifikasi T-SQL (dialek `[ ]`, `GO`) | P2 |
| Oracle | sqlplus, SQLcl | TIDAK ADA | `go-ora` Go murni; `SET TRANSACTION READ ONLY` ada. Jarang di target pengguna komando (devops kecil/menengah) | P3 |
| ClickHouse | clickhouse-client | TIDAK ADA | vision.md: `db` "nanti: clickhouse". `clickhouse-go` Go murni; read-only lewat setting `readonly=1` (ditegakkan server, cocok dengan kontrak) | P2 |
| Cassandra / ScyllaDB | cqlsh, nodetool | TIDAK ADA | `gocql` Go murni; tidak ada read-only transaksi; harus via klasifikasi CQL + role read | P3 |
| Elasticsearch / OpenSearch (health, indices, search, mapping, snapshot, hapus index) | curl, elasticsearch-cli, opensearch-cli, Kibana Dev Tools | TIDAK ADA | vision.md: kandidat setelah v1.0 "search (Elasticsearch, OpenSearch)". REST API (tanpa SDK) cocok dengan aturan teknis; risk per method+path jelas (GET read, DELETE index destructive) | P2 (sangat umum untuk log/search; murah di biner) |
| InfluxDB / TimescaleDB / Prometheus | influx CLI, promtool | SEBAGIAN | Timescale = postgres (ADA lewat `db`). Influx: TIDAK ADA. Prometheus disebut sebagai kandidat "query metrics" di vision.md (domain lain) | P3 |
| CockroachDB | cockroach sql | SEBAGIAN | Lihat bagian 1 (postgres-wire, belum diuji; `db dump` tidak cocok, CRDB memakai `BACKUP`) | P3 |
| MariaDB khusus (Galera status `wsrep_%`, `mariadb-dump`, `max_statement_time`, sequences, system-versioned tables) | mariadb, mariadb-dump | SEBAGIAN | Skema `mariadb://`, timeout MariaDB, flag TLS MariaDB untuk dump ada. Galera/wsrep lewat `db query "show status like 'wsrep%'"`. `mariadb-dump` (nama biner baru di 11.x, `mysqldump` jadi symlink dan mungkin hilang) belum dideteksi | P3 |
| DynamoDB | aws dynamodb, NoSQL Workbench | TIDAK ADA | SigV4 sendiri sudah ada untuk S3 (bisa dipakai ulang); read = GetItem/Query/Scan. Kebutuhan harian pengguna devops self-hosted rendah | P3 |
| Kafka (topics, consumer groups + lag, produce/consume N pesan, reset offset) | kcat, kafka-topics, kafka-consumer-groups, kafkactl | TIDAK ADA | vision.md: kandidat setelah v1.0 "message queue (RabbitMQ, Kafka, NATS)". `franz-go` Go murni. Consumer lag adalah kebutuhan insiden harian di tim yang memakai Kafka | P2 |
| RabbitMQ (queues, depth, consumers, purge, publish, shovel) | rabbitmqadmin, rabbitmqctl | TIDAK ADA | Kandidat vision.md. Management HTTP API (tanpa SDK); purge/delete queue = destructive | P2 |
| NATS / JetStream (streams, consumers, pub/sub, KV) | nats CLI | TIDAK ADA | Kandidat vision.md; `nats.go` Go murni | P3 |
| etcd (get/put/del prefix, member list, endpoint health, snapshot) | etcdctl | TIDAK ADA | `go.etcd.io/etcd/client` menarik gRPC (besar). Dipakai di k8s self-managed; snapshot etcd adalah backup kritikal | P3 |
| Consul KV / catalog / health | consul CLI | TIDAK ADA | HTTP API sederhana; KV mirip `cache` | P3 |
| DuckDB / file Parquet lokal | duckdb CLI | TIDAK ADA | Butuh cgo (melanggar "Pure Go, tanpa cgo") | P3 |
| Data warehouse cloud (BigQuery, Snowflake, Redshift, Databricks) | bq, snowsql | TIDAK ADA | Redshift lewat postgres-wire (belum diuji); BigQuery/Snowflake butuh SDK besar | P3 |
| Neo4j / graph DB | cypher-shell | TIDAK ADA | | P3 |
| Valkey/KeyDB/Dragonfly | valkey-cli | ADA | kind `redis` (docs/features/caches.md) | - |
| Provisioning DB terkelola (buat RDS/Cloud SQL, ubah ukuran) | aws rds, gcloud sql | NON-GOAL | NG-6 "Infrastructure as Code, provisioning cloud" | - |

---

## Ringkasan hitungan

Dihitung dari semua baris tabel di atas (bagian 1-20):

| Status | Jumlah |
|---|---|
| ADA (termasuk "ADA (lewat jalur mentah)", "ADA (lewat alat asli)", "ADA (kemungkinan)") | 66 |
| SEBAGIAN | 71 |
| TIDAK ADA | 67 |
| NON-GOAL | 15 |
| **Total kemampuan** | **219** |

Gap berprioritas (SEBAGIAN + TIDAK ADA): P1 = 12 baris (10 gap unik: cek login db dan cache digabung, redaksi audit dan CREATE USER digabung), P2 = 47, P3 = 79.
Rincian: SEBAGIAN = 9 P1 + 19 P2 + 43 P3; TIDAK ADA = 3 P1 + 28 P2 + 36 P3.
Hitungan ini sudah memakai hasil verifikasi per baris di bagian akhir (7 baris pindah dari TIDAK ADA ke SEBAGIAN; prioritas tidak berubah).

## Top P1 (urut dampak)

1. **`komando test` untuk db/cache hanya cek TCP**, bukan login/versi, padahal help dan desain menjanjikan login (`conn.go testConn`). Agent tidak bisa memverifikasi kredensial, nama DB, dan TLS sebelum bekerja.
2. **Password di `CREATE USER/ALTER ROLE ... PASSWORD` tercatat utuh di `audit.jsonl`** (default `audit_sql=full`), dan tidak ada cara memakai `secret:` di SQL. Perlu redaksi literal password + `db` user helper.
3. **`db info`/`db status`**: versi, uptime, ukuran DB, koneksi vs max, primary/replica. `cache info` sudah ada; `db` belum (verb `status/info` di ux.md).
4. **Aktivitas sesi** (pg_stat_activity / PROCESSLIST) first-class, dengan filter query lama dan idle-in-transaction.
5. **Lock dan rantai blocking** (`pg_blocking_pids`, `innodb_lock_waits`).
6. **`db kill PID`** (cancel vs terminate) dengan dry-run yang menampilkan query yang akan dihentikan; sekarang hanya lewat `select pg_terminate_backend()` + `--allow-dangerous`.
7. **Ukuran DB/tabel/index terbesar** (insiden disk penuh); `db schema` tidak punya kolom ukuran.
8. **Foreign key (dan relasi) di `db schema`**: penting agar agent menulis JOIN yang benar dan menilai efek cascade.
9. **`pg_dump -Fc` (format custom)** di `db dump`: standar backup Postgres produksi.
10. **`pg_restore`** untuk file custom/directory di `db restore`.

Catatan tambahan di luar tabel prioritas: ukuran biner tidak lagi dibatasi, jadi engine baru (Mongo, MSSQL, ClickHouse, Kafka) dipilih dari kebutuhan harian; family berbasis HTTP (Elasticsearch/OpenSearch, RabbitMQ, Consul) tetap paling sederhana dibuat.

## Verifikasi per baris

Setiap baris di atas dicek ulang terhadap kode (`internal/cli`, `internal/dbx`, `internal/cachex`, `internal/driver`), `bin/komando ... --help` (offline) dan dokumen desain. Aturan yang dipakai konsisten: kemampuan yang bisa dijalankan lewat `db query`/`cache run` milik komando sendiri = SEBAGIAN; kemampuan yang butuh alat lain di host (`exec host -- pgbench`, `tunnel` + klien eksternal) tetap TIDAK ADA, sesuai baris lain di laporan ini. Nomor baris kode merujuk commit 4784fc9.

| # | Kemampuan (singkat) | Status akhir | Hasil cek | Bukti di kode |
|---|---|---|---|---|
| 1 | Daftarkan DB, password di vault | ADA | Benar | `conn.go:66` `--password-ref`; `driver/driver.go:159` `URL_HAS_PASSWORD` |
| 2 | PostgreSQL | ADA | Benar | `driver.go:63` skema postgres/postgresql; `dbx/dbx.go:37-53` pgx stdlib |
| 3 | MySQL / MariaDB | ADA | Benar | `driver.go:65` skema mysql/mariadb; `dbx/dbx.go:282-283` fallback `max_statement_time` |
| 4 | SQLite lokal | ADA | Benar | `dbx/dbx.go:59-67` `mode=ro` + `query_only(1)`; modernc (`dbx.go:23`) |
| 5 | SQLite di host remote | TIDAK ADA | Benar | `conn.go:93-94` "--via is not supported" |
| 6 | DB lewat bastion `--via` | ADA | Benar | `dbx/dbx.go:45-48` `DialFunc`; `dbx/mysql.go:43-46` `RegisterDialContext` |
| 7 | DB lewat VPN | ADA | Benar | `conn.go:387-393` `netx.Open` untuk VPN di `--via` |
| 8 | TLS Postgres | SEBAGIAN | Benar | `dbshell.go:157-160` hanya `PGSSLMODE`; `dbdump.go:63` URL utuh ke pg_dump |
| 9 | TLS MySQL CA sendiri | SEBAGIAN | Benar | `dbx/mysql.go:37-38` `tls=` apa adanya; grep `RegisterTLSConfig`: 0 hasil |
| 10 | Unix socket DB | TIDAK ADA | Benar | `driver.go:181-182` URL wajib host |
| 11 | Login IAM / token cloud | TIDAK ADA | Benar | `conn.go:66` daftar ref statis; grep `rds-iam`/`generate-db-auth`: 0 hasil |
| 12 | pgpass / my.cnf / pg_service | ADA | Benar | `komando import --help`: pgpass, mycnf, env, dbeaver; grep `pg_service`: 0 hasil |
| 13 | Cek koneksi + login | SEBAGIAN | Benar | `conn.go:490-502` hanya dial TCP; `everything.go:157` help "logged in to" |
| 14 | Query banyak DB | TIDAK ADA | Benar | `select.go:504-510` `singleConn` menolak >1 conn |
| 15 | Pilih DB lain | SEBAGIAN | Benar | `driver/sql.go:336` `USE` read; tidak ada flag `--database` di `db.go:83-87` |
| 16 | Replika baca | TIDAK ADA | Benar | grep `replica` di dbx/cli db: 0 hasil |
| 17 | Postgres-wire lain | SEBAGIAN | Benar | `dbx/dbx.go:101` `SHOW standard_conforming_strings`; `test/e2e/compose.yml` hanya postgres/mariadb/redis |
| 18 | MySQL-wire lain | SEBAGIAN | Benar | `test/e2e/compose.yml:23` hanya mariadb; tidak ada tes TiDB/Vitess |
| 19 | Jalankan SQL | ADA | Benar | `db.go:50-81` `db query` |
| 20 | Read-only default | ADA | Benar | `dbx/dbx.go:231` `ReadOnly: !o.Write`; sqlite `mode=ro` |
| 21 | Klasifikasi risiko | ADA | Benar | `driver/sql.go:234` `ClassifySQL`; `meta.go:481` `policy check --for` |
| 22 | Dry-run rollback | ADA | Benar | `dbx/dbx.go:246-256` rollback + `rolled_back` |
| 23 | SQL dari file/stdin | ADA | Benar | `db.go:79` `--file`, `-` = stdin |
| 24 | Parameter binding | ADA | Benar | `db.go:86` `--arg`; `dbx/dbx.go:194-195` satu statement |
| 25 | Variabel bernama | TIDAK ADA | Benar | `db.go:83-87` hanya `--arg`; grep `\set`/`gset`: 0 hasil |
| 26 | Multi-statement atomik | ADA | Benar | `dbx/dbx.go:231-251` satu tx; `driver/sql.go:418-421` `SQL_TX_CONTROL` |
| 27 | Transaksi interaktif | NON-GOAL | Benar | vision.md:189 "Satu koneksi per perintah" + Bukan tujuan vision.md:223 (alat asli); resources-and-db.md:72 |
| 28 | Savepoint | NON-GOAL | Benar | `driver/sql.go:339-342` `SAVEPOINT` di `txControl`; basis vision.md:189 + :223 |
| 29 | Statement non-transaksional | ADA | Benar | `driver/sql.go:298-323` `noTx`; `dbx/dbx.go:200-212` |
| 30 | Timeout query | ADA | Benar | `db.go:29` default 30 s; `dbx/dbx.go:267-288` `statement_timeout`/`max_execution_time` |
| 31 | lock_timeout | SEBAGIAN | Benar | grep `lock_timeout` di Go: 0 hasil; ux.md:329 |
| 32 | application_name | ADA | Benar | `dbx/dbx.go:50-51`; `db.go:245` `komando/<actor>` |
| 33 | Batalkan query | ADA | Benar | `root.go:64` `signal.NotifyContext`; `dbx/dbx.go:189-192` |
| 34 | EXPLAIN | ADA | Benar | `db.go:89-133` `db explain --analyze` |
| 35 | EXPLAIN JSON | SEBAGIAN | Benar | `db.go:107-126` hanya prefix tetap; tidak ada `--format` |
| 36 | \gexec | TIDAK ADA | Benar | grep `gexec`: 0 hasil |
| 37 | \watch | TIDAK ADA | Benar | `db.go:83-87` tidak ada `--repeat/--interval` |
| 38 | \timing | ADA | Benar | `out/out.go:74` `duration_ms` di meta |
| 39 | --safe-updates | ADA | Benar | `driver/sql.go:525-526` `sql-update-no-where`/`sql-delete-no-where` |
| 40 | Hasil per statement | ADA | Benar | `dbx/dbx.go:145-172` `StatementResult` |
| 41 | Tipe aman JSON | ADA | Benar | `driver/value.go:15-45` `JSONValue` |
| 42 | Output tabel teks | ADA | Benar | `db.go:302-311` tabwriter, potong >80 |
| 43 | Output JSON | ADA | Benar | `root.go:159` `-o auto|json|text` |
| 44 | Mode vertikal | TIDAK ADA | Benar | `root.go:136` hanya auto/json/text; grep `vertical`: 0 hasil |
| 45 | Ekspor CSV | TIDAK ADA | Benar | `root.go:136`; grep `csv` di Go: 0 hasil |
| 46 | Ekspor hasil besar | SEBAGIAN | Benar | `dbx/dbx.go:322-343` semua baris di memori; `root.go:168` `--max-output` |
| 47 | Paging hasil | SEBAGIAN | Benar | `dbx/dbx.go:323-325` `truncated`; tidak ada `--offset` |
| 48 | Pager less | SEBAGIAN | Benar | ux.md:314; tidak ada pager otomatis |
| 49 | Impor CSV | TIDAK ADA | Benar | `dbx/mysql.go:39-40` param lain jadi variabel sesi (LOAD DATA LOCAL tidak aktif); grep `CopyFrom`: 0 hasil |
| 50 | Salin data antar DB | TIDAK ADA | Benar | `dbdump.go:63,77` dump seluruh DB saja |
| 51 | Simpan output ke file | ADA | Benar | redirect shell; envelope `out` stabil |
| 52 | Daftar tabel + estimasi baris | ADA | Benar | `dbx/schema.go:93-101` relkind r,p,v,m,f + `reltuples` |
| 53 | Kolom/tipe/null/default/PK | ADA | Benar | `dbx/schema.go:122-130`, `mysql.go:131-133`, `schema.go:182` |
| 54 | Index | ADA | Benar | `dbx/schema.go:143`, `mysql.go:146-149` |
| 55 | Foreign key | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | `dbx/schema.go:14-21` tanpa FK; jalur mentah `db query` ke `pg_constraint` (SELECT = read, `driver/sql.go:335`) |
| 56 | Constraint check/exclusion | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | grep `pg_constraint`/`check_constraints`: 0 hasil; bisa lewat `db query` (read) |
| 57 | Trigger | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | grep `trigger` di dbx: 0 hasil; `SHOW TRIGGERS` read (`driver/sql.go:335`) |
| 58 | Daftar schema | SEBAGIAN | Benar | `dbx/schema.go:15` schema per tabel; tidak ada query `pg_namespace` terpisah |
| 59 | Daftar database | SEBAGIAN | Benar | `dbx/mysql.go:103` `DATABASE()` saja |
| 60 | Fungsi/prosedur | SEBAGIAN | Benar | tidak ada di `dbx/schema.go`; `db query` read |
| 61 | Sequence/enum/extension | SEBAGIAN | Benar | tidak ada di `dbx/schema.go`; `db query` read |
| 62 | Definisi view | SEBAGIAN | Benar | tidak ada di `dbx/schema.go`; `db query` read |
| 63 | DDL lengkap satu tabel | SEBAGIAN | Benar | `dbdump.go:63` pg_dump tanpa `-s -t`; grep `schema-only`: 0 hasil |
| 64 | Ukuran tabel/index | SEBAGIAN | Benar | `dbx/schema.go:14-21` tanpa kolom ukuran |
| 65 | Komentar tabel/kolom | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | grep `col_description`/`column_comment`: 0 hasil; bisa lewat `db query` (read) |
| 66 | Partisi | SEBAGIAN | Benar | `dbx/schema.go:96,99` relkind `p` jadi `table` |
| 67 | Hak akses per tabel | SEBAGIAN | Benar | tidak ada di `dbx`; `SHOW GRANTS` read |
| 68 | Cari tabel/kolom | SEBAGIAN | Benar | `dbx/schema.go:120-121` kolom hanya untuk tabel yang disebut |
| 69 | Diagram ER | NON-GOAL | Benar | vision.md:227 "GUI, TUI ..." (Bukan tujuan) |
| 70 | REPL interaktif | ADA (lewat alat asli) | Benar | `dbshell.go:137-196` psql/mysql/sqlite3 read-only |
| 71 | REPL pgcli/mycli | SEBAGIAN | Benar | `dbshell.go:76` hanya psql/mysql/sqlite3; `tunnel start --help` conn |
| 72 | Autocomplete SQL | NON-GOAL | Benar | resources-and-db.md:72 (REPL); vision.md:227 |
| 73 | Riwayat query | SEBAGIAN | Benar | `db.go:340-346` SQL di audit; `audit --command` |
| 74 | Query tersimpan | TIDAK ADA | Benar | `recipe run` hanya "on servers" (`recipe --help`); `ops.go:106-144` shell |
| 75 | $EDITOR | NON-GOAL | Benar | resources-and-db.md:72; vision.md:223 |
| 76 | \! shell escape | NON-GOAL | Benar | `driver/restore.go:83-88`; docs/features/databases.md:109; vision.md:223 |
| 77 | \h bantuan | NON-GOAL | Benar | vision.md:223 (alat asli); resources-and-db.md:72 |
| 78 | Dump ke file + gzip | ADA | Benar | `dbdump.go:222-243`, `writeAtomic` `dbdump.go:334-359` 0600, tanpa timpa |
| 79 | Dump SQLite | ADA | Benar | `dbdump.go:185-210` `VACUUM INTO` |
| 80 | pg_dump -Fc/-Fd/-Ft | TIDAK ADA | Benar | `dbdump.go:63` tanpa `-F`; grep `"-F`: 0 hasil |
| 81 | pg_restore | TIDAK ADA | Benar | `dbdump.go:64` psql; grep `pg_restore` di Go: 0 hasil |
| 82 | Dump paralel | TIDAK ADA | Benar | `dbdump.go:63,77` tanpa `-j`; grep `mydumper`: 0 hasil |
| 83 | Schema/data saja | TIDAK ADA | Benar | `dbdump.go:105` hanya `--to`; grep `schema-only`: 0 hasil |
| 84 | Pilih/kecualikan tabel | TIDAK ADA | Benar | `dbdump.go:105` hanya `--to` |
| 85 | Globals/semua DB | TIDAK ADA | Benar | grep `pg_dumpall`/`all-databases`: 0 hasil |
| 86 | Opsi restore | TIDAK ADA | Benar | `dbdump.go:129` hanya `--from`; grep `no-owner`: 0 hasil |
| 87 | Restore satu transaksi + cek file | ADA | Dikoreksi: bukti (tambah: hanya Postgres) | `dbdump.go:64` (psql), `dbdump.go:78` mysql tanpa transaksi; `driver/restore.go:26-96` |
| 88 | Pengaman restore | ADA | Benar | `dbdump.go:271-274` destructive `db-restore`; `common.go:203-227` |
| 89 | Kompresi zstd/lz4 | SEBAGIAN | Benar | `dbdump.go:230,301` hanya `.gz` |
| 90 | Dump langsung ke S3/server | SEBAGIAN | Benar | `dbdump.go:24-27` selalu ke komputer ini |
| 91 | Dump sebagai job | TIDAK ADA | Benar | `job start --help`: perintah shell di host, bukan `db dump` |
| 92 | Dump Go murni | TIDAK ADA | Benar | `dbdump.go:390-395` `TOOL_MISSING` |
| 93 | Backup terjadwal | NON-GOAL | Benar | vision.md:189, :227 (daemon); `cron set` ada |
| 94 | PITR/WAL | NON-GOAL | Benar | vision.md:223 (alat lengkap) |
| 95 | Verifikasi backup | TIDAK ADA | Benar | grep `pg_restore`: 0 hasil |
| 96 | Ringkasan server db | SEBAGIAN | Benar | `db.go:40` tanpa info/status; `ops.go:138-139` recipe di host; ux.md:38 |
| 97 | Aktivitas sesi | SEBAGIAN | Benar | `db.go:40` tanpa perintah aktivitas |
| 98 | Lock/blocking | SEBAGIAN | Benar | grep `pg_blocking_pids`/`lock_waits`: 0 hasil |
| 99 | Hentikan query/sesi | SEBAGIAN | Benar | `driver/sql.go:346,491-492` `sql-kill`; tidak ada `db kill` |
| 100 | Query lambat | SEBAGIAN | Benar | tidak ada perintah; `db query` read |
| 101 | Ukuran DB terbesar | SEBAGIAN | Benar | `dbx/schema.go:14-21` tanpa ukuran |
| 102 | Bloat/autovacuum | SEBAGIAN | Benar | `db query` read; tidak ada perintah |
| 103 | Index tak terpakai | SEBAGIAN | Benar | `db query` read; tidak ada perintah |
| 104 | Cache hit ratio | SEBAGIAN | Benar | `db query` read; tidak ada perintah |
| 105 | Replikasi/lag | SEBAGIAN | Benar | `driver/sql.go:335` `SHOW` read |
| 106 | Slot replikasi | SEBAGIAN | Benar | `driver/sql.go:349-350` slot -> `sql-server-config` |
| 107 | Konfigurasi server | SEBAGIAN | Benar | `driver/sql.go:480-481,473-474` SET GLOBAL/ALTER SYSTEM destructive |
| 108 | VACUUM/ANALYZE | ADA (lewat jalur mentah) | Benar | `driver/sql.go:306-307` noTx; `:493-495` `sql-vacuum-full` |
| 109 | Wraparound XID | SEBAGIAN | Benar | `db query` read; tidak ada perintah |
| 110 | Benchmark | TIDAK ADA | Benar | grep `pgbench`/`sysbench`: 0 hasil |
| 111 | Monitoring berkelanjutan | NON-GOAL | Benar | vision.md:228 dan :227 (TUI) |
| 112 | Health check DB | TIDAK ADA | Benar | `db.go:40` tanpa checks |
| 113 | Daftar user/role | SEBAGIAN | Benar | `db query` read; tidak ada perintah |
| 114 | Buat user / password di audit | SEBAGIAN | Benar | `driver/sql.go:470-471` `sql-privileges`; `db.go:346` SQL utuh; `store.go:131` default `full`; `common.go:387-396` tanpa redaksi |
| 115 | Template user read-only | TIDAK ADA | Benar | docs/features/databases.md:56; tidak ada perintah |
| 116 | Grant efektif | SEBAGIAN | Benar | `SHOW GRANTS` read; tidak ada perintah |
| 117 | RLS / policy | SEBAGIAN | Benar | `driver/sql.go:469-472` `CREATE POLICY` hanya write |
| 118 | Alat migrasi | NON-GOAL | Benar | resources-and-db.md:72 "migrasi" |
| 119 | Jalankan file migrasi | SEBAGIAN | Benar | `db.go:79` satu `--file`; `driver/sql.go:316` DDL MySQL noTx |
| 120 | Status migrasi | SEBAGIAN | Benar | `db query` read |
| 121 | Schema diff | TIDAK ADA | Benar | grep `diff` di dbx/cli db: 0 hasil |
| 122 | Generate migrasi | NON-GOAL | Benar | resources-and-db.md:72; vision.md:226 |
| 123 | Lint migrasi | SEBAGIAN | Benar | `driver/sql.go:462-546` tidak ada aturan lock/CONCURRENTLY |
| 124 | PgBouncer admin | TIDAK ADA | Benar | `dbx/dbx.go:86-89,101` cek string rules saat Open |
| 125 | Lewat PgBouncer transaction | SEBAGIAN | Benar | `dbx/dbx.go:53` pgx stdlib default; tanpa tes |
| 126 | ProxySQL/pgpool | TIDAK ADA | Benar | grep `proxysql`/`pgpool`: 0 hasil |
| 127 | Pool koneksi | NON-GOAL | Benar | vision.md:189 "Tanpa pool"; `dbx/dbx.go:81` 1 koneksi |
| 128 | Audit query | ADA | Benar | `db.go:340-350`; `meta.go:417-422` audit_sql |
| 129 | Redaksi SQL audit | TIDAK ADA | Benar | `db.go:340-347` full/hash/off saja; grep `redact` di db: 0 hasil |
| 130 | Blok fungsi berbahaya | ADA | Benar | `driver/sql.go:345-370` `sql-remote`, `sql-server-file`, `sql-program` |
| 131 | Tolak string rules | ADA | Benar | `dbx/dbx.go:96-124` `SQL_STRING_RULES` |
| 132 | Konfirmasi ketik nama | ADA | Dikoreksi: bukti ux.md backlog→kode | `common.go:208,334-347` `confirmDangerous` |
| 133 | --max-rows-affected | TIDAK ADA | Benar | grep `max-rows-affected`: 0 hasil |
| 134 | Masking kolom | TIDAK ADA | Benar | grep `mask` di dbx/cli db: 0 hasil |
| 135 | Opsi per conn | TIDAK ADA | Dikoreksi: bukti (tambah contoh help menyesatkan) | `cluster.go:78` satu-satunya pemakai `Options`; `conn.go:186` contoh `statement_timeout` |
| 136 | Redis/Valkey standalone | ADA | Benar | `driver.go:69-70`; `cachex.go:27-47` go-redis |
| 137 | Garnet/Upstash/ElastiCache | ADA (kemungkinan) | Benar | protokol sama; tanpa tes (`test/e2e/compose.yml:28` redis saja) |
| 138 | Redis Cluster | TIDAK ADA | Benar | `cachex.go:41` `redis.NewClient`; grep `ClusterClient`: 0 hasil |
| 139 | Sentinel cari master | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | `cachex.go:123-148` `SENTINEL` dinilai write, `cache run --write` mengirimnya; grep `sentinel` di Go: 0 hasil |
| 140 | ACL user + password | ADA | Benar | `cachex.go:30` `Username`, `Password` |
| 141 | TLS rediss | ADA | Benar | `cachex.go:34-36` TLS1.2 + `ServerName` |
| 142 | TLS CA sendiri | TIDAK ADA | Benar | `cachex.go:36` hanya `ServerName` |
| 143 | Pilih DB redis | SEBAGIAN | Benar | `cachex.go:28` DB dari URL; `SELECT` tidak dikenal = write |
| 144 | Redis lewat --via | ADA | Benar | `cachex.go:38-40` `o.Dialer` |
| 145 | Unix socket redis | TIDAK ADA | Benar | `driver.go:181-182` wajib host |
| 146 | Cek login cache | SEBAGIAN | Benar | `conn.go:490-502` TCP; `cachex.go:42` PING di `cache info` |
| 147 | REPL cache | TIDAK ADA | Benar | `cache.go:36` tanpa `shell` |
| 148 | cache get semua tipe | ADA | Benar | `cachex.go:162-246` |
| 149 | Tipe modul | SEBAGIAN | Benar | `cachex.go:242-243` `value: nil`; `JSON.GET` tidak di `readCmds` (`cachex.go:72-78`) |
| 150 | cache keys SCAN | ADA | Benar | `cachex.go:249-271` SCAN |
| 151 | SCAN TYPE | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | `cachex.go:256` tanpa TYPE; `SCAN` read (`cachex.go:72`) lewat `cache run` |
| 152 | Hitung key per pola | TIDAK ADA | Benar | `cachex.go:261-263` berhenti di limit |
| 153 | Jumlah key per DB | ADA | Benar | `cachex.go:77` `DBSIZE`, `INFO` read |
| 154 | INFO terstruktur | ADA | Benar | `cachex.go:274-303` |
| 155 | TTL/OBJECT/MEMORY | ADA | Benar | `cachex.go:72,84-85` read |
| 156 | Baca stream | ADA | Benar | `cachex.go:76,89` XRANGE/XPENDING/XINFO read; `:231-241` |
| 157 | XREAD | SEBAGIAN | Benar | `XREAD` tidak di `readCmds` (`cachex.go:72-78`) |
| 158 | Set string + TTL | ADA | Benar | `cache.go:182-202` |
| 159 | SET NX/XX | SEBAGIAN | Benar | `cache.go:224-262` `cache run --write` |
| 160 | Nilai dari file | TIDAK ADA | Benar | `cache.go:189` `ExactArgs(3)`, tanpa `--file` |
| 161 | EXPIRE/PERSIST | SEBAGIAN | Benar | `cache.go:231` contoh `EXPIRE` via `cache run --write` |
| 162 | Tulis hash/list/set | SEBAGIAN | Benar | `cache.go:36` hanya `set` string |
| 163 | Rename/copy | SEBAGIAN | Benar | `RENAME` tidak di `destructive` (`cachex.go:97-103`) = write |
| 164 | Hapus key tepat | ADA | Benar | `cache.go:204-222` `DataDelete` |
| 165 | Hapus per pola | TIDAK ADA | Benar | `cache.go:207` "no patterns" |
| 166 | Flush DB | ADA (lewat jalur mentah) | Benar | `cachex.go:98` `redis-flush` |
| 167 | Dry-run tulis cache | SEBAGIAN | Benar | `cache.go:63-66` "nothing sent" |
| 168 | bigkeys | TIDAK ADA | Benar | grep `bigkeys`: 0 hasil |
| 169 | memkeys | TIDAK ADA | Benar | grep `memkeys`: 0 hasil |
| 170 | hotkeys | TIDAK ADA | Benar | grep `hotkeys`: 0 hasil; `OBJECT FREQ` read (`cachex.go:85`) |
| 171 | Latensi | SEBAGIAN | Benar | `cachex.go:87` LATENCY read; `conn.go:491` test TCP |
| 172 | --stat | NON-GOAL | Benar | vision.md:228 |
| 173 | Slowlog | ADA (lewat jalur mentah) | Benar | `cachex.go:86` GET read; RESET = write |
| 174 | MONITOR | TIDAK ADA | Benar | `MONITOR` tidak terdaftar = write; `cachex.go:311` satu `Do()` |
| 175 | CLIENT LIST | ADA (lewat jalur mentah) | Benar | `cachex.go:83` read |
| 176 | CLIENT KILL | ADA (lewat jalur mentah) | Benar | `cachex.go:107` `redis-kill` |
| 177 | CONFIG GET | ADA (lewat jalur mentah) | Benar | `cachex.go:82` read |
| 178 | CONFIG SET | ADA (lewat jalur mentah) | Benar | `cachex.go:106` `redis-server-config` |
| 179 | Replikasi INFO | ADA | Benar | `cache.go:158-180` `cache info CONN replication` |
| 180 | MEMORY DOCTOR | ADA (lewat jalur mentah) | Benar | `cachex.go:84` read |
| 181 | BGSAVE/SAVE | ADA (lewat jalur mentah) | Benar | `cachex.go:99` SAVE `redis-blocking`; BGSAVE tidak terdaftar = write |
| 182 | DEBUG | ADA (lewat jalur mentah) | Benar | `cachex.go:99` `redis-blocking` |
| 183 | Ulangi perintah | TIDAK ADA | Benar | `cache.go:224-262` tanpa `-r/-i` |
| 184 | Health check cache | TIDAK ADA | Benar | `cachex.go:274-303` hanya angka mentah |
| 185 | PUBLISH | ADA (lewat jalur mentah) | Benar | tidak terdaftar = write, `cache run --write` |
| 186 | SUBSCRIBE | TIDAK ADA | Benar | `cachex.go:311` `Do()` satu balasan |
| 187 | PUBSUB CHANNELS | ADA (lewat jalur mentah) | Benar | `cachex.go:93` read |
| 188 | EVAL/FCALL | ADA (lewat jalur mentah) | Benar | `cachex.go:102` `redis-script-run`; `:78` `EVAL_RO` read |
| 189 | --eval file | TIDAK ADA | Benar | `cache.go:224-262` tanpa `--file` |
| 190 | Admin cluster | SEBAGIAN | Benar | `cachex.go:88` CLUSTER INFO/NODES read; tanpa `--cluster` |
| 191 | Sentinel admin | SEBAGIAN | Dikoreksi: TIDAK ADA→SEBAGIAN | `SENTINEL` tidak di `destructive`/`readCmds` (`cachex.go:72-113`) = write |
| 192 | Backup RDB | TIDAK ADA | Benar | `cache.go:36` tanpa dump/restore; vision.md:23 |
| 193 | Ekspor/impor per pola | TIDAK ADA | Benar | `cachex.go:78` DUMP read; RESTORE = write; tanpa bulk |
| 194 | Mass insert | TIDAK ADA | Benar | grep `pipe` di cachex/cache.go: 0 hasil |
| 195 | MIGRATE | SEBAGIAN | Benar | `cachex.go:101` `MIGRATE`→`redis-flush` |
| 196 | Hapus data = write | SEBAGIAN | Benar | `cachex.go:139-148` hanya DEL/UNLINK `DataDelete` |
| 197 | policy check redis berkutip | SEBAGIAN | Benar | `meta.go:478` `cachex.Classify(args)` vs `:481` `strings.Join` |
| 198 | Baca modul belum terdaftar | SEBAGIAN | Benar | `cachex.go:72-95` tanpa XREAD/JSON.GET/HELLO/NO-TOUCH |
| 199 | Memcached | TIDAK ADA | Benar | grep `memcache`: 0 hasil; vision.md:93 |
| 200 | MongoDB | TIDAK ADA | Benar | grep `mongo` di Go: hanya `ops.go:32` deteksi alat; vision.md:209 |
| 201 | MSSQL | TIDAK ADA | Benar | grep `mssql`: 0 hasil; vision.md:92 |
| 202 | Oracle | TIDAK ADA | Benar | grep `go-ora`/`oracle`: 0 hasil |
| 203 | ClickHouse | TIDAK ADA | Benar | grep `clickhouse`: 0 hasil; vision.md:92 |
| 204 | Cassandra | TIDAK ADA | Benar | grep `cassandra`/`gocql`: 0 hasil |
| 205 | Elasticsearch | TIDAK ADA | Benar | grep `elastic`/`opensearch`: 0 hasil; vision.md:207-208 |
| 206 | Influx/Timescale/Prometheus | SEBAGIAN | Benar | grep `influx`: 0 hasil; Timescale = kind postgres |
| 207 | CockroachDB | SEBAGIAN | Benar | lihat baris 17; grep `cockroach`: 0 hasil |
| 208 | MariaDB khusus | SEBAGIAN | Benar | `dbdump.go:42-48` flag TLS MariaDB; `:77` `mysqldump`; grep `mariadb-dump`: 0 hasil |
| 209 | DynamoDB | TIDAK ADA | Benar | grep `dynamodb`: 0 hasil |
| 210 | Kafka | TIDAK ADA | Benar | grep `kafka`: 0 hasil; vision.md:207 |
| 211 | RabbitMQ | TIDAK ADA | Benar | grep `rabbit`: 0 hasil; vision.md:207 |
| 212 | NATS | TIDAK ADA | Benar | grep `nats`: 0 hasil |
| 213 | etcd | TIDAK ADA | Benar | grep `etcd`: 0 hasil |
| 214 | Consul | TIDAK ADA | Benar | grep `consul`: 0 hasil |
| 215 | DuckDB | TIDAK ADA | Benar | grep `duckdb`: 0 hasil; vision.md:180 tanpa cgo |
| 216 | Warehouse cloud | TIDAK ADA | Benar | grep `bigquery`/`snowflake`: 0 hasil |
| 217 | Neo4j | TIDAK ADA | Benar | grep `neo4j`: 0 hasil |
| 218 | Valkey/KeyDB/Dragonfly | ADA | Benar | `driver.go:69`; docs/features/caches.md:5-6 |
| 219 | Provisioning DB | NON-GOAL | Benar | vision.md:226 "provisioning cloud" |
