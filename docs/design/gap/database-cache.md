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

- Ukuran biner: build rilis (`-s -w -trimpath`, CGO_ENABLED=0) **34,7 MB**: masih di bawah anggaran 40 MB, tapi sisa ruang hanya ~5 MB (vision.md "Aturan teknis"). `bin/komando` 51 MB yang terlihat di repo adalah build dev tanpa strip. Setiap driver baru (Mongo, MSSQL, ClickHouse, Cassandra) memperberat masalah ini; prioritas engine baru dinilai dengan memperhitungkan ini.
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
| Foreign key / relasi | psql `\d`, DataGrip diagram | TIDAK ADA | `dbx.Table` tidak punya FK. Workaround: `db query` ke `information_schema.table_constraints`/`pg_constraint` | **P1** (agent butuh relasi untuk JOIN yang benar dan untuk menilai dampak DELETE/ON DELETE CASCADE) |
| Constraint unique/check, exclusion | psql `\d` | TIDAK ADA | Unique hanya tersirat dari definisi index; CHECK tidak ada | P2 |
| Trigger | psql `\d`, `SHOW TRIGGERS` | TIDAK ADA | Penting saat menilai efek samping UPDATE/DELETE | P2 |
| Daftar schema/namespace (`\dn`) | psql | SEBAGIAN | Nama schema muncul per tabel; tidak ada daftar schema (yang kosong tidak terlihat) | P3 |
| Daftar database di server (`\l`, `SHOW DATABASES`) | psql, mysql | SEBAGIAN | Lewat `db query "select datname from pg_database"`; MySQL `db schema` hanya `DATABASE()` saat ini | P2 |
| Fungsi/prosedur (`\df`, `SHOW PROCEDURE STATUS`) | psql, mysql | SEBAGIAN | Lewat `db query` ke katalog | P3 |
| Sequence (`\ds`), tipe/enum (`\dT`), extension (`\dx`) | psql | SEBAGIAN | Lewat `db query`; enum penting untuk menulis INSERT yang valid | P3 |
| Definisi view (`\d+ view`, `SHOW CREATE VIEW`) | psql, mysql | SEBAGIAN | Lewat `db query "select pg_get_viewdef(...)"` / `SHOW CREATE VIEW` | P3 |
| DDL lengkap satu tabel (`SHOW CREATE TABLE`, `pg_dump -s -t`) | mysql, pg_dump | SEBAGIAN | MySQL: `db query "show create table x"` (read). Postgres: tidak ada fungsi bawaan; `db dump` tidak punya `--schema-only -t` | P2 |
| Ukuran tabel/index (`\dt+`, `\di+`) | psql | SEBAGIAN | Lewat `db query` (`pg_total_relation_size`, `information_schema.tables.data_length`). Tidak ada kolom ukuran di `db schema` | P2 |
| Komentar tabel/kolom (`\d+`, `COMMENT`) | psql, DataGrip | TIDAK ADA | Komentar sering berisi arti kolom: berguna untuk agent | P3 |
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
| Restore satu transaksi + cek file berbahaya | psql `--single-transaction` | ADA | `--single-transaction ON_ERROR_STOP=1`; file dengan `\!`, `\i`, `system` ditolak (`driver/restore.go`) | - |
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
| Konfirmasi ketik nama saat restore/drop di terminal | DataGrip "production" warning | ADA | ux.md backlog #17 (prompt dan ketik nama) | - |
| Batas jumlah baris yang diubah (`--max-rows-affected`) | (tidak umum; Atlas/ pt-archiver) | TIDAK ADA | `--dry-run` menunjukkan jumlahnya, tapi `--write` tanpa dry-run tidak punya batas pengaman (mis. UPDATE dengan WHERE yang salah menyentuh 1 juta baris) | P2 (lapisan aman murah untuk agent) |
| Masking kolom sensitif di output | DataGrip, Satori, pg_anonymizer | TIDAK ADA | `conn --option` sudah ada tapi tidak dipakai kind db | P3 |
| Opsi per conn yang dijanjikan (`statement_timeout`, `row_limit`) | — | TIDAK ADA | resources-and-db.md: "Options ... per-kind: statement_timeout, row_limit"; `conn --option` hanya dipakai `cluster` (namespace) | P3 |

---

## 12. Cache: koneksi dan topologi

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| Redis/Valkey/KeyDB/Dragonfly standalone | redis-cli, valkey-cli | ADA | kind `redis` (`redis://`, `rediss://`), go-redis v9 | - |
| Garnet, Upstash, ElastiCache/Memorystore non-cluster | redis-cli | ADA (kemungkinan) | Protokol sama; belum diuji | - |
| Redis Cluster (MOVED/ASK, ElastiCache cluster mode, `redis-cli -c`) | redis-cli `-c` | TIDAK ADA | `redis.NewClient` tunggal; perintah ke slot lain mendapat `MOVED` (ux.md edge case "Redis cluster (`MOVED`)"). `cache keys` hanya men-scan satu node | P2 (umum di ElastiCache/Azure besar) |
| Sentinel (temukan master) | redis-cli `-p 26379`, `SENTINEL get-master-addr-by-name` | TIDAK ADA | ux.md edge case "sentinel" belum ditutup | P2 |
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
| Filter key per tipe (`SCAN TYPE`) | redis-cli `--scan --type` (7+) | TIDAK ADA | | P3 |
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
| Sentinel admin (`SENTINEL masters`, failover) | redis-cli | TIDAK ADA | | P3 |

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

Penilaian memakai kriteria vision.md "Kriteria menambah family" (masuk model conn+kind+verb, read-only default jujur, Go murni tanpa SDK raksasa, kebutuhan harian, ada perawat) dan anggaran biner (build rilis 34,7 MB dari 40 MB).

| Kemampuan | Tools pembanding | Status komando | Bukti/catatan | Prioritas |
|---|---|---|---|---|
| MongoDB (find, aggregate, count, indexes, stats, currentOp, killOp, mongodump/restore) | mongosh, mongodump, Compass | TIDAK ADA | vision.md: kandidat setelah v1.0 ("dan mongodb"). Driver resmi Go murni tapi besar (+~6-8 MB); read-only bisa lewat `readPreference` + user read, tidak ada transaksi read-only setara, jadi klasifikasi (`find`/`aggregate` tanpa `$out/$merge`) jadi lapisan utama. Workaround: `exec host -- mongosh --eval` | P2 (DB non-SQL paling populer; anggaran biner menghambat) |
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
| SEBAGIAN | 64 |
| TIDAK ADA | 74 |
| NON-GOAL | 15 |
| **Total kemampuan** | **219** |

Gap berprioritas (SEBAGIAN + TIDAK ADA): P1 = 12 baris (10 gap unik: cek login db dan cache digabung, redaksi audit dan CREATE USER digabung), P2 = 47, P3 = 79.

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

Catatan tambahan di luar tabel prioritas: build rilis sudah 34,7 MB dari anggaran 40 MB, jadi engine baru (Mongo, MSSQL, ClickHouse, Kafka) perlu keputusan anggaran dulu; family berbasis HTTP (Elasticsearch/OpenSearch, RabbitMQ, Consul) paling murah.
