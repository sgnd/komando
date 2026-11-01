# Rancangan: resource non-SSH dan `komando db`

Status: **Fase 1 selesai** (`komando conn`, `internal/driver`, `guardConns`).
Fase 2 (`komando db`) belum dimulai.

Keputusan yang diambil saat Fase 1:

- Nama perintah `conn`. Kind diambil dari skema URL, jadi bentuknya
  `conn add NAME URL` (tanpa argumen KIND). Lihat `komando conn kinds`.
- `PROTECTED_HOST` tetap untuk host; conn memakai `PROTECTED_TARGET`.
  Tidak ada breaking change.
- Nama unik di antara host dan conn (`NAME_TAKEN`). Selector-nya tetap
  terpisah: `@db` di `exec` hanya memilih host.
- `conn test` di Fase 1 hanya mengecek TCP (atau keberadaan file untuk
  SQLite) dan bahwa `--password-ref` bisa dibaca. Login ke DB datang di Fase 2.
- Host yang dipakai sebagai `--via` tidak bisa dihapus (`HOST_IN_USE`);
  rename host ikut memperbarui `Via` di conn.

## Latar belakang

Sekarang komando hanya mengenal satu jenis target, yaitu **host SSH**. Semua
lapisan amannya terikat ke host:

| Lapisan | Di mana sekarang |
|---|---|
| Inventaris | `store.Host` di `state.json` |
| Kredensial | `PasswordRef` → `vault.Resolve` (`secret:`, `env:`, `file:`) |
| Seatbelt | `guard()` di `internal/cli/common.go`: `policy.Check` (regex atas perintah shell) + `Protected` butuh `--yes` |
| Dry-run | flag global `--dry-run` |
| Output | envelope JSON + exit code stabil (`internal/out`) |
| Audit | `audit()` → `audit.jsonl` |

Agent juga perlu bicara ke database, cache, dan object storage. Hari ini
caranya `komando exec web1 -- psql -c "..."`. Cara itu punya tiga masalah:

1. **Output tidak terstruktur.** Agent harus mem-parse tabel teks dari `psql`.
2. **Seatbelt lemah.** Regex `db-drop` hanya menangkap `DROP DATABASE`.
   `DELETE FROM users;` (tanpa `WHERE`) lolos.
3. **Password DB bocor.** Password masuk ke command line atau env di server,
   lalu ke `audit.jsonl`.

Tujuan rancangan ini: membawa **lapisan aman yang sama** ke resource non-SSH,
dimulai dari database.

## Bukan tujuan

- Menjadi klien DB lengkap (REPL, migrasi, ORM). Untuk itu sudah ada
  `psql`/`usql`.
- Mengubah `host` yang sudah ada. Tidak ada migrasi `state.json` yang
  merusak.
- Dalam fase ini: redis, s3, dan API cloud. Itu disiapkan lewat abstraksinya
  saja.

## Bagian 1: abstraksi resource (`conn`)

### Model data

Tambah satu map baru di `store.State`, di samping `Hosts`:

```go
type Conn struct {
    Name        string            `json:"name"`
    Kind        string            `json:"kind"`               // postgres | mysql | sqlite | (nanti: redis, s3)
    URL         string            `json:"url"`                // TANPA password, mis. postgres://app@db.internal:5432/app?sslmode=require
    PasswordRef string            `json:"password_ref,omitempty"` // secret:/env:/file:, sama dengan Host
    Via         string            `json:"via,omitempty"`      // nama host SSH untuk menjangkau resource ini
    Groups      []string          `json:"groups,omitempty"`
    Tags        []string          `json:"tags,omitempty"`
    Labels      map[string]string `json:"labels,omitempty"`
    Protected   bool              `json:"protected,omitempty"`
    Options     map[string]string `json:"options,omitempty"`  // per-kind: statement_timeout, row_limit, ...
    Notes       string            `json:"notes,omitempty"`
    CreatedAt   time.Time         `json:"created_at"`
    UpdatedAt   time.Time         `json:"updated_at"`
}

// State
Conns map[string]*Conn `json:"conns"`
```

Aturan:

- **Nama unik di antara host dan conn.** Dengan begitu, nanti satu selector
  (`@prod`, `tag:x`) bisa dipakai untuk keduanya tanpa ambigu.
- **URL tidak boleh berisi password.** Kalau `conn add` menerima
  `postgres://u:pass@...`, tolak dengan `USAGE` dan hint
  `komando secret set NAME` lalu `--password-ref secret:NAME`. Jangan simpan
  diam-diam.
- `Via` memakai rantai `Jump` yang sudah ada. `sshx.Dial(via)` lalu
  `client.Dial("tcp", addr)` di dalam proses. **Tidak perlu tunnel di latar
  belakang dan tidak ada port lokal yang terbuka.**

### Perintah

```
komando conn add NAME URL [--via HOST] [--password-ref REF] [--group G] [--tag T] [--protected]
komando conn list [SELECTOR]
komando conn edit NAME ...           # flag sama dengan add, plus --add-tag/--rm-tag
komando conn rm NAME
komando conn test SELECTOR           # connect + ping + versi server
```

Bentuknya disamakan dengan `host`, supaya agent yang sudah kenal `host` langsung
paham.

### Driver dan klasifikasi risiko

Paket baru `internal/driver`:

```go
type Risk int

const (
    RiskRead        Risk = iota // tidak mengubah apa pun
    RiskWrite                   // mengubah data
    RiskDestructive             // sulit/tidak bisa dibatalkan
)

type Verdict struct {
    Risk   Risk
    Rules  []policy.Rule // aturan yang cocok (untuk pesan error)
    Reason string
}
```

Setiap kind mengimplementasikan:

- `Classify(op) Verdict`: dipanggil **sebelum** apa pun dikirim ke server.
- `Dial(ctx, conn, dialer)`: membuka koneksi, opsional lewat SSH.

Lalu `guard()` digeneralisasi menjadi satu tempat keputusan untuk semua kind:

| Risk | Conn biasa | Conn `--protected` |
|---|---|---|
| read | jalan | jalan |
| write | jalan | butuh `--yes` (`PROTECTED_HOST` → dibuat umum: `PROTECTED_TARGET`) |
| destructive | butuh `--allow-dangerous` (`POLICY_BLOCKED`) | butuh `--allow-dangerous` **dan** `--yes` |

Exit code dan kode error memakai yang sudah ada (6 untuk policy). Agent tidak
perlu belajar kontrak baru.

> Catatan kompatibilitas: ganti nama `PROTECTED_HOST` → `PROTECTED_TARGET`
> adalah perubahan kontrak. Usulan: pertahankan `PROTECTED_HOST` untuk host,
> pakai `PROTECTED_TARGET` hanya untuk conn. Perlu diputuskan (lihat
> [Pertanyaan terbuka](#pertanyaan-terbuka)).

## Bagian 2: `komando db`

### Perintah

```
komando db query  CONN [SQL | -f FILE | -] [--write] [--limit N] [--param k=v ...]
komando db schema CONN [TABLE...]          # tabel, kolom, tipe, index, perkiraan jumlah baris
komando db explain CONN SQL                # EXPLAIN (tanpa ANALYZE kecuali --analyze --write)
komando db dump   CONN --to PATH           # fase 3, lewat job
```

Contoh:

```bash
komando conn add prod-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:prod-db-pass --protected

komando db schema prod-db users
komando db query prod-db "select id, email from users where created_at > now() - interval '1 day'"
komando db query prod-db --write --dry-run "update users set plan='pro' where id=42"
komando db query prod-db --write --yes "update users set plan='pro' where id=42"
```

### Read-only sebagai default, ditegakkan oleh DB-nya sendiri

Ini keputusan terpenting: **`db query` tanpa `--write` berjalan di transaksi
read-only di sisi server.**

- Postgres: `BEGIN READ ONLY` … `ROLLBACK`
- MySQL: `START TRANSACTION READ ONLY` … `ROLLBACK`
- SQLite: buka dengan `mode=ro`

Jadi walaupun klasifikasi SQL keliru, server tetap menolak penulisan. Regex
dan parser hanya menjadi **lapisan kedua** untuk pesan error yang jelas,
bukan satu-satunya pengaman. Ini juga sejalan dengan catatan di
`komando policy`: guardrail bukan batas keamanan.

Kalau query read-only ditolak server (mis. Postgres `25006
read_only_sql_transaction`), kembalikan:

```json
{"code":"WRITE_REQUIRES_FLAG","hint":"this statement modifies data; re-run with --write (try --dry-run first)"}
```

dengan exit 6.

### Klasifikasi SQL (untuk `--write`)

Klasifikasi dilakukan per statement, setelah komentar dan string literal
dibuang:

| Kelas | Contoh |
|---|---|
| read | `SELECT`, `WITH … SELECT`, `SHOW`, `EXPLAIN` (tanpa ANALYZE), `DESCRIBE` |
| write | `INSERT`, `UPDATE … WHERE`, `DELETE … WHERE`, `CREATE TABLE/INDEX`, `ALTER … ADD` |
| destructive | `DROP`, `TRUNCATE`, `UPDATE`/`DELETE` **tanpa `WHERE`**, `ALTER … DROP`, `GRANT`, `REVOKE`, `ALTER ROLE/USER`, `VACUUM FULL`, `COPY … TO PROGRAM` |
| tidak dikenal | dianggap **write** |

- **Multi-statement** (`a; b`): risikonya diambil dari yang tertinggi. Di MySQL,
  multi-statement dimatikan di driver (`multiStatements=false`), kecuali
  lewat `-f FILE --write`.
- Aturan-aturan ini didaftarkan sebagai `policy.Rule` dengan ID seperti
  `sql-drop`, `sql-delete-no-where`, dan seterusnya, supaya muncul di
  `komando policy` dan bisa dirujuk di pesan error.

Parser: mulai dengan tokenizer kecil buatan sendiri (keyword pertama + cek
`WHERE` di level atas). Jangan langsung menarik parser SQL penuh. Kalau
nanti kurang, pertimbangkan `pg_query_go` (cgo, berat) atau
`vitess/sqlparser` (khusus MySQL).

### Dry-run

- `--write --dry-run` di Postgres: jalankan di dalam `BEGIN`, laporkan
  `rows_affected` (dan `RETURNING` kalau ada), lalu `ROLLBACK`. Dry-run
  sungguhan, bukan sekadar menampilkan rencana.
- Di MySQL, DDL melakukan auto-commit. Jadi untuk DDL, dry-run hanya
  mengembalikan klasifikasi dan tidak mengeksekusi apa pun. DML tetap
  di-rollback seperti Postgres.
- Output selalu menyertakan `"dry_run": true` dan `"rolled_back": true`.

### Bentuk output

```json
{
  "ok": true,
  "command": "db.query",
  "data": {
    "conn": "prod-db",
    "risk": "read",
    "columns": [{"name": "id", "type": "int8"}, {"name": "email", "type": "text"}],
    "rows": [[1, "a@x.io"], [2, "b@x.io"]],
    "row_count": 2,
    "truncated": false,
    "rows_affected": null
  },
  "meta": {"version": "…", "duration_ms": 41}
}
```

- `rows` berupa array of arrays, lebih hemat token dibanding array of objects.
- `--limit` default 500. Batas byte memakai `max_output_bytes` yang sudah ada.
  Kalau terpotong, `truncated: true` dan hint menyarankan `LIMIT`/`WHERE`.
- Tipe data: timestamp → RFC3339, `bytea`/BLOB → `{"base64": "…"}`, numeric
  besar → string (supaya presisi tidak hilang di JSON).
- `-o text` menampilkan tabel biasa lewat `Texter`.

### Timeout dan beban

- `statement_timeout` (Postgres) / `max_execution_time` (MySQL) diset dari
  `--timeout`, default 30 detik untuk `db query` (bukan 5 menit seperti
  `exec`).
- Satu koneksi per perintah, tanpa pool. komando adalah CLI yang berumur
  pendek.
- `application_name = komando/<actor>` supaya terlihat di
  `pg_stat_activity`.

### Audit

Satu baris per perintah, memakai `audit()` yang sudah ada:

```json
{"command":"db.query","conns":["prod-db"],"risk":"write","sql":"update users set plan='pro' where id=42","rows_affected":1,"ok":true,"dry_run":false,"actor":"claude"}
```

- Password tidak pernah masuk (URL disimpan tanpa password).
- SQL bisa mengandung data sensitif. Tambah setting
  `audit_sql: full | hash | off`, default `full`.
- Parameter `--param` disimpan sebagai nama saja, tanpa nilainya.

### Error

| Situasi | Kode | Exit |
|---|---|---|
| Conn tidak ada | `CONN_NOT_FOUND` | 3 |
| Gagal konek / auth DB | `DB_CONNECT` / `DB_AUTH` | 4 |
| Host `--via` gagal | error SSH yang sudah ada (`HOSTKEY_MISMATCH`, …) | 4 |
| Error SQL (syntax, constraint) | `DB_ERROR` + `sqlstate` di `data` | 5 |
| Diblok policy | `POLICY_BLOCKED` / `WRITE_REQUIRES_FLAG` / `PROTECTED_TARGET` | 6 |
| Timeout | `TIMEOUT` | 7 |

Setiap error membawa `hint`, sesuai aturan yang sudah ada.

### Dependensi

| Kind | Library | Catatan |
|---|---|---|
| postgres | `github.com/jackc/pgx/v5` | murni Go, `DialFunc` bisa diarahkan ke SSH |
| mysql | `github.com/go-sql-driver/mysql` | `RegisterDialContext` untuk SSH |
| sqlite | `modernc.org/sqlite` | murni Go, tanpa cgo; berguna untuk tes dan file lokal |

Biner akan membesar beberapa MB. Kalau ini jadi masalah, driver bisa
dipisah dengan build tag (`-tags nodb`).

**Alternatif yang ditolak:** menjalankan `psql`/`mysql` di server lewat
`exec`. Cara ini tanpa dependensi, tapi butuh klien terpasang di server,
outputnya teks, dan password harus dikirim ke server. Bisa tetap ditawarkan
sebagai fallback `--via-cli` kalau ada permintaan.

## Bagian 3: perubahan di bagian lain

- `komando guide`: tambah bagian "database: lihat schema dulu, query
  read-only, `--write --dry-run`, baru `--write`".
- `komando schema`: otomatis ikut karena memakai cobra.
- `komando policy`: tampilkan aturan SQL, dikelompokkan per kind.
- `AGENTS.md`: tambah aturan "jangan pakai `exec … psql`, pakai `komando db`".
- `docs/usage.md`: bagian baru "Databases".
- Tes: unit test untuk tokenizer SQL (tabel kasus: komentar, string berisi
  `;`, CTE, `DELETE` tanpa `WHERE`). Tes integrasi memakai SQLite, lalu
  Postgres dan MySQL di CI lewat service container.

## Rencana bertahap

| Fase | Isi | Hasil |
|---|---|---|
| 1 | `store.Conn`, `conn add/list/edit/rm/test`, `internal/driver`, generalisasi `guard()` | fondasi; belum ada query |
| 2 | `db query/schema/explain` untuk postgres + sqlite, read-only, `--write`, dry-run rollback, `--via` | fitur utama |
| 3 | mysql, `db dump`/`restore` via `job`, `audit_sql` | lengkap untuk DB |
| 4 | kind `redis` (`cache get/keys/ttl/info`; blok `FLUSHALL`, `KEYS *` di protected) | membuktikan abstraksinya untuk kind kedua |
| 5 | kind `s3` | — |

Fase 4 sengaja diletakkan sebelum S3. Redis juga butuh `--via` dan klasifikasi
per perintah, jadi menjadi tes yang bagus untuk melihat apakah abstraksi
`driver` sudah tepat.

## Pertanyaan terbuka

1. **Nama perintah:** `conn`, `resource`, atau `db add` langsung (tanpa
   abstraksi umum)? Rancangan ini memilih `conn` karena pendek dan generik.
2. **Kode error protected:** pertahankan `PROTECTED_HOST` untuk host dan
   tambah `PROTECTED_TARGET` untuk conn, atau samakan semuanya (breaking)?
3. **Selector bersama:** apakah `komando conn test @prod` dan
   `komando exec @prod` sebaiknya berbagi grup yang sama? Rancangan ini
   menyiapkannya (nama unik), tapi belum mengaktifkannya.
4. **Default `audit_sql`:** `full` (mudah di-debug) atau `hash` (lebih aman
   untuk data pribadi)?
5. **Ukuran biner:** apakah naik kira-kira 5–8 MB bisa diterima, atau driver
   DB perlu jadi build terpisah?
