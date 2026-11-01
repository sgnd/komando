# komando

[![CI](https://github.com/sgnd/komando/actions/workflows/ci.yml/badge.svg)](https://github.com/sgnd/komando/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Satu command line yang aman untuk semua pekerjaan DevOps — server, database, cache, storage, dan lainnya. Untuk Anda dan AI agent Anda.**

🇬🇧 [English](README.md)

Biasanya kita memakai banyak alat sekaligus: Termius untuk server, TablePlus
untuk database, `redis-cli` untuk cache, web console untuk storage, `kubectl`
untuk cluster. Masing-masing punya login, perintah, dan cara merusaknya
sendiri. **komando** menyatukannya di balik satu command line yang bisa
dipakai dengan baik oleh Anda maupun AI agent (Claude Code, Codex, atau bot
Anda sendiri):

- **Mengingat semua yang Anda kelola** dalam satu daftar: server, database, cache, storage.
- **Mengunci password** di brankas terenkripsi. AI tidak pernah melihatnya.
- **Jawaban jelas**: teks mudah dibaca untuk Anda, data terstruktur (JSON) untuk AI.
- **Punya sabuk pengaman**: hanya membaca kecuali Anda minta lain, perintah berbahaya diblokir, produksi bisa dilindungi.
- **Mencatat riwayat** semua yang dikerjakan.

```
Anda ──minta──▶ AI agent ──▶ komando ──▶ server, database, cache, storage, ...
```

Tanpa jendela, tanpa menu. Cukup perintah.

## Instalasi

Buka terminal (macOS: aplikasi **Terminal**; Linux: terminal Anda; Windows:
pasang [WSL](https://learn.microsoft.com/windows/wsl/install) dulu) lalu tempel:

```bash
curl -fsSL https://raw.githubusercontent.com/sgnd/komando/main/install.sh | sh
```

Cek apakah berhasil:

```bash
komando version
```

Cara lain: unduh file dari halaman
[Releases](https://github.com/sgnd/komando/releases), atau baca skripnya dulu
dengan `curl -fsSLO https://raw.githubusercontent.com/sgnd/komando/main/install.sh`
lalu jalankan `sh install.sh`. Developer yang punya Go bisa memakai
`go install github.com/sgnd/komando/cmd/komando@latest`.

## Langkah pertama

Anda butuh **nama user** dan **alamat IP** server. Penyedia hosting Anda
menampilkannya di dashboard. Di bawah ini, `ubuntu` dan `203.0.113.10` hanya
contoh; ganti dengan milik Anda.

```bash
# 1. Tambahkan server dan beri nama singkat (web1)
komando host add web1 ubuntu@203.0.113.10

# 2. Cek apakah bisa terhubung
komando test web1

# 3. Tanyakan sesuatu
komando facts web1            # server ini apa?
komando recipe run health web1   # sehat atau tidak?
komando exec web1 -- uptime   # jalankan perintah apa saja
```

Login pakai password? Simpan sekali saja. Anda mengetiknya, tidak ada yang
tampil di layar, dan disimpan terenkripsi:

```bash
komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

Tandai server produksi sebagai protected. Setelah itu tidak ada yang bisa
diubah di sana kecuali perintahnya memakai `--yes` ("ya, saya yakin"):

```bash
komando host edit web1 --protected
```

### Database dan cache

Tambahkan dengan cara yang sama, pakai nama. Database privat dijangkau lewat
server (`--via`), jadi tidak perlu dibuka ke internet:

```bash
komando secret set app-db-pass
komando conn add app-db postgres://app@10.0.0.5:5432/app \
  --via web1 --password-ref secret:app-db-pass --protected

komando db schema app-db                          # ada tabel apa saja?
komando db query app-db "select count(*) from users"
komando cache info my-cache                       # cache Redis, ditambah dengan conn add
```

Query hanya membaca kecuali Anda menambahkan `--write`. Coba perubahan dulu
dengan `--write --dry-run`: perintahnya dijalankan, hasilnya ditampilkan,
lalu dibatalkan (rollback).

## Serahkan ke AI agent Anda

Salin isi [`AGENTS.md`](AGENTS.md) ke file instruksi agent Anda (Codex:
`AGENTS.md`, Claude Code: `CLAUDE.md`, di folder tempat Anda bekerja), atau
cukup katakan ke agent:

> Gunakan CLI `komando` untuk mengelola server dan database saya. Jalankan `komando guide`
> dulu dan ikuti petunjuknya. Jangan pernah memakai `--allow-dangerous` atau
> `--yes` tanpa bertanya kepada saya.

Lalu cukup minta: *"Kenapa web1 lambat?"*, *"Update semua server"*,
*"Berapa user yang daftar hari ini?"*, *"Perpanjang sertifikat di web2"*.

## Bisa apa saja?

| Tugas | Perintah |
|-------|----------|
| Melihat dan mengecek semuanya sekaligus (server dan conn) | `list`, `test` |
| Menyimpan daftar server dan cara login | `host`, `group`, `key`, `secret` |
| Membawa yang sudah ada (ssh config, .pgpass, my.cnf, .env) atau pindah komputer | `import`, `export` |
| Menjalankan perintah di satu atau banyak server | `exec`, `script`, `job` (tugas lama) |
| Membaca, mengubah, dan menyalin file | `fs`, `upload`, `download` |
| Cek kesehatan (39 pemeriksaan siap pakai) | `facts`, `recipe` |
| Mengelola service, log, Docker, software, user, jadwal | `svc`, `logs`, `docker`, `pkg`, `user`, `cron` |
| Tes jaringan, menjangkau server privat | `net`, `tunnel` |
| Menjangkau yang ada di balik VPN, beberapa sekaligus tanpa pindah-pindah | `vpn`, `--via` |
| Menyimpan daftar database, cache, dan storage | `conn` |
| Query dan backup database (PostgreSQL, MySQL, SQLite) | `db` |
| Membaca dan mengubah cache (Redis, Valkey) | `cache` |
| Kubernetes dan Docker Swarm: status, log, apply, restart, scale | `cluster` |
| Melihat, mengunduh, dan mengunggah file di object storage (S3, MinIO, R2, ...) | `storage`, `upload`, `download` |
| Melihat riwayat dan aturan keamanan | `audit`, `policy` |

Berikutnya: cluster (Kubernetes, k3s, Swarm), container
registry, FTP, dan impor konfigurasi yang sudah Anda punya (kubeconfig,
`.pgpass`, profil AWS, ...). Lihat [roadmap](docs/design/vision.md).

Panduan lengkap per tugas, satu halaman per fitur: **[docs/features](docs/features/README.md)** (bahasa Inggris
sederhana). Bantuan untuk perintah apa pun: `komando <perintah> --help`.

## Keamanan, dalam satu menit

- Perintah seperti `rm -rf /`, `reboot`, `DROP TABLE`, atau `FLUSHALL` **diblokir** kecuali diizinkan manusia.
- Server dan database **protected** menolak perubahan tanpa `--yes` (melihat tetap boleh; tandai perintah `exec` dengan `--read-only`).
- Query database dan perintah cache **hanya membaca** kecuali Anda menambahkan `--write`. Untuk database, database itu sendiri yang menegakkannya.
- `--dry-run` menampilkan apa yang *akan* terjadi.
- Edit file hanya mengubah teks yang Anda sebut, tidak pernah meninggalkan file setengah jadi, dan bisa menyimpan backup.
- Jika identitas server berubah, komando **menolak terhubung**.
- Semuanya tercatat: `komando audit`.

## Istilah singkat

| Istilah | Arti |
|---------|------|
| Server | Komputer (biasanya di cloud) yang menjalankan aplikasi Anda. |
| Terminal / CLI | Jendela tempat mengetik perintah, bukan klik-klik. |
| SSH | Cara aman untuk login dan mengendalikan server Linux dari jauh. |
| Database | Tempat aplikasi menyimpan datanya dalam tabel (PostgreSQL, MySQL, SQLite). |
| Cache | Penyimpanan cepat dan sementara untuk mempercepat aplikasi (Redis). |
| Conn | Istilah komando untuk apa pun yang Anda hubungkan selain server: database, cache, atau bucket storage. |
| AI agent | AI yang bisa menjalankan perintah sendiri untuk menyelesaikan tugas. |
| SSH key | Sepasang file sebagai bukti identitas; lebih aman dari password. |
| Flag | Opsi tambahan pada perintah, seperti `--yes` atau `--dry-run`. |
| sudo | Menjalankan perintah sebagai administrator (root). |
| JSON | Teks terstruktur yang mudah dibaca program. |
| Bastion / jump host | Server gerbang untuk menjangkau server privat. |
| Tunnel | Membuat layanan di server (mis. database) muncul di komputer Anda. |
| Exit code | Angka hasil program: 0 = sukses, selain itu = ada masalah. |

## Kontribusi

Laporan bug, ide, dan pull request sangat diterima — dalam Bahasa Indonesia
atau English. Lihat [CONTRIBUTING.md](CONTRIBUTING.md). Masalah keamanan:
[SECURITY.md](SECURITY.md).

## Lisensi

[MIT](LICENSE)
