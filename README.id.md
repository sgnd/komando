# komando

[![CI](https://github.com/sgnd/komando/actions/workflows/ci.yml/badge.svg)](https://github.com/sgnd/komando/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Biarkan AI agent merawat server Anda — dengan aman, lewat command line.**

🇬🇧 [English](README.md)

Biasanya server dikelola dengan aplikasi seperti Termius: login, ketik
perintah, ulangi. **komando** mengerjakan hal yang sama dalam bentuk yang bisa
dipakai dengan baik oleh AI agent (Claude Code, Codex, atau bot Anda sendiri):

- **Mengingat server Anda**, seperti buku kontak.
- **Mengunci password** di brankas terenkripsi. AI tidak pernah melihatnya.
- **Jawaban jelas**: teks mudah dibaca untuk Anda, data terstruktur (JSON) untuk AI.
- **Punya sabuk pengaman**: perintah berbahaya diblokir, server produksi bisa dilindungi.
- **Mencatat riwayat** semua yang dikerjakan.

```
Anda ──minta──▶ AI agent ──▶ komando ──SSH──▶ server Anda
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
komando host test web1

# 3. Tanyakan sesuatu
komando facts web1            # server ini apa?
komando ops run health web1   # sehat atau tidak?
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

## Serahkan ke AI agent Anda

Salin isi [`AGENTS.md`](AGENTS.md) ke file instruksi agent Anda (Codex:
`AGENTS.md`, Claude Code: `CLAUDE.md`, di folder tempat Anda bekerja), atau
cukup katakan ke agent:

> Gunakan CLI `komando` untuk mengelola server saya. Jalankan `komando guide`
> dulu dan ikuti petunjuknya. Jangan pernah memakai `--allow-dangerous` atau
> `--yes` tanpa bertanya kepada saya.

Lalu cukup minta: *"Kenapa web1 lambat?"*, *"Update semua server"*,
*"Perpanjang sertifikat di web2"*.

## Bisa apa saja?

| Tugas | Perintah |
|-------|----------|
| Menyimpan daftar server dan cara login | `host`, `group`, `key`, `secret` |
| Menjalankan perintah di satu atau banyak server | `exec`, `script`, `job` (tugas lama) |
| Membaca, mengubah, dan menyalin file | `fs`, `cp` |
| Cek kesehatan (39 pemeriksaan siap pakai) | `facts`, `ops` |
| Mengelola service, log, Docker, software, user, jadwal | `svc`, `logs`, `docker`, `pkg`, `user`, `cron` |
| Tes jaringan, menjangkau server privat | `net`, `tunnel` |
| Melihat riwayat dan aturan keamanan | `audit`, `policy` |

Panduan lengkap per tugas: **[docs/usage.md](docs/usage.md)** (bahasa Inggris
sederhana). Bantuan untuk perintah apa pun: `komando <perintah> --help`.

## Keamanan, dalam satu menit

- Perintah seperti `rm -rf /`, `reboot`, atau `DROP DATABASE` **diblokir** kecuali diizinkan manusia.
- Server **protected** menolak perubahan tanpa `--yes` (perintah bertanda `--read-only` tetap boleh melihat).
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
