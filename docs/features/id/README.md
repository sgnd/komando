# Fitur komando

🇬🇧 [English](../README.md)

Satu halaman per fitur, tugas demi tugas. Baru di sini? Mulai dari
[README](../../../README.id.md). Agent: jalankan `komando guide`.

| Fitur | Yang bisa Anda lakukan | Perintah |
|-------|------------------------|----------|
| [Server](servers.md) | menambahkan server, login dengan key atau password | `host`, `key`, `secret` |
| [Pindahan dan ganti komputer](import.md) | impor ssh config, .pgpass, my.cnf, .env; ekspor ke komputer lain | `import`, `export` |
| [Target](targets.md) | memilih apa yang dikerjakan perintah: satu nama, grup, tag, semuanya | `list`, `test`, `group` |
| [Menjalankan perintah](commands.md) | menjalankan perintah dan skrip, tugas lama, perintah tersimpan | `exec`, `script`, `job`, `recipe`, `shell` |
| [Cek kesehatan dan jaringan](health.md) | server ini apa, sehat atau tidak, bisa menjangkau X atau tidak | `facts`, `recipe`, `net` |
| [File](files.md) | membaca, mengubah, dan menyalin file dengan aman | `fs`, `upload`, `download` |
| [Service, log, Docker, paket, user](system.md) | administrasi sehari-hari | `svc`, `logs`, `docker`, `pkg`, `user`, `cron` |
| [Server privat dan tunnel](tunnels.md) | menjangkau server dan layanan yang tidak ada di internet | `--via`, `tunnel` |
| [VPN](vpn.md) | menjangkau target lewat WireGuard, SOCKS, atau VPN Anda sendiri, beberapa sekaligus | `vpn`, `--via` |
| [Database](databases.md) | query, backup, dan restore PostgreSQL, MySQL, SQLite | `conn`, `db` |
| [Cache](caches.md) | membaca dan mengubah Redis dan Valkey | `cache` |
| [Storage](storage.md) | melihat, mengunduh, dan mengunggah file di bucket S3 dan di server FTPS/SFTP/FTP | `storage`, `upload`, `download` |
| [Cluster](cluster.md) | Kubernetes dan Docker Swarm: status, daftar, log, apply, restart, scale | `cluster` |
| [Container registry](registry.md) | melihat daftar repository dan tag, memeriksa image, menghapus yang lama | `registry` |
| [Keamanan](safety.md) | sabuk pengaman, dan apa yang harus dilakukan saat salah satunya menghentikan Anda | `policy`, `audit` |
| [Standar keamanan](security-standards.md) | seberapa jauh komando memenuhi OWASP, NIST, ISO 27001 dan SLSA | `doctor`, `audit verify` |
| [Hasil dan error](output.md) | output JSON dan teks, exit code, error yang sering muncul | — |
| [Pengaturan dan file](settings.md) | pengaturan, dan tempat komando menyimpan datanya | `config`, `doctor` |
| [Istilah](glossary.md) | kata-kata yang dipakai, dalam bahasa sederhana | — |

Bantuan untuk perintah apa pun: `komando <command> --help`. Referensi lengkap
yang bisa dibaca program ada di `komando schema`.

## Menulis halaman-halaman ini

- Satu fitur per file. Fitur baru mendapat halamannya sendiri dan satu baris di tabel atas.
- Tulis untuk pemula: kalimat pendek, contoh nyata dulu, baru detailnya.
- Perbarui halaman di commit yang sama dengan fiturnya, bersama
  `komando guide` (`internal/cli/guide.md`), skill agent
  (`internal/cli/skill.md`, disalin ke `skills/komando/SKILL.md`) dan `CHANGELOG.md`.
- Aturan untuk perintah dan flag ada di [docs/design/ux.md](../../design/ux.md).
- Setiap halaman punya terjemahan bahasa Indonesia di id/ dengan nama yang sama; perbarui keduanya di commit yang sama.
