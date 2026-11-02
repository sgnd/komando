# Menjalankan perintah

Menjalankan perintah dan skrip di satu atau banyak server, tugas lama, dan perintah tersimpan. [Semua fitur](README.md)

## Menjalankan perintah

```bash
komando exec web1 -- uptime
komando exec @web -- 'df -h /'                    # semua server web sekaligus
komando exec @web --sudo -- systemctl is-active nginx
komando exec web1 --dry-run -- 'apt-get -y upgrade'  # tampilkan, jangan jalankan
komando script @web ./deploy.sh --arg v1.2.3     # jalankan skrip lokal di server
```

Opsi yang berguna: `--timeout 10m`, `--parallel 20`, `--fail-fast`,
`-e KEY=VALUE`, `-C /some/dir`, `--stream` (output langsung).

Password untuk perintah di server diambil dari vault, jadi tidak pernah
diketik atau terlihat: `-e DB_PASS=secret:prod-db`. komando mengisi nilainya
dalam perjalanan ke server.

## Tugas lama

Apa pun yang lambat (backup, upgrade, build) berjalan sebagai *job* yang
tetap jalan di server walaupun koneksi Anda terputus:

```bash
komando job start db1 -- 'pg_dump app | gzip > /backup/app.sql.gz'
komando job status <id>
komando job logs <id>
komando job wait <id>
komando job kill <id>
komando job list
```

## Recipe (perintah siap pakai dan tersimpan)

Simpan perintah sekali dan pakai berulang kali. `{{app}}` adalah isian
kosong yang Anda isi dengan `--var app=...`. Recipe Anda berada di samping
recipe bawaan (`health`, `disk`, `cert-expiry`, ...) di
`komando recipe list`. komando menganggap recipe sebagai perubahan, jadi
server protected meminta `--yes`, kecuali Anda menyimpannya dengan
`--read-only` karena recipe itu hanya melihat. (`ops` dan `snippet` adalah
nama lain untuk `recipe`.)

```bash
komando recipe add restart-app 'systemctl restart {{app}}' --sudo
komando recipe add disk 'df -h {{path=/}}' --read-only
komando recipe run restart-app @web --var app=shop
```
