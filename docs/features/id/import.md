# Pindahan dan ganti komputer

Bawa server dan database yang sudah Anda punya, dan pindahkan semuanya ke
komputer lain. [Semua fitur](README.md)

## Impor yang sudah Anda punya

```bash
komando import ssh-config --dry-run       # lihat dulu apa yang akan ditambahkan
komando import ssh-config                 # server dari ~/.ssh/config
komando import pgpass                     # database PostgreSQL dari ~/.pgpass
komando import mycnf                      # MySQL/MariaDB dari ~/.my.cnf
komando import env ./shop/.env --group shop   # DATABASE_URL, REDIS_URL, ... dari file .env
```

| Sumber | Membaca | Menambahkan |
|--------|---------|-------------|
| `ssh-config` | `~/.ssh/config` (termasuk `ProxyJump`) | server |
| `pgpass` | `~/.pgpass` | conn PostgreSQL |
| `mycnf` | bagian `[client]` di `~/.my.cnf` | conn MySQL/MariaDB |
| `env` | file `.env` | satu conn untuk setiap nilai yang berupa URL database, cache, atau storage |
| `kubeconfig` | `~/.kube/config` | satu conn Kubernetes per context |
| `docker` | `~/.docker/config.json` (dan credential helper) | conn registry |
| `filezilla` | `sitemanager.xml` milik FileZilla | server (situs SFTP; yang FTP ditampilkan dalam daftar) |
| `rclone` | `rclone.conf` | server (remote SFTP) |
| `dbeaver` | `data-sources.json` milik DBeaver | conn database (set password-nya setelahnya) |
| `komando` | file dari `komando export` | server, conn, dan recipe |

- Password yang ditemukan di file-file ini masuk ke vault sebagai
  `<name>-pass`. Password itu tidak pernah muncul di daftar, output, atau
  riwayat komando.
- Mengimpor file yang sama lagi tidak mengubah apa pun. Database lain yang
  kebetulan bernama sama mendapat nama kosong berikutnya (`shop-2`).
- Yang tidak bisa diimpor komando ditampilkan dalam daftar, beserta
  alasannya: misalnya baris `.pgpass` dengan `*`, atau jenis URL yang tidak
  dikenal komando.

Termius dan TablePlus tidak punya format ekspor terbuka. Dari Termius, ekspor
host Anda sebagai SSH config lalu pakai `komando import ssh-config FILE`;
untuk database, tulis URL-nya di file `.env` lalu pakai
`komando import env FILE`.

## Pindah ke komputer lain

```bash
komando export --to komando-backup.json       # server, conn, dan recipe; tanpa password
komando export @prod --to prod.json           # hanya yang dipilih target
```

Di komputer yang lain:

```bash
komando import komando komando-backup.json
komando secret set prod-db-pass               # file itu mendaftar password yang perlu diset lagi
```

File ekspor tidak berisi password, hanya namanya. Salin password-nya dengan
`komando secret set`, atau set `KOMANDO_HOME` ke salinan `~/.komando` jika
Anda memindahkan seluruh foldernya.
