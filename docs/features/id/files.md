# File

Membaca, mengubah, dan menyalin file di server. [Semua fitur](README.md)

## Membaca dan mengubah file

```bash
komando fs cat web1 /etc/nginx/nginx.conf --tail 50
komando fs ls web1 /var/www
komando fs stat web1 /etc/hosts --sha256
```

Ubah satu bagian teks dengan aman. File hanya diubah jika teks lama
ditemukan **tepat satu kali**, dan `--backup` menyimpan versi sebelumnya:

```bash
komando fs replace web1 /etc/nginx/nginx.conf \
  --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
```

Menulis seluruh file (atomik; `--if-changed` melewati isi yang sama persis):

```bash
komando fs write web1 /etc/app/.env --from ./app.env --sudo --mode 0640 --if-changed
```

`--dry-run` menampilkan perubahannya sebagai diff. `--validate` memeriksa
file baru sebelum dipasang; `%s` adalah path-nya. Kalau pemeriksaan gagal,
file lama tidak berubah (`VALIDATION_FAILED`), jadi salah ketik tidak bisa
mengunci Anda dari server:

```bash
komando fs write web1 /etc/sudoers.d/deploy --from ./deploy.sudoers --sudo --validate 'visudo -cf %s'
komando fs replace web1 /etc/ssh/sshd_config --old 'PermitRootLogin yes' --new 'PermitRootLogin no' --sudo --validate 'sshd -t -f %s'
```

Juga: `fs mkdir`, `fs mv`, `fs chmod`, `fs rm`.

## Menyamakan isi folder (sync)

`sync` hanya mengirim yang baru atau berubah, jadi jalankan kedua kalinya
cepat. Satu sisi adalah folder di sini; sisi lain adalah server (banyak
sekaligus) atau storage:

```bash
komando sync ./site @web:/var/www/site --exclude .git --dry-run   # setiap file yang akan disentuh
komando sync ./site @web:/var/www/site --exclude .git
komando sync ./site web1:/var/www/site --delete --allow-dangerous # juga hapus yang tidak ada lagi di ./site
komando sync web1:/var/log/app ./logs/web1                         # arah sebaliknya
komando sync ./backups backups:2026/                               # ke conn storage
```

File dianggap berubah kalau ukurannya beda atau lebih baru di sumber. Setiap
file ditulis dengan nama sementara lalu dipindahkan ke tempatnya.

## Menyalin file

Path di server ditulis `TARGET:PATH`.

```bash
komando upload @web ./release.tar.gz /tmp/release.tar.gz    # ke banyak server sekaligus
komando upload web1 ./site /var/www/site -r
komando download web1 /var/log/nginx/error.log --to ./logs/
komando download @web /etc/nginx/nginx.conf --to ./configs/  # → ./configs/<server>/nginx.conf
```

Download tidak pernah menimpa file yang sudah ada di komputer Anda
(`FILE_EXISTS`); tambahkan `--overwrite` kalau memang itu maksudnya. File
ditulis dengan nama sementara dulu, jadi koneksi yang putus tidak pernah
meninggalkan file setengah jadi.
