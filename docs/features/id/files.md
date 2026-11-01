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

Juga: `fs mkdir`, `fs mv`, `fs chmod`, `fs rm`.

## Menyalin file

Path di server ditulis `TARGET:PATH`.

```bash
komando upload @web ./release.tar.gz /tmp/release.tar.gz    # ke banyak server sekaligus
komando upload web1 ./site /var/www/site -r
komando download web1 /var/log/nginx/error.log --to ./logs/
komando download @web /etc/nginx/nginx.conf --to ./configs/  # → ./configs/<server>/nginx.conf
```
