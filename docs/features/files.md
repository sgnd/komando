# Files

Read, edit and copy files on servers. [All features](README.md)

## Read and edit files

```bash
komando fs cat web1 /etc/nginx/nginx.conf --tail 50
komando fs ls web1 /var/www
komando fs stat web1 /etc/hosts --sha256
```

Edit one piece of text safely. It only changes the file if the old text is
found **exactly once**, and `--backup` keeps the previous version:

```bash
komando fs replace web1 /etc/nginx/nginx.conf \
  --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
```

Write a whole file (atomic; `--if-changed` skips identical content):

```bash
komando fs write web1 /etc/app/.env --from ./app.env --sudo --mode 0640 --if-changed
```

Also: `fs mkdir`, `fs mv`, `fs chmod`, `fs rm`.

## Copy files

Remote paths are written `TARGET:PATH`.

```bash
komando upload @web ./release.tar.gz /tmp/release.tar.gz    # to many servers at once
komando upload web1 ./site /var/www/site -r
komando download web1 /var/log/nginx/error.log --to ./logs/
komando download @web /etc/nginx/nginx.conf --to ./configs/  # → ./configs/<server>/nginx.conf
```
