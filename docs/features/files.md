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
komando cp ./release.tar.gz @web:/tmp/            # upload to many servers
komando cp -r ./site web1:/var/www/site
komando cp web1:/var/log/nginx/error.log ./logs/  # download
komando cp @web:/etc/nginx/nginx.conf ./configs/  # → ./configs/<server>/nginx.conf
```
