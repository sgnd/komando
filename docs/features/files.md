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

`--dry-run` shows the change as a diff. `--validate` checks the new file
before it goes into place; `%s` is its path. If the check fails, the old file
stays as it was (`VALIDATION_FAILED`), so a typo cannot lock you out:

```bash
komando fs write web1 /etc/sudoers.d/deploy --from ./deploy.sudoers --sudo --validate 'visudo -cf %s'
komando fs replace web1 /etc/ssh/sshd_config --old 'PermitRootLogin yes' --new 'PermitRootLogin no' --sudo --validate 'sshd -t -f %s'
```

Also: `fs mkdir`, `fs mv`, `fs chmod`, `fs rm`.

## Keep a folder in step (sync)

`sync` sends only what is new or changed, so the second run is quick. One
side is a folder here; the other is servers (many at once) or storage:

```bash
komando sync ./site @web:/var/www/site --exclude .git --dry-run   # every file it would touch
komando sync ./site @web:/var/www/site --exclude .git
komando sync ./site web1:/var/www/site --delete --allow-dangerous # also remove what ./site no longer has
komando sync web1:/var/log/app ./logs/web1                         # the other way
komando sync ./backups backups:2026/                               # into a storage conn
```

A file counts as changed when its size differs or it is newer in the
source. Each file is written under a temporary name and moved into place.

## Copy files

Remote paths are written `TARGET:PATH`.

```bash
komando upload @web ./release.tar.gz /tmp/release.tar.gz    # to many servers at once
komando upload web1 ./site /var/www/site -r
komando download web1 /var/log/nginx/error.log --to ./logs/
komando download @web /etc/nginx/nginx.conf --to ./configs/  # → ./configs/<server>/nginx.conf
```

Downloads never replace a file that is already on your computer
(`FILE_EXISTS`); add `--overwrite` when you mean to. A download is written
under a temporary name first, so a broken connection never leaves half a
file.
