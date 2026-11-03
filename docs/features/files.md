# Files

Read, edit and copy files on servers. [All features](README.md)

## Read and edit files

```bash
komando fs cat web1 /etc/nginx/nginx.conf --tail 50
komando fs ls web1 /var/www            # ls -l style with -o text; no PATH = your home folder
komando fs stat web1 /etc/hosts --sha256
komando fs cat web1 '~/app/.env'       # ~ is the login user's home, like scp
```

`fs cat` shows text. A binary file is refused in `-o text` (so
`fs cat ... > file` never writes a broken copy); save it with
`komando download` instead. When a file is longer than `--max-bytes`, the
output says it was cut, and the hash is `sha256_read` (of the part read),
not `sha256`.

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

A path that is a symbolic link (for example `sites-enabled/app` pointing to
`sites-available/app`) is followed: the file it points to is written, its
mode and owner kept, and the link stays a link (`followed:` in the result).
`--no-follow` refuses instead. A missing parent folder is `FOLDER_NOT_FOUND`;
add `-p` to create it. `--owner` needs `--sudo`.

Also `fs mkdir`, `fs mv`, `fs chmod` and `fs rm`, which behave like the
commands you know, with two safety differences:

- `fs mv` never replaces an existing file (`FILE_EXISTS`, exit 8) unless you
  add `--overwrite`. Moving into an existing folder puts the file inside it.
- `fs rm` on a path that is not there says `not found` and still succeeds,
  like `rm -f`. A folder needs `--recursive` (and `--allow-dangerous`).
  Paths are taken literally: `'/tmp/*.log'` is not a pattern; use
  `komando exec` for that.

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

A file counts as changed when its size or mode differs, or it is newer in
the source; modes and modification times are copied too. Each file is
written under a temporary name and moved into place. A destination folder
that does not exist is created (`--dry-run` says so).

A source that does not exist is an error (`PATH_NOT_FOUND`, exit 3), and
`--delete` never runs from an empty source, so a typo cannot wipe the
destination. Symbolic links are not copied; they are listed as `skipped`.
For a single file use `komando upload` / `komando download`.

## Copy files

Remote paths are written `TARGET:PATH`; `TARGET:` alone and `TARGET:~/x`
mean the login user's home folder, like scp. A local file whose name has a
colon (`a:b.txt`) is read as local when it exists; otherwise write `./a:b.txt`.

```bash
komando upload @web ./release.tar.gz /tmp/release.tar.gz    # to many servers at once
komando upload web1 ./nginx.conf /etc/nginx/nginx.conf --sudo  # a root-owned file
komando upload web1 ./site /var/www/site -r
komando download web1 /var/log/nginx/error.log --to ./logs/
komando download web1 /var/log/secure --sudo --to ./logs/    # a file only root can read
komando download @web /etc/nginx/nginx.conf --to ./configs/  # → ./configs/<server>/nginx.conf
```

Folders (`-r`) follow one rule, so the same copy run twice gives the same
result:

| Command | Result |
|---|---|
| `cp -r site web1:/var/www/site` | `/var/www/site` is the copy; run it again and it is updated in place (never `site/site`) |
| `cp -r site/ web1:/var/www/html` | the *contents* of `site` go into `html` |
| `cp -r site web1:/var/www/html` (html exists) | `/var/www/html/site` |

`--sudo` handles single files. For a folder, upload it to a place you own
and move it with `komando exec web1 --sudo -- cp -r /tmp/site/. /var/www/site/`,
or use `komando sync` for repeatable deploys. Symbolic links are not copied
(listed as `skipped`). When some files of a folder cannot be read, the rest
are still copied; the result lists them under `errors` and exits 5.

Downloads never replace a file that is already on your computer
(`FILE_EXISTS`); add `--overwrite` when you mean to. Uploads replace the
file on the server and say so (`replaced: true`). A download is written
under a temporary name first, so a broken connection never leaves half a
file.
