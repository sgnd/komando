# Files

Read, edit and copy files on your servers, safely. [All docs](README.md)

## Quick start

```bash
komando fs cat web1 /etc/nginx/nginx.conf --tail 50          # read a file
komando fs replace web1 /etc/nginx/nginx.conf \
  --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
komando upload @web ./release.tar.gz /tmp/release.tar.gz     # copy to many servers
komando download web1 /var/log/nginx/error.log --to ./logs/  # copy to this computer
komando sync ./site @web:/var/www/site --dry-run             # send only what changed
```

`~` in a path is the login user's home folder, as with `scp`. Quote it
(`'~/app/.env'`) so your own shell does not expand it.

## Read files and folders

```bash
komando fs cat web1 /etc/nginx/nginx.conf --tail 50
komando fs cat web1 /var/log/syslog --head 20 --line-numbers
komando fs cat web1 /var/log/auth.log --sudo          # a file only root can read
komando fs cat web1 '~/app/.env'
komando fs ls web1 /var/www                           # ls -l style with -o text
komando fs ls web1 -a                                 # no PATH: your home folder; -a shows dotfiles
komando fs ls web1 /srv -r --max 200                  # walk folders (up to 1000 entries by default)
komando fs stat web1 /etc/hosts --sha256              # exists:false instead of an error when missing
```

`fs cat` shows text. In `-o text`, a binary file is refused, so
`fs cat ... > file` never writes a broken copy; save it with
`komando download` instead. A file longer than `--max-bytes` (1 MiB) is cut:
the output says so, and its hash is `sha256_read` (of the part read), not
`sha256`. `--tail` alone reads the end of the file, so the last lines are
the file's real last lines; for such a long file `--line-numbers` cannot
know their numbers and leaves them out (the `note` says so).

For an AI agent, `fs cat` masks the whole file first and then takes
`--head`/`--tail`, so a cut never uncovers part of a secret. A hidden private
key shows as one line, and `lines` and line numbers then count the file as
shown (the output has a `note`). When something is hidden, the hash is left
out: it would let a weak value be guessed from the rest of the file.

## Edit a file

`fs replace` is the safest way to change a config file. It changes the file
only if the old text is found exactly once, and `--backup` keeps the
previous version as `PATH.bak`:

```bash
komando fs replace web1 /etc/nginx/nginx.conf \
  --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
komando fs replace web1 /etc/ssh/sshd_config --regex \
  --old '(?m)^#?PasswordAuthentication .*$' --new 'PasswordAuthentication no' --sudo
```

`--all` replaces every match instead. `--regex` treats `--old` as a Go
regular expression; `$1` in `--new` inserts a group.

For an AI agent, `fs replace` works on the file as the agent sees it, with
`[hidden]` in place of each secret. `--old 'DB_PASSWORD=[hidden]'` matches the
line whatever the value is. A match that cuts into a hidden value, or a `$1`
that would copy one, is refused (`HIDDEN_VALUE`), and whether `--old` matches
never depends on a hidden value. An edit that would uncover a hidden value
is refused too (`HIDDEN_VALUE`): renaming `DB_PASSWORD=` to a name that does
not look secret, or cutting `postgres://` or `Bearer ` off, while the value
stays. Whether `--new` happens to equal a hidden value never shows: such an
edit counts as a change (the file is written again), and no hash of the file
is reported. `fs write --if-changed` and its `would_change` do the same for a
file with a hidden value. Masking stays a best effort.

`{{secret:NAME}}` in `--new` or in the text `fs write` writes becomes the
vault value on the server. When an AI agent asks for that, komando stops
with `SECRET_DESTINATION` until a person allows it: the agent adds `--yes`
and the window names the secret and the server and file it goes to. An
agent's `--dry-run` reads no secret and shows `{{secret:NAME}}` as written.

`fs write` writes a whole file. The new file is written next to the old one
and then moved into place, so a server never sees half a file:

```bash
komando fs write web1 /etc/app/.env --from ./app.env --sudo --mode 0640 --if-changed
komando fs write web1 /etc/app/env --content 'PORT=8080' --sudo --backup
komando fs write web1 '~/notes.txt' --content 'checked' --append
```

The content comes from `--content`, `--from FILE`, or stdin (`--from -`).
`--if-changed` skips the write when the content is already the same.

### Check before it goes live

`--dry-run` shows the change as a diff. `--validate` checks the new file
before it goes into place; `%s` is its path. If the check fails, the old
file stays as it was (`VALIDATION_FAILED`), so a typo cannot lock you out:

```bash
komando fs write web1 /etc/sudoers.d/deploy --from ./deploy.sudoers --sudo --validate 'visudo -cf %s'
komando fs replace web1 /etc/ssh/sshd_config --old 'PermitRootLogin yes' --new 'PermitRootLogin no' --sudo --validate 'sshd -t -f %s'
```

### Flags for both

| Flag | What it does |
|------|--------------|
| `-s`, `--sudo` | Write a root-owned file (writes a temporary file, then `sudo install`). |
| `--backup` | Keep the previous version as `PATH.bak`. A backup is never overwritten: when `PATH.bak` exists, the new one is `PATH.bak.<UTC time>` (e.g. `nginx.conf.bak.20261105T031500Z`). The result's `backup` names the file. With `--sudo` the backup belongs to root, mode 0600. Backups stay next to the file and add up, one per edit: remove old ones with `fs rm`, and keep them out of folders where every file is loaded (`sites-enabled/`, `conf.d/*.conf`). |
| `--mode 0640` | File mode (default: keep the old mode, or 0644 for a new file). An SFTP server that does not allow setting modes (storage boxes, SFTP-only accounts) is fine when its new files are no more open than asked: the result's `mode` is the one the file got. Otherwise the write fails with `CHMOD_FAILED`. |
| `--owner USER:GROUP` | Owner of the file (needs `--sudo`; the group is optional). |
| `-p`, `--parents` | Create missing parent folders; without it, a missing folder is `FOLDER_NOT_FOUND`. |
| `--no-follow` | Refuse to write through a symbolic link. |

By default, a path that is a symbolic link (for example `sites-enabled/app`
pointing to `sites-available/app`) is followed: the file it points to is
written, its mode and owner are kept, and the link stays a link. The result
shows `followed:`.

## Undo a change

`fs replace` and `fs write` with `--backup` keep the previous version next to
the file and name it in the result (`backup`). In a terminal they also print
the undo command:

```text
Changed /etc/nginx/nginx.conf on web1. To undo: komando fs restore web1 /etc/nginx/nginx.conf --sudo
```

`fs restore` puts the newest backup back. Add `--dry-run` first to see the
change. The file as it is now becomes a new backup, so a restore can be undone
too. `--from FILE` picks an older backup.

```bash
komando fs restore web1 /etc/nginx/nginx.conf --sudo --dry-run
komando fs restore web1 /etc/nginx/nginx.conf --sudo
komando svc reload web1 nginx                 # if a service reads the file
```

Without `--backup` there is no copy: `komando audit` says what changed, when
and where (`komando audit --target web1 --since 2h`), so you can change it
back by hand. For a database change, restore from a dump (`db dump` before
the change, `db restore` to go back); for a Kubernetes deployment, `cluster
rollback`.

## Move, remove and change files

```bash
komando fs mkdir web1 /srv/app/releases                 # always creates parents, like mkdir -p
komando fs mv web1 /srv/app/new.conf /srv/app/app.conf
komando fs chmod web1 0640 /etc/app/.env
komando fs rm web1 /tmp/old.tar.gz
```

They behave like the commands you know, with these safety differences:

- `fs mv` never replaces an existing file (`FILE_EXISTS`, exit 8) unless you
  add `--overwrite`. Moving into an existing folder puts the file inside it.
- `fs rm` on a path that is not there says `not found` and still succeeds,
  like `rm -f`. A folder needs `--recursive`, which also needs
  `--allow-dangerous`.
- Paths are taken literally: `'/tmp/*.log'` is not a pattern. Use
  `komando exec` for that.
- All of them take `--sudo`; `fs chmod -r` changes a whole folder.

## Copy files

`upload` sends files to servers (many at once). `download` brings them to
this computer. Both also work with [storage](storage.md) conns.

```bash
komando upload @web ./release.tar.gz /tmp/release.tar.gz      # to many servers at once
komando upload web1 ./nginx.conf /etc/nginx/nginx.conf --sudo  # a root-owned file
komando upload web1 ./run.sh /opt/app/bin/run.sh --mode 0755 -p
komando upload web1 ./site /var/www/site -r                    # a folder
komando download web1 /var/log/nginx/error.log --to ./logs/
komando download web1 /var/log/secure --sudo --to ./logs/      # a file only root can read
komando download @web /etc/nginx/nginx.conf --to ./configs/    # → ./configs/<server>/nginx.conf
```

Without a destination, `upload` puts the file in the login user's home
folder under its own name, and `download` saves into the current folder.

`komando cp` does the same with `SRC DST`, like `scp`. Remote paths are
written `TARGET:PATH`; `TARGET:` alone, or `TARGET:~/x`, is the login user's
home folder:

```bash
komando cp ./app.tar.gz @web:/tmp/app.tar.gz
komando cp -r ./site web1:/var/www/site
komando cp web1:/var/log/nginx/error.log ./logs/
```

TARGET can be any selector (`tag:edge:/srv/site`, `label:env=prod:/tmp/x`),
a server you have not added with its port (`root@10.0.0.5:2222:/tmp/x`), or
an IPv6 address in brackets (`[2001:db8::1]:/tmp/x`).

A local file whose name has a colon (`a:b.txt`) is read as local when it
exists; otherwise write `./a:b.txt`. Single-file copies report a `sha256`
so you can check them.

### Copy folders

Folders (`-r`) follow one rule, so running the same copy twice gives the same
result:

| Command | Result |
|---|---|
| `cp -r site web1:/var/www/site` | `/var/www/site` is the copy; run it again and it is updated in place (never `site/site`) |
| `cp -r site/ web1:/var/www/html` | the *contents* of `site` go into `html` |
| `cp -r site web1:/var/www/html` (html exists) | `/var/www/html/site` |

`upload` to a [storage](storage.md) conn follows the same rule: without a
destination, `upload backups ./site -r` puts the folder under `site/`, and a
destination ending in `/` counts as an existing folder.

`--sudo` works for single files only (downloads up to 512 MiB). For a
root-owned folder, upload it to a place you own and move it with
`komando exec web1 --sudo -- cp -r /tmp/site/. /var/www/site/`. `komando
sync` has no `--sudo` either: it writes only where the login user may
write.

Symbolic links are not copied; they are listed as `skipped`. When some files
in a folder cannot be read, the rest are still copied; the result lists the
failures under `errors` and komando exits 5.

### What a copy replaces

- Downloads never replace a file that is already on your computer
  (`FILE_EXISTS`). Add `--overwrite` when you mean to.
- Uploads replace the file on the server and say so (`replaced: true`).
- A download is written under a temporary name first, so a broken
  connection never leaves half a file.

## Keep a folder in step (sync)

`sync` copies a folder one way and sends only what is new or changed, so the
second run is quick. One side is a folder on this computer. The other side
is servers (many at once) or a [storage](storage.md) conn:

```bash
komando sync ./site @web:/var/www/site --exclude .git --dry-run   # every file it would touch
komando sync ./site @web:/var/www/site --exclude .git
komando sync ./site web1:/var/www/site --delete --allow-dangerous # also remove what ./site no longer has
komando sync web1:/var/log/app ./logs/web1                         # from a server to here
komando sync ./backups backups:2026/ --exclude '*.tmp'             # into a storage conn
komando sync backups:2026/ ./restore                               # from storage to here
```

- A file counts as changed when its size or mode differs, or when it is
  newer in the source. Modes and modification times are copied too.
- Each file is written under a temporary name and moved into place.
- A destination folder that does not exist is created (`--dry-run` says
  so).
- `--exclude` skips names or paths (shell globs, repeatable).
- A source that does not exist is an error (`PATH_NOT_FOUND`, exit 3), and
  `--delete` never runs from an empty source, so a typo cannot wipe the
  destination.
- Symbolic links are not copied; they are listed as `skipped`.

For a single file, use `komando upload` or `komando download`.
