# Files

Read, edit and copy files on your servers, safely. [All docs](README.md)

## Read a file

```bash
komando fs cat web1 /etc/nginx/nginx.conf --tail 50
```

Typed alone at your terminal, `komando fs cat` asks for the server (from
your list), then the file.

```bash
komando fs cat web1 /var/log/syslog --head 20 --line-numbers
komando fs cat web1 /var/log/auth.log --sudo          # a file only root can read
komando fs cat web1 '~/app/.env'
```

`~` in a path is the login user's home folder, as with `scp`. Quote it
(`'~/app/.env'`) so your own shell does not expand it.

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

## List a folder

```bash
komando fs list web1 /var/www
```

```text
MODE        SIZE    MODIFIED          NAME
drwxr-xr-x  -       2026-11-12 09:14  assets/
-rw-r--r--  4.2 KB  2026-11-12 09:14  index.html
```

```bash
komando fs list web1 -a                       # no PATH: your home folder; -a shows dotfiles
komando fs list web1 /srv -r --limit 200      # walk folders (up to 1000 entries by default)
komando fs stat web1 /etc/hosts --sha256      # exists:false instead of an error when missing
```

## Edit a file

`fs replace` is the safest way to change a config file. It changes the file
only if the old text is found exactly once, and `--backup` keeps the
previous version as `PATH.bak`:

```bash
komando fs replace web1 /etc/nginx/nginx.conf \
  --old 'worker_connections 768;' --new 'worker_connections 4096;' --sudo --backup
```

```text
replaced 1 match(es) in /etc/nginx/nginx.conf
backup: /etc/nginx/nginx.conf.bak
Changed /etc/nginx/nginx.conf on web1. To undo: komando fs restore web1 /etc/nginx/nginx.conf --sudo
```

Typed alone, `komando fs replace` asks for the server, the file, the text
to change and what it should become.

```bash
komando fs replace web1 /etc/ssh/sshd_config --regex \
  --old '(?m)^#?PasswordAuthentication .*$' --new 'PasswordAuthentication no' --sudo
```

`--all` replaces every match instead. `--regex` treats `--old` as a Go
regular expression; `$1` in `--new` inserts a group.

On a group, `fs replace` makes the same edit on every server
(`komando fs replace @web ... --dry-run` first shows each server's diff),
and `fs restore @web PATH` puts back each server's own newest backup. Each
server has its own result; one where `--old` is not found fails on its own
(`NO_MATCH`) while the others are changed. `fs write` changes one server's
file; to put one file on many servers use `komando upload`.

### Write a whole file

`fs write` writes a whole file. The new file is written next to the old one
and then moved into place, so a server never sees half a file:

```bash
komando fs write web1 /etc/app/.env --from ./app.env --sudo --mode 0640 --if-changed
komando fs write web1 /etc/app/env --content 'PORT=8080' --sudo --backup
komando fs write web1 '~/notes.txt' --content 'checked' --append
```

The content comes from `--content`, `--from FILE`, or stdin (`--from -`).
`--if-changed` skips the write when the content is already the same. The
flags both commands share are under [Reference](#reference).

By default, a path that is a symbolic link (for example `sites-enabled/app`
pointing to `sites-available/app`) is followed: the file it points to is
written, its mode and owner are kept, and the link stays a link. The result
shows `followed:`. `--no-follow` refuses to write through a link.

### Check before it goes live

`--dry-run` shows the change as a diff. `--validate` checks the new file
before it goes into place; `%s` is its path. If the check fails, the old
file stays as it was (`VALIDATION_FAILED`), so a typo cannot lock you out:

```bash
komando fs write web1 /etc/sudoers.d/deploy --from ./deploy.sudoers --sudo --validate 'visudo -cf %s'
komando fs replace web1 /etc/ssh/sshd_config --old 'PermitRootLogin yes' --new 'PermitRootLogin no' --sudo --validate 'sshd -t -f %s'
```

### Secrets in a file

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

## Undo a change

`fs replace` and `fs write` with `--backup` keep the previous version next to
the file and name it in the result (`backup`). At a terminal they also print
the undo command (see the sample above).

`fs restore` puts the newest backup back. Add `--dry-run` first to see the
change. The file as it is now becomes a new backup, so a restore can be undone
too. `--copy PATH` picks an older backup.

```bash
komando fs restore web1 /etc/nginx/nginx.conf --sudo --dry-run
komando fs restore web1 /etc/nginx/nginx.conf --sudo
komando svc reload web1 nginx                 # if a service reads the file
```

On a Windows server `fs restore` does not work yet: copy the backup back
with `komando exec win1 -- Copy-Item ...` ([Windows servers](windows.md)).

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
komando fs rm web1 /tmp/old.tar.gz --dry-run
komando fs rm web1 /tmp/old.tar.gz
```

They behave like the commands you know, with these safety differences:

- `fs mv` never replaces an existing file (`FILE_EXISTS`, exit 8) unless you
  add `--overwrite`. Moving into an existing folder puts the file inside it.
- `fs rm` deletes for good. At your terminal komando asks you to type the
  path (several paths: how many); an AI agent or a script adds
  `--allow-dangerous` after a person agrees (`POLICY_BLOCKED` otherwise;
  `--dry-run` shows what goes). See [Safety](safety.md). On a path that is
  not there it says `not found` and still succeeds, like `rm -f`.
- A folder needs `--recursive` as well, with the same question (and the
  same `--allow-dangerous` for an agent or a script).
- Paths are taken literally: `'/tmp/*.log'` is not a pattern. Use
  `komando exec` for that.
- All of them take `--sudo`; `fs chmod -r` changes a whole folder.
  `fs chmod --sudo` does not follow a link another server user made
  (`IS_A_SYMLINK`).

## Copy files

`upload` sends files to servers (many at once). `download` brings them to
this computer. Both also work with [storage](storage.md) conns.

```bash
komando upload @web ./release.tar.gz /tmp/release.tar.gz      # to many servers at once
komando download web1 /var/log/nginx/error.log --to ./logs/
```

Typed alone, `komando upload` asks where to (servers or file storage), which
file or folder on this computer, and where it should go.

```bash
komando upload web1 ./nginx.conf /etc/nginx/nginx.conf --sudo  # a root-owned file
komando upload web1 ./run.sh /opt/app/bin/run.sh --mode 0755 -p
komando upload web1 ./site /var/www/site -r                    # a folder
komando download web1 /var/log/secure --sudo --to ./logs/      # a file only root can read
komando download @web /etc/nginx/nginx.conf --to ./configs/    # → ./configs/<server>/nginx.conf
```

Without a destination, `upload` puts the file in the login user's home
folder under its own name, and `download` saves into the current folder.

An upload over a file that is there keeps that file's mode (a 0600 `.env`
stays 0600); a new file gets the local file's mode. `--mode` sets it.

`komando cp` is `upload` or `download` written `SRC DST`, like `scp`: the
same code, flags and results. Remote paths are written `TARGET:PATH`;
`TARGET:` alone, or `TARGET:~/x`, is the login user's home folder. A storage
conn works too (`backups:2026/db.sql.gz`):

```bash
komando cp ./app.tar.gz @web:/tmp/app.tar.gz
komando cp -r ./site web1:/var/www/site
komando cp web1:/var/log/nginx/error.log ./logs/
```

TARGET can be any [target](targets.md) (`tag:edge:/srv/site`,
`label:env=prod:/tmp/x`), a server you have not added with its port
(`root@10.0.0.5:2222:/tmp/x`), or an IPv6 address in brackets
(`[2001:db8::1]:/tmp/x`).

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

A folder given as a symbolic link (`./current -> releases/42`) is copied as
the folder it names, as `scp -r` does. Symbolic links inside a folder are not
copied; they are listed as `skipped`. When some files in a folder cannot be
read, the rest are still copied; the result lists the failures under
`errors` and komando exits 5.

### What a copy replaces

- Downloads never replace a file that is already on your computer. One
  file stops with `FILE_EXISTS` (exit 8); a folder (`-r`), from a server or
  from storage, keeps those files, copies the rest and says how many it
  kept (`kept`). Add `--overwrite` when you mean to replace them.
- Uploads replace the file on the server and say so (`replaced: true`).
- Every file, both ways, is written under a temporary name first and moved
  into place when complete, so a broken connection never leaves half a
  file. (Moving a new file into place on a server makes the SSH user its
  owner; use `--sudo` for a single file whose owner must stay.)

### Big files and Ctrl-C

- At a terminal, a file of 8 MiB or more going to or from one server shows
  its progress on stderr (`app.tar.gz: 120.0 of 512.0 MB`). Nothing is
  shown when stderr is not a terminal, or for an AI agent; stdout never
  gets it.
- Ctrl-C stops a copy, or a sync, within a moment. The file being copied is
  not left behind, files already copied stay, and komando exits 1 with
  `CANCELLED`. Run the same command again to finish: `sync` sends only
  what is still missing. Closing the terminal stops it the same way. A
  second Ctrl-C ends komando at once, and still removes the half-copied
  file (and any other temporary file or sign-in browser profile this run
  made).
- For a copy that may take longer than a few minutes, or over a shaky
  link, run it on the server as a job: `komando job start`.

## Keep a folder in step (sync)

`sync` copies a folder one way and sends only what is new or changed, so the
second run is quick. One side is a folder on this computer. The other side
is servers (many at once) or a [storage](storage.md) conn:

```bash
komando sync ./site @web:/var/www/site --exclude .git --dry-run   # every file it would touch
komando sync ./site @web:/var/www/site --exclude .git
komando sync ./site web1:/var/www/site --delete --dry-run          # also remove what ./site no longer has
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
- `--delete` removes files for good: at your terminal komando asks you to
  type the destination (`web1:/var/www/site`); an AI agent or a script adds `--allow-dangerous`
  after a person agrees.
- A source that does not exist is an error (`PATH_NOT_FOUND`, exit 3), and
  `--delete` never runs from an empty source, so a typo cannot wipe the
  destination.
- Symbolic links inside the folder are not copied; they are listed as
  `skipped`. A source folder given as a link is synced as the folder it
  names.
- Ctrl-C stops it within a moment; files already copied stay, and the
  next run sends the rest.
- `--sudo` writes on the servers as root, for a folder the SSH user cannot
  write (`komando sync ./conf.d web1:/etc/nginx/conf.d --sudo`): each file
  goes in as `upload --sudo` puts one, staged in the SSH user's `/tmp`
  (only they can read it), checked by root and installed with the source
  file's mode, keeping the owner of a file that is there. A folder another
  user may change stops it (`SHARED_FOLDER_CONFLICT`). The folder must be
  readable by the SSH user, and `--sudo` is for a folder going to servers
  (to read a file only root can read, use `download --sudo`).

For a single file, use `komando upload` or `komando download`.

## Limits

- `fs write` works on one server per run; a target that picks several
  stops with an error (use `komando upload` for many).
- `fs cat` reads at most `--max-bytes` (1 MiB by default) and refuses a
  binary file in `-o text`.
- `fs list` shows up to 1000 entries unless `--limit` says otherwise.
- `fs rm` and `fs chmod` take paths literally: no patterns.
- `--sudo` in copies works for single files only (downloads up to 512 MiB).
  For a root-owned folder, upload it to a place you own and move it with
  `komando exec web1 --sudo -- cp -r /tmp/site/. /var/www/site/`.
- `sync` has no `--sudo`: it writes only where the login user may write.
- Symbolic links inside a folder are not copied by `cp -r`, `upload -r`,
  `download -r` or `sync`.
- `--sudo` writes are refused into a folder another server user can change
  (by owner, group, mode or access list: `SHARED_FOLDER_CONFLICT`); write
  such a file as that user.
- Backups stay next to the file and add up, one per edit.
- On Windows servers, `fs restore`, `fs replace`, `fs rm`, `mkdir`, `mv`,
  `chmod`, `sync` and folder copies do not work yet ([Windows servers](windows.md)).
- Masking of secrets for AI agents is a best effort.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `NO_MATCH` | `fs replace` did not find the `--old` text | read the file with `komando fs cat` and copy the exact text (spaces count) |
| `VALIDATION_FAILED` | `--validate` rejected the new file; the file was not changed | fix the content and run it again |
| `HIDDEN_VALUE` | the edit would cut into, copy or uncover a value komando hid from an AI agent | match the whole `NAME=[hidden]`, or write `{{secret:NAME}}` |
| `SECRET_DESTINATION` | an AI agent asked to write a vault value into a file | a person allows it in komando's window |
| `FOLDER_NOT_FOUND` | the folder for the new file does not exist | add `-p` (`--parents`) |
| `FILE_EXISTS` | `fs mv` or a download would replace a file | add `--overwrite` when you mean it |
| `PATH_NOT_FOUND` | the source of a copy or sync does not exist | check the path |
| `PERMISSION_DENIED` | the login user may not read or write the file | add `--sudo` |
| `SHARED_FOLDER_CONFLICT` | `--sudo` into a folder another server user can change | write the file as that user, without `--sudo` |
| `CHMOD_FAILED` | an SFTP server does not allow setting modes, and its new files are more open than asked | write without `--mode`, or on a server that allows it |
| `POLICY_BLOCKED` | `fs rm`, `rm -r` or `sync --delete` from an AI agent or a script without `--allow-dangerous` | check with `--dry-run`, ask a person, then add `--allow-dangerous` |
| `CANCELLED` | Ctrl-C stopped a copy or sync | run the same command again to finish |

## Reference

Flags `fs write` and `fs replace` share:

| Flag | What it does |
|------|--------------|
| `-s`, `--sudo` | Write a root-owned file (writes a temporary file, then `sudo install`). Not into a folder another server user can change (by owner, group, mode or access list): that stops with `SHARED_FOLDER_CONFLICT`; write such a file as that user. |
| `--backup` | Keep the previous version as `PATH.bak`. A backup is never overwritten: when `PATH.bak` exists, the new one is `PATH.bak.<UTC time>` (for example `nginx.conf.bak.20261105T031500Z`). The result's `backup` names the file. With `--sudo` the backup belongs to root, mode 0600. Backups stay next to the file and add up, one per edit: remove old ones with `fs rm`, and keep them out of folders where every file is loaded (`sites-enabled/`, `conf.d/*.conf`). |
| `--mode 0640` | File mode (default: keep the old mode, or 0644 for a new file). An SFTP server that does not allow setting modes (storage boxes, SFTP-only accounts) is fine when its new files are no more open than asked: the result's `mode` is the one the file got. Otherwise the write fails with `CHMOD_FAILED`. |
| `--owner USER:GROUP` | Owner of the file (needs `--sudo`; the group is optional). |
| `-p`, `--parents` | Create missing parent folders; without it, a missing folder is `FOLDER_NOT_FOUND`. |
| `--no-follow` | Refuse to write through a symbolic link. |
| `--validate 'CMD %s'` | Check the new file before it goes into place. |
