# Files

Read, edit and copy files on your servers, safely. [All docs](README.md)

There is no file command. Everything on a server except copying is
`komando host ssh exec TARGET [--read-only] -- COMMAND` with the tool you
know (`cat`, `ls`, `cp`, `mv`, `chmod`, `rm`). Copying files is
`komando copy`. For how `exec` works, see
[Services, logs, Docker, packages, users](system.md).

## Read a file

```bash
komando host ssh exec web1 --read-only -- tail -n 50 /etc/nginx/nginx.conf
```

Typed alone at your terminal, `komando host ssh exec` asks for the server
(from your list), then the command.

```bash
komando host ssh exec web1 --read-only -- head -n 20 /var/log/syslog
komando host ssh exec web1 --read-only --sudo -- cat /var/log/auth.log   # a file only root can read
komando host ssh exec web1 --read-only -- cat '~/app/.env'
```

`~` in a path is expanded by the server's shell, not by komando. Quote it
(`'~/app/.env'`) so your own shell does not expand it first.

`exec` shows text. To save a binary file, or any file, to this computer
use `komando copy` (see [Copy files](#copy-files)). A very long output is
cut: the result says so (`stdout_truncated` in JSON). Read the end of a
long file with `tail`, and count its lines with `wc -l`.

For an AI agent, komando masks secret values in output (`[hidden]`), and a
private key shows as one hidden line. Masking is a best effort.

## List a folder

```bash
komando host ssh exec web1 --read-only -- ls -l /var/www
```

```text
drwxr-xr-x 2 www-data www-data 4096 Nov 12 09:14 assets
-rw-r--r-- 1 www-data www-data 4301 Nov 12 09:14 index.html
```

```bash
komando host ssh exec web1 --read-only -- ls -la                  # your home folder, with dotfiles
komando host ssh exec web1 --read-only -- find /srv -maxdepth 2   # walk folders
komando host ssh exec web1 --read-only -- sh -c 'stat /etc/hosts && sha256sum /etc/hosts'
```

Lost: the table with a fixed shape, `exists: false` instead of an error for
a missing file, and the `--limit` on a walk. The tool's own text and exit
code come back instead.

## Edit a file

Lost: `fs replace`, `fs write` and `fs restore`, with their check that the
old text is found exactly once, `--validate` before the file goes live,
`--backup` and the undo command. komando no longer validates, backs up or
undoes a file edit for you. Do it yourself, in this order:

1. Copy the file: `cp FILE FILE.bak`.
2. Change it with one targeted command.
3. Read it back.
4. Check it with the tool's own check before a service reads it
   (`nginx -t`, `sshd -t`, `visudo -cf FILE`).

```bash
komando host ssh exec web1 --sudo -- cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
komando host ssh exec web1 --sudo -- sed -i 's/worker_connections 768;/worker_connections 4096;/' /etc/nginx/nginx.conf
komando host ssh exec web1 --read-only --sudo -- grep worker_connections /etc/nginx/nginx.conf
komando host ssh exec web1 --sudo -- nginx -t
komando host ssh exec web1 --sudo -- systemctl reload nginx        # if a service reads the file
```

Never use `sed -i` without the copy first. To undo, copy the `.bak` back:

```bash
komando host ssh exec web1 --sudo -- cp /etc/nginx/nginx.conf.bak /etc/nginx/nginx.conf
```

To put a whole file on a server, change it on this computer and send it
with `komando copy`:

```bash
komando copy ./app.env web1:/etc/app/.env --sudo --overwrite
```

Without a copy, there is no backup: `komando audit list` says what changed,
when and where (`komando audit list --target web1 --since 2h`), so you can
change it back by hand. For a database change, restore from a backup
(`komando database postgres backup` before the change, `komando database
postgres restore` to go back).

### Secrets in a file

For an AI agent, the file is read with `[hidden]` in place of each secret.
An agent cannot change a line that holds a hidden value, and komando no
longer writes `{{credential:NAME}}` into a file for it. This is an
accepted loss at v0.18.0: nothing writes a credential reference into a
config line. A ready-made change snippet is planned. A person
edits such a line in a `shell`.

TODO(cut): how an agent changes a config line that holds a hidden value,
and the `HIDDEN_VALUE` code, wait on O-24.

## Move, remove and change files

```bash
komando host ssh exec web1 --sudo -- mkdir -p /srv/app/releases
komando host ssh exec web1 --sudo -- mv -n /srv/app/new.conf /srv/app/app.conf
komando host ssh exec web1 --sudo -- chmod 0640 /etc/app/.env
komando host ssh exec web1 --dry-run -- rm /tmp/old.tar.gz
komando host ssh exec web1 -- rm /tmp/old.tar.gz
```

They are the commands you know. With `exec`, these safety rules apply:

- `rm` of files deletes for good. A rule stops it: at your terminal komando
  asks you to type the server's name; an AI agent or a script adds
  `--allow-dangerous` after a person agrees (`POLICY_BLOCKED` otherwise;
  `--dry-run` shows the stop). See [Safety](safety.md). A folder needs
  `rm -r`, with the same question. `rm -f` on a path that is not there still
  succeeds.
- `mv` replaces an existing file unless you add `-n`. Moving into an
  existing folder puts the file inside it.
- Paths are taken as the server's shell reads them: `'/tmp/*.log'` is a
  pattern when you write a shell for it (`sh -c 'rm /tmp/*.log'`), and the
  same rule stops it.
- `--sudo` runs the command as root; `chmod -R` changes a whole folder.

## Copy files

`komando copy SOURCE DESTINATION` copies files in both directions: to
servers (many at once), from servers, and to and from
[storage](storage.md). A remote path is written `TARGET:PATH`; `TARGET:`
alone, or `TARGET:~/x`, is the login user's home folder. This computer's
paths have no prefix.

```bash
komando copy ./release.tar.gz @web:/tmp/release.tar.gz          # to many servers at once
komando copy web1:/var/log/nginx/error.log ./logs/              # from a server
```

Typed alone, `komando copy` asks where from, where to, and which file or
folder.

```bash
komando copy ./nginx.conf web1:/etc/nginx/nginx.conf --sudo     # a root-owned file
komando copy -r ./site web1:/var/www/site                       # a folder
komando copy web1:/var/log/secure ./logs/ --sudo                # a file only root can read
komando copy @web:/etc/nginx/nginx.conf ./configs/              # -> ./configs/<server>/nginx.conf
komando copy ./db.sql.gz backups:2026/db.sql.gz                 # into a storage entry
```

An upload over a file that is there keeps that file's mode (a 0600 `.env`
stays 0600); a new file gets the local file's mode.

TARGET can be any [target](targets.md) (`tag:edge:/srv/site`,
`label:env=prod:/tmp/x`), a server you have not added with its port
(`root@10.0.0.5:2222:/tmp/x`), or an IPv6 address in brackets
(`[2001:db8::1]:/tmp/x`).

A local file whose name has a colon (`a:b.txt`) is read as local when it
exists; otherwise write `./a:b.txt`. Single-file copies report a `sha256`
so you can check them.

TODO(cut): `--mode`, `-p` (parents), `--size`, `--continue` and the other
other copy options wait on the `copy` leaf
options (PR B). The text below keeps the behaviour of each.

### Stream a file through stdout or stdin

`-` as the destination streams one file to stdout, and `-` as the source
uploads from stdin. Nothing is saved on this computer on the way, so an app
(or a phone through [ssh-gate](safety.md)) can read and write files with
them. An ssh-gate key counts as an AI agent, so its streams keep the rules
below for agents: a file over 16 MiB is refused, and a text file arrives
with secret values as `[hidden]` (such a copy cannot be uploaded back).
`--progress` does not go with a stream to stdout.

```bash
komando copy web1:/etc/nginx/nginx.conf - > nginx.conf
komando copy backups:reports/q3.pdf - | open -f
komando copy web1:/var/log/app.log - | grep ERROR
komando copy - web1:/etc/app/motd < motd.txt
pg_dump app | komando copy - backups:dumps/app.sql
```

- **stdout is the file's.** With a stream to stdout, stdout carries the
  file's bytes as they are, binary too, and nothing else, whatever `-o`
  says. komando's own answer goes to stderr: with `-o json` one envelope at
  the end, either the result or the error, and the exit code says which.
  In text mode nothing is said when it worked.
- If a stream breaks off, the bytes already on stdout stay there: the exit
  code is not 0 and the envelope on stderr says why. Compare `bytes` and
  `sha256` when you need to be sure.
- **Uploads from stdin** go to one server or entry, into a destination
  that must name the file (stdin has no name). On a server the content goes
  to a temporary file that is moved into place only at the end; an object
  store finishes the upload only at the end of the stream.
- A stream that ends early, or sends more than `--size` says, stops with
  `SIZE_CONFLICT` (exit 8) and replaces nothing. Give `--size` whenever the
  sender could be cut off.
- Content holding a value komando hid (`[hidden]`, `[credential:NAME]`) is
  refused: a masked copy would destroy the real value.
- `-r` and several servers do not go with `-` (`USAGE`). A stream from a
  server reads as the SSH user; read a root-only file with
  `exec --read-only --sudo -- cat FILE`.
- `--dry-run` says what would happen and reads nothing; it answers on
  stdout, as every dry run does.
- For an AI agent a stream keeps what a copy to a file keeps, before a
  byte is written: text with secret values as `[hidden]`, a binary file
  holding a vault value, a secret or personal data komando hides refused
  (`SENSITIVE_FILE`), and anything over 16 MiB refused (`FILE_TOO_LARGE`),
  as bytes on stdout cannot be taken back.

### Copy between two servers or entries

With `TARGET:PATH` on both sides, `copy` goes from one server or
[storage](storage.md) entry to another: server to server, storage to
storage, or one of each.

```bash
komando copy web1:/var/backups/db.sql.gz web2:/var/backups/
komando copy -r web1:/var/www/site backups:sites/
komando copy backups:2026/db.sql.gz dr-backups:2026/
```

- The data streams through your computer, from the source straight into
  the destination, and is never saved on its disk. The servers do not
  need to reach each other.
- Each side is one server or one entry (no `@group`).
- The file at the destination is replaced, as an upload replaces it
  (`replaced: true`); a new file on a server gets the source's mode.
- A single file reports its `sha256`; the result names the `source` too.
- A protected destination asks once. The audit log has one record for the
  whole copy: source, destination, size and `sha256`.
- An AI agent copies a file that is a secret by name (`.env`, a private
  key) only after the user allows it (`--reveal`). The copy is also read on
  its way: a file holding anything komando hides from an AI agent (a vault
  value, a secret by its shape, or personal data where the source hides it)
  stops with `SENSITIVE_FILE` before it is put in place. In a folder copy
  that file is listed in `errors` and the rest are copied.
- `--progress` writes the same lines as any copy.

TODO(cut): whether `copy` to a WinRM, Telnet or serial target works waits
on O-43.

### Go on with a copy that was cut off (--continue)

`--continue` goes on with one big file where an earlier copy stopped:

```bash
komando copy web1:/var/backups/db.sql.gz ./ --continue
komando copy ./db.sql.gz web1:/var/backups/db.sql.gz --continue
komando copy web1:/var/backups/db.sql.gz web2:/var/backups/ --continue
```

- When the destination has part of the file, komando checks that part
  against the same part of the source (sha256), sends only the rest and
  then checks the whole file against the source. The result says how much
  was there already (`continued_from_bytes`) and the file's `sha256`.
- With `--continue` the file is written in place, not under a temporary
  name, so a copy that stops again can be continued again. It never
  writes through a symbolic link (`USAGE`): name the file itself.
- A destination that is longer than the source, or differs from it,
  stops with `RESUME_CONFLICT` (exit 8) and is not touched. Copy it again
  without `--continue` (a download needs `--overwrite` to replace it).
- A whole file is only checked; nothing is sent.
- S3, Google Cloud Storage, Azure Blob and WebDAV store a file whole and
  cannot add to one: `RESUME_UNSUPPORTED` (exit 2). SFTP, FTP, FTPS and
  SMB storage can.
- `--continue` takes one file, never `-r` (use `--sync`, which sends only
  what is missing), `--sudo` or `--overwrite`, and needs a Linux or other
  Unix server.
- An AI agent gets a text file of up to 16 MiB with secret values shown as
  `[hidden]`, which cannot be continued (`RESUME_UNSUPPORTED`). A larger
  file that holds a value from komando's vault stops with
  `SENSITIVE_FILE`, and the part that run added is removed again.

### Copy folders

Folders (`-r`) follow one rule, so running the same copy twice gives the same
result:

| Command | Result |
|---|---|
| `copy -r site web1:/var/www/site` | `/var/www/site` is the copy; run it again and it is updated in place (never `site/site`) |
| `copy -r site/ web1:/var/www/html` | the *contents* of `site` go into `html` |
| `copy -r site web1:/var/www/html` (html exists) | `/var/www/html/site` |

A copy to [storage](storage.md) follows the same rule: without a
destination folder, `copy -r ./site backups:` puts the folder under
`site/`, and a destination ending in `/` counts as an existing folder.

A folder given as a symbolic link (`./current -> releases/42`) is copied as
the folder it names, as `scp -r` does. Symbolic links inside a folder are not
copied; they are listed as `skipped`. When some files in a folder cannot be
read, the rest are still copied; the result lists the failures under
`errors` and komando exits 5.

### What a copy replaces

- A copy to this computer never replaces a file that is already there.
  One file stops with `FILE_EXISTS` (exit 8); a folder (`-r`), from a
  server or from storage, keeps those files, copies the rest and says how
  many it kept (`kept`). Add `--overwrite` when you mean to replace them.
- A copy to a server replaces the file there and says so (`replaced:
  true`).
- Every file, both ways, is written under a temporary name first and moved
  into place when complete, so a broken connection never leaves half a
  file (except with `--continue`, above, which writes in place on
  purpose). (Moving a new file into place on a server makes the SSH user
  its owner; use `--sudo` for a single file whose owner must stay.)

### Big files and Ctrl-C

- At a terminal, a file of 8 MiB or more going to or from one server shows
  its progress on stderr (`app.tar.gz: 120.0 of 512.0 MB`). Nothing is
  shown when stderr is not a terminal, or for an AI agent; stdout never
  gets it.
- A program that draws its own progress bar (an app, a script, an AI
  agent) adds `--progress` to `copy` with `-o json`. The error output
  (stderr) then gets one JSON object per line, at most about four a
  second, and a last one when the command ends; the result on stdout stays
  as it is. A total is `null` while komando cannot know it (a folder from a
  server is read as it is copied). Lines on stderr that are not JSON (a
  warning) are not progress: skip them. Without `-o json`, `--progress`
  changes nothing.

  ```
  {"event":"progress","file":"site/index.html","bytes_done":1048576,"bytes_total":4194304,"files_done":3,"files_total":12}
  {"event":"done","file":"site/app.js","bytes_done":4194304,"bytes_total":4194304,"files_done":12,"files_total":12,"ok":true}
  ```

  `file` is the file being copied (inside a folder, its path in the
  folder); the counts cover every server of the run. The lines hold names
  and counts only, never what is in a file.
- Ctrl-C stops a copy within a moment. The file being copied is not left
  behind, files already copied stay, and komando exits 1 with `CANCELLED`.
  Run the same command again to finish: with `--sync` it sends only what is
  still missing. Closing the terminal stops it the same way. A second
  Ctrl-C ends komando at once, and still removes the half-copied file (and
  any other temporary file or sign-in browser profile this run made).
- For a copy that may take longer than a few minutes, or over a shaky
  link, run it on the server: `komando host ssh exec` keeps a long run in a
  session, and `--attach ID` comes back to it ([Long
  runs](system.md#long-runs)).

## Keep a folder in step (sync)

`copy --sync` copies a folder one way and sends only what is new or
changed, so the second run is quick. One side is a folder on this
computer. The other side is servers (many at once) or a
[storage](storage.md) entry:

```bash
komando copy ./site @web:/var/www/site --sync --exclude .git --dry-run   # every file it would touch
komando copy ./site @web:/var/www/site --sync --exclude .git
komando copy ./site web1:/var/www/site --sync --delete --dry-run         # also remove what ./site no longer has
komando copy web1:/var/log/app ./logs/web1 --sync                        # from a server to here
komando copy ./backups backups:2026/ --sync --exclude '*.tmp'            # into a storage entry
komando copy backups:2026/ ./restore --sync                              # from storage to here
```

- A file counts as changed when its size or mode differs, or when it is
  newer in the source. Modes and modification times are copied too.
- Each file is written under a temporary name and moved into place.
- A destination folder that does not exist is created (`--dry-run` says
  so).
- `--exclude` skips names or paths (shell globs, repeatable).
- `--delete` removes files for good: at your terminal komando asks you to
  type the destination (`web1:/var/www/site`); an AI agent or a script adds
  `--allow-dangerous` after a person agrees.
- A source that does not exist is an error (`PATH_NOT_FOUND`, exit 3), and
  `--delete` never runs from an empty source, so a typo cannot wipe the
  destination.
- `--delete` also stops before it empties a folder that the source lists
  as empty while the destination still has files in it
  (`EMPTY_FOLDER_CONFIRM_REQUIRED`, exit 6): a listing cut short, for
  example by a dropped FTP connection, looks just like that. The error
  lists each folder and how many files would go (`error.details.folders`
  in JSON).
  - At your terminal, komando asks you to type the folder.
  - An AI agent adds `--allow-dangerous` after a person agrees; komando
    then names the folders in its window.
  - A script names each folder it empties on purpose:
    `--emptied old-assets` (repeatable). `--allow-dangerous` alone does
    not do here: an unattended run is the one that would lose files with
    nobody watching. A folder name that matches nothing is an error.
  - The other way: remove the folder on the destination first
    (`komando host ssh exec web1 -- rm -r /var/www/site/old-assets`, which
    its own rule stops, or `komando storage s3 object delete` for
    storage), then sync.
- Symbolic links inside the folder are not copied; they are listed as
  `skipped`. A source folder given as a link is synced as the folder it
  names.
- Ctrl-C stops it within a moment; files already copied stay, and the
  next run sends the rest.
- `--sudo` writes on the servers as root, for a folder the SSH user cannot
  write (`komando copy ./conf.d web1:/etc/nginx/conf.d --sync --sudo`): each
  file goes in staged in the SSH user's `/tmp` (only they can read it),
  checked by root and installed with the source file's mode, keeping the
  owner of a file that is there. A folder another user may change stops it
  (`SHARED_FOLDER_CONFLICT`). The folder must be readable by the SSH user,
  and `--sudo` is for a folder going to servers (to read a file only root
  can read, copy it from the server with `--sudo`).

For a single file, `komando copy` without `--sync` is enough.

## Limits

- `exec` returns the tool's own text, cut at a size limit
  (`stdout_truncated`); it has no fixed shape for a folder listing or a
  file's details.
- `rm` and `chmod` take paths as the server's shell reads them.
- `--sudo` in copies works for single files and for a folder with `--sync`.
  For a root-owned folder, copy it to a place you own and move it with
  `komando host ssh exec web1 --sudo -- cp -r /tmp/site/. /var/www/site/`.
- Symbolic links inside a folder are not copied by `copy -r` or `--sync`.
- `--sudo` writes are refused into a folder another server user can change
  (by owner, group, mode or access list: `SHARED_FOLDER_CONFLICT`); write
  such a file as that user.
- Backups of an edit are the ones you make: they stay next to the file and
  add up, one per `cp`.
- On Windows servers, the file tools are PowerShell through `exec`, and
  `copy` moves single files ([Windows servers](windows.md)).
- Masking of secrets for AI agents is a best effort.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `FILE_EXISTS` | a copy to this computer would replace a file | add `--overwrite` when you mean it |
| `PATH_NOT_FOUND` | the source of a copy does not exist | check the path |
| `PERMISSION_DENIED` | the login user may not read or write the file | add `--sudo` |
| `SHARED_FOLDER_CONFLICT` | `--sudo` into a folder another server user can change | write the file as that user, without `--sudo` |
| `POLICY_BLOCKED` | `rm`, `rm -r` or `copy --sync --delete` from an AI agent or a script without `--allow-dangerous` | check with `--dry-run`, ask a person, then add `--allow-dangerous` |
| `READ_ONLY_VIOLATION` | `--read-only` does not know that the command only reads | check the command, then run it without `--read-only` |
| `EMPTY_FOLDER_CONFIRM_REQUIRED` | `copy --sync --delete` would empty a folder that the source lists as empty | check the source; a script adds `--emptied FOLDER`, an AI agent asks a person and adds `--allow-dangerous` |
| `CANCELLED` | Ctrl-C stopped a copy | run the same command again to finish |
| `SIZE_CONFLICT` | an upload from stdin sent another number of bytes than `--size` | send the whole file again; nothing was replaced |
| `RESUME_CONFLICT` | `--continue` found a destination longer than the source, or one that differs from it, before the copy or by its sum after it | copy it again without `--continue` |
| `FILE_CHANGED` | the file changed while `--continue` copied it | run the same command again |
| `RESUME_UNSUPPORTED` | `--continue` to S3, Google Cloud Storage, Azure Blob or WebDAV, which cannot add to a file | copy it again without `--continue` |
| `SENSITIVE_FILE` | a copy for an AI agent holds a value komando hides | a person copies it in a terminal |

## Reference

Flags of `komando copy`:

| Flag | What it does |
|------|--------------|
| `-r`, `--recursive` | Include everything under a folder. |
| `--overwrite` | Replace what is there. |
| `--sync` | Compare by size, mode and time, and copy only what changed. |
| `--delete` | With `--sync`: remove what the source does not have. Dangerous. |
| `--exclude GLOB` | Skip names or paths; repeatable. |
| `--emptied FOLDER` | With `--sync --delete`: allow this folder to be emptied; repeatable. |
| `-s`, `--sudo` | Write on the servers as root. Not into a folder another server user can change (`SHARED_FOLDER_CONFLICT`). |
| `--progress` | With `-o json`: progress as one JSON object per line on stderr. |
| `--dry-run` | Show the per-file plan and the stop the real run would hit; change nothing. |
