# Storage: buckets and file servers

Browse, download and upload files in S3-compatible buckets and on FTPS, SFTP
and FTP servers, with the same commands. [All features](README.md)

`komando storage` works with S3 and every S3-compatible service (MinIO,
Cloudflare R2, Wasabi, DigitalOcean Spaces, Backblaze B2, Garage). Add the
bucket as a conn; the folder in the URL limits the conn to that folder.

```bash
komando secret set backups-secret               # the secret access key
komando conn add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --password-ref secret:backups-secret

komando storage ls backups                      # one level; --recursive for everything
komando download backups 2026/app.sql.gz            # into the current folder
komando upload backups ./app.sql.gz 2026/app.sql.gz
komando storage link backups 2026/app.sql.gz --expires 24h   # temporary download link
komando storage rm backups 2026/old.sql.gz --allow-dangerous
komando storage cat backups logs/app.log --tail 50   # read a text object without downloading it
```

Folders and cleanups:

```bash
komando upload backups ./reports reports -r          # a folder: new and changed files
komando download backups reports -r --to ./reports   # a prefix: files already here stay
komando sync ./site backups:site --exclude '*.tmp'   # keep a folder in step (see Files)
komando storage rm backups --prefix daily/ --older-than 30d --dry-run   # old backups, listed
komando storage rm backups --prefix daily/ --older-than 30d --allow-dangerous
```

`storage rm --prefix` refuses to remove more than `--limit` objects
(default 1000); check the dry-run list and raise it if that is what you mean.

- Downloads never overwrite a file unless `--overwrite`; the file is
  readable only by you. `--to` takes a file name, a folder (one that exists,
  or a name ending in `/`: the file keeps its name inside), or `-` for
  stdout (`-o text` only). `storage download` takes the same flags as
  `komando download`, including `-r` for a folder.
- A key ending in `/` is a folder: `upload backups ./a.pdf reports/` stores
  `reports/a.pdf`.
- `upload` replaces an object with the same key (the result says
  `"replaced": true`). `rm` takes exact keys only, no folders or patterns,
  and needs `--allow-dangerous` because deleted objects are gone.
- A protected conn needs `--yes` for `upload`, `rm` and `link`. `--dry-run`
  sends no change but checks: `upload` says the key and whether it would
  replace an object, `download` where the file would go and its size, `rm`
  lists the objects one per line with size and date.
- Keys cannot leave the conn's folder (`../` is refused, also in a dry run).
- `ls` of a folder that has nothing in it, or does not exist, is
  `FOLDER_NOT_FOUND` (exit 3) on every kind of storage. Empty "folder
  marker" objects that S3 consoles create are left out of listings and
  downloads.
- `cat` shows text only (binary is `NOT_TEXT`, exit 2: download it).
  `--head` or `--tail` (one of them, 1 or more lines); a cut at `--max-bytes`
  is said on stderr.
- A link names the address in the conn URL: when komando reaches the
  storage through `--via`, the result warns that people outside that network
  cannot open it. The download keeps its name, also with non-ASCII letters.
- A link works for anyone who has it until it expires. Share it like a
  password. It is not written to the history.
- Safest setup: give komando an access key that can only do what you need
  (read-only for reports, one bucket only). The service then enforces it.

## AWS logins (SSO, roles, temporary keys)

Instead of a stored key, a conn can use an AWS CLI profile. komando asks
`aws configure export-credentials` for the profile's current keys each
time, so SSO and assumed roles work as you set them up:

```bash
komando conn add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod
```

When an SSO login has expired, the answer is `AWS_LOGIN_REQUIRED`: a person
runs `aws sso login --profile prod` once. Amazon ECR registries work the same
way (see Registries).

## File servers (FTPS, SFTP, FTP)

Web hosting and older systems often give you only file access. Add the
server as a conn; the folder in the URL is where komando starts, and keys
cannot leave it.

| Kind | URL example | Notes |
|------|-------------|-------|
| FTPS | `ftps://deploy@files.example.com/public_html` | FTP with TLS. Add `?tls=skip-verify` only for a self-signed certificate you trust. |
| SFTP | `sftp://deploy@files.example.com/uploads` | File access over SSH, for accounts without a shell. The path is from the server's root (often your home folder on hosting). |
| FTP  | `ftp://deploy@files.example.com/www?insecure=1` | No encryption: the password and files travel in clear. komando refuses it without `?insecure=1`. Prefer FTPS or SFTP. |

```bash
komando secret set hosting-pass
komando conn add site 'ftps://deploy@files.example.com/public_html' --password-ref secret:hosting-pass

komando storage ls site --recursive
komando upload site ./index.html index.html
komando download site logs/error.log
komando storage rm site old/index.html --allow-dangerous
```

- An upload goes to a temporary name first and is renamed into place, so a
  failed upload never leaves half a file under the real name. Missing
  folders are created.
- SFTP checks the server's identity like any SSH host (it is remembered the
  first time, and a change is refused with `HOSTKEY_MISMATCH`), and can use
  your SSH keys as well as a password.
- `--via` works the same as for other conns: through a bastion or a VPN.
- File servers have no temporary links: `storage link` is for S3 only.
