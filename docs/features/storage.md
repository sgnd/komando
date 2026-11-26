# Storage: buckets and file servers

Browse, download, upload and share files in S3-compatible buckets, Google
Cloud Storage, Azure Blob Storage, on WebDAV, FTPS, SFTP and FTP servers, and
on Windows (SMB) shares, all with the same commands. [All docs](README.md)

## Add a bucket

```bash
komando storage add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --ask-password
komando test backups                          # can komando reach it and log in?
```

Typed alone, `komando storage add` asks for each part step by step.

For S3, the user part of the URL is the access key ID. The secret access
key goes in the vault, like a password: `--ask-password` asks for it
(hidden), or store it first and point at it:

```bash
komando secret set backups-secret
komando storage add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --password-ref credential:backups-secret
```

The safest setup is an access key that can only do what komando needs
(read-only for reports, one bucket only). The service then enforces it.

The folder in the URL is where the conn starts. Keys are relative to it and
cannot leave it (`../` is refused, also in a dry run).

At a terminal, a command with the storage or the file left out asks for
it, with a list of your storages. Typed alone, `komando storage list`
asks which storage. An AI agent or a script gets `USAGE` (exit 2) with a
full example in the hint.

| Kind | URL example | Notes |
|------|-------------|-------|
| S3 and compatible | `s3://ACCESS_KEY_ID@my-bucket/backups?endpoint=https://minio.internal:9000&region=us-east-1` | AWS S3, MinIO, Cloudflare R2, Wasabi, DigitalOcean Spaces, Backblaze B2, Garage. Leave out `endpoint` for AWS. If the endpoint's DNS is wrong or missing, add `&resolve=IP` (or `IP:PORT`): komando connects to that address and still checks the certificate against the endpoint's name. |
| Google Cloud Storage | `gs://my-bucket/backups` | Logs in like gcloud (application default credentials), or with a service account key in `--password-ref`. See [Google Cloud and Azure](#add-a-google-cloud-or-azure-bucket). |
| Azure Blob Storage | `azblob://ACCOUNT@my-container/backups` | The storage account's key, or a SAS token, in `--password-ref`. |
| WebDAV | `webdavs://alice@cloud.example.com/remote.php/dav/files/alice` | Nextcloud, ownCloud, a NAS, Apache or nginx. Add `?tls=skip-verify` only for a self-signed certificate you trust. `webdav://` (no encryption) is refused without `?insecure=1`. |
| FTPS | `ftps://deploy@files.example.com/public_html` | FTP with TLS. Add `?tls=skip-verify` only for a self-signed certificate you trust. |
| SFTP | `sftp://deploy@files.example.com/uploads` | File access over SSH, for accounts without a shell. The path starts at the server's root (on hosting, often your home folder). |
| SMB (Windows shares) | `smb://alice@fileserver.corp.lan/team/reports?domain=CORP` | A Windows file server, Samba, a NAS or Azure Files. The first part of the path is the share. See [Windows shares](#add-a-windows-share-smb). |
| FTP | `ftp://deploy@files.example.com/www?insecure=1` | No encryption: the password and files travel in clear. Refused without `?insecure=1`. Prefer FTPS or SFTP. |

**A certificate from your own CA** (a company MinIO, or a proxy that
inspects TLS): store the CA and name it in the URL, for S3, Google Cloud
and Azure. komando then trusts that CA as well as the usual ones, and
still checks the certificate fully. Without it, the error is
`STORAGE_TLS` with this hint.

```bash
komando secret set corp-ca < corp-ca.crt
komando storage add minio 's3://AKIAEXAMPLE@media?endpoint=https://minio.corp.lan:9000&ca=credential:corp-ca' --ask-password
```

### AWS logins (SSO, roles, temporary keys)

Instead of a stored key, a conn can use a profile from `~/.aws/config`
(`default` uses the usual AWS login chain). komando reads the profile
itself, with no aws CLI needed, and fetches fresh keys each time, so SSO,
assumed roles and temporary keys work as you set them up:

```bash
komando storage add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod
```

- `AWS_LOGIN_REQUIRED`: the SSO login has expired. A person runs
  `komando login aws --profile prod` once. It opens the sign-in page and
  saves the login where the aws CLI keeps it, so both share it.
- `AWS_PROFILE_NOT_FOUND`: the profile is not in `~/.aws/config`.

Amazon ECR registries use AWS logins the same way (see
[Container registries](registry.md)).

## Browse and read files

```bash
komando storage list backups                  # one level (up to 1000 entries; -n/--limit)
```

```text
SIZE      MODIFIED              KEY
DIR       -                     2026/
48.2 MiB  2026-11-12 02:00 UTC  app.sql.gz
```

```bash
komando storage list backups 2026/ --recursive        # everything under 2026/
komando storage cat backups logs/app.log --tail 50    # read text without downloading it
komando storage cat backups config/app.env --head 20
```

- `storage list backups 2026` and `storage list backups 2026/` both list
  what is in the folder 2026, on every kind of storage. On a bucket, a
  prefix that names no folder (`storage list backups logs/app-2026-11`)
  lists the keys that start with it.
- Listing a folder that is empty or does not exist is `FOLDER_NOT_FOUND`
  (exit 3), on every kind of storage. The empty "folder marker" objects
  that S3 consoles create are left out of listings and downloads.
- `cat` shows text only; binary is `NOT_TEXT` (exit 2), so download it
  instead. Use `--head` or `--tail` (one of them, 1 or more lines). It reads
  at most `--max-bytes` (1 MiB by default) and says on stderr when it cut
  the file.

## Download and upload

```bash
komando download backups 2026/app.sql.gz                    # into the current folder
komando upload backups ./app.sql.gz 2026/app.sql.gz
```

```text
backups: app.sql.gz (48.2 MiB)
uploaded ./app.sql.gz -> 2026/app.sql.gz (48.2 MiB), replaced the old object
```

Typed alone, `komando download` asks which server or storage, then the
path.

```bash
komando download backups reports/q3.pdf --to ~/Downloads/   # into a folder
komando download backups logs/app.log --to - | less         # to stdout
komando download backups reports -r --to ./reports          # a whole folder
komando upload backups ./a.pdf reports/                     # stores reports/a.pdf
komando upload backups ./reports reports -r                 # a whole folder
```

`komando storage download` and `komando storage upload` do the same for
storage conns only, and `komando cp` writes the same copy as
`cp ./a.pdf backups:reports/`. A folder upload (`-r`) sends only new and
changed files, like `komando sync`.

- Downloads never overwrite a file on your computer unless you add
  `--overwrite`. The file is readable only by you. `--to` takes a file name,
  a folder (one that exists, or a name ending in `/`: the file keeps its
  name inside), or `-` to stream it to stdout (any `-o`: komando's own
  answer then goes to stderr). A folder download keeps files that are
  already there.
- `komando storage upload CONN - KEY` (or `upload CONN - KEY`) streams
  stdin into KEY; `--size N` makes a stream of another length fail with
  `SIZE_CONFLICT` and replace nothing. See
  [Stream a file through stdout or stdin](files.md#stream-a-file-through-stdout-or-stdin).
- Uploads replace an object with the same key; the result says
  `"replaced": true`. A key ending in `/` is a folder.
- On a protected conn, `upload` asks a person at a terminal first; an AI
  agent or a script adds `--yes` after a person agrees.
- `--dry-run` sends nothing, but checks: `upload` shows the key and
  whether it would replace an object, `download` where the file would go
  and its size.
- `--continue` goes on with one file that was cut off. A download keeps
  the part already on your computer when it matches the object (sha256),
  fetches the rest and checks the whole file. An upload can go on only on
  an SFTP, FTP, FTPS or SMB conn; S3, Google Cloud Storage, Azure Blob
  and WebDAV store a file whole and cannot add to one, so a cut file there
  stops with `RESUME_UNSUPPORTED` (upload it again without
  `--continue`). Storage
  cannot work out the sum of part of an object, so komando reads the part
  already copied once more to check it.
- `komando cp` also copies between two storage conns, or between a conn
  and a server: `komando cp backups:2026/db.sql.gz dr-backups:2026/`. The
  data streams through your computer and is never saved on its disk.
- To keep a folder in step and send only new and changed files, use
  `komando sync` (see [Files](files.md)):

```bash
komando sync ./site backups:site --exclude '*.tmp'
komando sync backups:2026/ ./restore
```

## Share a file with a temporary link

```bash
komando storage link backups 2026/app.sql.gz --expires 24h   # default 1h, at most 7d
```

```text
https://my-bucket.s3.eu-west-1.amazonaws.com/db/2026/app.sql.gz?X-Amz-Algorithm=AWS4-HMAC-SHA256&...
```

```bash
komando storage link media site/report.pdf                   # Google Cloud and Azure too
komando storage link backups 2026/app.sql.gz --endpoint https://files.example.com
```

- For an AI agent, `storage link` needs a person's yes (`--reveal`): a
  link is the file as it is, past the hiding that `storage cat` and
  `storage download` apply. Without it the command stops with
  `SENSITIVE_FILE`; for a file that is a secret by its name (`.env`, a
  key) it always does.
- The link works for anyone who has it until it expires. Share it like a
  password. It is not written to the audit history.
- On a protected conn, `link` asks a person at a terminal first; an AI
  agent or a script adds `--yes` after a person agrees.
- The link uses the address in the conn URL. When komando reaches the
  storage through `--via`, the result warns that people outside that network
  cannot open it. Use `--endpoint` to sign it for the public address.
- The download keeps the file's name, also with non-ASCII letters.
- A conn that logs in with an AWS profile (SSO, an assumed role) signs the
  link with temporary keys, so the link stops working when they expire,
  often after an hour, whatever `--expires` says. The result warns about
  it. For a link that lasts, give the conn an access key of its own.

## Make folders, move and rename files

```bash
komando storage mkdir backups reports/2026 --dry-run       # check first
komando storage mkdir backups reports/2026                 # missing parents too
komando storage mv backups db/old.sql.gz archive/          # into a folder, same name
komando storage mv backups reports/draft.pdf reports/q3.pdf --overwrite
komando storage chmod backups 0640 config/app.yml          # SFTP only
```

```text
would move db/old.sql.gz -> archive/old.sql.gz (48.1 MiB, by a copy that is checked before the original is deleted; replaces a file: no)
```

- `mkdir` makes the folder and any missing folders above it. A folder that
  is already there is fine. S3, Google Cloud and Azure have no real
  folders: `mkdir` stores an empty folder marker (`reports/2026/`), as
  their web consoles do, so `storage list` shows the empty folder.
- `mv` moves one file or folder inside one conn. A `DST` ending in `/` is
  a folder: the file moves into it and keeps its name. A file already at
  `DST` stops the move (`FILE_EXISTS`) unless you add `--overwrite`; a
  folder at `DST` is never replaced.
- On a file server (SFTP, FTP, FTPS, WebDAV, SMB) `mv` is one rename on
  the server, and it moves folders too. Where the server cannot rename
  over a file, `--overwrite` first moves the old file aside
  (`.komando-old-NAME`) and puts it back if the rename fails, so a failed
  move never loses it.
- A path is written plainly: `.` or `//` in it stops with `USAGE`.
- S3, Google Cloud and Azure cannot rename. There `mv` copies the object
  on the server, checks that the copy has the same size and checksum, and
  only then deletes the original (`method: copy_then_delete` in the
  result). If the check fails, the original stays and the copy is
  deleted (`MOVE_FAILED`). It moves one object at a time, not a folder
  (`STORAGE_UNSUPPORTED`). In a bucket that keeps old versions, the
  original's old versions stay.
- `chmod` sets the Unix mode of a file or folder, in digits (`0644`,
  `640`, `2775`), and the result says the old mode too. Only SFTP servers
  have modes; on any other kind it stops with `STORAGE_UNSUPPORTED` before
  komando contacts the storage.
- All three are changes, like `upload`: try them with `--dry-run`, a
  protected conn asks a person first (an AI agent or a script adds `--yes`
  after a person agrees), and each run is in `komando audit`.

## Delete files

```bash
komando storage rm backups --prefix daily/ --older-than 30d --dry-run   # list old backups
komando storage rm backups --prefix daily/ --older-than 30d             # delete them
komando storage rm backups 2026/old.sql.gz                              # exact keys
```

```text
SIZE      MODIFIED              KEY
48.1 MiB  2026-10-01 02:00 UTC  daily/app-2026-10-01.sql.gz
48.0 MiB  2026-10-02 02:00 UTC  daily/app-2026-10-02.sql.gz
would delete 2 objects (96.1 MiB)
```

Deleted objects are gone (unless the bucket keeps old versions, see
below). At your terminal komando asks you first: you type the key's name,
or for several objects how many. With `--prefix` it first lists what
would go (the first 20 objects, the count and the size). Anything else
cancels and deletes nothing. An AI agent or a script adds
`--allow-dangerous` (and `--yes` on a protected conn) after a person
agrees. See [Safety](safety.md#what-needs-a-yes).

- Without `--prefix`, `rm` takes exact keys only, no patterns.
- `--prefix` removes everything under a folder (`/` for the whole conn);
  `--older-than` (`30d`, `12h`, `90m`) keeps the newer ones.
- `--prefix` refuses to remove more than `--max-remove` objects (1000 by
  default; `TOO_MANY`). Check the dry-run list, and raise the cap if that
  is what you mean.
- `--dry-run` lists the objects one per line with size and date.

### Old versions (S3 versioning)

A bucket with versioning keeps every overwritten or deleted object, and
`rm` leaves those behind (S3 adds a delete marker). See them, and remove a
key with every version:

```bash
komando storage list backups app/ --all-versions               # every version and delete marker
komando storage rm backups app/config.json --all-versions --dry-run
komando storage rm backups app/config.json --all-versions      # really gone
```

`--all-versions` takes exact keys and works on S3 and S3-compatible
stores; it asks first like any `rm`.

## Add a Google Cloud or Azure bucket

```bash
komando storage add media gs://my-bucket/site                     # logs in like gcloud
komando secret set media-sa < key.json                            # or a service account key
komando conn edit media --password-ref credential:media-sa

komando secret set files-key                                      # key1 from the portal, or a SAS token
komando storage add files azblob://mystorageacct@uploads/2026 --password-ref credential:files-key
```

- Google Cloud Storage without `--password-ref` uses the login gcloud
  keeps (`gcloud auth application-default login`), the
  `GOOGLE_APPLICATION_CREDENTIALS` file, or the server's own account on
  Google Cloud. `STORAGE_AUTH` says when there is none. A service account
  key is the JSON file from the console.
- Azure Blob Storage takes the storage account's key (`key1` or `key2`)
  or a SAS token (the part after `?`, starting with `sv=`). A SAS token that
  can only read and list keeps komando to reading.
- Links (`storage link`) need a key that can sign them: a service
  account key for Google Cloud, the account key for Azure. gcloud's own login
  and a SAS token cannot.
- An emulator or another cloud takes `?endpoint=URL`, for example
  `azblob://devstoreaccount1@media?endpoint=http://127.0.0.1:10000/devstoreaccount1`
  for Azurite. An `http://` endpoint on another computer sends the files
  (and for S3 the AWS session token) unencrypted, so it is refused
  (`INSECURE_PROTOCOL`) unless the conn goes `--via` an SSH server or the
  URL adds `&insecure=1`. One on this computer (localhost, 127.0.0.1) is fine.
- gcloud's own login goes only to Google (`https://…googleapis.com`), never
  to an emulator or another endpoint. A service account key needs an
  `https://` endpoint: over `http://` its token would travel unencrypted,
  so komando refuses it (`INSECURE_PROTOCOL`).
  A SAS token is refused over `http://` for the same reason; the Azure
  account key only signs, so an emulator like Azurite works with it.

## Add a file server (WebDAV, FTPS, SFTP, FTP)

Web hosting and older systems often give you only file access. Add the
server as a conn:

```bash
komando secret set hosting-pass
komando storage add site 'ftps://deploy@files.example.com/public_html' --password-ref credential:hosting-pass
komando storage list site --recursive
komando upload site ./index.html index.html
komando download site logs/error.log
```

- Uploads go to a temporary name first and are renamed into place, so a
  failed upload never leaves half a file under the real name. Missing
  folders are created.
- SFTP checks the server's identity like any SSH server: it is remembered
  the first time, and a change is refused with `HOSTKEY_MISMATCH`. SFTP can
  use your SSH keys as well as a password.
- WebDAV makes missing folders as it uploads. For Nextcloud and ownCloud,
  the path is `remote.php/dav/files/USER`, and an app password (Settings,
  Security) is safer than your own.
- A WebDAV upload goes to a temporary name (`.komando-upload-…`) and is
  moved into place with WebDAV `MOVE` only when it arrived whole, so a cut
  upload never replaces the file there. The server must allow `MOVE` (nginx:
  `dav_methods PUT DELETE MKCOL COPY MOVE;`), and a proxy in front must keep
  the URL's scheme and address. If the server removes the old file and then fails
  the move, the new content stays under its temporary name
  (`UPLOAD_NOT_RENAMED` names it).

## Add a Windows share (SMB)

A shared folder on a Windows server, Samba, a NAS or Azure Files (the
`\\fileserver\team` you open in Explorer) is a conn too:

```bash
komando secret set team-share
komando storage add team 'smb://alice@fileserver.corp.lan/team/reports?domain=CORP' --password-ref credential:team-share
komando storage list team
komando upload team ./q3.pdf 2026/q3.pdf
```

- **The URL:** `smb://USER@HOST/SHARE/FOLDER`. The first part of the path
  is the share's name (`team`); the rest is the folder the conn starts in.
  `cifs://` means the same.
- **A domain account** (`CORP\alice`): add `?domain=CORP`. The usual SMB
  form `smb://CORP;alice@host/share` works too; use one of them, not both.
  A local account on the server needs no domain.
- **The password** goes in the vault (`--password-ref`), never in the URL.
  komando logs in with NTLMv2.
- **Safe on the wire:** komando speaks SMB 2 and 3 and signs every message,
  so nobody on the way can change what the server sends. The traffic is
  encrypted when the server asks for it (SMB 3 encryption, which Azure Files
  turns on by default; on Windows, "Encrypt data access" on the share; on
  Samba, `smb encrypt = required`). Without it, `komando doctor` warns about
  conns that cross the network.
- **Port 445 is often blocked** across the internet. Reach the server
  `--via` an SSH server in its network, or through a VPN, like any other
  conn.
- **Azure Files:** `smb://STORAGEACCOUNT@STORAGEACCOUNT.file.core.windows.net/SHARE`
  with the storage account's key as the password.
- Uploads go to a temporary name first. An existing file is moved aside,
  the new one renamed into place, and the old one removed only then; if the
  rename fails, the old file comes back.

## Check, change, rename or remove a storage

A storage is a conn, so the conn commands work on it:

```bash
komando list kind:storage                     # your storages
komando test backups                          # can komando reach it and log in?
komando conn show backups                     # its URL, way in and password reference
komando conn edit backups --url 's3://AKIAEXAMPLE@my-bucket/db?region=eu-central-1'
komando conn edit backups --via web1          # reach it through a bastion or a VPN
komando conn edit backups --protected         # every change then needs a person's yes
komando conn rename backups db-backups
komando conn rm backups                       # komando forgets it; the files stay
```

`--via` works the same as for other conns: through a bastion or a VPN.

## Limits

- Keys cannot leave the conn's folder (`../` is refused).
- `storage mv` stays inside one conn, and on S3, Google Cloud and Azure it
  moves one object at a time; `storage chmod` is for SFTP conns only.
- `storage cat` shows text only, at most `--max-bytes` (1 MiB by default).
- `storage rm` without `--prefix` takes exact keys, no patterns; with
  `--prefix` it stops above `--max-remove` objects (1000 by default) and
  above a million objects under the prefix.
- **Buckets that keep old versions** (S3 versioning, Google Cloud object
  versioning or soft delete, Azure blob versioning or soft delete): `rm`
  removes the current object only. The provider keeps the old versions (S3
  adds a delete marker), they still cost storage, and they can be brought
  back in the provider's console or CLI. On S3, `--all-versions` lists and
  removes them (see [Old versions](#old-versions-s3-versioning)); on Google
  Cloud and Azure komando does not, and a lifecycle rule on the bucket does.
- File servers (WebDAV, FTPS, SFTP, FTP, SMB) have no temporary links:
  `storage link` is for S3, Google Cloud and Azure. gcloud's own login and
  an Azure SAS token cannot sign a link either.
- A link signed with temporary AWS keys stops working when they expire.
- SMB: Kerberos tickets are not used, and a guest login cannot sign, so a
  user name is required.
- FTP and FTPS: a listing can end early and still look complete. On plain
  FTP, and on FTPS when the connection closes after the encryption is set
  up, the only sign is the server's answer at the end, and a server that
  says "226 Transfer complete" anyway is believed. komando stops when the
  connection closes before the encryption is set up, and `sync --delete`
  stops before it empties a folder the source lists as empty
  (`EMPTY_FOLDER_CONFIRM_REQUIRED`, see [files.md](files.md)). A folder
  that only lists some of its files is not caught: run `sync --delete`
  from an FTP or FTPS source with `--dry-run` first and read what it
  would delete.

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `STORAGE_AUTH` | the storage refused the login, or there is none (Google Cloud) | check the key with `komando conn show backups`, or log in with gcloud |
| `STORAGE_CONNECT` | komando could not reach the bucket or file server | `komando test backups`; reach it `--via` a server or a VPN |
| `STORAGE_TLS` | the certificate does not check out | name your CA with `?ca=credential:NAME` |
| `STORAGE_ERROR` | for example, another program has the file open | close it there and run it again |
| `BUCKET_NOT_FOUND` | the bucket (or SMB share) does not exist | check the name in the conn URL |
| `FOLDER_NOT_FOUND` | the folder is empty or does not exist (exit 3) | check it with `komando storage list backups` |
| `OBJECT_NOT_FOUND` | no such key | `komando storage list backups PREFIX` shows the keys |
| `NOT_TEXT` | `storage cat` of a binary file (exit 2) | download it instead |
| `FILE_EXISTS` | the download would overwrite a file on this computer | pick another `--to`, or add `--overwrite` |
| `TOO_MANY` | more objects match than `--max-remove` | narrow `--prefix` or `--older-than`, or raise `--max-remove` after checking the list |
| `INSECURE_PROTOCOL` | the URL sends the login or the files unencrypted across the network | use the TLS form (`webdavs://`, `ftps://`, `https://`), `--via`, or add `?insecure=1` |
| `AWS_LOGIN_REQUIRED`, `AWS_PROFILE_NOT_FOUND` | the AWS SSO login expired, or the profile is missing | a person runs `komando login aws --profile prod`; or fix `aws_profile` |
| `HOSTKEY_MISMATCH` | an SFTP server's identity changed | do not change anything; report it, it may be an attack |
| `POLICY_BLOCKED` | `rm` without `--allow-dangerous` (exit 6) | run it at a terminal, or add the flag after a person agrees |

Every code is in [Error codes](error-codes.md).
