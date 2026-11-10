# Storage: buckets and file servers

Browse, download, upload and share files in S3-compatible buckets, Google
Cloud Storage, Azure Blob Storage, on WebDAV, FTPS, SFTP and FTP servers, and
on Windows (SMB) shares, all with the same commands. [All docs](README.md)

## Quick start

```bash
komando secret set backups-secret                    # the secret access key
komando conn add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --password-ref secret:backups-secret
komando storage ls backups                           # one level; --recursive for everything
komando download backups 2026/app.sql.gz             # into the current folder
komando upload backups ./app.sql.gz 2026/app.sql.gz
```

## Supported storage

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

The folder in the URL is where the conn starts. Keys are relative to it and
cannot leave it (`../` is refused, also in a dry run).

## Add a bucket

For S3, the user part of the URL is the access key ID. The secret access
key goes in the vault, like a password:

```bash
komando secret set backups-secret
komando conn add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --password-ref secret:backups-secret
```

The safest setup is an access key that can only do what komando needs
(read-only for reports, one bucket only). The service then enforces it.

### AWS logins (SSO, roles, temporary keys)

Instead of a stored key, a conn can use a profile from `~/.aws/config`
(`default` uses the usual AWS login chain). komando reads the profile
itself, with no aws CLI needed, and fetches fresh keys each time, so SSO,
assumed roles and temporary keys work as you set them up:

```bash
komando conn add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod
```

- `AWS_LOGIN_REQUIRED`: the SSO login has expired. A person runs
  `komando login aws --profile prod` once. It opens the sign-in page and
  saves the login where the aws CLI keeps it, so both share it.
- `AWS_PROFILE_NOT_FOUND`: the profile is not in `~/.aws/config`.

Amazon ECR registries use AWS logins the same way (see
[Container registries](registry.md)).

## Add a Google Cloud or Azure bucket

```bash
komando conn add media gs://my-bucket/site                       # logs in like gcloud
komando secret set media-sa < key.json                            # or a service account key
komando conn edit media --password-ref secret:media-sa

komando secret set files-key                                      # key1 from the portal, or a SAS token
komando conn add files azblob://mystorageacct@uploads/2026 --password-ref secret:files-key
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
  for Azurite.

## Add a file server (WebDAV, FTPS, SFTP, FTP)

Web hosting and older systems often give you only file access. Add the
server as a conn:

```bash
komando secret set hosting-pass
komando conn add site 'ftps://deploy@files.example.com/public_html' --password-ref secret:hosting-pass
komando storage ls site --recursive
komando upload site ./index.html index.html
komando download site logs/error.log
```

- Uploads go to a temporary name first and are renamed into place, so a
  failed upload never leaves half a file under the real name. Missing
  folders are created.
- SFTP checks the server's identity like any SSH host: it is remembered the
  first time, and a change is refused with `HOSTKEY_MISMATCH`. SFTP can use
  your SSH keys as well as a password.
- WebDAV makes missing folders as it uploads. For Nextcloud and ownCloud,
  the path is `remote.php/dav/files/USER`, and an app password (Settings,
  Security) is safer than your own.
- File servers have no temporary links: `storage link` is for S3, Google
  Cloud and Azure.

## Add a Windows share (SMB)

A shared folder on a Windows server, Samba, a NAS or Azure Files (the
`\\fileserver\team` you open in Explorer) is a conn too:

```bash
komando secret set team-share
komando conn add team 'smb://alice@fileserver.corp.lan/team/reports?domain=CORP' --password-ref secret:team-share
komando storage ls team
komando upload team ./q3.pdf 2026/q3.pdf
```

- **The URL:** `smb://USER@HOST/SHARE/FOLDER`. The first part of the path
  is the share's name (`team`); the rest is the folder the conn starts in.
  `cifs://` means the same.
- **A domain account** (`CORP\alice`): add `?domain=CORP`. The usual SMB
  form `smb://CORP;alice@host/share` works too; use one of them, not both.
  A local account on the server needs no domain.
- **The password** goes in the vault (`--password-ref`), never in the URL.
  komando logs in with NTLMv2; Kerberos tickets are not used.
- **Safe on the wire:** komando speaks SMB 2 and 3 and signs every message,
  so nobody on the way can change what the server sends. The traffic is
  encrypted when the server asks for it (SMB 3 encryption, which Azure Files
  turns on by default; on Windows, "Encrypt data access" on the share; on
  Samba, `smb encrypt = required`). Without it, `komando doctor` warns about
  conns that cross the network. A guest login cannot sign, so a user name is
  required.
- **Port 445 is often blocked** across the internet. Reach the server
  `--via` an SSH host in its network, or through a VPN, like any other conn.
- **Azure Files:** `smb://STORAGEACCOUNT@STORAGEACCOUNT.file.core.windows.net/SHARE`
  with the storage account's key as the password.
- Uploads go to a temporary name first. An existing file is moved aside,
  the new one renamed into place, and the old one removed only then; if the
  rename fails, the old file comes back.
- A share that does not exist is `BUCKET_NOT_FOUND`, a wrong user or
  password is `STORAGE_AUTH`, and a file that another program has open says
  so.

## Browse and read files

```bash
komando storage ls backups                            # one level (up to 1000 entries; --limit)
komando storage ls backups 2026/ --recursive          # everything under 2026/
komando storage cat backups logs/app.log --tail 50    # read text without downloading it
komando storage cat backups config/app.env --head 20
```

- `ls` of a folder that is empty or does not exist is `FOLDER_NOT_FOUND`
  (exit 3), on every kind of storage. The empty "folder marker" objects
  that S3 consoles create are left out of listings and downloads.
- `cat` shows text only; binary is `NOT_TEXT` (exit 2), so download it
  instead. Use `--head` or `--tail` (one of them, 1 or more lines). It reads
  at most `--max-bytes` (1 MiB by default) and says on stderr when it cut
  the file.

## Download and upload

```bash
komando download backups 2026/app.sql.gz                    # into the current folder
komando download backups reports/q3.pdf --to ~/Downloads/   # into a folder
komando download backups logs/app.log --to - -o text | less # to stdout
komando download backups reports -r --to ./reports          # a whole folder
komando upload backups ./app.sql.gz 2026/app.sql.gz
komando upload backups ./a.pdf reports/                     # stores reports/a.pdf
komando upload backups ./reports reports -r                 # a whole folder
```

`komando storage download` is the same command with the same flags.
`komando storage upload` sends single files only; for a folder use
`komando upload -r`, which sends only new and changed files, like `komando sync`.

- Downloads never overwrite a file on your computer unless you add
  `--overwrite`. The file is readable only by you. `--to` takes a file name,
  a folder (one that exists, or a name ending in `/`: the file keeps its
  name inside), or `-` for stdout (`-o text` only). A folder download keeps
  files that are already there.
- Uploads replace an object with the same key; the result says
  `"replaced": true`. A key ending in `/` is a folder.
- To keep a folder in step and send only new and changed files, use
  `komando sync` (see [Files](files.md)):

```bash
komando sync ./site backups:site --exclude '*.tmp'
komando sync backups:2026/ ./restore
```

## Share a file with a temporary link

```bash
komando storage link backups 2026/app.sql.gz --expires 24h   # default 1h, at most 168h (7 days)
komando storage link media site/report.pdf                   # Google Cloud and Azure too
komando storage link backups 2026/app.sql.gz --endpoint https://files.example.com
```

- The link works for anyone who has it until it expires. Share it like a
  password. It is not written to the audit history.
- The link uses the address in the conn URL. When komando reaches the
  storage through `--via`, the result warns that people outside that network
  cannot open it. Use `--endpoint` to sign it for the public address.
- The download keeps the file's name, also with non-ASCII letters.

## Delete files

```bash
komando storage rm backups 2026/old.sql.gz --allow-dangerous                   # exact keys
komando storage rm backups --prefix daily/ --older-than 30d --dry-run          # list old backups
komando storage rm backups --prefix daily/ --older-than 30d --allow-dangerous  # delete them
```

- Deleted objects are gone, so `rm` needs `--allow-dangerous`.
- Without `--prefix`, `rm` takes exact keys only, no patterns.
- `--prefix` removes everything under a folder (`/` for the whole conn);
  `--older-than` (`30d`, `12h`, `90m`) keeps the newer ones.
- `--prefix` refuses to remove more than `--limit` objects (1000 by
  default). Check the dry-run list, and raise the limit if that is what you
  mean.

## Good to know

- A protected conn needs `--yes` for `upload`, `rm` and `link`.
- `--dry-run` sends no change, but checks: `upload` shows the key and
  whether it would replace an object, `download` where the file would go
  and its size, `rm` lists the objects one per line with size and date.
- `--via` works the same as for other conns: through a bastion or a VPN.
