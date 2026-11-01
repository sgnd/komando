# Object storage

Browse, download and upload files in S3 and compatible storage. [All features](README.md)

`komando storage` works with S3 and every S3-compatible service (MinIO,
Cloudflare R2, Wasabi, DigitalOcean Spaces, Backblaze B2, Garage). Add the
bucket as a conn; the folder in the URL limits the conn to that folder.

```bash
komando secret set backups-secret               # the secret access key
komando conn add backups 's3://AKIAEXAMPLE@my-bucket/db?region=eu-west-1' --password-ref secret:backups-secret

komando storage ls backups                      # one level; --recursive for everything
komando storage download backups 2026/app.sql.gz            # into the current folder
komando storage upload backups ./app.sql.gz 2026/app.sql.gz
komando storage link backups 2026/app.sql.gz --expires 24h   # temporary download link
komando storage rm backups 2026/old.sql.gz --allow-dangerous
```

- Downloads never overwrite a file; the file is readable only by you.
- `upload` replaces an object with the same key (the result says
  `"replaced": true`). `rm` takes exact keys only, no folders or patterns,
  and needs `--allow-dangerous` because deleted objects are gone.
- A protected conn needs `--yes` for `upload`, `rm` and `link`. `--dry-run`
  shows that the change would be allowed and sends nothing.
- Keys cannot leave the conn's folder (`../` is refused).
- A link works for anyone who has it until it expires. Share it like a
  password. It is not written to the history.
- Safest setup: give komando an access key that can only do what you need
  (read-only for reports, one bucket only). The service then enforces it.
