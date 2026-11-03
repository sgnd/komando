# Container registries

See what images a registry holds, copy images between registries, and clean
up old ones: Docker Hub, GHCR, GitLab, Harbor, ECR, or your own `registry:2`. [All features](README.md)

## Add a registry

```bash
komando import docker                         # registries you are logged in to (~/.docker/config.json)
komando secret set ghcr-token                 # or add one by hand
komando conn add ghcr registry://myuser@ghcr.io --password-ref secret:ghcr-token
komando conn add local 'registry://me@registry.lan:5000?tls=false' --via bastion   # no TLS, behind a bastion
```

The password is usually an access token with read rights (write rights to
copy into it, delete rights to delete).

Amazon ECR logins last 12 hours, so komando gets a fresh one from the aws
CLI each time (`aws ecr get-login-password`); leave out `--password-ref`:

```bash
komando conn add ecr registry://AWS@123456789012.dkr.ecr.eu-west-1.amazonaws.com --option aws_profile=prod
```

## Use it

```bash
komando registry ls harbor                    # repositories (Docker Hub and GHCR do not allow this)
komando registry ls ghcr myorg/api            # tags of one repository
komando registry inspect ghcr myorg/api:1.4.2 # digest, size, platforms, created, labels
komando registry copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2   # between registries
komando registry copy ghcr:myorg/api:1.4.2 harbor:                  # same name and tag
komando registry rm harbor myorg/api:old --allow-dangerous
komando registry prune harbor myorg/api --keep 10 --dry-run            # what would go
komando registry prune harbor myorg/api --keep 10 --older-than 30d --allow-dangerous
```

- `copy` takes `CONN:IMAGE` on both sides, like `komando cp`. It copies every
  platform of a multi-platform image and keeps the digest, so signatures and
  pinned deployments stay valid. Layers the destination already has are
  skipped; within one registry they are linked instead of copied where the
registry allows it (otherwise copied). Only the
  destination changes, so only a protected destination needs `--yes`. The
  result says `"replaced": true` when the destination tag pointed to another
  image.

- `rm` deletes the image the tag points at, so every other tag on the same
  image goes too: `rm --dry-run` names them (`would_remove_tags`) before
  anything is deleted. The disk space comes back after the registry's garbage
  collection.
- `prune` deletes old images of one repository: `--keep N` keeps the newest
  N tags, `--older-than 30d` deletes only images built before that age
  (both together: a tag must pass both to go), and `--match REGEX` limits
  it to some tags (`'^v'`). `latest`, tags that do not match, and tags with
  no build date always stay, and so does any image a kept tag points at.
  `--dry-run` lists what would be deleted and why each other tag stays.
- A tag or repository that is not there is "not found" (exit 3) and the
  message says what is: `mirror/busybox:latest not found; tags: stable`.
- A protected registry conn also needs `--yes` to delete.
