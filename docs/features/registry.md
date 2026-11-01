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

## Use it

```bash
komando registry ls harbor                    # repositories (Docker Hub and GHCR do not allow this)
komando registry ls ghcr myorg/api            # tags of one repository
komando registry inspect ghcr myorg/api:1.4.2 # digest, size, platforms, created, labels
komando registry copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2   # between registries
komando registry copy ghcr:myorg/api:1.4.2 harbor:                  # same name and tag
komando registry rm harbor myorg/api:old --allow-dangerous
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
  image goes too. The disk space comes back after the registry's garbage
  collection.
- A protected registry conn also needs `--yes` to delete.
