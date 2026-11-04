# Container registries

See which images a registry holds, copy images between registries, and
clean up old ones. Works with Docker Hub, GHCR, GitLab, Harbor, Amazon ECR
and your own `registry:2`. [All features](README.md)

## Quick start

```bash
komando import docker                                              # registries you are logged in to
komando registry ls ghcr myorg/api                                 # tags of one repository
komando registry inspect ghcr myorg/api:1.4.2                      # digest, size, platforms, labels
komando registry copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2   # copy between registries
komando registry rm harbor myorg/api:old --dry-run                 # what a delete would remove
```

`ls` and `inspect` only read. `copy` writes to the destination. `rm`
deletes and needs `--allow-dangerous`.

## Add a registry

```bash
komando import docker                         # from ~/.docker/config.json
komando secret set ghcr-token                 # or add one by hand
komando conn add ghcr registry://myuser@ghcr.io --password-ref secret:ghcr-token
komando conn add local 'registry://me@registry.lan:5000?tls=false' --via bastion   # no TLS, behind a bastion
```

The password is usually an access token. It needs read rights to look,
write rights to copy into the registry, and delete rights to delete. For
Docker Hub use `registry://myuser@docker.io`.

**Amazon ECR.** ECR logins last 12 hours, so komando gets a fresh one from
AWS each time, with your usual AWS login (no aws CLI needed). Leave out
`--password-ref` and name the AWS profile:

```bash
komando conn add ecr registry://AWS@123456789012.dkr.ecr.eu-west-1.amazonaws.com --option aws_profile=prod
```

If the SSO login has expired, the error is `AWS_LOGIN_REQUIRED`: a person
runs `komando login aws --profile prod` once.

## Look at images

```bash
komando registry ls harbor                    # repositories (Docker Hub and GHCR do not allow this)
komando registry ls ghcr myorg/api            # tags of one repository
komando registry inspect ghcr myorg/api:1.4.2 # digest, size, platforms, created, labels
```

A tag or repository that is not there is "not found" (exit 3), and the
message says what is there: `mirror/busybox:latest not found; tags: stable`.

## Copy images

```bash
komando registry copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2   # between registries
komando registry copy ghcr:myorg/api:1.4.2 harbor:                  # keep the same name and tag
komando registry copy harbor:app:latest harbor:app:stable           # another tag on the same registry
```

- Both sides are written `CONN:IMAGE`, as with `komando cp`. The image is
  `REPO[:TAG]` or `REPO@DIGEST`.
- Every platform of a multi-platform image is copied, and the digest stays
  the same, so signatures and pinned deployments stay valid.
- Layers the destination already has are skipped. On the same registry they
  are linked instead of copied, where the registry allows it.
- Only the destination changes, so only a protected destination needs `--yes`.
- The result says `"replaced": true` when the destination tag pointed to a
  different image before.

## Delete images

```bash
komando registry rm harbor myorg/api:old --dry-run          # lists every tag that would go
komando registry rm harbor myorg/api:old --allow-dangerous
```

`rm` deletes the image the tag points at, so every other tag on the same
image goes too. `--dry-run` names them (`would_remove_tags`) before
anything is deleted. A protected registry conn also needs `--yes`. The disk
space comes back after the registry runs its garbage collection.

### Delete old images

```bash
komando registry prune harbor myorg/api --keep 10 --dry-run   # what would go, and why the rest stays
komando registry prune harbor myorg/api --keep 10 --older-than 30d --match '^v' --allow-dangerous
```

`prune` deletes old images of one repository:

- `--keep N` keeps the newest N matching tags.
- `--older-than 30d` deletes only images built before that age. With both,
  a tag must pass both to go.
- `--match REGEX` limits it to some tags.

`latest`, tags that do not match, and tags with no build date always stay,
and so does any image that a kept tag points at.
