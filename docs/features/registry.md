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

### HTTPS with your own certificate

By default komando checks the registry's certificate against the CAs your
computer trusts. A registry with a certificate from a private CA (mkcert,
an internal CA) is refused with `REGISTRY_TLS`. Two ways to fix it:

```bash
komando secret set lan-ca < ca.crt            # 1. preferred: trust that CA, the check stays on
komando conn add lan 'registry://me@registry.lan?ca=secret:lan-ca' --password-ref secret:lan-token
komando conn add lan 'registry://me@registry.lan?tls=skip-verify' --password-ref secret:lan-token   # 2. no check at all
```

| URL option | What it does |
|---|---|
| (none) | HTTPS, certificate checked against your computer's CAs |
| `?ca=secret:NAME` | HTTPS, certificate checked against those CAs plus the PEM certificate in the vault secret `NAME`: a CA, or the registry's own certificate |
| `?resolve=IP` | connect to this IP address instead of the one DNS gives for the name (like `curl --resolve`). `IP:PORT` sets the port too; write IPv6 in brackets: `[2001:db8::1]:443`. TLS keeps using the name in the URL. Goes with every other option in this table; see "Wrong or missing DNS" below |
| `?tls=skip-verify` | HTTPS, but the certificate is not checked (like Docker's `insecure-registries`). Anyone on the path can pretend to be the registry; `komando doctor` warns about it |
| `?tls=false` | plain HTTP, nothing encrypted (a `registry:2` on a private network) |

The CA secret counts as used by the conn: `secret list` shows it, `secret rm`
refuses it, `secret mv` changes the URL too, and `export` lists it under
`secrets_needed`.

**No CA at hand?** If the CA is somewhere else (mkcert on another
computer) and the registry sends only its own certificate, store that
certificate as `ca=`. komando then trusts exactly that certificate (it is
pinned), still checks the name and the dates, and refuses any other. When
the registry gets a new certificate, store the new one.

```bash
komando secret set lan-cert < registry.crt    # the registry's own certificate, PEM
komando conn add lan 'registry://me@registry.lan?ca=secret:lan-cert'
```

**Through a server (`--via`).** komando sends the registry's name to the
last server on the `--via` path, and that server looks it up, so its
`/etc/hosts` and its DNS apply. The certificate check and the `Host` header
still use the name in the URL. This helps when the registry's public DNS
points somewhere else than the address your servers use:

```bash
komando conn add app-registry 'registry://me@registry.example.com?ca=secret:app-ca' --via web1
```

**Wrong or missing DNS (`?resolve=`).** If you can reach the registry from
your computer, you do not need a server for this. Give its IP address in
the URL, as `curl --resolve` does. komando connects to that address and
still sends the name, so the TLS options work as they do without it: the
certificate is checked against the name (with or without `ca=`), or not
checked at all with `tls=skip-verify`:

```bash
komando conn add app-registry 'registry://me@registry.example.com?ca=secret:app-ca&resolve=203.0.113.10'
komando conn add lan-registry 'registry://me@registry.lan?tls=skip-verify&resolve=203.0.113.20'
komando test app-registry
```

Only connections to the registry's own name go to that IP. A login service
or a download on another host is looked up as usual. With `--via`, the last
server on the path connects to the IP. `komando tunnel` uses the IP too.

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

`prune` deletes old images of one repository. Give `--keep`,
`--older-than`, or both:

- `--keep N` keeps the newest N matching tags.
- `--older-than 30d` deletes only images built before that age. With both,
  a tag must pass both to go.
- `--match REGEX` limits it to tags that match this pattern (a regular
  expression, such as `^v` for tags starting with v).

`latest`, tags that do not match, and tags with no build date always stay,
and so does any image that a kept tag points at.
