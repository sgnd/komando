# Container registries

See which images a registry holds, copy images between registries, and
clean up old ones. Works with Docker Hub, GHCR, GitLab, Harbor, Amazon ECR,
Azure Container Registry, Google Artifact Registry and your own
`registry:2`. [All docs](README.md)

## See the tags of an image

```bash
komando import docker                          # registries you are logged in to
komando list kind:registry                     # the names the import gave (ghcr.io -> ghcr ...)
komando registry list ghcr myorg/api           # tags of one repository
```

Typed alone at a terminal, `komando registry list` asks for the registry,
with a list of yours to pick from, then the repository (empty lists every
repository).

```text
1.4.1
1.4.2
latest
```

`list` and `inspect` only read. `copy` writes to the destination. `rm`
and `prune` delete images. An AI agent gives every argument; a missing one
is a `USAGE` error (exit 2) whose hint shows an example.

## Add a registry

```bash
komando import docker                         # from ~/.docker/config.json
komando registry add ghcr registry://alice@ghcr.io --ask-password                         # asks for the token, hidden
komando registry add ghcr registry://alice@ghcr.io --password-ref secret:ghcr-token       # a token you stored with secret set
komando registry add harbor 'registry://alice@harbor.lan:5000?tls=false' --via bastion    # no TLS, behind a bastion
```

The password is usually an access token. It needs read rights to look,
write rights to copy into the registry, and delete rights to delete. For
Docker Hub use `registry://alice@docker.io`.

`import docker` reads each `docker login` from `~/.docker/config.json`,
asking the credential helper (`credsStore`, `credHelpers`) when docker
keeps the login there. Amazon ECR, Google registries logged in through
gcloud, and Azure registries logged in with `az acr login` hold a token
that lasts only hours: komando adds those without it and logs in with
your AWS, Google or Azure login each time (see below).

To take a registry off your list: `komando conn rm ghcr` (the registry
itself is not touched).

### Docker Hub

```bash
komando registry add dockerhub registry://alice@docker.io --ask-password
komando registry list dockerhub alice/app       # tags of your repository
komando registry inspect dockerhub nginx        # an official image: library/nginx:latest
```

- An official image's name without a `/` (`nginx`) means
  `library/nginx`, as with `docker pull`.
- Docker Hub has no list of every repository: `registry list dockerhub`
  without a repository gives `REGISTRY_UNSUPPORTED`; name one.
- Docker Hub limits pulls (fewer without a login) and counts every manifest
  read. Past the limit, komando stops with `REGISTRY_RATE_LIMIT` and says
  when to try again. `list` and `rm` read tags with requests Docker Hub does
  not count; `prune` reads each image once.

### Amazon ECR

ECR logins last 12 hours, so komando gets a fresh one from AWS each time,
with your usual AWS login (no aws CLI needed). Leave out `--password-ref`
and name the AWS profile:

```bash
komando registry add ecr registry://AWS@123456789012.dkr.ecr.eu-west-1.amazonaws.com --option aws_profile=prod
```

If the SSO login has expired, the error is `AWS_LOGIN_REQUIRED`: a person
runs `komando login aws --profile prod` once. See [Cloud logins](cloud.md).

### Azure Container Registry

Leave out `--password-ref` and komando logs in with your Azure login, the
way `az acr login` does: it gets an Azure token and trades it with the
registry for a registry login that lasts a few hours. It does this each
time, keeps nothing, and needs no `az` program:

```bash
komando registry add acr registry://myregistry.azurecr.io
komando test acr
```

komando looks for an Azure login in this order:

1. a service principal: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
   `AZURE_CLIENT_SECRET`;
2. a workload identity on AKS: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
   `AZURE_FEDERATED_TOKEN_FILE`;
3. the token the Azure CLI saved after `az login` (Linux and macOS). It
   lasts about an hour, and any `az` command renews it; komando reads it
   but cannot renew it itself;
4. the managed identity of the Azure machine komando runs on
   (`AZURE_CLIENT_ID` picks a user-assigned one).

The login needs the `AcrPull` role on the registry to look, `AcrPush` to
copy images into it and `AcrDelete` to delete. Without a login the error
is `AZURE_LOGIN_REQUIRED`; a missing role gives `REGISTRY_AUTH`. A registry
token or the admin user works too: put the user in the URL and give
`--password-ref`, as for any registry.

The Azure token is good for your whole subscription, not only the
registry, so komando sends it only over https to a registry whose
certificate is checked. A conn with `?tls=false` or `?tls=skip-verify`
stops with a usage error; use `?ca=` for a private CA, or a registry token
with `--password-ref`.

### Google Artifact Registry and Container Registry

Hosts like `europe-west1-docker.pkg.dev`, `gcr.io`, `eu.gcr.io`, `us.gcr.io` and
`asia.gcr.io` log in with your Google login when the conn has no
`--password-ref`, as `gcloud auth configure-docker` sets up: komando gets a
Google access token (it lasts an hour) each time and logs in as
`oauth2accesstoken`. The login is the one komando uses for `gs://` storage
and `gcp-sm:`: `GOOGLE_APPLICATION_CREDENTIALS` (a service account key
file), the login from `gcloud auth application-default login`, or the
machine's service account on Google Cloud. No `gcloud` program is needed:

```bash
komando registry add gar registry://europe-west1-docker.pkg.dev
komando registry list gar my-project/my-repo/api
```

To use a service account key from the vault instead, store the key file
and name the user `_json_key`:

```bash
komando secret set gar-key < key.json
komando registry add gar registry://_json_key@europe-west1-docker.pkg.dev --password-ref secret:gar-key
```

The login needs the Artifact Registry Reader role to look, Writer to copy
images into it, and Repository Administrator to delete. With no Google
login at all, komando reads without one, so public images still work; a
login that has run out, or a `GOOGLE_APPLICATION_CREDENTIALS` file or
gcloud login file that is missing or broken, gives `GCP_LOGIN_REQUIRED`.
As with Azure, the Google token is good for your whole project, so it goes
only over https to a registry whose certificate is checked: not with
`?tls=false` or `?tls=skip-verify`.

### HTTPS with your own certificate

By default komando checks the registry's certificate against the CAs your
computer trusts. A registry with a certificate from a private CA (mkcert,
an internal CA) is refused with `REGISTRY_TLS`. Two ways to fix it:

```bash
komando secret set harbor-ca < ca.crt        # 1. better: trust that CA (its PEM certificate), the check stays on
komando registry add harbor 'registry://alice@harbor.lan?ca=secret:harbor-ca' --password-ref secret:harbor-token
komando registry add harbor 'registry://alice@harbor.lan?tls=skip-verify' --password-ref secret:harbor-token   # 2. no check at all
```

The URL options are in [Reference](#reference). The CA secret counts as
used by the conn: `secret list` shows it, `secret rm` refuses it,
`secret rename` changes the URL too, and `export` lists it under
`secrets_needed`.

If the CA is somewhere else (mkcert on another computer)
and the registry sends only its own certificate, store that certificate as
`ca=`. komando then trusts exactly that certificate (it is pinned), still
checks the name and the dates, and refuses any other. When the registry
gets a new certificate, store the new one.

```bash
komando secret set harbor-cert < registry.crt    # the registry's own certificate, PEM
komando registry add harbor 'registry://alice@harbor.lan?ca=secret:harbor-cert'
```

### When DNS points somewhere else

Sometimes the registry's public DNS points somewhere other than the address
your servers use, or the name has no DNS at all. There are two ways around
it.

Through a server (`--via`): komando sends the registry's name to the last
server on the `--via` path, and that server looks it up, so its
`/etc/hosts` and its DNS apply. The certificate check and the `Host` header
still use the name in the URL:

```bash
komando registry add harbor 'registry://alice@registry.example.com?ca=secret:harbor-ca' --via web1
```

With `?resolve=`: if you can reach the registry from your computer, you do
not need a server for this. Give its IP address in the URL, as
`curl --resolve` does. komando connects to that address and still sends the
name, so the TLS options work as they do without it: the certificate is
checked against the name (with or without `ca=`), or not checked at all
with `tls=skip-verify`:

```bash
komando registry add harbor 'registry://alice@registry.example.com?ca=secret:harbor-ca&resolve=203.0.113.10'
komando registry add harbor 'registry://alice@harbor.lan?tls=skip-verify&resolve=203.0.113.20'
komando test harbor
```

Only connections to the registry's own name go to that IP. A login service
or a download on another host is looked up as usual. With `--via`, the last
server on the path connects to the IP. `komando tunnel` uses the IP too.

## Look at images

```bash
komando registry list harbor                    # repositories (Docker Hub and GHCR do not allow this)
komando registry list ghcr myorg/api            # tags of one repository
komando registry inspect ghcr myorg/api:1.4.2   # digest, size, platforms, created, labels
```

Typed alone at a terminal, `komando registry inspect` asks for the
registry, then the image.

```text
myorg/api:1.4.2
  digest: sha256:4c2e...
  media type: application/vnd.oci.image.index.v1+json
  size: 48.2 MB in 7 layers, compressed
  platforms: linux/amd64, linux/arm64
  created: 2026-11-02 10:14 WIB
```

A tag or repository that is not there is "not found" (exit 3), and the
message says what is there: `mirror/busybox:latest not found; tags: stable`.

`list` shows at most 1000 entries (`--limit` changes it). A cut list has
`"truncated": true` in JSON and the line `(the first 1000 tags in shop/api;
there are more: raise -n)` at a terminal.

Names follow the OCI rules: a repository is lower-case letters, digits,
`.`, `_`, `-` and `/` between parts (`shop/api`); a tag is up to 128
letters, digits, `.`, `_` and `-`; a digest is `sha256:` and 64 hex digits.
Anything else is refused with `USAGE` before komando sends a request.

## Copy images

```bash
komando registry copy ghcr:myorg/api:1.4.2 harbor:prod/api:1.4.2   # between registries
komando registry copy ghcr:myorg/api:1.4.2 harbor:                  # keep the same name and tag
komando registry copy harbor:app:latest harbor:app:stable           # another tag on the same registry
```

Typed alone at a terminal, `komando registry copy` asks where from
(`ghcr:myorg/api:1.4.2`), then where to.

- Both sides are written `CONN:IMAGE`, as with `komando cp`. The image is
  `REPO[:TAG]` or `REPO@DIGEST`.
- Every platform of a multi-platform image is copied, and the digest stays
  the same, so signatures and pinned deployments stay valid.
- Layers the destination already has are skipped. On the same registry they
  are linked instead of copied, where the registry allows it.
- Only the destination changes, so only a protected destination needs `--yes`.
- The result says `"replaced": true` when the destination tag pointed to a
  different image before.
- `harbor:prod/api` (no tag) keeps the source's tag; a source given by
  digest needs a destination tag. Copying an image onto itself is refused.
- `--dry-run` reads both registries: it shows the source image (`source`)
  and says `"would_replace": true` when the destination tag points to
  another image now.

## Delete images

```bash
komando registry rm harbor shop/api:1.9 --dry-run     # lists every tag that would go
komando registry rm harbor shop/api:1.9
```

`rm` deletes the image the tag points at, so every other tag on the same
image goes too. Name the tag or digest: `rm` never picks `latest` by
itself. `--dry-run` names every tag that would go (`would_remove_tags`)
before anything is deleted:

```text
$ komando registry rm harbor shop/api:1.9 --dry-run
would delete shop/api@sha256:4c2e...
with it goes every tag on that image: 1.9, latest
latest is one of them: docker pull without a tag stops working
```

komando checks the first 200 tags of the repository; with more,
`tags_note` says others may point at the image too.

Deleting cannot be undone. At your terminal komando asks you first: it
names the image and every tag that goes, and you type the image's name
(`Type the name shop/api:1.9 to continue`). An AI agent or a script adds
`--allow-dangerous` after a person agrees; a protected registry also needs
`--yes`. See [Safety](safety.md#what-needs-a-yes).

The disk space comes back after the registry runs its garbage collection.

### Delete old images

```bash
komando registry prune harbor shop/api --keep 10 --dry-run   # what would go, and why the rest stays
komando registry prune harbor shop/api --keep 10 --older-than 30d --match '^v'
```

`prune` deletes old images of one repository. At your terminal komando
asks you first: type the repository's name. An AI agent or a script adds
`--allow-dangerous` after a person agrees. Give `--keep`, `--older-than`,
or both:

- `--keep N` keeps the newest N matching tags.
- `--older-than 30d` deletes only images built before that age. With both,
  a tag must pass both to go.
- `--match REGEX` limits it to tags that match this pattern (a regular
  expression, such as `^v` for tags starting with v).

```text
shop/api: would delete 2 images of 14 tags
  - v1.0                 2026-03-02 09:12 WIB  sha256:91ab2c3d4e5f
  - v1.1                 2026-04-10 15:40 WIB  sha256:7f3e1d2c3b4a
keeps 12 tags:
  = latest               latest is always kept
  = v2.9                 one of the newest
  ...
```

`latest`, tags that do not match, and tags with no build date always stay,
and so does any image that a kept tag points at. A multi-platform index
has the build date of its first image, so the rules apply to it like to
any image.

## Limits

- Docker Hub and GHCR have no list of every repository: name one.
- `list` shows at most 1000 entries unless you raise `--limit`.
- `rm` and its dry run check the first 200 tags of a repository for other
  tags on the same image.
- `prune` reads each tag's digest, then each image once, and stops with
  `TOO_MANY_TAGS` above 1000 tags (`--match` does not lift it, since every
  tag is read): delete some first with `registry rm`.
- A registry with deletes turned off (a `registry:2` without
  `REGISTRY_STORAGE_DELETE_ENABLED=true`) answers `rm` and `prune` with
  `REGISTRY_UNSUPPORTED`.
- The Azure and Google tokens go only over https with a checked
  certificate: not with `?tls=false` or `?tls=skip-verify`.
- Disk space comes back only after the registry's own garbage collection.

## Troubleshooting

| Code | What it means | What to do |
|------|---------------|------------|
| `REGISTRY_AUTH` (exit 4) | the registry refused the login, or the token lacks a right | check the user in the conn URL and its `--password-ref` (a token with the right scopes or role) |
| `REGISTRY_NOT_FOUND` (exit 3) | no such repository | `komando registry list harbor` shows the repositories |
| `REGISTRY_UNSUPPORTED` (exit 5) | the registry does not allow it: no list of every repository, or deletes turned off | name the repository; turn deletes on in the registry |
| `REGISTRY_RATE_LIMIT` (exit 5) | too many requests (Docker Hub's pull limit) | wait the time the hint says, or log in |
| `REGISTRY_TLS` (exit 4) | the certificate is from a private CA, or for another name | add `?ca=secret:NAME`, or use the name the certificate is for |
| `REGISTRY_UNREACHABLE` (exit 4) | the registry did not answer | `komando test harbor`, and check its `--via` path |
| `AWS_LOGIN_REQUIRED` (exit 4) | the ECR profile's AWS login ran out | a person runs `komando login aws --profile prod` |
| `AZURE_LOGIN_REQUIRED` (exit 4) | no Azure login found | set a service principal, or a person runs `az login` |
| `GCP_LOGIN_REQUIRED` (exit 4) | the Google login ran out or its file is broken | a person runs `gcloud auth application-default login`, or set `GOOGLE_APPLICATION_CREDENTIALS` |
| `TOO_MANY_TAGS` (exit 2) | `prune` on a repository with more than 1000 tags | delete some first with `registry rm` |

## Reference

URL options of a `registry://` conn:

| URL option | What it does |
|---|---|
| (none) | HTTPS, certificate checked against your computer's CAs |
| `?ca=secret:NAME` | HTTPS, certificate checked against those CAs plus the PEM certificate in the vault secret `NAME`: a CA, or the registry's own certificate |
| `?resolve=IP` | connect to this IP address instead of the one DNS gives for the name (like `curl --resolve`). `IP:PORT` sets the port too; write IPv6 in brackets: `[2001:db8::1]:443`. TLS keeps using the name in the URL. Goes with every other option in this table; see [When DNS points somewhere else](#when-dns-points-somewhere-else) |
| `?tls=skip-verify` | HTTPS, but the certificate is not checked (like Docker's `insecure-registries`). Anyone on the path can pretend to be the registry; `komando doctor` warns about it |
| `?tls=false` | plain HTTP, nothing encrypted (a `registry:2` on a private network) |
