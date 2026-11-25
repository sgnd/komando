# Cloud logins

komando talks to AWS itself, with no aws CLI: it uses the profiles in
your `~/.aws/config`, and a person renews an SSO login with one command,
`komando test NAME`. [All docs](README.md)

TODO(cut): cloud accounts as entries of their own (`komando cloud aws add
NAME`, `discover`, and the providers `gcp`, `azure`, `alibaba`, `tencent`
and `digitalocean`) arrive one per minor release after v0.18.0 (rows C313
to C318). Until then a cloud login belongs to the entry that uses it: a
storage, a queue or a registry.

## Log in to AWS IAM Identity Center (SSO)

For a profile in `~/.aws/config` that uses SSO (`sso_session` or
`sso_start_url`), or a profile that assumes a role from one
(`role_arn` with `source_profile`):

```bash
komando storage s3 add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod
komando test backups                                               # a person signs in once in the browser
komando storage s3 object list backups                             # uses the login until it runs out
```

There is no separate login command. The sign-in is the person step of
`komando test NAME`, run once at a terminal for an entry that uses the
profile. komando shows a code and opens the AWS sign-in page in your
browser. Confirm the same code there. The login is saved where the aws CLI
keeps it (`~/.aws/sso/cache`, readable only by you), so komando, the AWS
SDKs and the aws CLI all use it. The kept login lasts 8 hours at most
(the `login_for` setting), and agents reuse it.

- Without `aws_profile`, komando uses `AWS_PROFILE`, else `default`. It
  does not ask: the usual profile is the answer.
- `komando test backups --dry-run` checks the profile and shows its
  sign-in page (`sso_start_url`) and region, and logs in to nothing.
- A profile with keys in `~/.aws/credentials` needs no login. `komando
  test` for it says so (`AWS_FAILED`).
- komando opens only an `https://` sign-in address in the browser. On a
  machine without a browser, open the printed address on any device.
- Ctrl-C while komando waits for the sign-in stops it (`CANCELLED`); the
  old login, if any, stays as it was.

**AI agents** cannot log in: the sign-in happens in a person's browser.
An agent gets `NEEDS_PERSON` (exit 6) with the hint *ask the user to run
`komando test backups` in their own terminal*. After the person logs in,
the agent's commands use that login; when it ends, the agent's command
fails and the hint names `test`. A script without a terminal gets
`NEEDS_PERSON` (exit 6), as an agent does. komando never puts the token in
a command line, its output or the audit log.

## Use an AWS profile in an entry

An entry names a profile with `--option aws_profile=NAME`. komando reads
the profile each time, so SSO, assumed roles and temporary keys work as
the aws CLI uses them, and no key is stored in komando:

```bash
komando storage s3 add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod   # S3
komando queue sqs add prod-sqs sqs://eu-west-1 --option aws_profile=prod                         # SQS
komando registry oci add ecr registry://123456789012.dkr.ecr.eu-west-1.amazonaws.com --option aws_profile=prod
komando storage s3 edit backups --option aws_profile=staging                                     # another profile
```

- The region comes from the entry (`region=` for S3, the address for SQS
  and ECR), not from the profile.
- `aws_profile=default` uses the usual AWS chain: the `AWS_*` variables,
  the default profile, or the role of the machine komando runs on.
- Secrets from AWS Secrets Manager use the usual chain too (`AWS_PROFILE`
  picks the profile). They come from a credential store of the provider
  `aws-sm`, and a credential points at an item in it:

  ```bash
  komando credential store aws-sm add my-vault
  komando credential password add app-pass --user app --store my-vault --item prod/app
  ```

See [Storage](storage.md#aws-logins-sso-roles-temporary-keys),
[Queues](queues.md#add-an-sqs-region) and
[Container registries](registry.md).

## Add a storage for every S3 bucket

Each bucket is one storage entry. Add them one at a time:

```bash
komando storage s3 add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod
komando storage s3 add media 's3://media-bucket?region=eu-west-1' --option aws_profile=prod
```

Each entry uses its profile (`aws_profile`), so no key is copied. Later
commands read `~/.aws/config` (or `AWS_CONFIG_FILE`), so keep the profile
there, or they stop with `AWS_PROFILE_NOT_FOUND`.

## See and end an AWS login

`komando status` lists the SSO logins of the profiles in `~/.aws/config`
(made by `komando test`, `aws sso login` or an AWS SDK): the profiles
that share each one and when its token runs out. A login with a refresh
token (`renews: true`) gets a new token by itself after that, for as long
as the AWS session lasts.

```bash
komando test backups --end     # end the kept login of backups now
komando test --end             # every kept login
```

`test --end` ends the kept login of that entry. Profiles that share the
login (one `sso-session`) share it, so the next command of any of them
needs `komando test NAME` again. It never shows the token.

TODO(cut): whether `test --end` also tells AWS to end the token (what
`aws sso logout` does) waits on the cut plan's `test --end` row (C325).

## Google Cloud and Azure

Google Cloud and Azure sign-in are not available yet. What works instead:

- **Google Cloud**: your application default credentials
  (`GOOGLE_APPLICATION_CREDENTIALS`, or the file gcloud saved), or a
  service account key in a credential:

  ```bash
  komando credential token add gcs-key                                # the service account key, key.json
  komando storage gcs add media gs://my-bucket/site --credential gcs-key
  ```

- **Azure**: an Azure blob storage takes the storage account key or a SAS
  token. Key Vault secrets come from a credential store of the provider
  `azure-kv` and use a service principal (`AZURE_TENANT_ID`,
  `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), a token the Azure CLI saved,
  or the machine's managed identity.

  ```bash
  komando credential token add blob-key                               # the storage account key
  komando storage azblob add files azblob://mystorageacct@uploads --credential blob-key
  ```

TODO(cut): how a key file is given to `credential token add` waits on the
`Options` of that leaf (PR B).

Registries on Google Cloud and Azure log in the same way: see
[Container registries](registry.md).

A cloud login goes only to the cloud's own sign-in address:

- A Google login file that names addresses (a workload or workforce
  identity file, `external_account`; an impersonated service account) is
  used only when they are Google's token services
  (`https://sts.googleapis.com/v1/token`,
  `https://iamcredentials.googleapis.com/...`).
- `AZURE_AUTHORITY_HOST` has to be one of Azure's sign-in hosts.
- gcloud's login and the cloud registry logins never go to an entry with a
  CA of its own (`?ca=`) or `?resolve=`.

For an AI agent's command, more is fixed, because the agent sets the
variables on its own command line:

- As a Google login file only a gcloud login
  (`gcloud auth application-default login`) or a service account key is
  used; any other kind stops with `NEEDS_PERSON`: the user sets that login
  up in their own terminal.
- `AWS_ENDPOINT_URL`, `AWS_ENDPOINT_URL_*` and a profile's `endpoint_url`
  are not followed, nor a container credentials address
  (`AWS_CONTAINER_CREDENTIALS_FULL_URI`) that is not ECS's or EKS's. An
  emulator or VPC endpoint goes in the entry (`endpoint=`).
- The file named by `AZURE_FEDERATED_TOKEN_FILE`,
  `AWS_WEB_IDENTITY_TOKEN_FILE` (or `web_identity_token_file` in an AWS
  profile) may not be a private key, komando's own data, a credential
  store or a file that holds secrets by its name: `NEEDS_PERSON` (no flag
  lifts it; the user sets the login up in their own terminal).

## Limits

- Only AWS has a person step in `komando test`; Google Cloud and Azure use
  the logins above.
- `aws`, `gcp` and `azure` (any case) cannot be the name of a new entry,
  as `all` cannot: those words are the cloud providers.

## Troubleshooting

| Code | What happened | What to do |
|---|---|---|
| `AWS_LOGIN_REQUIRED` (exit 4) | the SSO login of the profile ran out, or was never made | a person runs `komando test NAME`, the command in the hint |
| `AWS_FAILED` (exit 4) | the profile has no SSO and gave no keys, or the role it assumes was refused | the hint says which: add the keys to `~/.aws/credentials`, or check the role and its source profile |
| `AWS_PROFILE_NOT_FOUND` (exit 3) | the profile is not in `~/.aws/config` or `~/.aws/credentials` | add it, or fix the entry's `--option aws_profile` |
| `NEEDS_PERSON` (exit 6) | an AI agent ran the person step of `komando test` | the person runs `komando test NAME` in their own terminal |
| `CANCELLED` (exit 1) | Ctrl-C while waiting for the sign-in | run it again; the old login is unchanged |
