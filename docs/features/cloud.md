# Cloud logins

komando talks to AWS itself, with no aws CLI: it uses the profiles in
your `~/.aws/config`, and a person renews an SSO login with one command.
[All docs](README.md)

## Log in to AWS IAM Identity Center (SSO)

For a profile in `~/.aws/config` that uses SSO (`sso_session` or
`sso_start_url`), or a profile that assumes a role from one
(`role_arn` with `source_profile`):

```bash
komando login aws --profile prod                                   # a person signs in once in the browser
komando conn add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod
komando storage list backups                                       # uses the login until it runs out
```

komando shows a code and opens the AWS sign-in page in your browser.
Confirm the same code there. The login is saved where the aws CLI keeps
it (`~/.aws/sso/cache`, readable only by you), so komando, the AWS SDKs
and the aws CLI all use it.

- Without `--profile`, komando uses `AWS_PROFILE`, else `default`. It
  does not ask: the usual profile is the answer.
- `komando login aws --profile prod --dry-run` checks the profile and
  shows its sign-in page (`sso_start_url`) and region, and logs in to
  nothing.
- A profile with keys in `~/.aws/credentials` needs no login. Running
  `komando login aws` for it says so (`AWS_FAILED`).
- Cloud logins are lower case: `komando login AWS` stops with `USAGE`
  and points to `komando login aws`.
- komando opens only an `https://` sign-in address in the browser. On a
  machine without a browser, open the printed address on any device.
- Ctrl-C while komando waits for the sign-in stops it (`CANCELLED`); the
  old login, if any, stays as it was.

**AI agents** cannot log in: the sign-in happens in a person's browser.
An agent gets `NEEDS_PERSON` (exit 6) with the hint *ask the user to run
`komando login aws --profile prod` in their own terminal*. After the
person logs in, the agent's commands use that login. A script without a
terminal gets `NEEDS_TERMINAL` (exit 2). komando never puts the token in
a command line, its output or the audit log; the audit records only
`login.aws` and the profile name.

## Use an AWS profile in a conn

A conn names a profile with `--option aws_profile=NAME`. komando reads
the profile each time, so SSO, assumed roles and temporary keys work as
the aws CLI uses them, and no key is stored in komando:

```bash
komando conn add backups 's3://my-bucket/db?region=eu-west-1' --option aws_profile=prod   # S3
komando conn add orders sqs://eu-west-1 --option aws_profile=prod                         # SQS
komando registry add ecr registry://AWS@123456789012.dkr.ecr.eu-west-1.amazonaws.com --option aws_profile=prod
komando conn edit backups --option aws_profile=staging                                    # another profile
```

- The region comes from the conn (`region=` for S3, the address for SQS
  and ECR), not from the profile.
- `aws_profile=default` uses the usual AWS chain: the `AWS_*` variables,
  the default profile, or the role of the machine komando runs on.
- Secrets from AWS Secrets Manager (`--password-ref aws-sm:NAME`) use the
  usual chain too (`AWS_PROFILE` picks the profile).

See [Storage](storage.md#aws-logins-sso-roles-temporary-keys),
[Queues](queues.md#add-an-sqs-region) and
[Container registries](registry.md).

## Add a conn for every S3 bucket

```bash
komando import aws --dry-run      # what it would add
komando import aws                # one storage conn per bucket of each profile
komando import aws ~/work/aws-config
```

Each conn uses its profile (`aws_profile`), so no key is copied. A
profile whose login has run out, or that has no keys, is skipped with a
note saying what fixes it: `komando login aws --profile NAME` for an SSO
profile, the credentials file for the others. Then run the import again.
See [Moving in](import.md).

With a FILE, the conns keep only each profile's name: later commands read
`~/.aws/config` (or `AWS_CONFIG_FILE`), so put the profiles there too, or
they stop with `AWS_PROFILE_NOT_FOUND`.

## End an AWS login

komando has no AWS logout: `komando logout` is for servers, and
`komando status` lists only server logins. To end an AWS login early, run
`aws sso logout`, or delete the profile's file in `~/.aws/sso/cache`.

## Google Cloud and Azure

Google Cloud and Azure sign-in are not available yet. What works instead:

- **Google Cloud**: your application default credentials
  (`GOOGLE_APPLICATION_CREDENTIALS`, or the file gcloud saved), or a
  service account key in the vault:

  ```bash
  komando secret set gcs-key < key.json
  komando conn add media gs://my-bucket/site --password-ref secret:gcs-key
  ```

- **Azure**: an Azure blob conn takes the storage account key or a SAS
  token. Key Vault secrets (`--password-ref azure-kv:VAULT/NAME`) use a
  service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
  `AZURE_CLIENT_SECRET`), a token the Azure CLI saved, or the machine's
  managed identity.

  ```bash
  komando secret set blob-key
  komando conn add files azblob://mystorageacct@uploads --password-ref secret:blob-key
  ```

Registries on Google Cloud and Azure log in the same way: see
[Container registries](registry.md).

## Limits

- Only AWS has a `komando login`; Google Cloud and Azure use the logins
  above.
- komando has no AWS logout and does not list AWS logins in
  `komando status`.
- `aws`, `gcp` and `azure` (any case) cannot be the name of a new server,
  conn or VPN, as `all` cannot: those words are the cloud logins.

## Troubleshooting

| Code | What happened | What to do |
|---|---|---|
| `AWS_LOGIN_REQUIRED` (exit 4) | the SSO login of the profile ran out, or was never made | a person runs `komando login aws --profile NAME`, the command in the hint |
| `AWS_FAILED` (exit 4) | the profile has no SSO and gave no keys, or the role it assumes was refused | the hint says which: add the keys to `~/.aws/credentials`, or check the role and its source profile |
| `AWS_PROFILE_NOT_FOUND` (exit 3) | the profile is not in `~/.aws/config` or `~/.aws/credentials` | add it, or fix the conn's `--option aws_profile` |
| `NEEDS_PERSON` (exit 6) | an AI agent ran `komando login aws` | the person runs it in their own terminal |
| `CANCELLED` (exit 1) | Ctrl-C while waiting for the sign-in | run it again; the old login is unchanged |
