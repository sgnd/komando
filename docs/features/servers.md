# Servers

Add servers, log in with keys or passwords, and keep the list tidy. [All features](README.md)

## Check what you added

`host add` and `host edit` check what they save: the port (1-65535), the
user name, that every `--via` step exists (and does not loop back), and that
an `--identity` file is there. A server added under another spelling of a
protected one (`TARGET.`, another case) is protected too, with a warning.
`komando doctor` checks the whole inventory the same way.

Changing where or how komando logs in to a protected server (address, port,
user, key, password, `--via`) needs `--yes`, like any other change to it.

`komando host ssh-command NAME` prints the OpenSSH command for a server.
Servers behind `--via` get one `ProxyCommand` per hop, so each hop uses its
own key and komando's known_hosts; a SOCKS VPN becomes `nc -X 5`. VPNs that
run inside komando cannot be used by OpenSSH: use `komando shell NAME`.

`komando host trust NAME --reset` forgets and re-pins a server's key after a
rebuild; with `--dry-run` it only counts the pinned entries.

`komando host rm` (and `conn rm`) takes names or a target: `host rm 'tmp-*'`
or `host rm @old --dry-run` lists what it would remove. Protected ones need
`--yes`, and a server that another one still reaches through `--via` stays.

## Add servers

```bash
komando host add web1 ubuntu@203.0.113.10                 # name + user@address
komando host add web2 ubuntu@203.0.113.11 --group web --tag prod
komando host add db1 admin@10.0.0.5 --via bastion         # reached through "bastion"
komando host import --ssh-config ~/.ssh/config             # import what you already have
komando list                                          # see them all
komando test all                                      # can we log in everywhere?
```

Servers behind the same `--via` hosts share one connection to them within a
command: `komando exec @db -P 10` logs in to the bastion once and reaches the
ten servers through it, like OpenSSH's ControlMaster, so the bastion's
connection limits (`MaxStartups`) and its login log see one client.

Change or remove later:

```bash
komando host edit web1 --add-tag canary --port 2222
komando host edit web1 --protected        # production: changes need --yes
komando host rm web2
```

## Servers with no open SSH port (AWS SSM, GCP IAP, Cloudflare)

When a server is reached through a cloud tool instead of a plain SSH port,
give komando that tool's command, as in OpenSSH's `ProxyCommand` (`%h` is
the address, `%p` the port, `%r` the user):

```bash
komando host add web1 ec2-user@i-0abc123 --ssm     # AWS Systems Manager: the address is the instance ID
komando host add vm1 me@vm1 --proxy-command 'gcloud compute start-iap-tunnel %h %p --listen-on-stdin --zone europe-west1-b'
komando host add box me@ssh.example.com --proxy-command 'cloudflared access ssh --hostname %h'
komando conn add rds postgres://app@mydb.xyz.rds.amazonaws.com/app --via web1   # a database behind it
```

The tool must be installed and logged in on this computer. For `--ssm`,
komando speaks AWS Session Manager itself when the aws CLI or its
session-manager-plugin is not installed (with your usual AWS login;
`komando login aws` for SSO); set `KOMANDO_EXPERIMENTAL=ssm` to use it even
when they are. Sessions your account encrypts with KMS work too: komando
asks KMS for the session key with your login, so that login needs
`kms:GenerateDataKey` on the key, as the plugin does.
`import ssh-config` keeps
`ProxyCommand` lines; `import` of an export file drops them, because they
run programs on your computer.

## Log in without typing passwords

If you can already log in with `ssh` on this computer, komando usually just
works: it uses the same keys (files like `~/.ssh/id_ed25519`, and the
ssh-agent program that holds unlocked keys). Otherwise it uses a stored password.

**Store a password safely.** You type it, nothing is shown, it is saved encrypted:

```bash
komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

**Better: use a key.** Create one and install it on your servers:

```bash
komando key gen deploy                          # ed25519; --type rsa|ecdsa, -b BITS, -C COMMENT
komando key deploy deploy @web --set-default
komando key deploy ~/.ssh/id_ed25519.pub web1   # a .pub file works too
komando key list                                # NAME TYPE FINGERPRINT USED_BY
```

RSA keys need at least 3072 bits. A key with a passphrase needs the
passphrase in the vault: `komando secret set work-pass`, then
`komando key add work ~/.ssh/id_work --passphrase-ref secret:work-pass`.

When someone leaves, or a key is replaced, remove it everywhere at once. It
takes a key from the keychain, a `.pub` file, or the key line itself:

```bash
komando key revoke ~/keys/budi.pub @prod --dry-run   # how many lines per server
komando key revoke ~/keys/budi.pub @prod
komando key revoke old-deploy @web --user deploy     # another user's file (sudo)
```

Revoking the key komando itself logs in with needs `--allow-dangerous`.

**sudo needs a password?**

```bash
komando secret set web1-sudo
komando host edit web1 --sudo-ref secret:web1-sudo
```

References can also point to an environment variable (`env:MY_VAR`) or a
file (`file:/path`).

## Passwords from your password manager

Every `--password-ref` (servers, conns, VPNs) can point at the password
manager your team already uses, instead of komando's own vault:

| Reference | Reads it from | Login it uses |
|-----------|---------------|---------------|
| `secret:NAME` | komando's vault (`komando secret set NAME`) | — |
| `env:VAR` | an environment variable | — |
| `file:PATH` | a file | — |
| `vault:secret/shop#db_password` | HashiCorp Vault or OpenBao, KV v1 or v2 | `VAULT_ADDR` and `VAULT_TOKEN` (or `~/.vault-token`), `VAULT_NAMESPACE`, `VAULT_CACERT` |
| `aws-sm:shop/db#password` | AWS Secrets Manager; `#key` picks a JSON field | your AWS login (`AWS_PROFILE`, `~/.aws`, SSO via `komando login aws`) |
| `gcp-sm:db-pass@my-project` | Google Secret Manager, latest version | Google application-default credentials (`GOOGLE_APPLICATION_CREDENTIALS`, or on Google Cloud) |
| `bw://shop-db/password` | Bitwarden or Vaultwarden; the field is `password`, `username`, `notes`, `uri`, `totp` or a custom field | `KOMANDO_BW_EMAIL`, `KOMANDO_BW_PASSWORD` (decrypts the vault here), `KOMANDO_BW_SERVER` for Vaultwarden or bitwarden.eu, optional API key `KOMANDO_BW_CLIENT_ID`/`KOMANDO_BW_CLIENT_SECRET` |
| `kdbx:~/team.kdbx#Servers/web1` | a KeePass or KeePassXC file (KDBX 3.1 and 4); `#UserName` or another field after the entry | `KOMANDO_KDBX_PASSWORD` and/or `KOMANDO_KDBX_KEYFILE` |
| `op://Vault/Item/field` | 1Password, through a 1Password Connect server | `OP_CONNECT_HOST`, `OP_CONNECT_TOKEN` |

```bash
komando conn add shop-db postgres://app@db.lan/shop --password-ref vault:secret/shop#db_password
```

komando talks to Vault, AWS, Google, Bitwarden, KeePass files and
1Password Connect itself: no `vault`, `aws`, `gcloud`, `bw` or `op` program
is needed. Without Connect, `op://` still uses the 1Password CLI for now;
that path will be removed, because the CLI is closed source and komando
uses only open-source parts. It reads the value when it needs it and never stores it;
the login (and any MFA) stays with you.
