# Servers

Add your servers, choose how komando logs in to them, and keep the list
tidy. [All docs](README.md)

## Add a server

Give each server a short name, then its user and address:

```bash
komando host add web1 ubuntu@203.0.113.10
komando test web1                                # can komando log in?
```

```text
added web1
  address: 203.0.113.10
  user: ubuntu
Next: komando test web1
```

```text
NAME  KIND  RESULT  LATENCY  USER    SUDO  NOTE
web1  host  ok      48ms     ubuntu  yes   -
```

Typed alone at your terminal, `komando host add` asks for each part, one
line at a time: a name, the address, the user, the port, how komando logs
in, and whether it is production. Any command typed with an argument
missing asks for it the same way (see
[Running commands](commands.md#at-your-terminal-komando-asks-for-what-is-missing));
scripts and AI agents get a usage error with an example.

More ways to write it:

```bash
komando host add web2 ubuntu@203.0.113.11 --group web --tag prod
komando host add web2 ubuntu@203.0.113.11:2222               # another SSH port
komando host add db1 admin@10.0.0.5 --via bastion            # reached through bastion
komando host add web2 --address 203.0.113.11 --user deploy --key deploy
```

The flags you will use most:

| Flag | What it does |
|------|--------------|
| `-g`, `--group` / `-t`, `--tag` / `--label KEY=VALUE` | Sort servers so one [target](targets.md) can pick many. |
| `--key NAME` / `--identity PATH` | Log in with a key from komando's key list (`komando key`), or with a key file. |
| `--password-ref` / `--sudo-ref` | Where the login or sudo password is kept (see [Use a password](#use-a-password)). |
| `--via bastion` | Reach the server through other servers or a VPN first ([tunnels](tunnels.md)). |
| `--protected` | Mark a production server (see [Protect a production server](#protect-a-production-server)). |
| `-e`, `--env KEY=VALUE` | Export a variable before every command on this server. |
| `--notes TEXT` | Free notes; agents see them in `host show`. |
| `--port N` | The SSH port (default 22); same as `:N` after the address. |
| `--overwrite` | Replace a server that already has this name. |

komando checks what you save: the port (1-65535), the user name, that the
address does not start with `-` (ssh would read it as an option), that
every `--via` step exists and does not loop back, and that an `--identity`
file is there. A path that names a step twice (`--via a,b,a`) stops with
`VIA_CYCLE`. A server at the same address and port as a protected one (in
another case, with a trailing `.`, or a name that resolves to the same IP)
is protected too, with a warning. `komando doctor` checks the whole list
the same way.

`komando test` tells you, per server, the login user and whether sudo works
without a password (`SUDO`). `komando facts` reports the same sudo check,
plus much more ([Health](health.md)).

Servers behind the same `--via` hosts share one connection to them within a
command: `komando exec @db -P 10` logs in to the bastion once and reaches
the ten servers through it, like OpenSSH's ControlMaster. The bastion's
connection limits (`MaxStartups`) and its login log see one client.

Already have servers in `~/.ssh/config`, or on another computer? Import
them instead ([Moving in](import.md)):

```bash
komando import ssh-config
```

### A Windows server

Add `--os windows` for a server with OpenSSH, or give a `winrm://` address
for one with WinRM. komando then runs PowerShell there. See
[Windows servers](windows.md) for setup and what works.

```bash
komando host add win1 Administrator@10.0.0.9 --os windows --ask-password
komando host add win2 winrm://Administrator@10.0.0.9 --ask-password
```

### A new server that is still starting

Right after you create or rebuild a cloud server, SSH may not answer yet.
`--wait` tests again every few seconds until every server passes:

```bash
komando test @new --wait 5m                                  # until SSH answers and the login works
komando exec @new --read-only -- cloud-init status --wait    # then: until its own start-up is done
```

It does not wait out a changed host key (`HOSTKEY_MISMATCH`) or a refused
login (`AUTH_FAILED`: retrying could get your address banned): those fail
at once. `data.waited_ms` (in `-o json`) says how long it waited.

## Add many servers from a spreadsheet

Setting up ten or twenty servers? Write them in a spreadsheet, save it as
CSV, and import it in one go. The first row names the columns:

```csv
name,address,user,port,groups,tags,sudo-ref,via,protected,notes
bastion,203.0.113.10,ubuntu,,edge,prod,secret:ubuntu-sudo,,no,
web1,10.0.0.11,ubuntu,2222,"web,ubuntu",prod,secret:ubuntu-sudo,bastion,yes,front end
web2,10.0.0.12,ubuntu,,"web,ubuntu",prod,secret:ubuntu-sudo,bastion,yes,
```

```bash
komando import csv servers.csv --dry-run      # check every row, change nothing
komando import csv servers.csv --group fleet  # add them all (and to the group fleet)
```

Only `name` and `address` are needed. The columns are `name`, `address`
(or `ip`), `user`, `port`, `key`, `identity`, `password-ref`, `sudo-ref`,
`via`, `groups` (or `role`), `tags`, `protected` (yes or no) and `notes`; a
cell with several groups or tags separates them with commas, `;` or spaces.
Each row is checked like `host add`, and rows may use each other in `via`.
komando checks every row before it writes anything: one bad row (an unknown
column, a bad port, a `via` to a server that does not exist) stops the whole
import and lists every problem. Servers that already exist are skipped;
`--overwrite` replaces them (a protected one asks first). Lines starting
with `#` are comments.

Passwords never go into the file: point `password-ref` and `sudo-ref` at
the vault (`komando secret set ubuntu-sudo` first).

## Change a server

`host edit` changes only the options you pass:

```bash
komando host edit web1 --add-tag canary --port 2222
komando host edit web1 --rm-group old --label dc=jkt         # an empty value removes a label
komando host edit web1 --unset via,sudo-ref                   # clear settings (see `--help` for the list)
```

```text
changed: web1
```

To change many servers at once, give several names or a
[target](targets.md). Every server gets the same change, and the command
changes all of them or none:

```bash
komando host edit @web --sudo-ref secret:ubuntu-sudo --dry-run   # which servers would change
komando host edit @web --sudo-ref secret:ubuntu-sudo
komando host edit web1 web2 db1 --add-tag canary
```

One yes covers the whole command. When an AI agent asks, komando's window
lists every server the command changes and which of them are protected, so
the person says yes once, knowing all of them. `--address` works on one
server only (two servers never share one).

## Protect a production server

```bash
komando host edit web1 --protected
```

On a protected server, every change on the server needs a yes. For the
entry itself, so do: changing how komando logs in (address, port, user,
key, password, `--via`), replacing a secret it uses, turning protection
off, renaming it and removing it. Tags, groups, labels and notes change
without one.

At your terminal komando asks you first
(`web1 is protected. Change it anyway? [y/N]`); an AI agent or a script
adds `--yes` after a person agrees, and an agent's `--yes` opens komando's
approval window. See [Safety](safety.md) for the details.

## Rename a server

`host rename` gives a server a new name and keeps everything else:

```bash
komando host rename web1 web-01 --dry-run   # what would change
komando host rename web1 web-01
```

The address, login, references, protected mark, groups, tags and labels
stay. Servers, conns and tunnels that go through it (`--via`), and its jobs
and tunnels, follow the new name in the same step. Pinned host keys belong
to the address, so `host trust` is not needed again. Renaming a protected
server asks first. `conn rename` and `vpn rename` do the same for conns and
VPNs, `key rename` for a key, and `group rename` for a group.

`komando rename OLD NEW` finds the kind for you: it renames the one
server, conn, VPN, secret, key or group named OLD with that kind's own
rename. When two kinds share the name, it names the two commands to pick
from.

`key rename OLD NEW` renames one key: the servers that use it follow. A key
komando made lives in the sealed store, so no file moves; a key you added
with `key add` stays where it is. Public keys already installed on servers
keep their comment; they still work, since the key itself does not change.

`group rename OLD NEW` renames a group on every member (it asks first when
a protected server or conn is in it). To merge two groups, use
`group add NEW @OLD` and then `group rm OLD`.

### Rename a whole project at once

When a project or a customer gets a new name, `rename --starts-with` renames
every server, conn, VPN, secret, key and group whose name starts with the
old prefix, in one step:

```bash
komando rename --starts-with shop- acme-shop- --dry-run   # the old -> new list per kind, and every reference
komando rename --starts-with shop- acme-shop-
komando rename --starts-with shop- acme-shop- --in-notes --in-labels --dry-run   # notes and labels too: what changes, what is kept
```

- It renames every name that starts with `shop-`. When the old prefix
  ends in `-`, the name without it is renamed too: group `shop`
  becomes `acme-shop`. `--kind host,conn` renames only some kinds.
- Every reference follows: `--via` paths (also a server in the middle
  of one, as in `shop-vpn,shop-bastion`), password, sudo, key, preshared
  key and passphrase references, `secret:NAME` options in conn URLs, the
  key a server uses, group membership, jobs and tunnels. A key komando made
  (`key gen`) lives in the sealed store, so no file moves; a key file you
  added stays where it is.
- The protected mark, labels, notes and creation time stay.
  Names inside URLs belong to the resource, not to komando, so in
  `s3://shop-admin@shop-prod` the user and the bucket stay.
- `--in-notes` also replaces old names in notes, and
  `--in-labels` in label values (label names stay). Only what clearly means
  an entry follows: server, conn, VPN and secret names as whole words, a
  group written `@shop`, and a pattern such as `shop-db-*` when it matches
  the same servers, conns and VPNs after the rename. These stay, because
  they often mean something else: the old prefix without its `-` (`db shop`
  is usually a database, not the group), group names without `@`, key
  names (`bucket shop-dev`), and a name that is also the user, host, bucket
  or database in a conn URL. The result lists each one under `kept`, with
  the reason, so you can fix it by hand.
- Without `--in-labels`, every label value that names
  an old entry stays and is listed under `kept` with what it would become.
  A conn's `host=` label matters: `komando doctor` reads it to warn when a
  conn of a protected server is not protected itself. Without `--in-notes`,
  one warning counts the notes that still name old entries.
- It renames all or nothing. Your list and the vault are each written
  once. When a new name is taken, or two old names would get one new name,
  nothing changes (`NAME_TAKEN`, with every clash listed). A connected VPN
  must go down first (`VPN_IN_USE`).
- Protected servers and conns among them need one yes for the whole
  command. An AI agent's `--yes` opens one window for a person, which says
  how many protected entries it covers. Pointing a reference at the new
  name of the same secret, key or VPN needs no yes: the same value goes to
  the same place.
- It is safe to repeat. When the new prefix starts with the old one
  (`team-` to `team-ops-`), names that have the new prefix already are left
  alone, so a second run changes nothing.

## Remove a server

`host rm` removes servers from komando's list. It does not touch the server
itself. It takes names or a [target](targets.md):

```bash
komando host rm @old --dry-run         # list what would be removed
komando host rm web2
komando host rm 'tmp-*'
```

A protected server asks first. A server that another server still reaches
through `--via` is kept (`HOST_IN_USE`, which lists every one of them).
`conn rm` works the same way for databases, caches and storage.

`host rm` does not forget a server's pinned host key (see
[Server keys](#server-keys-host-keys)).

## Log in with a key

If `ssh` already works on this computer, komando usually works too: it uses
the same keys (files like `~/.ssh/id_ed25519`, and the ssh-agent that holds
unlocked keys).

A key with a passphrase works while ssh-agent holds it (after `ssh-add`, or
from the macOS Keychain), also when it is the server's `--key` or
`--identity` (which `import ssh-config` sets from `IdentityFile`): komando
finds the agent's copy by its public key, as `ssh` does. When the agent
does not hold it, the server fails with `KEY_PASSPHRASE_REQUIRED`, and the
hint says how to load it or keep its passphrase in the vault.

To use a new key, create it and install it on your servers. komando logs in
with the servers' current login (for example a password) to install it:

```bash
komando key gen deploy                           # ed25519; --type rsa|ecdsa, -b BITS, -C COMMENT
komando key deploy deploy @web --set-default     # install it, then log in with it
komando key deploy ~/.ssh/id_ed25519.pub web1    # a .pub file works too
komando key list                                 # NAME TYPE FINGERPRINT USED BY
komando key show deploy                          # the public part (never the private key)
```

Keys made with `key gen` are sealed in komando's store (`store.db`); they
are never written to a file. `host ssh-command` hands one to the running
ssh-agent when another program needs it. RSA keys need at least 3072 bits.

To use a key file you already have, add it to komando's key list. The file
stays where it is. If it has a passphrase, store the passphrase in the vault first:

```bash
komando secret set work-pass
komando key add work ~/.ssh/id_work --passphrase-ref secret:work-pass
komando key edit work --passphrase-ref secret:new-pass      # change it later (--unset passphrase-ref clears it)
```

`komando key rm NAME` takes a key out of komando's key list; it refuses
while servers still use it (`KEY_IN_USE`). `--delete-file` also deletes the
key itself, but only for keys komando made (it removes the sealed record; a
key added with `key add` stays on disk). Such a key has no copy, so at your
terminal you type the key's name; an AI agent or a script adds
`--allow-dangerous` after a person agrees.

To replace a key everywhere, in order, see [Rotate keys and passwords](rotate.md).

## Remove a key from servers

When someone leaves, or a key is replaced, remove it everywhere at once.
`key revoke` takes a key from komando's key list, a `.pub` file, or the key
line itself:

```bash
komando key revoke ~/keys/alice.pub @web --dry-run   # how many lines per server
komando key revoke ~/keys/alice.pub @web
komando key revoke old-deploy @web --user deploy     # another user's file (uses sudo)
```

The `authorized_keys` file keeps its owner and mode. Revoking the key
komando itself logs in with needs `--allow-dangerous`, because you would
lock yourself out.

## Use a password

At your terminal, komando asks for the password when the server wants one,
as `ssh` does (`web1: Password:`, hidden as you type). Store it once to skip
the question, and so that AI agents and scripts can log in: they have no
one to ask. You type it, nothing is shown, and it is saved encrypted in
komando's vault (see [Secrets](secrets.md)). In one step, while adding the
server or later:

```bash
komando host add web2 root@203.0.113.20 --ask-password   # stored as secret:web2-pass
komando host edit web1 --ask-password                     # a new password (stored as secret:web1-pass)
```

`--ask-password` is for a person at a terminal (an AI agent asks you to run
it). It never replaces a secret that another server or conn uses. The same
in two steps, with a name you choose:

```bash
komando secret set web1-pass
komando host edit web1 --password-ref secret:web1-pass
```

A `--password-ref secret:NAME` whose secret is not in the vault yet gets a
warning right away, with the `secret set` command that stores it.

The password goes to the server's address on every login. So when an AI
agent gives a server or conn a password reference, or moves one that has
one to another address, port or `--via` path, a person allows it in
komando's window (`SECRET_DESTINATION`); see [Safety](safety.md#seatbelts-for-ai-agents).

komando sends the stored password at most once per login, and only when the
server asks for a password (hidden as you type); a refused one is not sent
again, so a wrong password in the vault cannot lock the account.

### Two-factor logins

When a server also asks for a one-time code (or any
other question), komando shows you the server's question with its name
(`web1: Verification code:`) and sends what you type, hidden unless the
server lets it show. Servers that log in at once (`komando exec @web`) ask
one at a time. Ctrl-C stops the login (`CANCELLED`). Only a person at a
terminal is asked: for an AI agent or a script the login stops with
`AUTH_FAILED`, the message quotes the server's question, and no wrong code
counts against the account. The agent asks you to log in once for it:

```bash
komando login web1        # type the password and the code once
komando logout web1       # end it sooner
```

`komando login` asks what the server asks and then keeps that login open
in the background for 8 hours (the `login_for` setting). Every command to
web1 uses it, your AI agent's too, so nobody types a code again until it
ends; komando's rules, approvals and audit still apply to each command.
A login to a jump host is used for every server behind it. `komando status`
lists the kept logins, and a login ends early when the server closes it or
its address changes.

Only a person at a terminal can run `komando login`; an AI agent's
`komando login web1 --dry-run` shows the plan (`would_log_in: false`, and
`meta.would_be_blocked` names `NEEDS_TERMINAL`).

### Sudo passwords and the vault

If `sudo` asks for a password on the server, store that too:

```bash
komando secret set web1-sudo
komando host edit web1 --sudo-ref secret:web1-sudo
```

Everything else about the vault (listing, checking, renaming and removing
secrets, and where its key is kept) is on one page: [Secrets](secrets.md).

## Passwords from your password manager

Every `--password-ref` and `--sudo-ref` (for servers, conns and VPNs) can
also point at an environment variable, a file, or the password manager your
team already uses:

| Reference | Reads it from | Login it uses |
|-----------|---------------|---------------|
| `secret:NAME` | komando's vault (`komando secret set NAME`) | none needed |
| `env:VAR` | an environment variable | none needed |
| `file:PATH` | a file | none needed |
| `vault:secret/shop#db_password` | HashiCorp Vault or OpenBao, KV v1 or v2 | `VAULT_ADDR` and `VAULT_TOKEN` (or `~/.vault-token`; OpenBao's `BAO_ADDR`, `BAO_TOKEN`, `~/.bao-token` work too), `VAULT_NAMESPACE`, `VAULT_CACERT` |
| `aws-sm:shop/db#password` | AWS Secrets Manager; `#key` picks a JSON field | your AWS login (`AWS_PROFILE`, `~/.aws`, SSO via `komando login aws`) |
| `gcp-sm:db-pass@my-project` | Google Secret Manager, latest version | Google application-default credentials (`GOOGLE_APPLICATION_CREDENTIALS`, or on Google Cloud) |
| `azure-kv:shop-vault/db-password#password` | Azure Key Vault, current version (`/VERSION` after the name picks another); `#key` picks a JSON field | a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), a workload identity on AKS (`AZURE_FEDERATED_TOKEN_FILE`), the Azure CLI's saved token, or the managed identity on Azure |
| `bw://shop-db/password` | Bitwarden or Vaultwarden; the field is `password`, `username`, `notes`, `uri`, `totp` or a custom field | `KOMANDO_BW_EMAIL`, `KOMANDO_BW_PASSWORD` (decrypts the vault here), `KOMANDO_BW_SERVER` for Vaultwarden or bitwarden.eu, optional API key `KOMANDO_BW_CLIENT_ID`/`KOMANDO_BW_CLIENT_SECRET` |
| `kdbx:~/team.kdbx#Servers/web1` | a KeePass or KeePassXC file (KDBX 3.1 and 4); `#UserName` or another field after the entry | `KOMANDO_KDBX_PASSWORD` and/or `KOMANDO_KDBX_KEYFILE` |
| `op://Vault/Item/field` | 1Password, through a 1Password Connect server | `OP_CONNECT_HOST`, `OP_CONNECT_TOKEN` |

```bash
komando conn add prod-db postgres://app@10.0.0.5/shop --password-ref vault:secret/shop#db_password
```

komando talks to Vault, AWS, Google, Azure, Bitwarden, KeePass files and
1Password Connect itself: you do not need the `vault`, `aws`, `gcloud`, `az`,
`bw` or `op` programs. It reads the value only when it needs it and never
stores it. The login (and any MFA) stays with you.

**Azure Key Vault.** Write `azure-kv:VAULT/NAME`, where `VAULT` is the
vault's name (`shop-vault` for `shop-vault.vault.azure.net`) or, in another
Azure cloud, its whole host name (`shop-vault.vault.azure.cn`). komando
tries these logins in order:

1. a service principal: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
   `AZURE_CLIENT_SECRET`;
2. a workload identity on AKS: `AZURE_TENANT_ID`, `AZURE_CLIENT_ID` and
   `AZURE_FEDERATED_TOKEN_FILE`;
3. a token the Azure CLI saved on this computer (Linux and macOS), while it
   lasts: after `az login`, run
   `az account get-access-token --resource https://vault.azure.net` and
   komando can use that token for about an hour. komando does not run `az`
   and cannot renew the token;
4. the managed identity of the Azure machine komando runs on
   (`AZURE_CLIENT_ID` picks a user-assigned one).

The login needs the "Key Vault Secrets User" role on the vault, or an access
policy that allows Get on secrets.

## Servers with no open SSH port (AWS SSM, GCP IAP, Cloudflare)

Some servers are reached through a cloud tool instead of a plain SSH port.
Give komando that tool's command, as in OpenSSH's `ProxyCommand` (`%h` is the
address, `%p` the port, `%r` the user):

```bash
komando host add web1 ec2-user@i-0abc123 --ssm     # AWS Systems Manager: the address is the instance ID
komando host add web2 me@web2 --proxy-command 'gcloud compute start-iap-tunnel %h %p --listen-on-stdin --zone europe-west1-b'
komando host add db1 me@ssh.example.com --proxy-command 'cloudflared access ssh --hostname %h'
komando conn add prod-db postgres://app@mydb.xyz.rds.amazonaws.com/app --via web1   # a database behind it
```

A `--proxy-command` tool must be installed and logged in on this computer.
On Windows the command runs in cmd.exe, so write it for cmd.exe. A proxy
command runs on this computer, so an AI agent needs a person's yes to add
or import one.

For `--ssm`, komando speaks AWS Session Manager itself when the aws CLI or
its session-manager-plugin is not installed. It uses your usual AWS login
(`komando login aws` for SSO). Set `KOMANDO_EXPERIMENTAL=ssm` to use the
built-in client even when they are installed. Sessions that your account
encrypts with KMS work too: komando asks KMS for the session key with your
login, so that login needs `kms:GenerateDataKey` on the key, as the plugin
does.

## Server keys (host keys)

The first time komando connects to a server, it remembers the server's key
(its fingerprint) in its own `known_hosts`. If the key changes later,
komando refuses to connect (`HOSTKEY_MISMATCH`), because someone may be
pretending to be your server.

That first time, nothing proves the key is really your server's. komando
says on stderr which key it trusted:

```text
komando: first connection to web1 (203.0.113.10:22): trusted its ssh-ed25519 host key SHA256:pVt2...
```

The audit log keeps it too (`host.key-pinned` in `komando audit`), and the
JSON answer lists it in `meta.host_keys_pinned`, so an AI agent can show
it to you. Compare that fingerprint with the server's own: run
`ssh-keygen -lf /etc/ssh/ssh_host_ed25519_key.pub` on the server's console,
or look in your cloud console (many show the host key fingerprints in the
first boot log). If they differ, stop using the server and ask whoever
runs it: someone may be in between.

### Replace a key after a rebuild

After a real rebuild, check the new fingerprint another way (your cloud
console or the server's own console), then replace the old key:

```bash
komando host trust web1 --reset --dry-run   # how many pinned keys would go
komando host trust web1 --reset             # shows the old and new key, asks once
```

Only a person at a terminal replaces a pinned key: komando shows the old
and the new fingerprint and asks once. An AI agent or a script gets
`NEEDS_PERSON` (exit 6) whatever flags it adds, because an agent that
re-pins the key could be talking to an impostor; its hint names the
command for you to run. Without `--reset`, `host trust` never adds a
second key: a different key stops with `HOSTKEY_MISMATCH`, and a server
that cannot be reached keeps its old key.

After you rebuild a whole group (same addresses, new keys), give `host
trust` the group instead of one name. It takes every kind of target, like
`exec`: `@group`, `tag:`, `'web*'` or `a,b`.

```bash
komando host trust @web                 # new servers get pinned; changed keys are refused
komando host trust @web --reset         # after the rebuild: one yes for all of them
```

`data.results` (in `-o json`) lists every server with its new `fingerprint`
and, when the key changed, its `old_fingerprints`. With `--reset` you answer
once: the question names every server whose key changes, with the start of
its new fingerprint. Compare them with your cloud console first.

`komando host rm` does not forget a server's key. If you remove a server
and add it again at the same address, it must still show the same key, so
`rm` plus `add` is no way around `HOSTKEY_MISMATCH`. `host rm` says which
keys it kept (`host_keys_kept`); after a rebuild, replace them with `host
trust --reset`.

### Pin a key before the first connection

`komando host trust web1` (without `--reset`) pins a key before the first
connection; the same key again changes nothing. The key is fetched the way
komando reaches the server: directly, or through its `--via` path, VPN or
proxy command.

To check every new server before komando uses it, refuse unknown keys and
pin them one by one, comparing the `fingerprint` in each answer with the
server's own first:

```bash
komando config set host_key_policy strict   # unknown keys stop with HOSTKEY_UNKNOWN
komando host trust web1                     # data.results[0] has key_type and fingerprint
```

`HOSTKEY_UNKNOWN` says which fingerprint the server shows. With `strict`,
an AI agent cannot pin a first key by itself: `host trust` needs your yes in
komando's window, which shows the fingerprint to compare (with the default
`accept-new` the first login pins it anyway).

## Use OpenSSH with the same settings

`host ssh-command` prints the `ssh` command that reaches a server with the
same address, user, key, `known_hosts` file and `--via` path komando uses:

```bash
komando host ssh-command web1
$(komando host ssh-command web1 -o text)      # open a shell with OpenSSH
```

Servers behind `--via` get one `ProxyCommand` per hop, so each hop uses its
own key. A SOCKS VPN becomes `nc -X 5`. VPNs that run inside komando cannot
be used by OpenSSH; use `komando shell SERVER` for those.

A key made with `komando key gen` is sealed in komando's store and is never
written to a file. For OpenSSH, `host ssh-command` gives it to the ssh-agent
your shell already runs (`SSH_AUTH_SOCK`), which keeps it for one hour, and
the printed line picks it with its public key. With no ssh-agent it stops
with `SSH_AGENT_NEEDED`: start one with `eval "$(ssh-agent)"`, or use
`komando shell SERVER`.

Only a person at a terminal can run `host ssh-command`: it writes a copy of
the pinned host keys for OpenSSH. An AI agent gets `NEEDS_PERSON` and is
told to use `komando exec` or `komando shell`.

## Limits

- A server name uses letters, digits, `.`, `_` and `-` (see
  [Targets](targets.md#limits)). A server cannot be named `aws`, `gcp` or
  `azure`: `komando login aws` is the AWS login.
- `--address` in `host edit` works on one server only.
- A key file added with `key add` is never moved or deleted by komando.
- `--ask-password`, `komando login`, `host ssh-command` and replacing a
  pinned host key (`host trust --reset`) need a person at a terminal.
- `op://` reads 1Password only through a 1Password Connect server: the
  1Password CLI is closed source, and komando uses only open-source parts.
- The Azure CLI's saved token works for about an hour; komando does not run
  `az` and cannot renew it.
- A server that another server reaches through `--via` cannot be removed
  until those servers change.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `AUTH_FAILED` | the server refused the login, or asked a question (a two-factor code) with no person at a terminal | check the user and password; for a code, run `komando login SERVER` once |
| `KEY_PASSPHRASE_REQUIRED` | the key is encrypted and no ssh-agent holds it | `ssh-add PATH`, or store its passphrase and use `--passphrase-ref` |
| `HOSTKEY_MISMATCH` | the server shows another host key than the pinned one: rebuilt, or someone is in between | check the fingerprint another way; after a real rebuild, `komando host trust SERVER --reset` in your own terminal |
| `HOSTKEY_UNKNOWN` | `host_key_policy` is `strict` and this key is not pinned yet | compare the fingerprint, then `komando host trust SERVER` |
| `HOST_IN_USE` | another server reaches this one through `--via` | change their `--via` first, or remove them in the same command |
| `VIA_CYCLE` | the `--via` path leads back to itself, or names a step twice | name each server or VPN once, and not the server itself |
| `NAME_TAKEN` | a rename would give two entries one name | pick other names, or rename or remove what is in the way |
| `VPN_IN_USE` | a rename needs a connected VPN to go down | `komando vpn down NAME` first |
| `KEY_IN_USE` | `key rm` on a key a server still uses | give the server another key: `komando host edit SERVER --key OTHER` |
| `KEY_EXISTS` | `key gen`, `key add` or `key rename` to a name that is taken | choose another name, or `komando key rm NAME` first |
| `SECRET_DESTINATION` | an AI agent asked to send a password to a server | a person allows it in komando's window |
| `SECRET_UNRESOLVED` | komando could not read a reference (no login for the password manager, or no such secret) | follow the hint: it names the logins that work |
| `SSH_AGENT_NEEDED` | `host ssh-command` for a key komando made, with no ssh-agent running | `eval "$(ssh-agent)"`, or use `komando shell SERVER` |
| `NEEDS_PERSON` | only a person at a terminal can do this (`host trust --reset`, `host ssh-command`) | run the command in your own terminal |
| `NEEDS_TERMINAL` | `komando login` without a person at a terminal | a person runs `komando login SERVER` |
| `IMPORT_INCOMPLETE` | some servers were not imported (listed under `skipped`) | fix them in the source and import again |
