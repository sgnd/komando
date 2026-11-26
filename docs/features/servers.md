# Servers

Add your servers, choose how komando logs in to them, and keep the list
tidy. [All docs](README.md)

## Add a server

Save how to log in as a credential, then give each server a short name and
its address. The user name lives in the credential:

```bash
komando credential password add admin-web --user ubuntu
komando host ssh add web1 203.0.113.10 --credential admin-web
komando test web1                                # can komando log in?
```

```text
added web1
  address: 203.0.113.10
  credential: admin-web
Next: komando test web1 · komando host ssh show web1
```

```text
NAME  TYPE  RESULT  LATENCY  USER    SUDO  NOTE
web1  host  ok      48ms     ubuntu  yes   -
```

Typed alone at your terminal, `komando host ssh add` asks for each part,
one line at a time: a name, the address, the port, which credential logs
in, and whether it is production. Any command typed with an argument
missing asks for it the same way (see
[Running commands](commands.md#at-your-terminal-komando-asks-for-what-is-missing));
scripts and AI agents get a usage error with an example.

More ways to write it:

```bash
komando host ssh add web2 203.0.113.11 --credential admin-web --group web --tag prod
komando host ssh add web2 203.0.113.11:2222 --credential admin-web   # another SSH port
komando host ssh add db1 10.0.0.5 --credential admin-web --via bastion   # reached through bastion
```

The flags you will use most:

| Flag | What it does |
|------|--------------|
| `-g`, `--group` / `-t`, `--tag` / `--label KEY=VALUE` | Sort servers so one [target](targets.md) can pick many. |
| `--credential NAME` | The credential komando logs in with: a password, or a key from komando's key list (`komando credential key`). It holds the user name too (see [Log in with a key](#log-in-with-a-key) and [Use a password](#use-a-password)). |
| `--sudo-credential NAME` | The credential that holds the sudo password (see [Sudo passwords](#sudo-passwords)). |
| `--via bastion` | Reach the server through other servers or a VPN first ([tunnels](tunnels.md)). |
| `--protected` | Mark a production server (see [Protect a production server](#protect-a-production-server)). |
| `-e`, `--env KEY=VALUE` | Export a variable before every command on this server. A value from the vault (`KEY=credential:NAME`) is left out of an AI agent's commands: the agent could read it back unmasked (`printenv KEY \| rev`). It goes to an agent's `exec` only when the agent adds `--yes` and you allow it in komando's window. |
| `--notes TEXT` | Free notes; agents see them in `host ssh show`. |
| `--port N` | The SSH port (default 22); same as `:N` after the address. |
| `--overwrite` | Replace a server that already has this name. |

<!-- TODO(cut): logging in with ssh-agent and the keys in `~/.ssh` alone, with no credential, waits on the leaf Options of `host ssh add` (PR B). -->

komando checks what you save: the port (1-65535), that the address does not
start with `-` (ssh would read it as an option), and that every `--via` step
exists and does not loop back. A path that names a step twice
(`--via a,b,a`) stops with `VIA_CYCLE`. A server at the same address and
port as a protected one (in another case, with a trailing `.`, or a name
that resolves to the same IP) is protected too, with a warning.
`komando doctor` checks the whole list the same way.

`komando test` tells you, per server, the login user and whether sudo works
without a password (`SUDO`).

Servers behind the same `--via` hosts share one connection to them within a
command: `komando host ssh exec @db -P 10` logs in to the bastion once and
reaches the ten servers through it, like OpenSSH's ControlMaster. The
bastion's connection limits (`MaxStartups`) and its login log see one
client.

komando does not read `~/.ssh/config` and has no spreadsheet import. Add
each server with its own `host ssh add`. Moving to another computer: export
your list and import it there ([Moving computers](import.md)).

### A Windows server

Add `--os windows` to a server with OpenSSH, or add it under the `winrm`
provider for one with WinRM. komando then runs PowerShell there. See
[Windows servers](windows.md) for setup and what works.

```bash
komando host ssh add win1 10.0.0.9 --os windows --credential admin-win
komando host winrm add win2 10.0.0.9 --credential admin-win
```

### A new server that is still starting

Right after you create or rebuild a cloud server, SSH may not answer yet.
`--wait` tests again every few seconds until every server passes:

```bash
komando test @new --wait 5m                                              # until SSH answers and the login works
komando host ssh exec @new --read-only -- cloud-init status --wait       # then: until its own start-up is done
```

It does not wait out a changed host key (`HOSTKEY_MISMATCH`) or a refused
login (`AUTH_FAILED`: retrying could get your address banned): those fail
at once. `data.waited_ms` (in `-o json`) says how long it waited.

## Change a server

`host ssh edit` changes only the options you pass:

```bash
komando host ssh edit web1 --port 2222 --label dc=jkt           # an empty label value removes the label
komando host ssh edit web1 --unset via                          # clear a setting (see `--help` for the list)
```

```text
changed: web1
Next: komando host ssh show web1 · komando test web1
```

<!-- TODO(cut): the flags that add and remove tags and groups on `edit` wait on the leaf Options of the table (PR B). Put servers in a group with `komando group edit`. -->

To change many servers at once, give several names or a
[target](targets.md). Every server gets the same change, and the command
changes all of them or none:

```bash
komando host ssh edit @web --sudo-credential ubuntu-sudo --dry-run   # which servers would change
komando host ssh edit @web --sudo-credential ubuntu-sudo
komando host ssh edit web1 web2 db1 --label team=ops
```

One yes covers the whole command. When an AI agent asks, komando's window
lists every server the command changes and which of them are protected, so
the person says yes once, knowing all of them. `--address` works on one
server only (two servers never share one).

## Protect a production server

```bash
komando host ssh edit web1 --protected
```

On a protected server, every change on the server needs a yes. For the
entry itself, so do: changing how komando logs in (address, port,
credential, `--via`), replacing a credential it uses, turning protection
off, renaming it and removing it. Tags, groups, labels and notes change
without one.

At your terminal komando asks you first
(`web1 (protected): this command changes it. Continue? [y/N]`); an AI agent or a script
adds `--yes` after a person agrees, and an agent's `--yes` opens komando's
approval window. See [Safety](safety.md) for the details.

## Rename a server

`host ssh rename` gives a server a new name and keeps everything else:

```bash
komando host ssh rename web1 web-01 --dry-run   # what would change
komando host ssh rename web1 web-01
```

The address, credential, protected mark, groups, tags and labels stay.
Entries and tunnels that go through it (`--via`) follow the new name in the
same step. Pinned host keys belong to the address, so `host ssh trust` is
not needed again. Renaming a protected server asks first. Every provider
has its own `rename` (`database postgres rename`, `vpn wireguard rename`),
and so do `credential KIND rename` and `group rename`.

`credential key rename OLD NEW` renames one key: the servers that use it
follow. A key komando made lives in the sealed store, so no file moves; a
key you added with `credential key add` stays where it is. Public keys
already installed on servers keep their comment; they still work, since the
key itself does not change.

`group rename OLD NEW` renames a group on every member (it asks first when
a protected entry is in it). To merge two groups, add the members of one to
the other with `group edit NEW --add NAME,NAME` and then run
`group remove OLD`.

komando has no bulk rename of a whole project at once (`--starts-with`,
`--in-notes`, `--in-labels`). Rename each entry with its own `rename`. This
is a recorded loss.

## Remove a server

`host ssh remove` takes servers out of komando's list. It does not touch
the server itself. It takes names or a [target](targets.md):

```bash
komando host ssh remove @old --dry-run         # list what would be removed
komando host ssh remove web2
komando host ssh remove 'tmp-*'
```

A protected server asks first. A server that another server still reaches
through `--via` is kept (`HOST_IN_USE`, which lists every one of them).
`remove` works the same way on every provider (`database postgres remove`,
`cache redis remove`, ...).

`host ssh remove` does not forget a server's pinned host key (see
[Server keys](#server-keys-host-keys)).

## Log in with a key

If `ssh` already works on this computer, komando usually works too: it uses
the same keys (files like `~/.ssh/id_ed25519`, and the ssh-agent that holds
unlocked keys).

A key with a passphrase works while ssh-agent holds it (after `ssh-add`, or
from the macOS Keychain): komando finds the agent's copy by its public key,
as `ssh` does. When the agent does not hold it, the server fails with
`KEY_PASSPHRASE_REQUIRED`, and the hint says how to load it.

To use a new key, create it and install it on your servers:

```bash
komando credential key create deploy --user ubuntu   # ed25519; -b BITS, -C COMMENT
komando credential key list                          # NAME TYPE FINGERPRINT USED BY
komando credential key show deploy                   # the public part
komando host ssh edit @web --credential deploy       # log in with it
```

A key made with `credential key create` is sealed in komando's store
(`store.db`); it is never written to a file and never shown. RSA keys need
at least 3072 bits.

To put a public key on a server, for yourself or for someone else:

```bash
komando credential key install web1 --user alice --public-key-file ~/keys/alice.pub
komando credential key install web1 --user alice --public-key-file ~/keys/alice.pub --from-address 203.0.113.50
```

The key goes into `authorized_keys` of that user; `--from-address` limits
it to logins from one address. It adds a way to log in that komando did not
make, so only a person at a terminal runs it. An AI agent gets
`NEEDS_PERSON` and the hint names the command for you to run.

To use a key file you already have, add it to komando's key list. The file
stays where it is. The credential holds the user it logs in as and its
passphrase:

```bash
komando credential key add work ~/.ssh/id_work --user ubuntu
komando host ssh edit web1 --credential work
```

<!-- TODO(cut): the arguments of `credential key add` (the file), the `--type` of `credential key create`, how a key's passphrase is given, and how a key komando made is installed on servers (the form of `credential key install` without a public-key file, and `--set-default`) wait on the leaf Options of the table (PR B). -->

`komando credential key remove NAME` takes a key out of komando's key list;
it refuses while servers still use it (`KEY_IN_USE`). `--delete-file` also
deletes the key itself, but only for keys komando made (it removes the
sealed record; a key added from a file stays on disk). Such a key has no
copy, so at your terminal you type the key's name; an AI agent or a script
adds `--allow-dangerous` after a person agrees.

To replace a key everywhere, in order, see [Rotate keys and passwords](rotate.md).

### Keys with a certificate

Where servers trust a certificate authority (SSH CA, `TrustedUserCAKeys`)
instead of each key, komando logs in with the key's OpenSSH user
certificate, as `ssh` does: `KEY-cert.pub` next to a key file is offered
first, then the key alone. For a certificate kept elsewhere, or for a key
komando made, name it:

```bash
komando credential key add corp ~/.ssh/id_corp --user ubuntu --cert ~/certs/id_corp-cert.pub
komando credential key edit deploy --cert ~/Downloads/deploy-cert.pub   # --unset cert goes back to KEY-cert.pub
```

komando reads the certificate at each login, so a renewed file is used at
once. A certificate for another key is refused (`KEY_INVALID`); one that is
not valid now is left out (`credential key add` warns), and the key alone
is offered. An ssh-agent that holds a certificate offers it too.

### Servers with a host certificate

Where servers have host keys signed by a certificate authority (an
`@cert-authority` line in `known_hosts`), trust the CA once instead of
pinning each server:

```bash
komando credential certificate add corp --key ~/corp-host-ca.pub --hosts '*.corp.example' --dry-run   # the servers it matches now
komando credential certificate add corp --key ~/corp-host-ca.pub --hosts '*.corp.example'
komando credential certificate add corp --from ~/.ssh/known_hosts   # its @cert-authority lines
komando credential certificate list
komando credential certificate remove corp
```

<!-- TODO(cut): the options of `credential certificate add` (`--key`, `--hosts`, `--from`) wait on the leaf Options of the table (PR B). -->

A server whose name a CA's patterns match is asked for its host certificate
first. A pin always wins: a pinned server's key, plain or inside a
certificate, must match its pin, or the connection stops with
`HOSTKEY_MISMATCH`. For a server with no pin, the certificate is trusted,
with no pin, when the CA signed it, the
name komando dials is among its names and it is valid now. Any other
certificate falls back to its plain key and the pins. With
`host_key_policy strict` a trusted certificate counts as known. A server
whose credential is made with `--ask` is never trusted through a CA: a
typed password goes only where a person met the key.

A pattern names at least the domain: `*.corp.example`, `web*.corp.example`,
`10.1.2.*`. `*`, `*.*`, `*.com` and any other public suffix, such as
`*.co.uk` or `*.github.io`, are refused (`CA_HOSTS_INVALID`). A certificate
that names no server is refused. Names match whatever their case and one
trailing dot.
Adding a CA trusts every server it ever signs, so only a person at a
terminal can add one (`NEEDS_PERSON`); an AI agent may preview it with
`--dry-run` and remove a CA, which only narrows trust.

`credential certificate remove` only drops a CA from komando's list. A
signed key that was stolen cannot be cut off by itself: komando has no
never-trust list for a key (an `@revoked` line). The workaround is to
remove the CA and sign every key again. This is a recorded loss and a
security gap.

### Lend a jump host your ssh-agent

Some work needs your keys on the server itself, for example a `git pull`
there over SSH, or a hop that komando does not make. `--forward-agent`
lends the server the keys in your ssh-agent while komando is connected, as
`ssh -A` does:

```bash
komando host ssh edit bastion --forward-agent        # asks first
komando host ssh edit bastion --unset forward-agent  # stop lending it
```

Anyone who is root on that server can use your keys while komando is
connected to it, so it is off by default, set per server, and turning it
on asks you first (`SAFETY_SETTING`; an AI agent needs your yes in the
window). Your agent holds only the keys you added to it (`ssh-add`); keys
komando keeps sealed are never in it.

### Security keys (FIDO2)

A key on a security key (YubiKey, SoloKey, made with `ssh-keygen -t
ed25519-sk` or `-t ecdsa-sk`) is signed by the device, so komando uses it
through ssh-agent, as `ssh` does:

```bash
ssh-add ~/.ssh/id_ed25519_sk                                    # touch the key when it blinks
komando credential key add yubikey ~/.ssh/id_ed25519_sk --user ubuntu   # reads the public key from id_ed25519_sk.pub
komando host ssh edit web1 --credential yubikey
```

At each login the key asks for a touch. Without ssh-agent holding it, the
server fails with `KEY_PASSPHRASE_REQUIRED` and the hint says to `ssh-add`
it. Keep `id_ed25519_sk.pub` next to the key file: komando finds the key in
the agent by it.

## Remove a key from servers

When someone leaves, or a key is replaced, remove it everywhere at once.
`credential key uninstall` takes a public key out of the `authorized_keys`
of the servers you name:

```bash
komando credential key uninstall @web --user alice --public-key-file ~/keys/alice.pub --dry-run   # how many lines per server
komando credential key uninstall @web --user alice --public-key-file ~/keys/alice.pub
```

<!-- TODO(cut): the arguments of `credential key uninstall` (which key, which user, and a form that looks in every user's file) wait on the leaf Options of the table (PR B). -->

The `authorized_keys` file keeps its owner and mode, and is read and written
as its own user. Removing a key cannot be undone, so at your terminal you
type the key's name; an AI agent or a script adds `--allow-dangerous` after
a person agrees. Removing the key komando itself logs in with would lock
you out: check with `--dry-run` first.

## Use a password

At your terminal, komando asks for the password when the server wants one,
as `ssh` does (`web1: Password:`, hidden as you type). Save it once as a
credential to skip the question, and so that AI agents and scripts can log
in: they have no one to ask. You type it, nothing is shown, and it is saved
encrypted in komando's vault (see [Credentials](credentials.md)):

```bash
komando credential password add web2-pass --user root
komando host ssh add web2 203.0.113.20 --credential web2-pass
komando host ssh edit web1 --credential web2-pass         # or point a server you have already added at it
```

A `--credential` whose credential is not in the vault yet gets a warning
right away, with the `credential password add` command that stores it.

The password goes to the server's address on every login. So when an AI
agent gives a server a credential, or moves one that has one to another
address, port or `--via` path, a person allows it in komando's window
(`SECRET_DESTINATION`); see [Safety](safety.md#seatbelts-for-ai-agents).

komando sends the stored password at most once per login, and only when the
server asks for a password (hidden as you type); a refused one is not sent
again, so a wrong password in the vault cannot lock the account.

### Type the password each time (`--ask`)

Some passwords should never be kept on a laptop. A credential made with
`--ask` stores nothing: a person types the password whenever komando
connects, and it is used for that one command only.

```bash
komando credential password add web2-pass --user root --ask    # never stored
komando host ssh add web2 203.0.113.21 --credential web2-pass
komando host ssh edit web1 --credential admin-web               # back to a stored password
```

Who types it, and where:

- **You, at a terminal**: komando asks `web1: Password:` (hidden) when the
  server wants it, after any key, as `ssh` does.
- **An AI agent's command**: komando opens its own window on your screen.
  It names the agent, the server as `user@address:port`, the way komando
  dials there (a VPN, each jump host with its address, a proxy command)
  and the command (or says the command is hidden), and you type the
  password there. The
  agent never sees it. Every command that connects asks, even one that
  only looks (`komando test`). If you press Cancel the command
  stops with `DECLINED`, and the window stays shut for that server for a
  minute (a rename does not reopen it) (later commands get `DECLINED` at once), so an agent cannot ask
  again and again. With no screen (an SSH session, `KOMANDO_NO_DIALOG=1`,
  `ssh-gate`) it stops with `NEEDS_PERSON`.
- **A script** (no terminal): `NEEDS_PERSON`. Nobody can type it.
- **An app** that runs komando gets the same question in its own window.

The password goes to whatever answers at the end of the way there. If an
AI agent could choose that way, it could send you to a server it controls
and catch what you type, while the window still names the right server.
So komando keeps the way in your hands:

- **Only you set where it goes.** An AI agent that adds a server with an
  `--ask` credential, points a server at one, changes its address, port,
  `--via` path, proxy command, WinRM transport or its `tls=`, `ca=` or
  `auth=`, or changes a server or VPN on its way (a jump host's address, a
  VPN's server; also through `vpn PROVIDER add --overwrite`, or replacing
  the credential that holds an OpenVPN profile), or gives one another way
  at run time stops with `NEEDS_PERSON`. A server with no user logs in as
  the account komando runs as, taken from the system, never from `$USER`,
  which an agent can set. No flag lifts it: run that command in your own
  terminal if you want it. A dry run is never blocked and names the stop
  in `meta.would_be_blocked`. Other edits (tags, notes, groups) go on.
- **A key you have not logged in with needs you.** The first connection
  to a server with an `--ask` credential, whose host key komando has not
  seen yet, needs a person at a terminal: an AI agent's command stops with
  `NEEDS_PERSON`, opens no window and pins nothing. Run
  `komando test web1` (or any command) at your terminal once: komando
  prints the new key to compare, then asks the password. A pinned key is
  not enough on its own: komando pins keys by address, and an agent can
  pin whatever answers at an address through any server it adds there.
  So the typed password goes only to a key you have logged in to this
  server with; a key pinned some other way counts as a first connection
  (`nobody has logged in to web1 ... with a typed password yet`). A
  rename keeps what you met; `host ssh trust --reset` forgets it. An app's
  window warns on a first connection or login. The same holds while
  `host_key_policy` is `off`, and for a WinRM server with `tls=off` or
  `tls=skip-verify`: nothing checks who answers there.
- **The login's background process is yours.** An AI agent cannot do the
  person step of `komando test`, nor start its background process itself
  (both `NEEDS_PERSON`), whose questions it would answer as if it were
  you.

One command asks once per server: `komando host ssh exec @web -P 10` asks
each such server once, and a jump host once for every server behind it.
A password the server refuses is not sent again: the command forgets it,
and the next connection (in the same command or the next one) asks
again. The typed password is hidden in all output (`[hidden]`), never
written to disk, the audit log or a program's environment. komando zeroes
its own copy when the command ends; copies the SSH library made cannot be
zeroed and go when the command's process ends.

To type it once for a while instead, run `komando test web1` (below):
every command, an AI agent's too, uses that login until it ends, and
nobody is asked. A server that prints the password back cannot be masked
then: the command that uses the login never had it. A tunnel runs in the
background, so `komando host ssh tunnel start` asks now and hands the
password to the tunnel's process on its input; that process keeps it in
memory for the tunnel's whole life (its reconnects), until the tunnel
stops. `host ssh tunnel start` asks only for servers you have logged in to with
the key pinned for them: the background process could show a new key to
nobody.

Pointing a server at another credential unlinks the old one. komando never
deletes a credential itself: when no other entry uses it, the result names
it in `secrets_unused` with the `komando credential password remove` that
removes it. Changing the credential of a protected server needs the same
yes as any change to it.

### Two-factor logins

When a server also asks for a one-time code (or any
other question), komando shows you the server's question with its name
(`web1: Verification code:`) and sends what you type, hidden unless the
server lets it show. Servers that log in at once (`komando host ssh exec @web`) ask
one at a time. Ctrl-C stops the login (`CANCELLED`). Only a person at a
terminal is asked: for an AI agent or a script the login stops with
`AUTH_FAILED`, the message quotes the server's question, and no wrong code
counts against the account. The agent asks you to log in once for it:

```bash
komando test web1          # type the password and the code once
komando test web1 --end    # end it sooner
komando test --end         # end every kept login
```

`komando test` asks what the server asks and then keeps that login open
in the background for 8 hours (the `login_for` setting). Every command to
web1 uses it, your AI agent's too, so nobody types a code again until it
ends; komando's rules, approvals and audit still apply to each command.
A login to a jump host is used for every server behind it. `komando status`
lists the kept logins, and a login ends early when the server closes it or
its address changes.

Only a person at a terminal can do this step. An AI agent's `komando test`
on such a server stops with `NEEDS_PERSON` and the hint names the command
for you to run.

### Sudo passwords

If `sudo` asks for a password on the server, save that too:

```bash
komando credential password add web1-sudo --user ubuntu
komando host ssh edit web1 --sudo-credential web1-sudo
```

Everything else about the vault (listing, renaming and removing
credentials, and where its key is kept) is on one page: [Credentials](credentials.md).

## Credential stores

A credential can also read its value from the password manager your team
already uses. Add the store once with `komando credential store PROVIDER
add`, then point a credential at one item in it with `--store` and `--item`:

| Store provider | Reads it from | Login it uses |
|----------------|---------------|---------------|
| `vault` | HashiCorp Vault or OpenBao, KV v1 or v2 | `VAULT_ADDR` and `VAULT_TOKEN` (or `~/.vault-token`; OpenBao's `BAO_ADDR`, `BAO_TOKEN`, `~/.bao-token` work too), `VAULT_NAMESPACE`, `VAULT_CACERT` |
| `aws-sm` | AWS Secrets Manager; a key picks a JSON field | your AWS login (`AWS_PROFILE`, `~/.aws`, or SSO through `komando test` on an AWS entry) |
| `gcp-sm` | Google Secret Manager, latest version | Google application-default credentials (`GOOGLE_APPLICATION_CREDENTIALS`, or on Google Cloud) |
| `azure-kv` | Azure Key Vault, current version; a key picks a JSON field | a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`, `AZURE_CLIENT_SECRET`), a workload identity on AKS (`AZURE_FEDERATED_TOKEN_FILE`), the Azure CLI's saved token, or the managed identity on Azure |
| `bitwarden` | Bitwarden or Vaultwarden; the field is `password`, `username`, `notes`, `uri`, `totp` or a custom field | `KOMANDO_BW_EMAIL`, `KOMANDO_BW_PASSWORD` (decrypts the vault here), `KOMANDO_BW_SERVER` for Vaultwarden or bitwarden.eu, optional API key `KOMANDO_BW_CLIENT_ID`/`KOMANDO_BW_CLIENT_SECRET` |
| `keepass` | a KeePass or KeePassXC file (KDBX 3.1 and 4); a field after the entry | `KOMANDO_KDBX_PASSWORD` and/or `KOMANDO_KDBX_KEYFILE` |
| `onepassword` | 1Password, through a 1Password Connect server | `OP_CONNECT_HOST`, `OP_CONNECT_TOKEN` |
| `env` | an environment variable | none needed |
| `file` | a file | none needed |

```bash
komando credential store vault add my-vault
komando credential password add prod-db-pass --user app --store my-vault --item prod-db-password
komando database postgres add prod-db postgres://10.0.0.5/shop --credential prod-db-pass
```

A store is a named entry like any other: `komando test my-vault` checks it,
and `credential store vault list`, `show`, `edit`, `rename` and `remove`
work as on every provider.

komando talks to Vault, AWS, Google, Azure, Bitwarden, KeePass files and
1Password Connect itself: you do not need the `vault`, `aws`, `gcloud`, `az`,
`bw` or `op` programs. It reads the value only when it needs it and never
stores it. The login (and any MFA) stays with you.

**Azure Key Vault.** A store of provider `azure-kv` names the vault: its
name (`shop-vault` for `shop-vault.vault.azure.net`) or, in another Azure
cloud, its whole host name (`shop-vault.vault.azure.cn`). komando tries
these logins in order:

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

`AZURE_AUTHORITY_HOST` picks another Azure cloud's sign-in host
(`https://login.microsoftonline.us`, `https://login.chinacloudapi.cn`);
any other host is refused, because the login goes there.

The login needs the "Key Vault Secrets User" role on the vault, or an access
policy that allows Get on secrets.

## Servers with no open SSH port (AWS SSM, GCP IAP, Cloudflare)

Some servers are reached through a cloud tool instead of a plain SSH port.
Give komando that tool's command, as in OpenSSH's `ProxyCommand` (`%h` is the
address, `%p` the port, `%r` the user):

```bash
komando host ssh add web1 i-0abc123 --ssm --credential admin-web     # AWS Systems Manager: the address is the instance ID
komando host ssh add web2 web2 --credential admin-web --proxy-command 'gcloud compute start-iap-tunnel %h %p --listen-on-stdin --zone europe-west1-b'
komando host ssh add db1 ssh.example.com --credential admin-web --proxy-command 'cloudflared access ssh --hostname %h'
komando database postgres add prod-db postgres://mydb.xyz.rds.amazonaws.com/app --credential app-db --via web1   # a database behind it
```

A `--proxy-command` tool must be installed and logged in on this computer.
On Windows the command runs in cmd.exe, so write it for cmd.exe. A proxy
command runs on this computer, so an AI agent needs a person's yes to add
one.

For `--ssm`, komando speaks AWS Session Manager itself when the aws CLI or
its session-manager-plugin is not installed. It uses your usual AWS login
(`komando test` on your AWS entry for SSO). Set `KOMANDO_EXPERIMENTAL=ssm`
to use the built-in client even when they are installed. Sessions that your
account encrypts with KMS work too: komando asks KMS for the session key
with your login, so that login needs `kms:GenerateDataKey` on the key, as
the plugin does.

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

The audit log keeps it too (`host.key-pinned` in `komando audit list`), and the
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
komando host ssh trust web1 --reset --dry-run   # how many pinned keys would go
komando host ssh trust web1 --reset             # shows the old and new key, asks once
```

Only a person at a terminal replaces a pinned key: komando shows the old
and the new fingerprint and asks once. An AI agent or a script gets
`NEEDS_PERSON` (exit 6) whatever flags it adds, because an agent that
re-pins the key could be talking to an impostor; its hint names the
command for you to run. Without `--reset`, `host ssh trust` never adds a
second key: a different key stops with `HOSTKEY_MISMATCH`, and a server
that cannot be reached keeps its old key.

After you rebuild a whole group (same addresses, new keys), give `host ssh
trust` the group instead of one name. It takes every kind of target, like
`exec`: `@group`, `tag:`, `'web*'` or `a,b`.

```bash
komando host ssh trust @web                 # new servers get pinned; changed keys are refused
komando host ssh trust @web --reset         # after the rebuild: one yes for all of them
```

`data.results` (in `-o json`) lists every server with its new `fingerprint`
and, when the key changed, its `old_fingerprints`. With `--reset` you answer
once: the question names every server whose key changes, with the start of
its new fingerprint. Compare them with your cloud console first.

`komando host ssh remove` does not forget a server's key. If you remove a
server and add it again at the same address, it must still show the same
key, so `remove` plus `add` is no way around `HOSTKEY_MISMATCH`.
`host ssh remove` says which keys it kept (`host_keys_kept`); after a
rebuild, replace them with `host ssh trust --reset`.

### Pin a key before the first connection

`komando host ssh trust web1` (without `--reset`) pins a key before the
first connection; the same key again changes nothing. The key is fetched
the way komando reaches the server: directly, or through its `--via` path,
VPN or proxy command.

To check every new server before komando uses it, refuse unknown keys and
pin them one by one, comparing the `fingerprint` in each answer with the
server's own first:

```bash
komando config set host_key_policy strict   # unknown keys stop with HOSTKEY_UNKNOWN
komando host ssh trust web1                 # data.results[0] has key_type and fingerprint
```

When you already have the fingerprint (from the server's console or your
cloud provider), let komando compare it for you: `--fingerprint` pins the
key only when the server shows that one.

```bash
komando host ssh trust web1 --fingerprint SHA256:pVt2...   # pinned only if it matches
```

Any other key stops with `HOSTKEY_MISMATCH` (exit 4) and nothing is
pinned; the message shows both fingerprints. Give the fingerprint of the
key type the server offers (`key_type` in the answer; `ssh-keygen -lf
/etc/ssh/ssh_host_ed25519_key.pub` on the server prints it). It takes one
server, and its answer has `expected_fingerprint` next to `fingerprint`.
The other rules stay: with `strict`, an AI agent's first pin still needs
your yes, and replacing a pinned key still needs `--reset` at your
terminal.

`HOSTKEY_UNKNOWN` says which fingerprint the server shows. With `strict`,
an AI agent cannot pin a first key by itself: `host ssh trust` needs your
yes in komando's window, which shows the fingerprint to compare (with the
default `accept-new` the first login pins it anyway).

## Limits

- An entry name uses letters, digits, `.`, `_` and `-` (see
  [Targets](targets.md#limits)). A server cannot be named after a type or a
  provider (`host`, `ssh`) or `all`.
- `--address` in `host ssh edit` works on one server only.
- A key file added with `credential key add` is never moved or deleted by
  komando.
- A person at a terminal is needed for `komando test` with a two-factor
  login, `credential key install` and replacing a pinned host key
  (`host ssh trust --reset`).
- A server whose credential is made with `--ask` has its password typed by
  a person: a script, cron or CI job reaches it only through a
  `komando test` a person started, and its first connection needs a person
  at a terminal. A WinRM server has no kept login. Only a person changes
  where it goes, or a server or VPN on its way.
- What `--ask` cannot stop. komando knows an AI agent only by its
  environment (`CLAUDECODE`, `KOMANDO_AGENT` and the like); a program that
  hides them is treated as a person. Any program of your user can draw a
  window that looks like komando's, replace the komando binary, or read
  the memory of a running komando. Type the password only into a window
  that a command you expected opened, and keep agents away from your
  account's files if that matters.
  On Windows, komando's password window is its approval window, so its
  buttons read Deny and "Allow once", and spaces around the password are
  dropped.
- `onepassword` reads 1Password only through a 1Password Connect server:
  the 1Password CLI is closed source, and komando uses only open-source
  parts.
- The Azure CLI's saved token works for about an hour; komando does not run
  `az` and cannot renew it.
- A server that another server reaches through `--via` cannot be removed
  until those servers change.
- komando prints no `ssh` command for plain OpenSSH, `scp` or `git`, and
  hands no key to ssh-agent for an hour. Use `komando host ssh shell` and
  `komando copy`. This is a recorded loss.

## Troubleshooting

| Error code | What it means | What to do |
|------------|---------------|------------|
| `AUTH_FAILED` | the server refused the login, or asked a question (a two-factor code) with no person at a terminal | check the credential; for a code, run `komando test SERVER` once |
| `KEY_PASSPHRASE_REQUIRED` | the key is encrypted and no ssh-agent holds it | `ssh-add PATH` |
| `HOSTKEY_MISMATCH` | the server shows another host key than the pinned one: rebuilt, or someone is in between | check the fingerprint another way; after a real rebuild, `komando host ssh trust SERVER --reset` in your own terminal |
| `HOSTKEY_UNKNOWN` | `host_key_policy` is `strict` and this key is not pinned yet | compare the fingerprint, then `komando host ssh trust SERVER` |
| `HOST_IN_USE` | another server reaches this one through `--via` | change their `--via` first, or remove them in the same command |
| `VIA_CYCLE` | the `--via` path leads back to itself, or names a step twice | name each server or VPN once, and not the server itself |
| `NAME_TAKEN` | a rename would give two entries one name | pick other names, or rename or remove what is in the way |
| `VPN_IN_USE` | a rename needs a connected VPN to go down | `komando vpn PROVIDER stop NAME` first |
| `KEY_IN_USE` | `credential key remove` on a key a server still uses | give the server another credential: `komando host ssh edit SERVER --credential OTHER` |
| `KEY_EXISTS` | `credential key create`, `credential key add` or `credential key rename` to a name that is taken | choose another name, or `komando credential key remove NAME` first |
| `SECRET_DESTINATION` | an AI agent asked to send a password to a server | a person allows it in komando's window |
| `SECRET_UNRESOLVED` | komando could not read a credential store item (no login for the password manager, or no such item) | follow the hint: it names the logins that work |
| `NEEDS_PERSON` | only a person at a terminal can do this (`host ssh trust --reset`, `credential key install`, the person step of `test`), or a server with an `--ask` credential and nobody can type it, or its first connection (a host key nobody has logged in with), or an AI agent changed where its password goes (its address, port, `--via`, proxy command, a server or VPN on its way) | run the command in your own terminal, or `komando test SERVER` once |
| `DECLINED` | the person cancelled the password window of a server with an `--ask` credential (or did so less than a minute ago) | a person runs `komando test SERVER` |
