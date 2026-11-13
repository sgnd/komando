# Moving in and moving computers

Bring in the servers and databases you already have, and move everything to
another computer. [All docs](README.md)

## Import your servers

```bash
komando import ssh-config --dry-run              # see what would be added first
komando import ssh-config                        # servers from ~/.ssh/config
komando import env ./shop/.env --group shop      # DATABASE_URL, REDIS_URL, ... from a .env file
komando export --to komando-backup.json          # save everything (no passwords)
komando import komando komando-backup.json       # on the other computer
```

Typed alone, `komando import` asks for the source, then the file.

The import ends with the command that checks what came in:

```text
Next: komando test @shop
```

## Import what you already have

Write `komando import SOURCE [FILE]`. Without a file, komando reads the
usual place for that source.

| Source | Reads (default file) | Adds |
|--------|----------------------|------|
| `ssh-config` | `~/.ssh/config` (including `ProxyJump`) | servers |
| `pgpass` | `~/.pgpass` | PostgreSQL conns |
| `mycnf` | `[client]` sections of `~/.my.cnf` | MySQL/MariaDB conns |
| `env` | a `.env` file (default `.env`) | a conn for each value that is a database, cache or storage URL |
| `kubeconfig` | `~/.kube/config` | a Kubernetes conn per context |
| `docker` | `~/.docker/config.json` (and credential helpers) | registry conns |
| `filezilla` | FileZilla's `sitemanager.xml` | servers (SFTP sites; FTP sites are listed, not added) |
| `rclone` | `rclone.conf` | servers (SFTP remotes) |
| `mobaxterm` | MobaXterm's exported sessions (`.mxtsessions`; no default: give the file) | servers (SSH sessions; a session's folder becomes a group; other session types are listed) |
| `putty` | PuTTY's sessions exported from the Windows registry (no default: give the file, see below) | servers (SSH sessions; a `.ppk` key, a proxy and telnet or serial sessions are listed with what to do) |
| `aws` | `~/.aws/config` (and `credentials`) | an S3 storage conn per bucket of each profile; it uses the profile, so no key is copied ([Cloud logins](cloud.md#add-a-conn-for-every-s3-bucket)) |
| `dbeaver` | DBeaver's `data-sources.json` | database conns (set the passwords afterwards) |
| `komando` | a file from `komando export` | servers, conns, VPNs and recipes |
| `csv` | a spreadsheet saved as CSV (no default: give the file) | servers, one per row; see [Add many servers from a spreadsheet](servers.md#add-many-servers-from-a-spreadsheet) |

```bash
komando import pgpass                     # PostgreSQL databases from ~/.pgpass
komando import mycnf                      # MySQL/MariaDB from ~/.my.cnf
komando import kubeconfig                 # one conn per Kubernetes context
komando import ssh-config ~/work/ssh_config --group work
```

Flags: `-g`/`--group` adds everything imported to a group, and
`--overwrite` replaces entries that already have the same name (on a
protected one komando asks you first; an AI agent or a script adds `--yes`
after a person agrees). Without `--overwrite`, komando skips names it
already has.

### What happens to passwords

Passwords found in these files go to the vault as `<name>-pass`. They never
appear in komando's list, output or history.

### What komando checks

- Importing the same file again changes nothing. A different database that
  happens to have the same name gets the next free name (`shop-2`).
- Conns get the same TLS default as `conn add`: a database URL that says
  nothing about TLS gets TLS that checks the certificate (for example
  `sslmode=verify-full`, said in a note), and a `redis://`, `amqp://` or
  other clear-text URL to another computer is skipped unless it ends in
  `?insecure=1`.
- With `--overwrite`, the result lists what it replaced. Without a yes, a
  protected server or conn is skipped, in the dry run too.
- The result names the command that checks what came in in `data.next`,
  and a person sees it on stderr: `Next: komando test @shop`.
- Servers are checked like `host add` (ports, users, `--via`). A bad one is
  skipped, with the reason. A `csv` import is stricter: one bad row stops
  the whole import, and nothing is added.
- Whatever komando cannot import is listed, with the reason. For example: a
  `.pgpass` line with `*`, a URL kind komando does not know, a `Host *`
  pattern (its settings become defaults for the other servers), or an
  `Include` file that is missing. `HostName %h.example.com` is understood.
- A `ProxyCommand` runs on this computer, so an AI agent needs a person's
  yes (`--yes` and the approval window) to import one. Without it, that server is left out with the
  reason, the other servers still come in, and the import ends with
  `IMPORT_INCOMPLETE` (exit 1).

### Coming from PuTTY

PuTTY keeps its sessions in the Windows registry. Export them to a file,
then import that file (a dry run first lists what comes in):

```bash
reg export HKCU\Software\SimonTatham\PuTTY\Sessions putty.reg
komando import putty putty.reg --dry-run
komando import putty putty.reg
```

PuTTY keeps no passwords, so set them with `komando secret set` or use a
key. A key in PuTTY's own format (`.ppk`) is listed: convert it with
`puttygen KEY.ppk -O private-openssh -o KEY`, then `komando key add NAME
KEY`. A session that reaches its server through a proxy is listed too: set
the way there with `komando host edit NAME --via JUMP`.

### Coming from MobaXterm

In MobaXterm, right-click **User sessions** and pick **Export all sessions
to file**, then import that file:

```bash
komando import mobaxterm sessions.mxtsessions --dry-run
komando import mobaxterm sessions.mxtsessions
```

SSH sessions come in with their host, port and user, and the folder a
session sits in becomes a group. MobaXterm keeps passwords apart, so set
them with `komando secret set` or use a key.

### Coming from Termius or TablePlus

Termius and TablePlus have no open export format. From Termius, export your
hosts as an SSH config and run `komando import ssh-config FILE`. For
databases, put their URLs in a `.env` file and run `komando import env FILE`.

## Move to another computer

There are two ways. An export moves your servers, conns, VPNs, recipes,
your own deny rules and settings, but no passwords and no key files: you
set those again. Copying the folder moves everything, passwords included,
once the vault has a passphrase.

### Export and import (no passwords)

`export` saves your servers, conns and VPNs, and when you export everything
also your saved recipes, your own deny rules (`policy deny`) and your
settings:

```bash
komando export --to komando-backup.json       # everything; no passwords
komando export @prod --to prod.json           # only what a target picks (no recipes)
komando export                                # print it instead of writing a file
```

`export` writes the file with mode 0600, and refuses to replace an existing
file unless you add `--overwrite`.

On the other computer:

```bash
komando import komando komando-backup.json
komando secret set prod-db-pass               # the import lists the passwords to set again
```

The export file holds no passwords, only their names, so set them again
with `komando secret set`. The import adds your deny rules (they only stop
more), but changes no setting: it lists the settings that differ, each with
the `komando config set` command that sets it, because a file from someone
else must not turn a check off. When komando refuses something in the file,
the rest still comes in and the import ends with `IMPORT_INCOMPLETE` (exit 1):
fix those entries and import again (what is in already is skipped).

Private keys are never in an export file either. When a server logs in with
a key from `komando key`, `export` names the key (`keys_needed`) and its file
(`key_files`): copy that file to the other computer yourself. A key
komando made (`key gen`) is sealed in komando and has no file
(`keys_sealed`): make a new one on the other computer with `komando key gen
NAME` and put it on the servers with `komando key deploy`. The import
still adds the server, says which key it needs, and leaves the key out until
you bring it (ssh-agent or your default key may log in meanwhile):

```bash
komando key add deploy ~/Downloads/deploy     # the copied key file
komando host edit db1 --key deploy
```

An export file may come from someone else, so komando imports it with
these limits:

- A `ProxyCommand` is dropped, because it would run on this computer. Set it
  yourself with `komando host edit NAME --proxy-command ...`.
- A password reference is kept only if it names a `secret:` that does not
  exist here yet. Anything else is dropped, so a file cannot point your
  existing passwords at its servers.
- Recipes marked read-only are imported as changes. Mark them read-only
  again yourself with `komando recipe add NAME ... --read-only --overwrite`.

Each dropped setting is listed in the result.

### Copy the folder (everything, with passwords)

The vault's key must travel with it, so give the vault a passphrase first.
A key in `store.key` or in the system keychain does not travel: a copied
folder whose key stayed in the old computer's keychain cannot open its
secrets.

```bash
komando secret passphrase                     # on the old computer: type a passphrase (15+ characters)
# copy ~/.komando to the new computer (a USB stick, scp), then there:
export KOMANDO_VAULT_PASS='the passphrase'    # or type it when komando asks
komando doctor                                # the vault opens, the servers are there
```

On the new computer you can go back to a key file and move it into the
keychain: `komando secret passphrase --off --yes`, then `komando secret
keychain`. Copy SSH key files kept outside `~/.komando` (in `~/.ssh`) too.

### Restore from a backup (Time Machine, a new computer)

A backup of `~/.komando` (Time Machine, a disk image, a copy) holds the
store, but not always its key. `komando doctor` says where the key lives;
check it before you need the backup:

| Key lives in | The backup on this computer | The backup on a new computer |
|---|---|---|
| a passphrase | opens with the passphrase | opens with the passphrase |
| `store.key` (inside the folder) | opens | opens, so treat the backup like the passwords themselves |
| the OS keychain (the default) | opens: the keychain still has the key | does not open its secrets: the key stayed in the old computer's keychain |

So for a backup you can take to a new computer, give the vault a
passphrase first (`komando secret passphrase`), or keep an
[export](#export-and-import-no-passwords) next to it and set the passwords
again from your password manager.

Put the folder back with komando running nothing (no VPN, tunnel or job
started from it; `komando status` shows them), then:

```bash
komando doctor                                # the vault opens, the servers are there
```

When the key is in the keychain, the keychain also remembers how many
changes the store had. A restored copy is older, so every command then
stops with `STORE_OLD_COPY` (exit 6): its servers, rules, secrets or
pinned host keys may be out of date, and an old copy put back by someone
else looks the same. `komando doctor` and dry runs still work. If you put
it back yourself, accept it in your own terminal (an AI agent cannot):

```bash
komando doctor --accept-old-copy
```

Then check what changed since the backup: servers or rules you added
later, and host keys pinned since (`komando host trust` asks again for a
server it no longer knows).

## Limits

- Passwords, private key files and keys komando made never travel in an
  export file; set or copy them on the other computer.
- An import changes no setting: it lists the ones that differ.
- A copied folder opens its secrets on another computer only when the vault
  has a passphrase (or its key is in `store.key`, inside the folder).
- A backup put back on the same computer stops with `STORE_OLD_COPY` until
  a person runs `komando doctor --accept-old-copy`, when the key is in the
  keychain.
- Termius and TablePlus have no open export format (see
  [above](#coming-from-termius-or-tableplus)).

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `IMPORT_INCOMPLETE` (exit 1) | most things came in, some were refused (see `skipped`) | fix those entries in the file and import again; what is in already is skipped |
| `USAGE` (exit 2) | an unknown source, or `komando` or `csv` without a file | the hint lists the sources and an example |
| `FILE_EXISTS` (exit 8) | `export --to` a file that exists | add `--overwrite`, or pick another file |
| `PROTECTED_HOST`, `PROTECTED_TARGET` (exit 6) | `--overwrite` of a protected entry | at your terminal komando asks; a script adds `--yes` |
| `STORE_OLD_COPY` (exit 6) | a backup of the folder was put back; the keychain remembers a newer store | if you restored it on purpose, run `komando doctor --accept-old-copy` in your own terminal; otherwise find out who put it back |
| `VAULT_LOCKED` (exit 1) | a copied folder whose vault has a passphrase, without `KOMANDO_VAULT_PASS` | set `KOMANDO_VAULT_PASS`; see [Secrets](secrets.md#troubleshooting) |
