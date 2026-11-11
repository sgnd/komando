# Moving in and moving computers

Bring in the servers and databases you already have, and move everything to
another computer. [All docs](README.md)

## Quick start

```bash
komando import ssh-config --dry-run              # see what would be added first
komando import ssh-config                        # servers from ~/.ssh/config
komando import env ./shop/.env --group shop      # DATABASE_URL, REDIS_URL, ... from a .env file
komando export --to komando-backup.json          # save everything (no passwords)
komando import komando komando-backup.json       # on the other computer
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
| `aws` | `~/.aws/config` (and `credentials`) | an S3 storage conn per bucket of each profile; it uses the profile, so no key is copied |
| `dbeaver` | DBeaver's `data-sources.json` | database conns (set the passwords afterwards) |
| `komando` | a file from `komando export` or `komando host export` | servers, conns, VPNs and recipes |
| `csv` | a spreadsheet saved as CSV (no default: give the file) | servers, one per row; see [Add many servers from a spreadsheet](servers.md#add-many-servers-from-a-spreadsheet) |

```bash
komando import pgpass                     # PostgreSQL databases from ~/.pgpass
komando import mycnf                      # MySQL/MariaDB from ~/.my.cnf
komando import kubeconfig                 # one conn per Kubernetes context
komando import ssh-config ~/work/ssh_config --group work
```

Flags: `-g`/`--group` adds everything imported to a group, and
`--overwrite` replaces entries that already have the same name (a protected
one also needs `--yes`). Without `--overwrite`, komando skips names it
already has.

### What happens to passwords

Passwords found in these files go to the vault as `<name>-pass`. They never
appear in komando's list, output or history.

### What komando checks

- Importing the same file again changes nothing. A different database that
  happens to have the same name gets the next free name (`shop-2`).
- Servers are checked like `host add` (ports, users, `--via`). A bad one is
  skipped, with the reason. A `csv` import is stricter: one bad row stops
  the whole import, and nothing is added.
- Whatever komando cannot import is listed, with the reason. For example: a
  `.pgpass` line with `*`, a URL kind komando does not know, a `Host *`
  pattern (its settings become defaults for the other servers), or an
  `Include` file that is missing. `HostName %h.example.com` is understood.
- A `ProxyCommand` runs on this computer, so an AI agent needs a person's
  yes (`--yes`) to import one. Without it, that server is left out with the
  reason, and the other servers still come in.

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
(`key_files`): copy that file to the other computer yourself. The import
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
A key in `vault.key` or in the system keychain does not travel: a copied
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
