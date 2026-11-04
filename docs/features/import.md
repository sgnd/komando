# Moving in and moving computers

Bring in the servers and databases you already have, and move everything to
another computer. [All features](README.md)

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

```bash
komando import pgpass                     # PostgreSQL databases from ~/.pgpass
komando import mycnf                      # MySQL/MariaDB from ~/.my.cnf
komando import kubeconfig                 # one conn per Kubernetes context
komando import ssh-config ~/work/ssh_config --group work
```

Options: `-g`/`--group` adds everything imported to a group, and
`--overwrite` replaces entries that already have the same name (a protected
one also needs `--yes`). Without `--overwrite`, existing names are skipped.

### What happens to passwords

Passwords found in these files go to the vault as `<name>-pass`. They never
appear in komando's list, output or history.

### What komando checks

- Importing the same file again changes nothing. A different database that
  happens to have the same name gets the next free name (`shop-2`).
- Servers are checked like `host add` (ports, users, `--via`). A bad one is
  skipped, with the reason.
- Whatever komando cannot import is listed, with the reason. For example: a
  `.pgpass` line with `*`, a URL kind komando does not know, a `Host *`
  pattern (its settings become defaults for the other servers), or an
  `Include` file that is missing. `HostName %h.example.com` is understood.
- A `ProxyCommand` runs on this computer, so an AI agent needs a person's
  yes to import one.

### Coming from Termius or TablePlus

Termius and TablePlus have no open export format. From Termius, export your
hosts as an SSH config and run `komando import ssh-config FILE`. For
databases, put their URLs in a `.env` file and run `komando import env FILE`.

## Move to another computer

`export` saves your servers, conns and VPNs, and also your saved recipes
when you export everything:

```bash
komando export --to komando-backup.json       # everything; no passwords
komando export @prod --to prod.json           # only what a target picks (no recipes)
komando export                                # print it instead of writing a file
```

The file is written with mode 0600. It refuses to replace an existing file
unless you add `--overwrite`.

On the other computer:

```bash
komando import komando komando-backup.json
komando secret set prod-db-pass               # the import lists the passwords to set again
```

The export file holds no passwords, only their names, so set them again
with `komando secret set`. To move everything including the vault, copy the
whole `~/.komando` folder instead (or point `KOMANDO_HOME` at a copy).

An export file may come from someone else, so importing one is careful:

- A `ProxyCommand` is dropped, because it would run on this computer. Set it
  yourself with `komando host edit NAME --proxy-command ...`.
- A password reference is kept only if it names a `secret:` that does not
  exist here yet. Anything else is dropped, so a file cannot point your
  existing passwords at its servers.
- Recipes marked read-only are imported as changes. Mark them read-only
  again yourself with `komando recipe add NAME ... --read-only --overwrite`.

Each dropped setting is listed in the result.
