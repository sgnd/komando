# Moving in and moving computers

Bring in the servers and databases you already have, and move everything to
another computer. [All features](README.md)

## Import what you already have

```bash
komando import ssh-config --dry-run       # see what would be added first
komando import ssh-config                 # servers from ~/.ssh/config
komando import pgpass                     # PostgreSQL databases from ~/.pgpass
komando import mycnf                      # MySQL/MariaDB from ~/.my.cnf
komando import env ./shop/.env --group shop   # DATABASE_URL, REDIS_URL, ... from a .env file
```

| Source | Reads | Adds |
|--------|-------|------|
| `ssh-config` | `~/.ssh/config` (including `ProxyJump`) | servers |
| `pgpass` | `~/.pgpass` | PostgreSQL conns |
| `mycnf` | `~/.my.cnf` `[client]` sections | MySQL/MariaDB conns |
| `env` | a `.env` file | a conn for each value that is a database, cache or storage URL |
| `kubeconfig` | `~/.kube/config` | a Kubernetes conn per context |
| `docker` | `~/.docker/config.json` (and credential helpers) | registry conns |
| `komando` | a file from `komando export` | servers, conns and recipes |

- Passwords found in these files go to the vault as `<name>-pass`. They
  never appear in komando's list, output or history.
- Importing the same file again changes nothing. A different database that
  happens to have the same name gets the next free name (`shop-2`).
- What komando cannot import is listed, with the reason: for example a
  `.pgpass` line with `*`, or a URL kind komando does not know.

## Move to another computer

```bash
komando export --to komando-backup.json       # servers, conns and recipes; no passwords
komando export @prod --to prod.json           # only what a target picks
```

On the other computer:

```bash
komando import komando komando-backup.json
komando secret set prod-db-pass               # the file lists the passwords to set again
```

The export file holds no passwords, only their names. Copy them over with
`komando secret set`, or set `KOMANDO_HOME` to a copy of `~/.komando` if you
move the whole folder instead.
