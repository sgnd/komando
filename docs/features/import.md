# Moving in and moving computers

Bring in what `komando export` saved, and move everything to another
computer. [All docs](README.md)

## Import your entries

```bash
komando export --to komando-backup.json          # save everything (no passwords)
komando import komando-backup.json --dry-run     # on the other computer: see what would be added first
komando import komando-backup.json               # add it
```

Typed alone, `komando import` asks for the file.
TODO(cut): the exact usage line of `import` waits on the table (PR B).

The import ends with the command that checks what came in:

```text
Next: komando test @shop
```

## What komando imports

komando imports only its own file, the one `komando export` writes. The
importers for other tools (ssh config, pgpass, mycnf, env files, kubeconfig,
Docker, FileZilla, rclone, MobaXterm, SecureCRT, PuTTY, AWS, DBeaver and
CSV) are gone: add those entries with `komando TYPE PROVIDER add`, for
example `komando host ssh add web1`.

An export file made before v0.18.0 is refused. Import it with komando v0.17.0.
TODO(cut): the error code of a refused old file waits on the error catalog.

Flags: `-g`/`--group` adds everything imported to a group, and
`--overwrite` replaces entries that already have the same name (on a
protected one komando asks you first; an AI agent or a script adds `--yes`
after a person agrees). Without `--overwrite`, komando skips names it
already has.

### What happens to passwords

The export file holds no passwords, only their names. A sealed export
carries them (see [below](#a-sealed-export-everything-with-passwords)).
Passwords never appear in komando's list, output or history.

### What komando checks

- Importing the same file again changes nothing. A different database that
  happens to have the same name gets the next free name (`shop-2`).
- Entries get the same TLS default as `add`: a database URL that says
  nothing about TLS gets TLS that checks the certificate (for example
  `sslmode=verify-full`, said in a note), and a `redis://`, `amqp://` or
  other clear-text URL to another computer is skipped unless it ends in
  `?insecure=1`.
- With `--overwrite`, the result lists what it replaced. Without a yes, a
  protected entry is skipped, in the dry run too.
- A file cannot turn on what `host ssh edit` and `vpn PROVIDER edit` ask a
  person for: `forward_agent` on a server that did not lend your ssh-agent
  before, `legacy_crypto` or `allow_pap` on a VPN, and, for a VPN it replaces,
  a CA it no longer checks the server against or `mfa` or protection turned
  off. Each stops with `SAFETY_SETTING` (exit 6) until you say yes: at your
  terminal komando asks, a script adds `--yes`, and an AI agent's yes comes
  from you in komando's window. Settings in the file are never applied;
  the result lists them in `settings_differ` with the command to run.
- The result names the command that checks what came in in `data.next`,
  and a person sees it on stderr: `Next: komando test @shop`.
- Entries are checked like `add` (ports, users, `--via`). A bad one is
  skipped, with the reason. The file may hold several types; the result
  counts them per type, in an object keyed by the type word
  (`"database": 3`), and every record in the file carries a `type` field.
- Whatever komando cannot import is listed, with the reason.
- A `ProxyCommand` runs on this computer, so an AI agent needs a person's
  yes (`--yes` and the approval window) to import one. Without it, that server is left out with the
  reason, the other servers still come in, and the import ends with
  `IMPORT_INCOMPLETE` (exit 1).
- A record of an unknown type is refused, and so is a file that carries the
  approval code's seed. An export never writes that seed.

## Move to another computer

There are three ways. An export moves your entries of every type, snippets,
your own deny rules and settings, but no passwords and no key files: you
set those again. A [sealed export](#a-sealed-export-everything-with-passwords)
moves the same with the passwords in one file that opens only with a
passphrase you choose. Copying the folder moves everything, passwords
included, once the vault has a passphrase.

### Export and import (no passwords)

`export` saves your entries of every type, and when you export everything
also your saved snippets, your own deny rules (`policy create`) and your
settings:

```bash
komando export --to komando-backup.json       # everything; no passwords
komando export @prod --to prod.json           # only what a target picks (no snippets)
komando export                                # print it instead of writing a file
```

`export` writes the file with mode 0600, and refuses to replace an existing
file unless you add `--overwrite`.

On the other computer:

```bash
komando import komando-backup.json
komando credential password add prod-db-pass --user app   # the import lists the passwords to set again
```

The export file holds no passwords, only their names, so set them again
with `komando credential password add`. The import adds your deny rules (they only stop
more), but changes no setting: it lists the settings that differ, each with
the `komando config set` command that sets it, because a file from someone
else must not turn a check off. When komando refuses something in the file,
the rest still comes in and the import ends with `IMPORT_INCOMPLETE` (exit 1):
fix those entries and import again (what is in already is skipped).

Private keys are never in an export file either. When a server logs in with
a key from `komando credential key`, `export` names the key (`keys_needed`) and its file
(`key_files`): copy that file to the other computer yourself. A key
komando made (`credential key create`) is sealed in komando and has no file
(`keys_sealed`): make a new one on the other computer with `komando credential key create
NAME` and put its public key on the servers with `komando credential key install`. The import
still adds the server, says which key it needs, and leaves the key out until
you bring it (ssh-agent or your default key may log in meanwhile):

```bash
komando credential key add deploy ~/Downloads/deploy --user deploy   # the copied key file
komando host ssh edit db1 --credential deploy
```

TODO(cut): the arguments of `credential key add` wait on the table (PR B).

An export file may come from someone else, so komando imports it with
these limits:

- A `ProxyCommand` is dropped, because it would run on this computer. Set it
  yourself with `komando host ssh edit NAME --proxy-command ...`.
- A credential reference is kept only if it names a `credential:` that does not
  exist here yet. Anything else is dropped, so a file cannot point your
  existing passwords at its servers.
- Snippets marked read-only are imported as changes. Mark them read-only
  again yourself with `komando snippet create NAME ... --read-only --overwrite`.

Each dropped setting is listed in the result.

### A sealed export (everything, with passwords)

`--sealed` writes the export and the passwords its entries
use into one sealed file. Only a person at a terminal can make one (an AI
agent gets `NEEDS_PERSON`), and komando asks for a passphrase for the
file, twice, hidden:

```bash
komando export --sealed --to move.kmdseal                # asks a passphrase (15+ characters)
komando export --sealed --with-keys --to move.kmdseal    # and the private keys the servers use
komando export @prod --sealed --to prod.kmdseal          # only what a target picks
komando export --sealed --to move.kmdseal --dry-run      # what would be sealed; asks nothing
```

```text
Choose a passphrase for the file: 15 or more characters (random words work).
Passphrase (hidden):
Type it again (hidden):
sealed 2 hosts, 1 database, 2 credentials, 1 key into move.kmdseal (it opens with its passphrase)
check phrase: kangaroo maximum crush write exit shock
Next: komando import move.kmdseal (on the other computer; it asks for the passphrase)
```

TODO(cut): the text of the sealed line waits on the `Text()` of `export` (PR B).

The file is written with mode 0600; nothing in it is readable without the
passphrase, and changing a byte stops it from opening. A secret a server
names that is not in the vault is listed, and stays out. A security key
(FIDO2) stays on its device.

On the other computer, the same import reads it and asks for the
passphrase once:

```bash
komando import move.kmdseal
komando import move.kmdseal --overwrite   # also replace credentials that are here with another value (asks first)
```

The import keeps the limits of any export file (below). A password from the
file goes into the vault when that name is not here yet. When the vault
has that name with another value, it keeps its own, and the file's servers
do not get it, unless you add `--overwrite` and say yes. A key from the
file is kept in komando's store, as one `credential key create` made; a key with a name
that is here already is left out.

A wrong passphrase, or a file changed after it was sealed, stops with
`WRONG_PASSPHRASE`; a damaged file with `SEALED_FILE_INVALID`. Nothing is
imported then.

### Send everything to the iPhone app

From Linux or Windows, with only an iPhone, `--for-phone` seals the file to
a key the iPhone app makes for this one export. Only that phone opens it;
the terminal cannot:

```bash
komando export --for-phone --to phone.kmdseal
```

komando asks for the key file the phone shared (or the key itself, as the
phone shows it) and the key check the phone shows (64 letters and digits,
spaces and dashes do not matter). A key that does not match the key check
is refused (`PHONE_KEY_INVALID`), so a key file swapped on the way is
caught. Then it prints a check phrase of six words: move the file to the
phone any way you like, and check that the phone shows the same six words.
If they differ, do not use the file. The phone reads your entries,
their passwords and, with `--with-keys`, the keys.

The file is sealed with post-quantum encryption (X-Wing: ML-KEM-768 with
X25519), so a copy left in mail or a cloud backup stays closed even to a
future quantum computer. It needs the iPhone app for iOS 26 or later. A
file made by komando 0.14.0 (X25519 only) no longer opens on the phone,
and a key from an older app is refused: update the app and make the file
again.

The format is in [the sealed file design](../design/sealed-file.md).

### Copy the folder (everything, with passwords)

The vault's key must travel with it, so give the vault a passphrase first.
A key in `store.key` or in the system keychain does not travel: a copied
folder whose key stayed in the old computer's keychain cannot open its
secrets.

```bash
komando config vault passphrase                # on the old computer: type a passphrase (15+ characters)
# copy ~/.komando to the new computer (a USB stick, scp), then there:
export KOMANDO_VAULT_PASS='the passphrase'    # or type it when komando asks
komando doctor                                # the vault opens, the servers are there
```

On the new computer you can go back to a key file and move it into the
keychain: `komando config vault passphrase --off --yes`, then `komando config vault
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
passphrase first (`komando config vault passphrase`), or keep an
[export](#export-and-import-no-passwords) next to it and set the passwords
again from your password manager.

Put the folder back with komando running nothing (no VPN or tunnel
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
later, and host keys pinned since (`komando host ssh trust` asks again for a
server it no longer knows).

The store's settings row (its key mode, salt and scrypt cost) must stay
readable without the key, so komando also keeps a sealed copy of it. A
change to that row made outside komando stops every command with
`STATE_CORRUPT`; `komando doctor` reports the key mode and scrypt cost
only once the key has opened the store. To recover, in your own terminal
(an AI agent cannot):

```bash
komando doctor --reseal-meta
```

It opens the store with your key, checks that the key opens every record,
shows the key mode and scrypt cost it keeps, and seals that row again. If
your key does not open the store, it changes nothing: restore the folder
from a backup. An older copy than the keychain remembers is not sealed
again (`STORE_OLD_COPY`): accept it first, if you restored it on purpose.
A store made by an older komando gets the sealed copy the
first time you run any komando command in your own terminal (a note on
stderr says so); an AI agent's or a script's command never writes it, and
until then `komando doctor` warns.

## Limits

- Passwords, private key files and keys komando made never travel in a
  plain export file; set or copy them on the other computer, or use a
  [sealed export](#a-sealed-export-everything-with-passwords).
- Only a person at a terminal makes or opens a sealed file. A file for the
  phone opens only on that phone.
- An import changes no setting: it lists the ones that differ.
- A copied folder opens its secrets on another computer only when the vault
  has a passphrase (or its key is in `store.key`, inside the folder).
- A backup put back on the same computer stops with `STORE_OLD_COPY` until
  a person runs `komando doctor --accept-old-copy`, when the key is in the
  keychain.
- There is no importer for another tool's files (see
  [above](#what-komando-imports)).

## Troubleshooting

| Error | What it means | What to do |
|-------|---------------|------------|
| `IMPORT_INCOMPLETE` (exit 1) | most things came in, some were refused (see `skipped`) | fix those entries in the file and import again; what is in already is skipped |
| `USAGE` (exit 2) | no file given | the hint gives an example |
| `FILE_EXISTS` (exit 8) | `export --to` a file that exists | add `--overwrite`, or pick another file |
| `PROTECTED_TARGET` (exit 6) | `--overwrite` of a protected entry | at your terminal komando asks; a script adds `--yes` |
| `SAFETY_SETTING` (exit 6) | the file turns on agent forwarding, old VPN ciphers or PAP, or weakens a VPN it replaces | check the file; at your terminal komando asks, a script adds `--yes` |
| `STORE_OLD_COPY` (exit 6) | a backup of the folder was put back; the keychain remembers a newer store | if you restored it on purpose, run `komando doctor --accept-old-copy` in your own terminal; otherwise find out who put it back |
| `STATE_CORRUPT` (exit 1), "settings row was changed outside komando" | the readable settings row of `store.db` no longer matches its sealed copy | run `komando doctor --reseal-meta` in your own terminal; if your key does not open the store, restore a backup |
| `VAULT_LOCKED` (exit 1) | a copied folder whose vault has a passphrase, without `KOMANDO_VAULT_PASS` | set `KOMANDO_VAULT_PASS`; see [Credentials](credentials.md#troubleshooting) |
