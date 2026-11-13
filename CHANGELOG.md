# Changelog

All notable changes are listed here, newest first. Each version starts with
its highlights; the sections below them give the details. Versions follow
[Semantic Versioning](https://semver.org), and the format follows
[Keep a Changelog](https://keepachangelog.com).

## [Unreleased]

### Security
- `komando update` checks that a release comes from the komando project, not only that its files match its `checksums.txt`: someone able to replace a release's files could replace `checksums.txt` too. The release workflow now signs `checksums.txt` with the project's Ed25519 key (`checksums.txt.sig`), and komando checks it with the public key built in, before anything is downloaded or asked (in `--dry-run` too). A release without that signature stops with `RELEASE_SIGNATURE_NOT_FOUND`, a wrong one with `RELEASE_SIGNATURE_INVALID`; nothing is changed. Releases up to 0.13.0 are unsigned: to go back to one, use the install line with `KOMANDO_VERSION`.
- The release can sign the macOS binaries with the project's Developer ID and have Apple notarize them, so Gatekeeper accepts them. Until the owner adds the signing secrets, macOS binaries stay unsigned and the release log says so.

### Changed
- `download -r` from a server keeps the files that are already on this computer and copies the rest, as `download -r` from storage does; it used to stop at the first one with `FILE_EXISTS`. The result says how many it kept (`kept`). `--overwrite` still replaces them.
### Changed for scripts and agents
- `fs replace` and `fs restore` take a TARGET: on a group (`@web`) every server gets the same edit, or puts back its own newest backup. Their JSON is now one result per server, as `fs rm` and `exec` give: `data.results[]` (`host`, `ok`, `path`, `changed` or `would_change`, `replacements`, `diff`, `backup`, `error`) and `data.summary`; For one server the fields moved: `data.path` is now `data.results[0].path`, `data.changed` is `data.results[0].changed`, `data.would_change` is `data.results[0].would_change`, and the same for `replacements`, `diff`, `backup`, `from` and `note`. Error codes stay the same (`NO_MATCH`, `BACKUP_NOT_FOUND` ...). `fs write` stays one server.
### Added
- `job start --stdin-file FILE` gives the job's command FILE as its input, `job start --sudo-user USER` runs it as USER with `sudo -u` (both as in `exec`), and `job start --timeout 2h` stops the job after that long. A timed-out job is `killed` with `timed_out: true` in `job status`, and `job wait` says the timeout stopped it. When `exec` times out with `--sudo-user` or `--stdin-file FILE`, its hint now names the matching `job start` line.

### Fixed
- `job kill` on a server whose /bin/sh is dash (Debian, Ubuntu) stopped only the job's shell, not the commands it had started: dash refuses `kill -SIG -- -PGID`, and komando then fell back to the shell alone. It now signals the whole process group there too.

### Changed
- A job's `--env` values and its input (`--script`, `--stdin-file`) now reach the command through a pipe from the job's private folder instead of being read from files there, so a command run as another user gets them too. With a sudo password, the job first asks sudo whether it needs one and deletes it unread when it does not.
### Added
- `komando status` lists the AWS IAM Identity Center (SSO) logins of the profiles in `~/.aws/config`, with the profiles that share each one, when its token runs out and whether it renews itself (`data.aws_logins`). `komando logout aws --profile NAME` (or `--all`) ends one as `aws sso logout` does: AWS is told to end the token and the login in `~/.aws/sso/cache` is deleted. Before, `komando logout aws` was read as a server named aws.
### Added
- Docs: "Restore from a backup" in the import guide: which backups of `~/.komando` open on this computer and on a new one (passphrase, `store.key`, keychain), and what to do about `STORE_OLD_COPY` after a restore.
- `registry rm` and its dry run check every tag of the repository (up to 10000) for other tags on the image it deletes; they read only the first 200. `registry prune` reads repositories of up to 10000 tags (it stopped above 1000 with `TOO_MANY_TAGS`), asking for the tags' digests 8 at a time.
### Added
- `key revoke --all-users` (with sudo) removes the key from the `authorized_keys` of every user on the server, not only the login user's or one `--user`'s: someone who left may have put it into another account. The dry run names each user whose file holds it (`users`), and each file is read and written as its own user.
- `config set vpn_idle` to a longer time, or to `0` (never close), now counts as a safety setting like `login_for`: at a terminal komando asks first, and an AI agent needs a person's yes (`SAFETY_SETTING`). A VPN an agent can keep up for ever is a way into the network that nobody closes. A shorter time asks nothing.
### Added
- SSH user certificates: a key's OpenSSH certificate (`KEY-cert.pub` next to the key file, as `ssh` uses it) is offered at login, then the key alone, so servers that trust an SSH certificate authority let komando in. `key add --cert FILE` and `key edit --cert FILE` (`--unset cert`) name one kept elsewhere or for a key komando made; a certificate for another key is refused (`KEY_INVALID`) and one that is not valid now is left out with a warning. Keys show `cert_path` when one is set.
### Added
- A test now holds komando to the post-quantum SSH key exchange: with a server that offers `mlkem768x25519-sha256` (OpenSSH 9.9 and later), komando uses it first, so traffic recorded today cannot be read later with a quantum computer. The security standards page says so.
### Added
- A server's key and `--via` steps, and a conn's `--via` steps, now keep the record ID beside the name (`key_id`, `via_ids` in the JSON). The names stay what commands read and change; the IDs let a reference survive a rename made elsewhere, which sync between devices needs. An existing store gets the IDs at its next change.
### Added
- Docs: "What komando sends" in the README and SECURITY.md: nothing on its own (no statistics, crash reports or background update check); it connects only to what you added or named, AWS for `login aws`, and GitHub for `update`.
### Added
- `logs --container` (and `docker logs`) take `--since today`, `yesterday` and `now`, as the journal does: the server's own midnight or time, worked out on the server. They stopped with `USAGE` before.
- `net dns --type MX` (and CNAME, NS, TXT, SOA, SRV, PTR, CAA) works on servers without `dig`: komando asks the server's own resolver from `/etc/resolv.conf` over TCP through the SSH connection and shows the records as `dig +short` does. `DIG_MISSING` stays for a server with no resolver listed or no TCP forwarding. A PTR question for an IP address now asks its reverse name.
### Added
- `sync --sudo` sends a folder to servers as root, for folders the SSH user cannot write (`/etc/nginx/conf.d`): each file is installed as `upload --sudo` installs one (staged privately, checked by root, never through a folder another user may change, `SHARED_FOLDER_CONFLICT`), with the source file's mode, so the next run sends nothing new. `--delete` removes as root too.
### Added
- `komando import mobaxterm FILE` adds MobaXterm's SSH sessions from an exported `.mxtsessions` file, with each session's folder as a group.
- `komando import putty FILE` adds PuTTY's SSH sessions from a `.reg` file (`reg export HKCU\Software\SimonTatham\PuTTY\Sessions putty.reg`, UTF-16 or plain): user, address and port; a key file path is kept, a `.ppk` key, a proxy and telnet or serial sessions are listed with what to do.
### Added
- MongoDB: `db explain` shows a read's plan (`queryPlanner`; `--analyze` runs it and adds `executionStats`), and `db activity` lists what runs now (`currentOp`; `--all` adds idle connections), in the same row shape as for SQL databases. They said `NOT_SUPPORTED` before.
### Added
- `komando import aws-ec2` adds a server for each running EC2 instance of each AWS profile in `~/.aws/config`, in the profile's region, read with the profile's own login (SSO and roles too; nothing is changed in AWS): named by its `Name` tag, grouped by region, labelled with its instance ID. An instance with no public address, a Windows one and the key pair to add are listed with what to do.
### Added
- `host edit --forward-agent` lends a server your ssh-agent while komando is connected, as `ssh -A` does (for a `git pull` over SSH on it, or a hop komando does not make). It is off by default and set per server; turning it on asks first (`SAFETY_SETTING`, a person's yes for an AI agent), because root there can use your keys meanwhile. `--unset forward-agent` takes it back; `host ssh-command` adds `-o ForwardAgent=yes` for such a server.
### Added
- Security keys (FIDO2: `ed25519-sk`, `ecdsa-sk`): `key add` takes their key file (the public key from `FILE.pub`), and a server that logs in with one uses the copy in ssh-agent, found by its public key, as `ssh` does; the device asks for a touch. Without the agent holding it, the error says to `ssh-add` it instead of calling the file broken.
### Added
- S3 versioning: `storage list --all-versions` shows every version and delete marker under a prefix, and `storage rm KEY --all-versions` removes a key with all its versions, so it is really gone (plain `rm` leaves them behind). It asks first like any `rm`; Google Cloud and Azure buckets say `NOT_SUPPORTED`.

### Fixed
- A server could hide text in its output on your terminal (`ESC[8m`), make a line read in another order than it runs with bidi overrides (`U+202E`), or print over the `[web1]` name in front of its lines with a carriage return (`exec` on several servers, `cluster logs` of several pods). These now show as `\e[8m`, `\u202e` and `\r`. Colours and progress bars on one server stay as they were.
- The ssh gate let a key run commands on this computer through a listed server that is this computer under another name: its LAN address, a DNS name, a public IP or a port forward. It now refuses a server at one of this computer's own network addresses, or whose pinned host key is this computer's own SSH host key, as it refuses `localhost`.
- `doctor` checked only komando's folder and its main files for access by other users, not the `vpn/`, `login/` and `tunnels/` folders and the logs and state in them. It checks those too now, and the fix it names covers everything inside (`chmod -R go-rwx`).
- On Linux, another process of the same user (an AI agent's shell among them) could attach to a running komando or read its memory and environment through `/proc`, where vault values and the store's key are. komando now makes itself not dumpable (`PR_SET_DUMPABLE`); programs it starts are not affected.
- The logs of tunnels, server logins and VPN sessions stayed in komando's folder for good (tunnel logs piled up, one per tunnel). A log that nothing running uses is now removed after a week, when the next tunnel, login or VPN starts.
- A komando folder that was already there with others' access (after a copy, an unzip or a chmod) stayed readable by them; komando now makes its own folder (one that holds `store.db` or `store.key`) private again (0700) on Linux, macOS and BSD. The `komando-ssh-*` folders `host ssh-command` leaves in the temporary folder are removed by the next run once they are a day old.
- komando could leave a core file when it crashed, holding vault values and the store's key (Go strings cannot be wiped). It now turns core files off for itself (and the programs it starts) on Linux, macOS and BSD.
- `reboot` kept all the output of its commands on the server: a server that flooded it could fill this computer's memory. It now keeps 64 KiB, and a test checks that every remote command komando runs bounds its output.
- A `job start --sudo` that sudo refused before it began (no rights, a wrong password) left its env file, with the server's env values from the vault, and its script in the job folder on the server. Both are removed when the job ends, whatever happened.
- `cluster run TARGET -- cp POD:PATH DST` wrote a pod's files to this computer as they were for an AI agent (a `.env`, a key, real secret values), and held any amount of data in memory. It now copies as `download` does: for an agent a file that is a secret by its name is refused (`SENSITIVE_FILE`), a text file is written with its secret values `[hidden]`, and a binary or larger file holding a vault value is refused, all before anything is written; for everyone a copy from a pod stops at 512 MiB (`FILE_TOO_LARGE`).
- A second Ctrl-C, or closing the terminal (SIGHUP), ended komando without removing its temporary files: a half-copied download, a sign-in browser profile in the temporary folder, a database CA copy, an AWS token file being written. The first signal (SIGHUP too) now stops the command cleanly; the second removes what this run made, then exits. Sign-in profiles, CA copies and AWS token files left by a run that was killed outright are removed by the next run that makes one, once they are a day old.
- A server's own env value from the vault (`host edit --env API_TOKEN=secret:NAME`) went into every AI agent's command there, where `printenv API_TOKEN | rev` read it back unmasked. For an agent such values are now left out (a warning on `exec` and `job start` says which) unless it adds `--yes` and the user allows it in komando's window (`SECRET_DESTINATION`). Plain env values, and people's and scripts' commands, are unchanged.
- Hiding vault values in output told an AI agent which of its guesses was a secret: `secret show GUESS` or `exec web1 -- echo GUESS` printed `[secret:NAME]` on a hit. An agent's arguments, flags, `--script`, `--stdin-file` and `db query --file` that hold a vault value are now refused before anything runs, a dry run too (`SECRET_INPUT_INVALID`, exit 2), and the refusal is written to the audit log. The message never says which secret matched.
- An AI agent could switch off the old-copy check with `KOMANDO_KEYCHAIN=off`: komando then did not read the store's change count from the keychain, so an agent could move `store.db` and `store.key` aside (or put an old copy back) and work with a store that has no pinned host keys or protected servers. For an agent, `off` no longer covers the change count; a missing or older store stops with `STORE_OLD_COPY` as it does without `off`.
- `docker ps`, `docker stats`, `docker images` and `docker inspect` with `--sudo` on a server where sudo wants a password, or the login user may not use sudo, stop with `PERMISSION_DENIED` and a hint that names the fix, as the other docker commands do; they gave a plain remote error. Without sudo on the server it is `TOOL_MISSING`, and their docker failures are typed too (`DOCKER_MISSING`, `DOCKER_PERMISSION`, `NOT_FOUND`). For a login as root, the hint of every docker command now says to leave out `--sudo` (docker has no `--no-sudo`).
- On Windows, the hints for an encrypted key wrote it as `~/'.ssh\id_ed25519'`; they now write `~/.ssh/id_ed25519`.
- On Windows, the AI agent guard (`komando guide guard`) let globs such as `cat ~/.komand?/vault.ke?` through, and reads of `/proc/*/environ` (which Cygwin and MSYS shells have): it split paths only by `/`.
- On Windows, `cluster run TARGET -- cp C:\data pod:/tmp` took `C:\data` for pod `C`: it copied from that pod instead of sending the folder, and so skipped the check that keeps komando's data and secret files on this computer for an AI agent. A path with a drive letter is a path on this computer, as kubectl cp reads it.
- On Windows, a server, cluster or registry that refuses the connection is `CONNECTION_REFUSED` ("connection refused") as on other systems, not `CONNECT_FAILED` or `KEYSCAN_FAILED` with Windows' own words; `test --wait` and `host trust` tell it apart again.
- On Windows, a VPN's web sign-in stopped with "fork/exec ...: not supported by windows" when Chrome, Edge or Brave was installed: komando cannot give a browser its DevTools pipe there. The sign-in now opens in your own browser and you paste the address it ends on, as on a computer without one of those browsers.

## [0.13.0] - 2026-11-13

### Highlights

- **People type commands too.** The plain-language menu is gone. Type a
  command like `komando db query`; komando asks only for what is missing,
  with a list to pick from, shows the full command, and asks
  `Run it? [y/N, d]` before a change. After it works, `Next:` names the
  usual next step. AI agents see no change in how they are asked.
- **One command standard.** `list` is the listing verb everywhere (`ls`
  still works), flags and short letters mean one thing everywhere, and
  removing something asks you to type its name. `komando schema` says what
  each command needs before it runs (`confirm`).
- **Remote commands go after `--`.** `komando exec web1 -- apt-get install
  -y nginx`: words after `--` belong to the server, so apt's `-y` can no
  longer be read as komando's `--yes`.
- **Breaking for scripts: old names are removed, not kept.** For example
  `recipe add --sudo` is `--needs-sudo`, `db dump --on` is `--run-on`,
  `pkg security --apply` is `pkg upgrade --security`, `-n` in the cluster
  commands is `--namespace`, and `secret rm`, `key rm --delete-file` and
  `fs rm` need `--allow-dangerous`. `komando seal` is gone: a folder from
  before 0.12 is no longer read. The full list is under "Changed for
  scripts and agents" and "Removed".
- **Safer.** Over 35 security fixes, among them: an AI agent could take a
  VPN password through a program it placed in PATH; root could be made to
  write through a link another user planted on the server; the approval
  window now shows a whole script, and every Linux desktop needs the
  approval code; password-manager tokens leave the environment; on Windows
  komando's folder is yours alone.
- **Clearer.** Every message follows one style (what happened, why, the
  command to run next), and the documentation is rewritten for beginners,
  with an install page for Windows too.
- **Also:** `cluster apply` no longer takes over fields another tool owns
  unless you add `--force-conflicts`, and SQL Server certificates with a
  negative serial number are accepted.

### Changed for scripts and agents

This release makes every command follow one standard. `meta.contract`
stays 1. komando is used internally only, so a few answers changed shape
instead of keeping an old one beside the new (listed below under
"Removed"); every other JSON field of 0.12 is unchanged. What a script or
an AI agent may notice is listed here; the sections below say more about
each change.

New fields, all additive (left out when they have nothing to say):

- `error.suggestion`: the name komando thinks you meant, when a command,
  server, conn, group, secret, setting or flag is misspelled. The hint is
  then the whole command line with it in place.
- `error.thing`: which kind of item a shared not-found code is about
  (`KEY_NOT_FOUND` is an `ssh_key` or a `cache_key`, and so on).
- `meta.would_need`: under `--dry-run`, the flags the real run needs
  (`--allow-dangerous`, `--yes`).
- `meta.truncated`: `true` when a list stopped at its `--limit`.
- `meta.not_simulated`: under `--dry-run`, the steps the dry run could not
  try.
- In `komando schema`: `confirm` on each command (its approval tiers and
  the flag each needs) and `default_from` on a flag whose default comes
  from a setting.

Values in `komando schema` that changed (field names are the same):

| What | Before | Now |
|---|---|---|
| `flags[].type` of `--env` (host add/edit), `--label` (10 commands), `--option` (8) | `stringSlice` | `stringArray`: repeat the flag, commas are kept |
| `flags[].type` of `--ttl`, `--warn`, `--older-than` (3 commands) | `string` | `duration` |
| `flags[].type` of `cache get --limit` | `int64` | `int` |
| `--limit` on 34 list commands | not there | `int`, default 0 (all) where there was no limit |
| `flags[].type` of `--max-output` and every `--max-bytes` | `int`, `int64` or `string` | `bytes` (`256KiB`, `1MB`; KB means 1024) |
| `default` of a duration | `1h0m0s` | `1h` |
| `default` of `--timeout`, `--connect-timeout`, `--parallel`, `--host-key-policy`, `--max-output` | the value | `0` or empty, with `default_from` naming the setting |
| `default` of queue `--partition`, `--partitions`, `--replicas` | `-1` | none (the help says "the broker's") |
| `kind` of `storage link` and `cluster forward` | `read` | `change` |
| `shorthand` `-n` on `cluster events`, `cluster logs`, `cluster list` | `--limit` | `--namespace` (as on the other 17 cluster commands, which gain it) |
| `path` and `usage` of renamed commands | `secret get`, `... ls`, `... mv`, `db grants`, `pkg security --apply` | `secret show`, `... list`, `... rename`, `db user show`, `pkg upgrade --security` |
| `command` in the envelope and the audit log of renamed commands | `secret.get`, `fs.ls` (and the six other `.ls`), `host.mv` (and the five other `.mv`), `db.grants`, `pkg.security` for `pkg upgrade --security` | `secret.show`, `fs.list`, `host.rename`, `db.user.show`, `pkg.upgrade` |
| `usage` argument words | `KEY` for several things, `HOST`, `NAME` | one meaning per word (`OBJECT`, `SETTING`, `SERVER`, `USER`, `JOB`, `TUNNEL`, `TYPE/NAME`, ...) |

Synonyms (`ls`, `mv`, `get`, `keys`, plurals) stay for good, and
`komando schema` describes the command they run; `db grants` and `pkg
security --apply` are gone. The retired flags are gone (komando is used
internally only): `db dump/restore --on` (now `--run-on`), `--from` on
`db user`, `db grant` and `db revoke` (`--from-host`), `fs list --max`
(`--limit`), `fs restore --from` (`--copy`), `storage rm --limit` and
`-n` (`--max-remove`), `vpn add/edit --address` (`--proxy-address`),
`rename --prefix`, `--notes`, `--labels` (`--starts-with`,
`--in-notes`, `--in-labels`), `recipe add --sudo` (`--needs-sudo`),
`cron --sudo`/`-s` (`--user root`), `queue peek --wait` (`--idle`),
`cluster rollback --to` (`--revision`), `policy check --for`
(`--conn-kind`), `db query --csv`/`--tsv` (`-o csv`/`-o tsv`),
`key gen --overwrite`, `pkg security --apply` and `--keep-going` (`pkg
upgrade --security`), and `docker logs --priority` and `svc logs
--timestamps`, which did nothing there. Each is an unknown flag
(`USAGE`, exit 2). A bare number of seconds for `svc --wait` and
`reboot --wait` (`--wait 10`) and `-1` for queue `--partition`,
`--partitions` and `--replicas` are usage errors too.

Exit and error codes that changed:

| Command | Before | Now |
|---|---|---|
| `exec`, `job start`, `docker exec/compose/raw`, `cluster exec/shell/run`, `cache run` with words for the server and no `--` | ran (and took komando flags such as `-y` from those words) | `USAGE`, exit 2; nothing runs |
| `cluster events/logs/list -n 50` | a limit of 50 | `USAGE`, exit 2 (`-n` is the namespace; use `--limit 50`) |
| `--option a=on,b=x` (any KEY=VALUE flag with a comma before another KEY=) | two options | `USAGE`, exit 2 (repeat the flag) |
| `update web1` (a server or conn name) | tried to install version web1 | `USAGE`, exit 2, hint `komando pkg upgrade` |
| `host add aws ...` (`gcp`, `azure`; conn add and vpn add too) | added | `USAGE`, exit 2 (the names are kept for `komando login aws`) |
| `secret rm`, `key rm --delete-file`, `fs rm` | ran | `POLICY_BLOCKED`, exit 6, until a person agrees and `--allow-dangerous` is added |
| `storage link`, `cluster forward` through a read-only ssh-gate key | ran | `SSH_GATE_READ_ONLY`, exit 6 |
| `host trust --reset` (or a changed key) from an agent or a script | `SAFETY_SETTING`, exit 6, lifted by `--yes` | `NEEDS_PERSON`, exit 6; no flag lifts it |
| a person answers no to a filled-in command (a person only: no agent or script is asked, so the agent recording has no row for it) | exit 1 | `DECLINED`, exit 6 |
| `forward ...`, `script`, `prompt`, `host import`, `host export`, `db grants` | ran | unknown command, `USAGE`, exit 2 (use `tunnel`, `exec --script`, `status --short`, `import`, `export`, `db user show`) |
| `storage rm -n 10` and the other retired flags listed above | ran | unknown flag, `USAGE`, exit 2 |
| `cluster apply` (and `cluster run -- apply`) on a field another field manager owns | took the field over (server-side apply with force) | `K8S_CONFLICT`, exit 8, naming that manager; nothing is applied; `--force-conflicts` takes it over |

Text output (`-o text`) is not part of the contract, but agents read it:
the `next:` lines moved to stderr (`data.next` is unchanged), tables say
`yes` or `-` for a yes-or-no column and show times with their zone, and
an empty list reads `no <things> yet` or `no <things> match ...`.

`error.message` and `error.hint` are free text, and this release rewrites
many of them in plainer words (see "Changed" below); error codes and exit
codes are the same. A script that matches message text (`invalid port`,
`must be`, `unknown column`, `data.results`) should match the code
instead.

### Added

- `cluster apply --force-conflicts` (and `cluster run -- apply
  --force-conflicts`) takes over fields another field manager owns, as
  `kubectl apply --server-side --force-conflicts` does. Without it,
  apply no longer takes them over: an autoscaler's replicas or a
  `kubectl edit` stop it with `K8S_CONFLICT`, which names the manager
  and the fields, and nothing is applied. A protected cluster still
  needs a person's yes either way.
- `error.suggestion` holds the name komando thinks you meant when a
  command, server, conn, group, secret, setting or flag is misspelled,
  and the hint is then the whole command line with it in place (`run it
  again with exec: komando exec web1 -- uptime`). Additive. Words from
  other tools get the komando command that does that job: `komando ps`
  suggests `komando docker ps TARGET`, `kubectl` `komando cluster run
  TARGET -- ...`, `psql` and `mysql` `komando db query CONN`, `get`
  `komando list`, `delete web1` `komando host rm web1`.
- docs/features/error-codes.md has a table of the codes that mean the
  same (`PROTECTED_HOST` and `PROTECTED_TARGET`, `TARGET_EMPTY` and
  `NO_MATCHING_TARGETS`, ...) and which one new errors use. All of them
  stay.
- `error.thing` says which kind of item a shared not-found code is
  about: `KEY_NOT_FOUND` is `ssh_key` or `cache_key`, `NOT_FOUND` a Swarm
  service, stack or other object, `REGISTRY_NOT_FOUND` a `repository` or
  an `image_tag`, `K8S_NOT_FOUND` a `k8s_object`, `k8s_pod` or
  `k8s_container`, `CONN_NOT_FOUND` a `conn` or a `selector` that picked
  none. Additive; codes are unchanged. docs/features/error-codes.md
  lists the values and the codes a later contract splits them into.
- `vpn add/edit --label KEY=VALUE` and `--protected`, and `vpn edit
  --unset` (user, password-ref, psk-ref, id, remote-id, ca, check, notes),
  as on host and conn. `vpn edit` and `vpn rm` take several names or a
  selector (`NAME|TARGET...`); `vpn rm` lists the VPNs in `removed`
  (`would_remove` under `--dry-run`), even for one. A protected VPN needs `--yes` (a person's
  yes) to be changed, replaced or removed (`PROTECTED_TARGET`);
  `--protected=false` and `--mfa=false` need it too (`SAFETY_SETTING`).
  `vpn edit` of several VPNs prints `{"vpns": [...], "changed": [...]}`;
  one VPN prints `{"vpn": ...}` as before.
- `fs write --value TEXT` works as another name for `--content`.
- `komando rename OLD NEW` renames one entry of any kind: the server,
  conn, VPN, secret, key or group named OLD, through that kind's own
  rename (same checks, same envelope, e.g. `host.rename`). When two kinds
  share the name it names both commands (usage error); a name nothing
  has is a usage error, as before, whose hint shows `--starts-with`.
  `rename --starts-with OLD NEW` renames by prefix.
- `komando schema NAME` describes the command a second name runs:
  an alias (`schema fs ls`), a command ID as the envelope writes it
  (`schema secret.show`, `schema host.rename`) or a hidden synonym (`schema group show`). Before, hidden names gave
  `COMMAND_NOT_FOUND`.
- More names find the command you mean, each for good and silently:
  plurals and help words for every noun (`servers`, `server`,
  `databases`, `dbs`, `files`, `vpns`, `caches`, `queues`, `clusters`,
  `registries`, `tunnels`, `policies`, `crons`, `services`,
  `containers`); `cache list`/`ls` (= `cache keys`); `group show GROUP`,
  `job show`, `tunnel show TUNNEL`, `recipe show NAME`, `policy add`
  (= `deny`), `secret add` (= `set`); `describe` on `docker inspect`
  and `registry inspect`; `create` on `user add` and `db user add`;
  `copy` on `cp` and `secret cp`; `job stop` (= `kill`);
  `secret passwd` (= `passphrase`); `cluster info TARGET`
  (= `cluster status TARGET`). The envelope's `command` is that of the
  command they run.
- Every list command takes `-n/--limit` (`--limit` only in `cluster`,
  where `-n` is the namespace): `list`, `host/conn/vpn/key/secret/
  recipe/policy/job/tunnel/group list`, `svc/user/cron list`,
  `docker ps/images/stats`, `pkg installed/upgradable`, `net ports`,
  `db user ls`, `db activity`, `db locks`, `queue groups`,
  `cluster history` and `cluster helm ls/history`. Where there was no
  limit the default is 0, all, as before. A list that stops at its limit
  sets `meta.truncated: true` (new, additive), and in text mode one line
  on stderr says `showing N of more; use --limit 0 for all`. On commands
  that run on several servers the limit counts per server.
- `fs ls` counts with `-n/--limit` (default 1000, as before; 0 lists
  everything); `--max` there is gone.
  `job logs` takes `-n/--limit N` for the last lines, and `--tail` works
  on every log reader (`logs`, `svc logs`, `docker logs`,
  `cluster logs`, `job logs`) as another name for `--limit`.

- An unknown short flag gets a did-you-mean: `-n` where a command counts
  with `--limit`, `-it` (komando runs one command; `komando shell` or
  `komando cluster shell` for a shell), `-L`/`-R`/`-D` (port forwarding
  is `komando tunnel start`), `-w` for `--wait`, and otherwise the long
  flags that start with the same letter.
- `fs mkdir -p` (and `--parents`) is accepted and changes nothing:
  `fs mkdir` always makes the missing parents.
- More short flags, each with the meaning it has everywhere else:
  `cluster apply -f FILE`; `-c` for `--container` on `logs` and
  `cluster deploy`; `-a` for `--all` on `cache info`,
  `cluster helm values`, `db activity`, `user list` and `guide`;
  `docker compose -C DIR`; `host add/edit -e KEY=VALUE`. A command that
  changes things gets no `-a` (`fs replace`, `tunnel stop`, `vpn down`,
  `logout` keep `--all` only).
- `komando schema` names where a flag's real default comes from:
  `--timeout`, `--connect-timeout`, `--parallel`, `--host-key-policy` and
  `--max-output` carry `default_from` (`setting:default_timeout` and so
  on), and their help names the setting. Help texts give example values
  as "e.g. 30m", so they are not read as defaults.
- `upload`, `download` and `cp` show the progress of a file of 8 MiB or
  more going to or from one server on stderr, at a person's terminal only.
- A [Secrets](docs/features/secrets.md) page: save, use, check, rename,
  copy and remove secrets, where the key is kept, and what an AI agent
  runs or gets at each step.
- `job start --script FILE` (with `--arg` and `--interpreter`) runs a
  script from this computer as a background job, as `exec --script` does
  in the foreground. A long `exec --script` that times out names it.
- `komando schema` gives each command a `confirm` list (additive): the
  approval tier it always has, then each tier it reaches only sometimes,
  with the flag an AI agent or a script adds (`--allow-dangerous`, `--yes`,
  none for a person-only step) and when. It comes from the same rule table
  as komando's own stops.
- A dry run that could not try a step says so in the new
  `meta.not_simulated` (additive): `db query --dry-run` with a statement
  that commits by itself (MySQL DDL, sqlite VACUUM, CREATE DATABASE ...)
  lists it there; its result already said `skipped`.

### Changed

- The docs are rewritten for beginners: every feature page starts with the
  most common task as a command, shows what komando asks when something
  is left out, and ends with its limits and troubleshooting. The README is
  short, installing (also on Windows) has its own page, and the rules
  komando follows are in `docs/design/principles.md` and the command
  standard. Design notes and reviews left the repository.
- Commands named in hints, help and Next: lines use the words of the
  command they name: `komando test TARGET` (was `test CONN` and `test
  NAME`; komando fills in the name you gave, a VPN's too), `komando
  shell SERVER`, `komando conn rm TARGET`, `komando storage download
  CONN OBJECT`, `komando registry rm CONN IMAGE`, `komando cluster
  history TARGET TYPE/NAME`, `komando user lock web1 USER`, `komando
  policy rm RULE`, `komando queue lag CONN CONSUMER` and others. The
  groups `host`, `conn`, `vpn`, `key`, `secret`, `group`, `job`, `fs`,
  `policy`, `config`, `db user` and `cluster helm` show examples that
  walk look, dry run, change.
- Examples use one set of sample names: servers `web1`, `web2`, `db1`,
  `@web`; databases `prod-db`, `staging-db`; cache `prod-redis`; queue
  `prod-kafka`; storage `backups`; registries `ghcr`, `harbor`;
  clusters `prod-k8s`, `swarm1`; VPN `office`; users `alice`, `app`. A
  conn is never named after its family (`cache`, `events`), and cluster
  objects are written `TYPE/NAME` (`pod/api-7d9f-x2`).
- Help says "conn" for a database, cache, queue, storage, cluster or
  registry komando talks to (`conn kinds`, `conn rename`, `list`, the
  name check of the add questions), never "service" or "resource", which
  mean a systemd unit or a cluster object.
- Every change command's `--help` has a generated `Safety:` line after
  its first paragraph, from the same rule table as `komando schema`'s
  `confirm` (what it asks of a person, an AI agent and a script).
  Person-only commands end their summary with "(person only)". Help text
  is wrapped at 76 columns. Each change command shows a `--dry-run`
  example, and an example with `--yes`, `--allow-dangerous` or
  `--reveal` comes right after its dry run and ends with `# after a
  person's yes`.
- Command summaries (`Short`, the line in every list) follow one shape:
  a verb phrase with no flags, semicolons or approval notes ("needs
  --allow-dangerous" is gone from them; the generated Safety line in the
  help says it). Group summaries name the area and its main jobs in plain
  verbs (`Services on servers: check, start, stop, read logs`).
  Inventory `rm` commands end with "(from komando only)", and `secret
  rm` says the value goes for good. `host list`, `conn test`, `svc logs`
  and the other second spellings say what they do; "Same as `komando
  ...`" moved to the first line of their help.
- `komando --help` starts with Start (`host add`, `conn add`, `import
  ssh-config`, `list`, `test TARGET`, `guide install`), and a new
  Inventory group holds `host`, `conn`, `group`, `import`, `export` and
  `rename`, which Setup no longer crowds. `komando` alone at a terminal
  shows the same groups.
- Usage lines give each argument word one meaning (`komando schema`'s
  `usage` values change; every command takes the same arguments as
  before). SSH keys are `key deploy NAME TARGET` and `key revoke NAME
  TARGET`; a storage object is `OBJECT` and a setting `SETTING`, so `KEY`
  is only a cache key; `queue lag CONN CONSUMER`; the `fs` commands that
  take one server and `shell` say `SERVER`; `login [SERVER]`, `logout
  [SERVER...]`, `net check TARGET ADDRESS:PORT...`, `net dns TARGET
  DOMAIN`; accounts are `USER` (`user add TARGET USER`, `db user add CONN
  USER`); `job ... JOB`, `tunnel stop [TUNNEL...]`, `cron set/rm TARGET
  NAME`, `policy rm RULE`; cluster objects are `TYPE/NAME` (`TYPE NAME`
  still works); what runs after `--` is `-- COMMAND...` or `-- ARGS...`;
  a required flag shows with its value (`db restore CONN --from FILE`,
  `cron set ... --schedule SCHEDULE`, `ssh-gate line PUBLIC_KEY --name
  NAME`, `db user add/passwd ... --password-ref REF`, `tunnel start
  TARGET (-L SPEC | -R SPEC | -D SPEC)`); `host add NAME
  [[USER@]ADDRESS[:PORT]]`, `host/conn/vpn edit` and `rm TARGET...`,
  `registry inspect/rm CONN IMAGE`, `cert check TARGET|URL...`.
- A person asked for a TARGET reads which kinds it takes (`Target
  (servers)`, `Target (clusters)`, `Target (servers or file storage)`),
  and the picker and Tab offer only those. `fs cat` and the other
  one-server commands pick one server.
- More error hints name the komando command to run: `AMBIGUOUS_MATCH`
  (`komando fs cat`), `BUILTIN_RULE` (`komando policy list`),
  `CACHE_AUTH` and `DB_CONNECT` (`komando conn show`),
  `CONNECTION_REFUSED` (`komando host show`, now in backticks),
  `DOCTOR_FAILED`, `KEY_UNREADABLE`, `NO_MATCHING_TARGETS`,
  `PORT_IN_USE`, `RECIPE_EXISTS`, `UNKNOWN_SETTING`, `VPN_IN_USE` and
  `STORE_NEWER` (`komando update`).
- An unknown command word suggests at most two names, within one typo
  for a word of four letters or fewer and two for a longer one: `komando
  ps` no longer suggests cp, db, fs, pkg and vpn. The hint names a
  command only when there is one suggestion.
- Commands in hints use the words of the command they name, and komando
  fills them in: drivers say `komando test CONN` (was `komando conn
  test NAME`), and `komando login SERVER`, `komando shell SERVER`,
  `komando fs stat SERVER ~/.ssh` and `komando net check TARGET
  ADDRESS:443` replace HOST. The target the command was given now fills
  SERVER (a server) and NAME (in a command of its own noun, such as
  `komando conn edit NAME`) as well as TARGET and CONN.
- Every safety stop a flag lifts is built by one helper, so its hint
  reads the same wherever it comes from, results per server included
  (`check with --dry-run, ask the user; once they agree, run it again
  with --yes`). `komando schema`'s `error_codes` shows that hint for
  `POLICY_BLOCKED`, `PROTECTED_*`, `SAFETY_SETTING`,
  `SECRET_DESTINATION`, `OPEN_BIND` and `CONFIRM_REQUIRED`. The
  `PROTECTED_HOST` message says "server" (was "host"). Advice a hint
  carried (log in as another user first, trusting a kubeconfig program)
  is in the message now. "re-run with" reads "run it again with".
- Error hints say only the next step. What happened ("nothing was
  changed", "nothing was renamed", "the file was not changed") moved to
  the end of `error.message`, and every retry reads "run it again"
  (was "try again", "re-run", "run the command again"). `RESTORE_FAILED`
  says what the database holds per engine (PostgreSQL: nothing changed;
  MySQL: the statements before the line stay) and its hint is the
  `komando db restore` line to run again. A person's no (`DECLINED`) and
  Ctrl-C (`CANCELLED`) hints say to run it again. Codes and exits are
  unchanged.
- A name komando does not find is worded one way in `error.message`:
  `no server named "web9"`, `no topic named "orders"`, `no cache key
  named "x"` (was `host "web9" not found`, `topic orders does not
  exist` and others). The word is the one people read (server, SSH key,
  VPN), never `host`. `error.message` is free text; codes are unchanged.
- Every error code is written out in the source: `HOST_EXISTS`,
  `CONN_EXISTS` and `VPN_EXISTS` (and the not-found codes of `host`,
  `conn`, `vpn`, `job`, `key`, `recipe`, `secret` and `tunnel`) were
  built from the kind and missing from `komando schema`'s
  `error_codes`; they are listed now. Codes and exits are unchanged.
- Every safety stop that a flag lifts now has one hint wording, naming
  every flag the real run needs. An AI agent reads `check with --dry-run,
  ask the user; once they agree, run it again with --yes (komando then asks
  them in a window on their screen)`; a script reads `check with --dry-run,
  then run it again with --allow-dangerous:` followed by its own command
  line with the flag filled in (the flag goes before `--`). In a dry
  run, `meta.would_be_blocked.hint` says to run it again without
  `--dry-run`. Codes, messages and exit codes are unchanged; a few
  messages gained the advice their hint carried (a credential plugin, a
  proxy command, an open tunnel address, trusting a kubeconfig program).
- `storage link` and `cluster forward` are `kind: change` in `komando
  schema` (were `read`): they hand out access and already stopped on a
  protected target. An ssh-gate key added with `--read-only` is refused
  them (`SSH_GATE_READ_ONLY`, as before); a full key still runs them. At a
  terminal a filled-in one asks `Run it?` like any change.
- **Replacing a pinned host key is for a person at a terminal only.**
  `komando host trust NAME --reset` shows the old and new key and asks
  once (one question for a group, with "(protected)" when it is). An AI
  agent or a script gets `NEEDS_PERSON` (exit 6; was `SAFETY_SETTING`,
  which `--yes` lifted), before anything is fetched when a key is pinned,
  and no flag lifts it; the hint names the command for a person to run.
  A server with no pin yet is pinned as before.
- At a terminal, `registry prune` asks you to type the repository whose
  old images go (`Type the name shop/api`), not the conn's name.
- **`secret rm`, `key rm --delete-file` (a key komando made) and every
  `fs rm` now need `--allow-dangerous`** from an AI agent or a script:
  what they delete has no copy. Without it they stop with
  `POLICY_BLOCKED` (exit 6); `--dry-run` shows what would go and lists
  the flag in `meta.would_need`. At a terminal a person types the name
  of what goes instead. `fs rm` on a protected server stops with
  `POLICY_BLOCKED` first now (was `PROTECTED_HOST`), and its hint names
  `--yes` as well. `cron rm` and `pkg rm` (not an essential package) need
  no flag, as before.
- A command komando filled in at a terminal asks `Run it?` and then, for
  a step that cannot be undone, the typed name once, in the command
  itself; before, a prompted `cache rm` or `cluster rm` asked for a name
  twice (and two different ones). `cron rm`, `pkg rm` (not an essential
  package) and `db kill` ask for the name of what goes instead of `Run
  it?`; they still need no flag from an agent or a script.
- At a terminal, a step that cannot be undone asks you to type the name
  of what goes (the key, file, secret, topic, image or user), or how many
  when several go (`Type 37 (objects under daily/ in backups) to
  continue`), or the server's or conn's name for a whole-target step;
  never the word yes. On a protected target that one question covers the
  protection too, so komando no longer asks a [y/N] after it. A policy hit
  on a `--proxy-command` or a cluster login program asks for the name
  instead of [y/N]. The questions use three forms: `NAME (protected): ...
  Continue? [y/N]`, `Dangerous: ...` with the typed name, and `This turns
  off a komando safety check: ... Continue? [y/N]`.
- A destructive step on a protected target: the POLICY_BLOCKED hint now
  names both flags (`--allow-dangerous and --yes`), and a dry run lists
  every flag the real run needs in the new `meta.would_need`
  (`["--allow-dangerous","--yes"]`); before, a dry run stopped looking at
  the first stop.
- A person who answers no when komando asks before running a filled-in
  command (`Run it?`, the typed name) gets exit 6, like a no at any safety
  question, with the new code `DECLINED` and `Cancelled. Nothing was
  changed.` (was `CANCELLED`, exit 1). Ctrl-C there stays `CANCELLED`,
  exit 1, and now says `Stopped.`. AI agents and scripts are never asked,
  so nothing changes for them.
- `aws`, `gcp` and `azure` are reserved names for conns and VPNs too, as
  for servers and as `all` is: `conn add`, `vpn add`, `rename` and
  `import` refuse them (usage error, exit 2). An older entry with such a
  name keeps working; `komando login aws` stays the cloud login and notes
  on stderr (and in `meta.warnings`) how to rename it, and `doctor` warns.
- `komando update NAME` with the name of a server or conn (or a selector
  like `@web`) is a usage error (exit 2) whose hint is
  `komando pkg upgrade NAME`; before, it was taken as a version to
  install. A version (`update v0.6.0`) works as before.
- **Security updates are installed with `komando pkg upgrade TARGET
  --security`** (with `--keep-going` and `--refresh`): the same rollout
  as before, one server at a time with a check before and after, the
  same stops, and `pkg.upgrade` in the envelope and the audit log (was
  `pkg.security`). `pkg security` now only looks; `pkg security --apply`
  is gone.
- `vpn add/edit --proxy-address` is the address of a SOCKS or HTTP proxy
  VPN (was `--address`, which on `host add` is the server's address), and
  `policy check --conn-kind KIND` rates a statement for a conn kind (was
  `--for`, while `--kind` elsewhere is a list). The old names are gone.
- `recipe add --needs-sudo` marks a saved recipe as one that runs with
  sudo (was `--sudo`, which elsewhere runs the command itself with sudo),
  and `cron` reads root's crontab with `--user root` (`--sudo`/`-s` there
  is gone). The old flags are gone.
- `db dump` and `db restore` name the server that runs pg_dump,
  mysqldump or pg_restore with `--run-on HOST` (was `--on`, which on
  `db grant` names what the privileges are on). `--on` on dump and
  restore is gone.
- `komando rename` switches read as switches: `--starts-with` (was
  `--prefix`, which elsewhere takes a value), `--in-notes` (was
  `--notes`) and `--in-labels` (was `--labels`). The old names are gone.
- `host edit`, `conn edit` and `vpn edit` show `--add-group` and
  `--add-tag` in help; `--group/-g` and `--tag/-t` still work there, for
  good, and are no longer listed.
- `docker logs` no longer shows `--priority` (a container log has none)
  and `svc logs` no longer shows `--timestamps` (the journal always has
  times). Neither command takes that flag any more.
- `queue peek --idle 10s` is how long a Kafka peek waits with no new
  message (was `--wait`, which elsewhere means "wait for the result").
  `--wait` is gone.
- `cluster rollback` takes the revision as `--revision N` (kubectl's
  `--to-revision` works too, for good). `--to` is gone.
- `--from` now always means a file on this computer (`db restore`,
  `fs write`, `queue send`). The MySQL account host is `--from-host` on
  `db grant`, `db revoke`, `db user show/add/passwd/rm`, and the backup
  copy `fs restore` puts back is `--copy PATH`. The old `--from` there is
  gone.
- The top-level `komando forward` (another name for `tunnel`, easy to
  mix up with `cluster forward`) is gone: use `komando tunnel` (or `pf`).
- `db user show CONN USER` shows what a database user may do (was
  `db grants`, one letter from `db grant`, which is gone); the envelope's
  `command` is `db.user.show` (was `db.grants`).
- **`list` is the one listing verb**: `cluster list`, `cluster helm list`,
  `db user list`, `fs list`, `queue list`, `registry list` and
  `storage list` are the names in help, hints and docs. `ls` keeps
  working on every list command for good. The envelope's `command` is
  `fs.list` and so on (was `fs.ls`, `cluster.ls`, `cluster.helm.ls`,
  `db.user.ls`, `queue.ls`, `registry.ls`, `storage.ls`).
- `secret show NAME` is the name for checking a secret (it never prints
  the value to an agent); `secret get` keeps working for good. The
  envelope's `command` is `secret.show` (was `secret.get`), and an
  agent's output is masked as before.
- **Renaming an item is `rename`**: `host rename`, `conn rename`,
  `vpn rename`, `key rename`, `secret rename` and `group rename OLD NEW`.
  `mv` keeps working there for good and prints nothing extra. The
  envelope's `command` is `host.rename` and so on (was `host.mv`,
  `conn.mv`, `vpn.mv`, `key.mv`, `secret.mv`, `group.mv`). `fs mv` is
  unchanged.
- `cache get --limit` is listed as `int` in `komando schema` (was
  `int64`); the values it takes are the same.
- `storage rm --prefix` names its safety cap `--max-remove` (default
  1000), so it is not taken for a list's `--limit`. `--limit` and `-n`
  there are gone.
  The `TOO_MANY` message and hint name `--max-remove`.
- **In `cluster` commands, `-n` is now `--namespace`, as in kubectl**, on
  all 20 commands that take a namespace. `cluster events`, `logs` and
  `ls` keep `--limit`, now without a short form. A number after `-n`
  there (`-n 50`, the old count) is refused (exit 2) with the hint
  "`--limit 50`, or `--namespace=50` for a namespace named 50", so an
  old command line never reads 50 as a namespace.
- **`--env` (host add/edit), `--label` and `--option` take one KEY=VALUE
  each time and no longer split on commas.** Repeat the flag for more:
  `--label team=ops --label env=prod`. A value keeps its commas, and
  `--option a=on,b=x` (two pairs in one) is now a usage error (exit 2)
  that shows the repeated form, never one option. `komando schema` lists
  these flags as `stringArray`.
- `queue peek/send --partition` and `queue create --partitions/--replicas`
  no longer show `-1` as their default: their help says "default: the
  broker's", and `komando schema` lists no default for them. Leaving them
  out means the broker decides; `-1` is a usage error.
- Every size flag reads sizes the same way: `--max-output`, and
  `--max-bytes` on `fs cat`, `storage cat`, `job logs`, `db query` and
  `db explain`, take bytes or `256KiB`, `10MB`, `1GB` (KB = KiB = 1024).
  `--max-output 256KiB` was refused before. `komando schema` lists them
  with type `bytes`.
- Every flag that takes a time (`--timeout`, `--connect-timeout`,
  `--wait`, `--interval`, `--expires`, `--ttl`, `--warn`, `--older-than`)
  reads it the same way: `30s`, `10m`, `2h` or `7d`, and `0`. Days now
  work everywhere, a time below 0 is refused while the flags are read, and
  `komando schema` lists these flags with type `duration` and short
  defaults (`10m`, not `10m0s`). `svc restart --wait 10` and `reboot
  --wait 600` need a unit now (`10s`, `600s`).
- One rule table now says what a command needs before it runs; the
  stops stay in the commands, and a test checks each recorded stop
  against the table. At a terminal, a command komando asked you to fill in asks you to type the
  target's name for every change that stops an AI agent as dangerous:
  `reboot`, `svc stop` of sshd, `sync --delete` and `db kill` now ask
  for the name instead of `Run it?`. What AI agents and scripts get is
  unchanged.
- The test that records what AI agents and scripts get now also records
  every safety stop komando can show without a server (50 command lines:
  dangerous commands, protected servers and conns, safety settings,
  write flags, a large group and person-only commands), so a later change
  cannot quietly drop one.
- At a terminal, `group rm` now ends with the way back:
  `Next: komando group add GROUP TARGET...`. Deleting a group of more than
  3 members still needs `--yes` from an AI agent or a script.
- **Commands that hand words to another program now need `--` before
  them**: `exec`, `job start`, `docker exec`, `docker compose`,
  `docker raw`, `cluster exec`, `cluster shell`, `cluster run` and
  `cache run`. `komando exec web1 apt-get install -y nginx` read `-y`
  as komando's own `--yes`, and a trailing `--dry-run` was taken by
  komando while the rest ran; such a line is now a usage error (exit 2)
  that runs nothing and shows the form with `--`. komando's flags still
  go anywhere before `--`, and `-c` and `--script` are unchanged.
  `job start TARGET COMMAND` without `--` and `cache run CONN "GET k"`
  are refused too: write `job start TARGET -- COMMAND` and
  `cache run CONN -- "GET k"`.
- A flag synonym (`--tail`, `--to-revision`, `--value`, `-g`/`-t` on
  edit) is a hidden spelling of the same flag, so every safety check (the
  ssh gate's read-only keys included) sees the flag under either name. A
  test checks each spelling. A short alias such as `x` for `exec` prints
  nothing extra.
- Every command now carries an ID (its dotted path, such as
  `fs.list`), and the envelopes, the audit log, personal-data hiding, the
  ssh-gate tables and the other checks keyed by command use it. A test
  lists every ID and checks that every table key is one, so a rename that
  forgets a table fails. Audit records written before keep the ID of
  their time.
- `komando --help` now lists the commands under the same headings as
  `komando` alone: Servers, Data, Platform, Access, Overview and Setup.
- At a person's terminal, many more commands end with a `Next:` line of
  what usually comes next (`svc status` suggests `logs web1 --unit UNIT
  --since 30m`), and `group list GROUP`, `key show`, `job status`, `secret
  get` and `config get` now end with the commands for that item, as
  `host show` does. A conn's list fits its kind (a SQLite database has no
  `db user ls`); a Windows server and a Swarm manager get their own.
- A test now records what AI agents and scripts get from every command
  typed with too few arguments (stdout, stderr and exit code, in JSON and
  text). It guards the move from the menu to typed commands that ask a
  person for what is missing: agents and scripts must see no change.
- Shell completion now offers your databases for `db dump` and
  `db restore`. Questions that pick a saved recipe, a `--via` server or
  VPN, a `--key` or a setting now show a list of the ones you have
  instead of a blank line.
- New: komando's line-by-line questions for a person at a terminal (a
  value by its real name, a numbered list to pick from, `Run it? [y/N,
  d = --dry-run first]`, type a name to confirm). They are only ever
  asked when stdin, stdout and stderr are terminals, no AI agent runs
  komando, CI is not set, TERM is not dumb and the output is text.
- A person at a terminal who types a command with something missing is
  now asked for it instead of getting a usage error: `komando logs` asks
  `TARGET:` with a numbered list of your servers, `komando db query`
  uses your only database and asks `SQL:`, `komando fs replace web1
  /etc/x` asks `--old:` and `--new:`. komando then shows the whole line
  (`$ komando logs web1`) and runs it. A change asks `Run it? [y/N, d =
  --dry-run first]` first; one that deletes for good asks you to type the
  target's name; a protected target asks its usual [y/N] instead. A
  protected server is never picked for you. A command typed in full, and
  everything AI agents and scripts get, stays exactly as before.
- `komando host add`, `conn add`, `vpn add`, `db add`, `cache add`,
  `queue add`, `storage add`, `cluster add` and `registry add` typed alone
  at a terminal now ask their questions line by line in the normal screen
  (which kind, name, address or the parts of the URL, how to log in,
  production), show the commands, ask `Run it?`, and run them. A password
  pasted with the address is never drawn. When the test after an add
  fails, komando says the three commands to change, test again or remove
  it, instead of a menu.
- At a terminal, a `--proxy-command` or a cluster's login program that the
  dangerous-command filter blocks now asks `Blocked by policy: ... Run it
  anyway, this once? [y/N]` (No by default) instead of failing; the other
  dangerous commands still ask you to type the name. A yes you give at the terminal is recorded in
  `komando audit` as `confirm: tty`. Nothing is asked, and no answer
  counts, when CI is set. AI agents get exit 6 as before.
- `komando` alone at your terminal now prints what komando does, by
  group (START, SERVERS, DATA, PLATFORM, ACCESS, OVERVIEW, SETUP), with
  examples, and says how to add your first server when nothing is added
  yet. New help topics: `komando help safety`, `environment`,
  `exit-codes`, `output`. At your terminal, `host show`, `conn show` and
  `vpn show` end with the commands that work on that item, and after a
  command ends well komando may say what usually comes next (`Next:`) and,
  when it asked you for something, the line to type next time. All of
  this goes to stderr, and only at a person's terminal.

- **What to run next is on stderr only.** `next:` lines are gone from
  stdout (`host add`, `conn add`, `vpn add`, `import`, `update`,
  `registry list`; job start's "follow it with:" and policy deny's "try
  it:" lines). A person sees one `Next:` line on stderr, at most three
  commands, filled in: `host add web1` gives `Next: komando test web1 ·
  komando host show web1 · ...`, `job start` the real job IDs. JSON keeps
  `data.next` (and `data.next_steps`) as before. A script that read the
  `next:` line from `-o text` reads `data.next` instead.
- Every add, edit, rename and rm says what comes next: add → `test` and
  `show`, edit → `show` and `test`, rename → `show NEW`, rm → `list`
  (`fs rm` → `fs list`, `docker rm` → `docker ps --all`). `tunnel show`
  and `recipe show` end with the commands for that tunnel or recipe.

- A list with nothing in it says so in one wording on stdout:
  ``no SSH keys yet: `komando key gen NAME` ``, ``no conns yet: `komando
  conn add NAME URL` ``, `no cache keys match "user:*"`, `no audit
  entries match --failed (fewer filters show more)`. `conn list`, `vpn
  list` and `host list` with none of their kind, `docker ps/images`, `fs
  list` of an empty folder, `cluster history` and `cluster helm history`
  printed only a header or `(none)` before. JSON still returns an empty
  array.

- Text tables read one way: a yes-or-no column says `yes` or `-` (`vpn
  status` UP, `net check` OPEN, `recipe list` READ ONLY, `user list`
  ADMIN GROUP and LOCKED, where `?` is unknown, `rename` PROTECTED,
  RabbitMQ consumers ACTIVE; they said `yes`/`no`); a time carries its
  zone (`2026-11-07 14:30 WIB` in `audit`, `fs list`, `storage list` and
  `registry prune`, where storage times were UTC shown without one); an
  age is `3h` (`vpn status` SINCE); headers are words with spaces (`USED
  BY` in `key list` and `secret list`). A script that greps `-o text`
  for `no` in these columns reads `-o json` instead, which is unchanged.

- Change commands say what they did in words with `-o text`, never raw
  JSON keys: `host add/edit`, `conn add/edit`, `key gen/add` and `secret
  set` list each field as words (`password ref: secret:web1-pass`, was
  `password_ref`) and each warning as `warning: ...`; `secret rename/cp`
  (`renamed secret s1 to s2`), `secret rm`, `tunnel stop`, `host trust`
  (`would fetch the host key of web1 ... and remove 1 pinned key`) have
  a line of their own. JSON is unchanged.

- The skill, `komando guide` and AGENTS.md use each command's primary
  name (`secret show`, `host rename`, `fs list`, `storage list`, `pkg
  upgrade --security`, `db dump --run-on`, `rename --starts-with`) and
  teach the `--` before the words for another program on every command
  that takes them. `komando doctor` says when an AI agent's skill is from
  another komando version; run `komando guide install` again.
- komando's own lines on stderr start with a capital or a fixed label:
  `Hint:`, `Warning:`, `Note:`, `Dry run:`, `Skipped`, `Nothing to show`
  (were lower case). A stop reads `Stopped: <what>; nothing was changed`,
  every cut list or output says `Note: showing the first N; ...`, and at
  a terminal errors, hints, warnings and notes wrap at 80 columns without
  breaking a backticked command. An AI agent and a pipe still get each on
  one line.
- Ctrl-C reads the same everywhere: `Stopped. Nothing was run.` at a
  question, `Stopped (Ctrl-C) before the end; what already ran stays as it
  is` while a command runs, and `Stopped (Ctrl-C); the login was not kept`
  in `komando login`. A no at `doctor --accept-old-copy` says what stayed in the message and the command to
  run again in the hint (the hint said "nothing was changed in ...").
- Status words in `-o text` are lower case: `ok, exit 0`, `failed: exit 3`,
  `failed: timed out`, `failed: <why>` (were `ok exit=0`, `FAILED ...`),
  `audit log broken at line N`, and a failed server's block in a
  several-server result ends with `Error: <what> (code CODE)` and `Hint:`
  (was `error [CODE]:` and `hint:`).
- The typed question for a step that cannot be undone starts `This <what it
  does>.` (was `Dangerous: <what>.`), and every rule reason reads after
  "This": `deletes / or the home folder recursively` (was `recursive
  delete of / or home`), `starts a fork bomb ...`, `changes the owner of
  / recursively`, `removes every row (DELETE without WHERE)`, `restores
  a backup, which can overwrite existing data`, `matches your deny rule
  ...` (was `matches custom deny pattern ...`). These are also the
  `reason` values of `komando policy list` and part of `POLICY_BLOCKED`
  messages; rule IDs are unchanged.
- Error messages and hints say what is true about the input, never blame:
  `"x y" cannot be a server name`, `the port "0" in the conn URL is not a
  number from 1 to 65535`, `komando cannot read the conn URL ...`, `the
  kafka tls option takes true or skip-verify, not "yes"` (were `invalid
  ...`, `bad ...`, `... must be ...`). "unknown" appears only with the
  known values (`db grant --privileges` lists them). Hints use "for
  example" (not "e.g."), "server" and "conn" (not "host" or "service"),
  "your list" (not "inventory"), and plain words before JSON paths and
  stream names: `each server's result has its exit code and error output
  (data.results in -o json)`, `read the error output (stderr) ...`.
  Flag errors say what a flag takes (`--limit takes 1 or more`, was
  `--limit must be 1 or more`).
- The questions komando asks for a missing argument say "conn" for a
  database, cache or other conn (`To which server or conn?`, `No conns
  yet: ...`) and "like" for an example (`Name, like web1:`, was `Name,
  e.g. web1:`).
- Help says "your list" for the servers, conns and VPNs komando knows
  (`host add`, `host rm`, `doctor`, the target words in `komando schema`),
  and flag help gives examples with "like" or "for example", never
  "e.g.".
- `komando doctor` names each check in words (`komando folder`, `audit
  log`, `servers`, `SSH keys`, `AI agent skill`, `VPN office needs
  openconnect`) and, at a terminal, wraps a long detail at 80 columns (a
  pipe or a script gets each check on one line). `-o json` keeps
  the check names (`state`, `audit_log`, ...).

### Removed

- The old command names `forward` (now `tunnel`), `script` (`exec
  --script`), `prompt` (`status --short`), `host import` (`import
  ssh-config` or `import komando`), `host export` (`export`) and `db
  grants` (`db user show`). komando is used internally only, so a renamed
  command no longer keeps its old name; each is now an unknown command.
- The retired flags: `db dump/restore --on`, `--from` on `db user`, `db
  grant` and `db revoke`, `fs list --max`, `fs restore --from`, `storage
  rm --limit` and `-n`, `vpn add/edit --address`, `rename --prefix`,
  `--notes` and `--labels`, `recipe add --sudo`, `cron --sudo`/`-s`,
  `queue peek --wait`, `cluster rollback --to`, `policy check --for`,
  `db query --csv`/`--tsv`, `key gen --overwrite`, `docker logs
  --priority` and `svc logs --timestamps`. Each is an unknown flag now.
- `pkg security --apply` and `--keep-going`: `pkg upgrade TARGET
  --security` installs the security updates and audits as `pkg.upgrade`.
  A bare number of seconds for `svc` and `reboot --wait`, and `-1` for
  queue `--partition`, `--partitions` and `--replicas`.
- `recipe run` of a built-in recipe removed in 0.12 (`ports`, `dns`,
  `failed-units` ...) no longer names the command that replaced it; it is
  `RECIPE_NOT_FOUND` like any unknown recipe. Typing `ops`, `snippet`,
  `snippets`, `diag` or `policy allow` no longer suggests the command
  that took the name; `inspect` and `systemd` still suggest `facts` and
  `svc`.
- `import komando` reads only the export file (`komando-export/1`, or the
  envelope `komando export` prints); a plain list of hosts or the
  `{"hosts": [...]}` that `host export` printed before 0.12 is refused.
- Command IDs that kept a renamed command's old path: `host.mv`,
  `conn.mv`, `vpn.mv`, `key.mv`, `secret.mv`, `group.mv`, `secret.get`,
  `cluster.ls`, `cluster.helm.ls`, `db.user.ls`, `fs.ls`, `queue.ls`,
  `registry.ls`, `storage.ls` and `db.grants` are now `host.rename` ...
  `secret.show`, `cluster.list` ... `storage.list` and `db.user.show`, the
  command's path.
- Answers kept in an old shape beside the new one: under `--dry-run`,
  `host rm`, `conn rm` and `key rm` print only `would_remove` (no longer
  `removed` too); `vpn rm` always lists the VPNs (one VPN was a string);
  `host trust NAME` answers with `data.results` and `data.summary`, as
  for several servers (one server was a flat object).
- Homes from before 0.12 are no longer read: `komando seal` and `seal
  --undo`, the `NEEDS_SEAL` and `SEAL_UNFINISHED` codes, and the readers
  of `state.json`, a plain `runtime.json`, `vault.json` (with `vault.key`,
  a keychain key or a passphrase, and the old scrypt cost), `known_hosts`,
  `keys/` and a plain Tailscale `tailscaled.state` are gone (every
  internal home has `store.db`). A home without `store.db` starts empty,
  as a new install does; one that had a store (`store.key`,
  `runtime.pids` or the keychain's change count) and lost `store.db`
  still stops with `STATE_CORRUPT`, and the hint says to put `store.db`
  back from a backup. `doctor` no longer warns about old files beside
  `store.db`.
- `meta.deprecated` and the code behind it: nothing uses an old spelling
  now, so no command sets it. `komando schema` no longer resolves old
  names (an alias, a command ID and a hidden synonym still resolve), and
  `komando doctor` no longer lists the old spellings a stale AI agent
  skill teaches (it still says the skill is from another version).
- The menu that `komando` alone opened at a terminal, its task lists and
  the full-screen forms and review screen (owner decision 2026-11-12:
  person mode is commands). Everything it did is a command: `komando`
  alone shows them by group, `host show` lists the commands for a server,
  and a command typed with something missing asks for it. Running now is
  `komando status`, History and undo is `komando audit`, Check everything
  is `komando test all` and `komando doctor`.

### Fixed
- `komando schema` (`confirm`), the commands' Safety line and the tier
  table in docs/features/safety.md now name every stop an AI agent meets:
  `host ssh-command` and `secret keychain` (moving the key in) are for a
  person only (`NEEDS_PERSON`); `--yes` (`SAFETY_SETTING`) for an agent's
  `--proxy-command` on `host add` and `host edit`, a server with a proxy
  command in `import`, a kubeconfig context whose login runs a program or
  sends a file (`import kubeconfig`), `recipe add --overwrite --read-only`
  on a recipe that was not read-only, a first host key pin under strict
  host keys (`host trust`) and `guide uninstall`. The stops are unchanged;
  an agent that planned from `confirm` met them unannounced.
- `import komando` and `import csv` typed at a terminal without FILE ask
  for it (they have no usual file); before, the run stopped with "give the
  file to import".
- SQL Server: a certificate with a negative serial number, which SQL
  Server makes for itself, failed with `x509: negative serial number`.
  komando now parses it (`x509negativeserial=1`); the chain and the host
  name are still checked.
- On Windows, komando's folder (`KOMANDO_HOME`) gets an access list of its own when komando makes it, as does every folder above it that komando has to make: only you and SYSTEM may open it and everything inside. A folder made under `C:\` used to let every user of the computer read it, since file modes do nothing on Windows. `komando doctor` now reads the access lists there and names any file others may open, with the `icacls` commands that fix it (they set the folder's access list whole, so no entry for another account stays).
- On Windows, komando knew no running VPN session, tunnel or `komando login` as its own: it asked `ps` which program a process runs, and Windows has no `ps`. It now asks Windows, so `vpn status`, `tunnel list` and `status` see them and `vpn down` stops them.
- On Windows, `login aws` and a VPN's web sign-in open your browser (they printed the address only), and a VPN sign-in that komando watches finds Chrome, Edge or Brave where Windows installs them.
- On Windows, a server's `--proxy-command` runs in cmd.exe; it called `/bin/sh`, which Windows does not have. `%h`, `%r` and `%n` go in bare or in double quotes, and a server whose address, user or name holds `%`, `"` or a line break stops with `PROXY_FAILED` instead of running.
- On Windows, a server with no user logs in as you (`USERNAME`; komando read only `USER`, which Windows does not set), the audit log names you as the actor, and its `os_user` is your account instead of `uid -1`.
- A SQLite conn takes a Windows path: `sqlite://C:\data\app.db` (and `sqlite:///C:/data/app.db` on Windows). `C:` used to be read as a server name: the URL was refused, or `sqlite://C:/data/app.db` opened `/data/app.db`.
- In a Windows console, the red PROTECTED mark and a question that hides a pasted password show as meant: komando turns on the console's escape sequences while it runs (they showed as text like `←[1;31m`). A console too old for them gets no colour, and the hidden line is redrawn without them.
- An ssh-gate key gets the same answer for `cluster info`, `group show`, `tunnel show` and `recipe show` as for the command each names (`cluster status`, `group list`, `tunnel list`, `recipe list`); they were refused as komando's own plumbing.
- The approval hint a script or a person gets (`check with --dry-run, then run it again with --allow-dangerous: ...`) repeats the command line only when it holds no value that may be a secret: words after `--`, free text such as SQL, a value the mask hides, or the value of a flag such as `--content` or `--password`. Those get the same sentence without the line, so a password typed for a server command no longer lands in `error.hint` or a CI log.
- When komando fills in `cron rm`, `pkg rm` or `db kill` for a person, the name to type counts only what goes: written as an alias (`cron remove`), a plural (`crons rm`) or after `-o text`, the command's own words were counted too ("Type 3" for one task).
- The hidden synonyms `cluster info`, `group show`, `tunnel show` and `recipe show` get every check of the command they name: an AI agent with `KOMANDO_HOME` set to another folder needs a person's yes (`SAFETY_SETTING`), and a command that writes the audit log stops when it cannot (`AUDIT_UNAVAILABLE`). They used to skip both, like komando's own background commands.
- An s3, gcs or azblob conn with `?insecure=1` now needs a person's yes when an AI agent adds it, like the other kinds: an AWS session token would travel in clear.
- On a terminal without Unicode, a result's text (a file, a row, a log line) is no longer rewritten in ASCII; only komando's own lines are.

- `vpn status` could show a SOCKS, proxy or system VPN as down when it
  answered: the row was written over after the check filled it in.
- `queue purge` and `queue rm` name what they would delete: the person's
  "Dangerous:" prompt, the approval window and the agent's `POLICY_BLOCKED`
  message now say `deletes every message in orders-retry`, not only "a
  topic, queue or stream" on the conn.
- `queue ls` shows at most `--limit` (`-n`, default 1000) topics, queues or
  streams, the first by name, and marks a longer list `"truncated": true`
  with a hint to narrow it. On SQS and Kafka it no longer reads every
  queue's counts first, so a big account answers within the time limit.
- `queue peek --idle` on RabbitMQ, NATS, SQS or Pub/Sub is refused
  (`NOT_SUPPORTED`) instead of being ignored: only a Kafka peek waits.
- `queue peek` on a RabbitMQ quorum queue takes no more messages once one
  is near its delivery limit, so a single peek no longer counts down the
  deliveries of every message behind it.
- `komando queue --help` shows examples of the usual journey.
- `komando status` and the restart list after `secret passwd` no longer
  count a tunnel whose process id now belongs to another program (after a
  crash or a restart) as running.
- `komando db ls`, `cache show NAME`, `queue edit NAME`, `storage test NAME`
  and the like now say which shared command does it (`komando list
  kind:db`, `komando conn show`, `komando conn edit`, `komando test`,
  `komando conn rm`, `komando conn mv`) instead of only "unknown command".
- A blocked command given a selector (`host rm @prod`, `tag:edge`) now
  records the servers and conns it picked in the audit log instead of `-`,
  so `komando audit --failed --target web2` finds it.
- The `VAULT_KEY` hint for a server's password reference, and the
  `NO_PASSPHRASE` entry in the error catalog, named the old vault.key file;
  they now say store.key, where the sealed store keeps the key.
- `conn add` and `conn edit` refuse an `s3://`, `gs://` or `azblob://` conn
  whose `http://` endpoint crosses the network (`INSECURE_PROTOCOL`), as
  they already did for `sqs://` and `pubsub://`: the files and the AWS
  session token would travel unencrypted. Use https, `--via HOST`, or add
  `?insecure=1`; an endpoint on this computer is fine. `komando doctor`
  now flags such gs:// and azblob:// conns too.
- `secret set` and `queue send` read at most 1 MiB from stdin and stop
  with a clear `USAGE` error beyond it, so a wrong pipe cannot fill memory.
  `fs write` from stdin is not capped.
- A second Ctrl-C now ends komando at once when the clean stop after the
  first one hangs; before, every later Ctrl-C was ignored.
- Secret masking for AI agents no longer hides words in komando's own
  messages: "Would re-encrypt 3 secrets: the vault's key" and
  "KOMANDO_KEYCHAIN=off: ..." now read whole. Real values after `secrets:`
  or `NAME=` are still hidden.
- Text output on a terminal that cannot show Unicode (`TERM=dumb`, or a
  locale such as `LANG=C` that is not UTF-8) now writes komando's marks in
  ASCII (`+` for ✓, `*` for ●, `->` for →) instead of broken characters.
- `job rm --kill` on a protected server asks first (`PROTECTED_HOST` for
  an agent), as `job kill` does; it stopped the job without asking. The
  stop is in the audit log, and a job it could not stop (started with
  `--sudo`) keeps its record and says `komando job kill ID --sudo`.
- `fs chmod` works on servers with BSD `chmod` (FreeBSD, macOS): the
  `--` came after the mode, which BSD reads as a file name. `fs mkdir`
  and `fs chmod` now say what they did (`made: PATH`, `mode 640: PATH`)
  instead of printing nothing on one server, and `fs mv` into `DIR/` no
  longer prints a double slash.
- `policy deny` says the new rule's id and the commands that follow:
  `komando policy check 'COMMAND'` to try it and `komando policy rm ID` to
  undo it. Its JSON gains `id` and `next`.
- `fs` commands refused with `PERMISSION_DENIED` give the same command
  line with `--sudo` added as their hint (it said only "retry with
  --sudo"). With `--sudo` already given, the hint no longer suggests it.
- `exec` that times out, or loses its connection, now gives the exact
  `komando job start TARGET ... -- 'COMMAND'` line in its hint, with the
  same `--sudo`, `--dir` and `--env`, instead of "use `komando job start`".
- `job start` on several servers prints `komando job wait ID ID ...` with
  the real IDs (it printed `<id>`), and so does `next` in its JSON. A
  `job wait` for several jobs that are still running says
  `komando job wait ID ...` to wait again. It pointed at `data.results`,
  which job results do not have, and in text it suggested `job start`.
  A lost job's hint gives the exact `job start` line to run it again.
- `ssh-gate`: a key that may change things can now run `fs restore`, the
  undo of `fs replace --backup` and `fs write --backup`, on a server.
  It was refused as if it changed komando's own setup.
- Ctrl-C now stops `upload`, `download`, `cp` and `sync` (servers, and
  SFTP, FTP and SMB storage conns). komando caught the signal and went on
  copying to the last byte; a big upload ran for 20 s after Ctrl-C, and
  `sync` had to be killed. The copy now stops within a moment with
  `CANCELLED` (exit 1), and the file being copied is not left behind.
- A folder upload (`upload -r`, `cp -r`) writes each file under a
  temporary name and moves it into place, as `sync` does, so an
  interrupted upload no longer leaves a file on the server cut short.
- A download refused with `FILE_EXISTS` no longer prints
  "downloaded 1 file (0 B)" above the error, and its JSON result no longer
  counts the file.
- `upload -r`, `cp -r` and `sync` copy a folder given as a symbolic link
  (`./current -> releases/42`) as the folder it names. They sent nothing
  and still reported success ("skipped 1 file: .").

- Redis Cluster: `cache rm` with keys in different hash slots failed with
  `CROSSSLOT`; it now deletes them one by one. `cache run -- DBSIZE`
  counted one master only; it now adds up every master. `SCAN`,
  `RANDOMKEY`, `KEYS`, `FLUSHALL`, `FLUSHDB` and `SWAPDB`, which would reach
  one master only, stop with `NOT_SUPPORTED` before any approval is asked,
  and a `CROSSSLOT` error says what to do.
- `komando cache` (the bare group) shows examples of the usual journey;
  its questions for a person name commands (`komando cache add`,
  `--dry-run`) instead of menu rows. The caches page shows `cache add`, what
  happens when an argument is left out, how to test, change, rename and
  remove a cache, and how to save a Redis snapshot.
- `policy check --conn-kind memcached` rates the words memcached reads, like
  `cache run`: a line with a newline or other control character is
  dangerous (new rule `memcached-line`), and `mg "key T30"` is a write.
- `cache keys --limit 0` listed no keys yet said more matched, and
  `cache get --limit 0` (or a negative limit) quietly showed 100 items;
  both now stop with `USAGE` before connecting.
- `cache run` on Redis: more commands that change a cluster or Sentinel
  setup (`CLUSTER MEET`, `ADDSLOTS`, `FLUSHSLOTS`, `REPLICATE`, `SENTINEL
  SET`, `FAILOVER`, `REMOVE`, `CONFIG SET` ...) and that delete keys
  another way (`FT.DROPINDEX ... DD`, `FT.DROP`, `SET`/`GETEX` with an
  `EXAT`/`PXAT` already past) now need `--allow-dangerous` as well as
  `--write`. Read-only `CLUSTER REPLICAS`, `CLUSTER LINKS`, `SENTINEL
  MASTERS`, `SENTINEL GET-MASTER-ADDR-BY-NAME` and `SENTINEL CONFIG GET`
  no longer need `--write`.
- `cache run` on memcached: `stats reset` (clears the counters) and
  `stats detail on|off` (switches per-prefix counting on the server) now
  need `--write`; they were taken as reads. `stats detail dump` still reads.
- Security: `cache run` on memcached now rates the words memcached will
  read. An argument holding a newline (`get "a\r\nflush_all"`) used to
  pass as a read and run `flush_all` without `--write` or
  `--allow-dangerous`; such a line now stops with `USAGE` before anything
  is sent. Arguments are split at spaces as memcached does (`mg "key T30"`
  is a touch, so it needs `--write`), the command word is sent in lower
  case (memcached ignores `GET`), and `watch`, which never returns, stops
  with `NOT_SUPPORTED`.
- `import kubeconfig` notes a context that skips the API server's
  certificate check (`insecure-skip-tls-verify` without a CA), and a
  kubeconfig with both a CA and `insecure-skip-tls-verify` now checks the
  server against the CA instead of checking nothing.
- `cluster rm` and `cluster scale ... 0` at a person's terminal ask to
  type the object's name (`Type the name web to continue`). Before,
  Kubernetes asked for the cluster's name and Swarm for "yes", so the
  answer did not say what would go. Scripts and agents are unchanged
  (`--allow-dangerous`).
- Cluster commands refuse `.` and `..` as an object or namespace name
  before anything is sent (`K8S_INVALID`): as a path segment, `cluster rm
  prod pod ..` named another object than the one typed.
- A cluster whose kubeconfig logs in with a program that is not installed
  (`kubelogin`, `oidc-login` ...) now stops with `TOOL_MISSING` (exit 3)
  and the kubeconfig's own `installHint`, and a login program that fails
  with `LOGIN_FAILED` (exit 4), instead of `K8S_UNREACHABLE` and a hint to
  test the network.
- `cluster apply` sends the whole file to the server as a dry run before
  it applies anything: when the cluster refuses one object, nothing in the
  file is applied (`K8S_INVALID`, "nothing was applied: ..."). Before, the
  objects above the refused one were applied and the file was left half
  done.
- On a Mac whose user has no default keychain (a changed `HOME`: `sudo -E`,
  a sandbox, CI, a test run), komando no longer makes macOS show a
  "Keychain Not Found" dialog. It asks `security default-keychain` first
  (no dialog); without one, a new store keeps its key in `store.key`, the
  change count is not kept in the keychain, and `secret keychain` says
  "no default macOS keychain for this user".
- An AI agent reading `secret passphrase --dry-run` and `secret keychain
  --dry-run` as text saw words of komando's own sentences as `[hidden]`
  ("3 secrets: [hidden] vault's key", "KOMANDO_KEYCHAIN=[hidden]"); the
  sentences are reworded so nothing is masked.
- `secret passphrase --dry-run` previews for an AI agent or a script too
  (what would change, how many secrets, whether the current key opens
  them) with `meta.would_be_blocked: NEEDS_PERSON`, as `secret keychain`
  does, instead of stopping: a dry run is never blocked.
- `secret rm A B` removes every name in one change of the vault, or none:
  a failure part way no longer leaves some removed without an audit entry,
  and a reference another komando adds meanwhile is seen before the
  secret goes.
- `komando secret --help` and the Settings and Moving pages named
  `vault.json` and `vault.key`, the files of an earlier komando; they now
  say `store.db` and `store.key`. The help also lists the other places a
  `-ref` flag can read a password from (`env:`, `file:`, `vault:`,
  `aws-sm:`, `gcp-sm:`, `azure-kv:`, `op://`, `bw://`, `kdbx:`).
- `secret set NAME --from-env VAR` refuses an empty (or blank) variable
  with `USAGE`, as an empty pipe is refused, instead of storing an empty
  password.
- `secret set` and `secret check` never ask an AI agent for a value at a
  hidden prompt, also when the agent runs komando under a terminal: it
  gets `NEEDS_PERSON` at once instead of a prompt that waits forever.
  `secret set NAME --dry-run` without a value previews (`replaced`,
  `would_set`) with `meta.would_be_blocked: NEEDS_PERSON` instead of
  stopping.
- `tunnel stop` never signals a process that is not komando: after a
  crash or a restart a tunnel's pid may belong to another program, which
  it used to end. `tunnel list` shows such a tunnel as down and forgets it.
- A `--via` path that names a server or VPN twice (`office,office`,
  `a,b,a`) is refused with `VIA_CYCLE` and the path without the repeat;
  a VPN named twice got the wrong hint "put the VPN first", and a repeated
  server was accepted.
- `vpn down NAME --all` and `tunnel stop ID --all` are refused with
  `USAGE`, as `logout HOST --all` is; the names, even unknown ones, were
  ignored. `tunnel stop` is now in the audit log.
- `tunnel start -L/-R/-D` takes IPv6 addresses in brackets, as ssh does
  (`-L 8080:[::1]:80`); they were refused as an invalid spec. An open IPv6
  bind (`[::]`) still needs a person's yes.
- Ctrl-C while `vpn up` (or a command that connects a VPN by itself)
  waits for the VPN's session now stops it at once (`CANCELLED`); the wait
  of up to 75 seconds ignored it, so the VPN could come up after the
  person cancelled.
- Ctrl-C while `tunnel start` waits for its tunnel now stops the
  background process and forgets the tunnel (`CANCELLED`); it was ignored,
  so the tunnel could still come up after the person cancelled.
- `komando login HOST --dry-run` with nobody at a terminal (an AI agent)
  now prints the plan with `would_log_in: false` and `NEEDS_TERMINAL` in
  `meta.would_be_blocked`, instead of failing: a dry run is never blocked.
- `vpn down` (and its `--dry-run`) now says what the disconnect does to
  the servers and conns that use the VPN: with a person's login they stop
  answering until `komando vpn up NAME`; otherwise their next command
  connects it again (new JSON field `affects`).
- `vpn test` and `vpn up` of a SOCKS or HTTP proxy VPN without `--check`
  now connect to the proxy itself and fail with `VPN_DOWN` when it does
  not answer; they said ok for a dead proxy while `vpn status` said it was
  down.
- A VPN session no longer drops a connection that is still open when
  `vpn_idle` (30m) passes: a `shell`, `logs --follow` or `tunnel` through
  a WireGuard, OpenVPN, IPsec or SSL VPN session was cut after 30 minutes
  because only new logins counted as use.
- Security: `docker exec` and `logs --container` refuse a CONTAINER that
  is not a container name or ID. One starting with `-` reached docker as an
  option, so `docker exec web1 -- --privileged -u root api sh` ran a
  privileged exec (a way out of the container) without
  `--allow-dangerous`.
- Security: `net dns` refuses a name that is not a host name or an
  address. A name starting with `-` reached `dig` as an option, so
  `net dns web1 --type MX -- -f/etc/passwd` read a file on the server
  through a read-only command.
- `user add` and `user rm` on a server without `useradd` or `userdel`
  (Alpine without the `shadow` package) now fail with `TOOL_MISSING`
  (exit 3) and the hint `komando pkg install TARGET shadow`, like
  `user lock` and `unlock`, instead of a generic remote failure (exit 5).
  The JSON result keeps its shape.
- Menu and guided forms: Esc from the review screen goes back one
  question at a time, and Esc on the first question now leaves the form
  (nothing runs). Before, it went round to the review again, so Esc
  never got you out; only q or Ctrl-C did.
- Guided forms, lists that also take typing (a secret's name, a group,
  servers): what you type is now a row of its own at the top, and Enter
  takes it. Before, Enter took the first row that contained the text, so
  typing a new secret name `db` saved over `db-pass`, and a name that is
  part of another could not be typed. A typed answer also comes back as
  typed when you change it from the review.
- Guided forms can no longer put `--yes`, `--allow-dangerous` or
  `--reveal` in a command, even if a command's form hints name one. No
  form did; a test now checks every command's form for it.
- `import --overwrite --dry-run` now lists a protected conn as skipped,
  as the real run does, instead of "would add" plus a block the real run
  never hit. A protected conn is skipped like a protected server.
- Commands komando prints for you to copy quote every shell character
  (`;`, `|`, `&`, `*`, `~`, line breaks) and an empty value (`''`). The
  `config set` line an import gives for a differing setting is now
  runnable as shown, and a value from an imported file cannot add a
  second command to it.
- `host rm` of a server others go through (`--via`) names every server
  and conn that uses it, each with its `edit ... --unset via` command,
  instead of one per try.
- `key rm` names every server that still uses the key (with one
  `host edit A B --key OTHER` line) and its text output says "removed key
  NAME" instead of printing raw fields. JSON is unchanged.
- `import` ends with the command that checks what came in (`next: komando
  test ...`, JSON `next`), lists the names `--overwrite` replaced
  (`replaced`), and its dry run no longer says "the rest is in" when a
  server would be left out. A setting that differs shows `-` for an empty
  value.
- `import` now applies the TLS default `conn add` gives: a database URL
  without TLS settings gets verified TLS (`sslmode=verify-full`,
  `tls=true`, ...), and a clear-text `redis://`, `amqp://`, `nats://`,
  `kafka://` or `http://` endpoint to another computer is skipped with the
  `INSECURE_PROTOCOL` reason instead of being saved, so a password from a
  `.env` or `.pgpass` file no longer crosses the network unencrypted.
- `group add GROUP A B` and `group rm GROUP A B` take several targets, like
  `host rm` and `host edit`, instead of failing with "too many arguments".
- A server address that starts with `-` is refused (`host add`, `host
  edit`, every import). `user@-oProxyCommand=...` was saved, and `host
  ssh-command` could print it where `ssh` reads it as an option. A server
  saved that way before gets an error from `host ssh-command` instead of
  the line.
- `export` no longer tells you to copy `sealed:...` "key files" for keys
  komando made (they have no file): it says to run `komando key gen NAME`
  on the other computer and deploy that key (JSON `keys_sealed`). The
  import note for a missing key says the same.
- Asked for a missing argument, `import` offers its sources and `config
  get`/`config set` their settings as a list to pick from.

- `db dump` and `db restore` name their argument `CONN` (it was
  `DATABASE`), and no `db` usage line carries flags any more (`restore`,
  `user add`/`passwd`, `grant`/`revoke`), so shell completion and pickers
  offer your databases there. `db restore` without `--from` and `db grant`
  or `revoke` without `--privileges`/`--role` now give a runnable example
  in the hint.

- `db kill --dry-run` now fills `meta.would_be_blocked` (a protected
  conn, or `--session` without `--allow-dangerous`), as every other dry
  run does; before, it skipped the check and looked allowed.

- `komando db` shows five runnable examples and how to list, test,
  change, rename and remove a database (`list kind:db`, `test`, `conn edit`,
  `conn mv`, `conn rm`). The `db dump` question for `--to` is no longer
  marked required: without it the backup is `CONN-<date>.sql.gz`.

- `db dump --to FOLDER` saves `CONN-<date>.sql.gz` inside that folder
  (it failed with `FILE_EXISTS`), and `--to -` is refused with a usage
  error instead of creating a file named `-`.

- `db` error hints name the conn you gave (`komando db schema prod-db
  TABLE`), not a `CONN` placeholder, so the hint is the exact next
  command.

- `db restore` and `db user rm` typed without their arguments now hint a
  runnable `--dry-run` example (the hint said only "see --help").
- Google Cloud Storage: gcloud's own login is sent only to Google's
  HTTPS endpoints (`*.googleapis.com`). A `gs://` conn with an emulator or
  other `?endpoint=` used to send the person's gcloud token there too, in
  clear over `http://`. A service account key with an `http://` endpoint
  is refused with `INSECURE_PROTOCOL`.
- Azure Blob: a SAS token with an `http://` endpoint is refused
  (`INSECURE_PROTOCOL`): the token goes in every request as it is, so it
  would travel unencrypted. The account key, which only signs, still works
  with an emulator such as Azurite.
- `storage rm --prefix` typed at a terminal without `--allow-dangerous`
  now lists what would be deleted (the first 20 objects, the count and the
  size) before asking to type the conn's name; it used to ask first, with
  nothing shown. Agents and scripts are stopped as before, before anything
  is listed.
- S3: a bucket in another region than the conn's `region=` (or its
  regional endpoint) now says which region it is in and how to fix the
  conn (`conn edit NAME --url ...`), instead of a bare `STORAGE_ERROR:
  AuthorizationHeaderMalformed` or `400 Bad Request`.
- Storage errors name the conn in the command their hint suggests
  (`komando conn test backups`, `komando storage ls backups`), not the
  placeholder `NAME` or `CONN`.
- `storage ls CONN db` on a bucket (S3, Google Cloud, Azure) lists what is
  in the folder `db`, as on a file server; it used to list only the folder
  itself (`DIR db/`).
- `storage link` on an S3 conn with an AWS profile (SSO, an assumed role)
  warns that the link ends when the temporary keys do, which can be long
  before `expires_at`.
- `komando storage --help` shows the whole journey (add, test, list,
  edit, remove the conn) with examples; `storage add --help` has examples
  for an AWS profile, MinIO, Google Cloud, Azure and SFTP; `storage rm
  CONN` with no key names the next step, including `conn rm CONN` for
  taking the storage itself out of komando's list.
- S3, Google Cloud and Azure conns take `&ca=secret:NAME`, for an
  endpoint whose certificate comes from a private CA (a company MinIO, a
  TLS-inspecting proxy). There was no way to use one. A certificate that
  does not verify is now `STORAGE_TLS` with that hint, not a generic
  `STORAGE_ERROR`.
- An `azblob://` URL with a SAS token in it (`?sv=...&sig=...`) is refused
  as `URL_HAS_PASSWORD`, with the hint to store it in the vault, instead of
  "unknown azblob URL option".
- registry: Docker Hub's pull limit (HTTP 429) is now `REGISTRY_RATE_LIMIT`
  (exit 5) with when to retry (Retry-After) and the hint to log in, instead
  of a bare `REGISTRY_ERROR`.
- registry: on Docker Hub, `nginx` means `library/nginx`, as with
  `docker pull`; `registry ls dockerhub` without a repository says Docker
  Hub and GHCR have no list of repositories (`REGISTRY_UNSUPPORTED`)
  instead of a misleading `REGISTRY_AUTH`.
- registry: repository, tag and digest names are checked against the OCI
  grammar before they go into a URL or a token scope (`../`, `?` or a
  second `:` gave requests to other endpoints); upper case gets the
  lower-case name to use. `USAGE`, exit 2.
- registry prune: one manifest read per image instead of per tag (Docker
  Hub counts each read as a pull), and the help no longer says a
  multi-platform index always stays: it has its first image's build date
  and can go.
- registry prune: past 1000 tags, `TOO_MANY_TAGS` no longer suggests
  `--match` (every tag is still read, so it cannot help); build dates are
  read only for images a matching tag may take.
- registry ls, rm, prune and inspect read better at a terminal: a cut list
  says to raise `-n`, an empty one says what fills it, `rm` names every
  tag that goes with the image and warns when `latest` is one, `prune`
  lists what goes and why the rest stays, and build dates are in local
  time. JSON is unchanged.
- registry rm: when the tags cannot be listed, `tags` is `[]` (was `null`)
  with a `tags_note` saying other tags may point at the image.
- import docker: a registry that only has a `credHelpers` entry (Amazon
  ECR with `ecr-login`) is imported; Amazon ECR, Google (gcloud) and Azure
  identity-token logins are added without docker's hours-long token, so
  komando logs in with the cloud login each time instead of failing once
  the token runs out; a credential helper name that is a path is not run,
  and a helper gets 30 s.
- `docker rm`, `docker prune` and other docker deletes at a terminal now
  ask the person to type the server's name, like every other destructive
  command, instead of accepting a bare `yes`; `docker prune --all` asks
  once instead of twice.
- `svc`, `pkg`, `user`, `cron`, `docker` and `recipe run` now say why
  when sudo refuses before the command runs: `PERMISSION_DENIED` (sudo
  wants a password komando does not have, or the user may not use sudo)
  with the `host edit --sudo-ref` or `--user` command to run next, and
  `TOOL_MISSING` when the server has no sudo (add `--no-sudo` as root),
  instead of `COMMAND_FAILED` / `SVC_FAILED` with "read stderr".
- `komando svc`, `pkg`, `user`, `docker`, `cron`, `net`, `cert` and
  `recipe` alone now show the usual journey as examples. Examples, form
  hints and docs write times as `30m` (not `-30m`), as komando takes them
  everywhere; `user rm` shows a `--dry-run` first.
- `pkg rm` reports itself as `pkg.rm` in JSON, the audit log, dry runs and
  the Windows refusal (it said `pkg.remove` / `pkg remove`), and `pkg`
  commands given no package give the usual `missing arguments; usage: ...`
  error.
- `reboot --dry-run` puts `would_be_blocked` in `data` too, like every
  other dry run; `user add` and `user rm` show `user rm bob --remove-home`
  in dry runs and the audit log instead of the shell script; `recipe list
  --category` with an unknown category is a usage error that lists them,
  not an empty list.
- `docker start`, `stop`, `restart` and `rm` name their argument
  `CONTAINER...` and `docker pull` `IMAGE...` (was `NAME...`) in help and
  usage errors.
- `user lock`, `unlock` and `rm` check USERNAME like `user add` does, so a
  name starting with `-` is a usage error instead of an option of
  `usermod` or `userdel`.
- Ctrl-C ends `logs --follow` (and `svc logs`, `docker logs -f`) cleanly
  with exit 0 and the lines so far, as `--timeout` does, instead of an
  `interrupted` error with exit 1.
- `pkg upgradable` reads the package index as root when sudo needs no
  password, like `facts` and `pkg security`, so all three agree. On dnf and
  yum the login user's own cache could list other updates (48 against 4
  on Rocky 9).
- `komando login aws --profile ROLE` now works for a profile that assumes a
  role from an SSO profile (`role_arn` with `source_profile`): it logs in
  to that SSO, as the role's commands need. The SSO token file is written
  through a new private temporary file, so a file left at the old
  temporary name (or a link there) never gets the token.
- An AWS profile without SSO and without keys no longer says
  `AWS_LOGIN_REQUIRED` with the hint `komando login aws`, which cannot help
  it: it is `AWS_FAILED` and the hint says where the keys go. Ctrl-C while
  komando talks to AWS is `CANCELLED`, not `AWS_FAILED`.
- `komando login aws` run by an AI agent is now `NEEDS_PERSON` (exit 6)
  with the hint "ask the user to run `komando login aws --profile NAME` in
  their own terminal", like every other person-only step; a script without
  a terminal still gets `NEEDS_TERMINAL`. `--dry-run` is never blocked: it
  checks the profile and shows its SSO start URL and region, with
  `meta.would_be_blocked` for an agent. komando opens only an `https://`
  sign-in address in the browser.
- `komando login gcp` and `komando login azure` say that the browser login
  comes in a later release and what works today (application default
  credentials, a service principal, or a key in `--password-ref`), for any
  arguments, instead of a hint to store a "service account key" for Azure.
- `komando import aws` names the right fix per profile: `komando login aws
  --profile NAME` only for an SSO profile, the credentials file for a
  profile without keys or SSO (it said "the login has expired" for both).
- New page [Cloud logins](docs/features/cloud.md): `komando login aws`, the
  `aws_profile` option, `komando import aws`, the AWS error codes and what
  works for Google Cloud and Azure until their login comes. The agent
  guide lists `AWS_LOGIN_REQUIRED`.
- With `AWS_ENDPOINT_URL` set (LocalStack, moto), a profile that assumes a
  role sent its AssumeRole call to the real AWS, signed with the source
  access key: the AWS SDK leaves the role's STS client out of that
  setting. komando now applies it to STS too (`AWS_ENDPOINT_URL_STS` still
  wins).

- `komando update` on Windows said there was no komando release for
  Windows, although every release has `komando_windows_amd64.zip` and
  `komando_windows_arm64.zip`. It now updates Windows too, and a test keeps
  its list of platforms the same as the ones `make dist` builds.

- Tab completion now turns on as the README and the installer say. In zsh,
  `source <(komando completion zsh)` printed `command not found: compdef`
  in every new terminal when `~/.zshrc` had not run `compinit` (a new
  Mac's has not): the script now runs it when it is missing. For bash the
  line is `eval "$(komando completion bash)"`, because the bash 3.2 of
  macOS reads nothing from `source <(...)`. `komando completion SHELL
  --help` gives these lines instead of the bash-completion package and
  Homebrew paths.

- Tab completion of a CONN offers only the conns the command works with:
  `komando cache info <Tab>` lists caches, `komando db query <Tab>`
  databases (groups, `all` and `kind:` as before). It listed every conn,
  so a database could be picked for a cache command.

- `make licenses` (and so `make dist`) stopped at "archive/tar does not
  have module info" when Go ran a downloaded toolchain (go.mod's `go`
  line newer than the installed Go): the script now hands go-licenses
  Go's own GOROOT. Run on its own, it also covers the Windows builds.

- The install line says what went wrong in words: a `KOMANDO_VERSION`
  that does not exist, no connection, a missing `curl` or `tar`, a
  checksum that does not match. It checks `KOMANDO_INSTALL_DIR` before it
  downloads, and puts komando in place with a rename inside that folder,
  never by writing into a komando that is running. On Windows (Git Bash)
  it points to the `.zip` download; it no longer calls `komando` alone a
  menu.
- README: the Windows `.zip` is an install option, and `prompt` (now
  `status --short`) is no longer listed as a command.

### Fixed

- `key gen`, `key rm` and `rename` help said keys komando makes live in
  `~/.komando/keys`; they are kept in the sealed store, with no file, and
  `host ssh-command` hands them to ssh-agent. `key rm --delete-file`
  says it deletes the private key; servers.md and output.md (which listed
  the retired `KEY_FILE_EXISTS`) say the same.
- `group rm GROUP TARGET TARGET` (two or more targets) deleted the whole
  group instead of taking just those targets out of it. Now it takes out
  only the targets named; `group rm GROUP` alone still deletes the group
  (and asks first when it has more than 3 members).
- A Tailscale or Headscale VPN keeps its node state (the machine and node
  private keys) sealed in store.db, not in a plain `tailscaled.state` file
  under `~/.komando/vpn/`. `vpn rm` now also forgets that state
  and folder, so a VPN added again under the same name never joins as the
  old node.
- An AI agent's `download`, `cp`, `storage download` and `sync` never put
  the real text on this computer's disk: a text file is masked in memory
  before it is written. Before, the unmasked bytes sat in the temporary
  file until the download ended (and stayed there after a crash). A
  binary or larger file that holds a value from komando's vault now stops
  with SENSITIVE_FILE instead of being saved as is.
- `fs write`, `fs replace`, `fs restore` and `upload` with `--sudo`
  follow a link only when root made it and it leads into a folder root
  owns; any other link stops with IS_A_SYMLINK. Before, a link another
  user planted (an app's `.env` to `/etc/sudoers.d/x`) had root write a
  file of that user's choosing.
- `key revoke --user` edits that user's authorized_keys as the user, with
  a random temporary name. Before, root wrote a predictable temporary
  file in the user's `.ssh`, so a link the user planted there sent their
  own lines into a system file.
- `vpn up` for an AI agent hands the VPN password to openconnect only when
  openconnect and ocproxy sit in folders only root can change, or a
  person says yes (SECRET_DESTINATION). Before, an agent could put its
  own `openconnect` first in PATH and read the password it gets.
- `user add --key` writes the key as that user, not as root. Before, a
  user who linked `~/.ssh/authorized_keys` to a system file (such as
  /etc/shadow) got a line appended to it and its ownership, and so root.
- store.db zeroes the space a deleted record or an old key's copy leaves
  behind. Before, a removed secret's sealed bytes stayed in the file, and
  after `secret passphrase` they still opened with the old key.
- A plain runtime.json beside the sealed store is no longer trusted: it
  is read as empty. Before, a program that wrote one could point a server's held
  login at its own socket and see every command, password and file sent
  to that server.
- `fs write`, `fs replace`, `fs restore` and `upload` with `--sudo` no
  longer write into a folder that a user other than root and the SSH user
  can change (owned by that user, writable by a group other than root's,
  by everyone, or by a user or group its access list (ACL) names): that
  user could swap the file for a link while root
  writes. They stop with SHARED_FOLDER_CONFLICT, whose hint says how to
  write as that user instead. A link on the way to the file (not only the
  file itself) is followed only when root made it. `fs cat --sudo`, a
  `--sudo` download, `logs --file F --sudo` and the reads `fs replace
  --sudo` makes do not read through a link made by a user other than root
  and the SSH user (IS_A_SYMLINK), and `fs chmod --sudo` does not change
  the mode of what such a link names. `logs --file F --sudo --follow` keeps
  reading the file it opened, so after a log rotation run it again.
- The approval window for an AI agent's `exec --script FILE`,
  `job start --script FILE` and `exec --stdin-file FILE` shows the
  file's SHA-256 and every line of it, numbered, long lines wrapped and
  never cut. Before, it showed only the command line, so a person
  allowed a script they never saw. A file that is not valid text, holds
  bidi or zero-width characters, holds what looks like a password, key
  or token, or is too long to show whole (more than 40 lines as shown,
  or 16 KiB) gets no window, as for such a command line: masking
  `pass=x|sh</tmp/s` as `pass=[hidden]`, or leaving out line 11, would
  hide what runs. The agent is told to ask you to run it in your own
  terminal.
- On a Linux or BSD desktop the approval window needs the approval code
  (`komando config approval-code`): on X11 another program can click
  "Allow once" (xdotool), and on Wayland the agent, which sets komando's
  environment, can point `WAYLAND_DISPLAY` at a compositor of its own
  and click there. Without the code komando opens no window and the
  agent is told to ask you to turn it on or to run the command in your
  own terminal. macOS and Windows keep the plain window.
- settings.md says plainly what protects the vault from a program that
  runs as your own user and ignores komando's rules: only another OS
  user or the signed Mac app. Key file, keychain and passphrase modes do
  not.
- `upload` over a file that is there keeps that file's mode unless
  `--mode` is given. Before, it took the local file's mode, so a 0600
  `.env` on the server became 0644 (readable by every server user). A
  new file still gets the local file's mode.
- A job's folder on the server (`~/.komando/jobs/ID`) is made 0700, and
  its command, output and pid files 0600, whatever the server's umask.
  Before, other server users could read a job's output. The job itself
  still runs with the login's own umask.
- `download`, `cp` from a server, `storage download` and `sync` down keep
  the file's mode from the server but never make it writable by other
  users here: a 0777 file is saved 0755, a 0666 one 0644.
- `guide install`, `guide guard` and `guide uninstall` keep the old
  agent settings file as `.bak`, or `.bak.<UTC time>` when a `.bak` is
  there already, always 0600. Before, they wrote over your own
  `settings.json.bak` and kept its mode (often 0644, while settings can
  hold tokens).
- An AI agent's `db dump --run-on HOST` and `db restore --run-on HOST`
  need a person's yes (SECRET_DESTINATION) when HOST is not the conn's
  own `--via` server: the conn's password goes there. Before, an agent
  could send it to any server in the inventory.
- A password komando reads from `env:`, `file:`, `op://`, `bw://`,
  `kdbx:`, `vault:` or a cloud secret manager is hidden in its output as
  `[hidden]` from then on, like a value from komando's own vault (also
  its base64 and URL-encoded forms). Before, only values that looked like
  a password were masked.
- komando takes the password managers' unlock variables
  (`KOMANDO_BW_PASSWORD`, `KOMANDO_BW_CLIENT_SECRET`,
  `KOMANDO_KDBX_PASSWORD`, `KOMANDO_KDBX_KEYFILE`, `OP_CONNECT_TOKEN`,
  `VAULT_TOKEN`, `BAO_TOKEN`) out of its environment when it starts, as it
  already did with `KOMANDO_VAULT_PASS`. Before, every program it ran and
  every background tunnel, VPN session and login inherited them, where
  `ps eww` showed them for hours. Those background processes now get them
  on their input, and an `env:` reference to one (`--password-ref
  env:VAULT_TOKEN`) still works for a person.

## [0.12.0] - 2026-11-11

### Highlights

- **Upgrading: run `komando seal` once.** komando now keeps everything in
  one sealed file, `store.db`. A folder from an earlier komando must be
  moved first: until a person runs `komando seal` in their own terminal,
  every other command stops with `NEEDS_SEAL`, for AI agents too. It reads
  everything back before switching, keeps the old files in a sealed
  archive, and `komando seal --undo` puts them back.
- **Sealed local store:** servers, secrets, pinned host keys and the audit
  log are sealed record by record, so a record edited, swapped or removed
  outside komando is noticed. With the key in the OS keychain, an older
  copy of the folder put back stops commands with `STORE_OLD_COPY`.
- **Windows:** komando runs natively on Windows, with Credential Manager
  and its own "Allow once" window.
- **`ssh-command` keeps working with keys komando made:** the key goes to
  your running ssh-agent for an hour and is never written to a file.
- **Simpler and safer:** one command for each job (old names print what to
  use and go away in the next release), over 150 bugs fixed after a
  hands-on review of every command, and new stops against locking
  yourself out of a server.
- **Changed output:** `status --short` shows `vpn:N` (how many VPNs are
  up, not their names), a missing database privilege exits 5, and
  `job wait --wait-timeout` is gone (use `--timeout`).

### Added

- **Sealed local store** for every new komando folder: one file,
  `store.db`, keeps servers, conns, VPNs, keys, recipes, settings,
  secrets, remembered fingerprints and the audit log, each record sealed
  and bound to its ID, kind and version, so a record edited, swapped or
  removed outside komando is found. Its key is kept the three ways the
  vault key is: the OS keychain, a key file (`store.key`) or
  `KOMANDO_VAULT_PASS`. With a passphrase, every command needs it, reads
  included. A store made by a newer komando stops with `STORE_NEWER`.
  komando works only on the sealed store.
- **`komando seal`** moves a folder of an earlier komando into the sealed
  store, after reading everything back and comparing it; the old files are
  kept in a sealed archive and `komando seal --undo` puts them back. A
  person at a terminal only. A folder of before must be sealed before
  use: until then every other command (except `doctor`, `version`, `help`,
  `guide` and `schema`) stops with `NEEDS_SEAL`, for agents too.
- **Old copies are noticed:** with the store's key in the OS keychain, the
  keychain also remembers how many changes the store has had. An older
  copy put back stops commands with `STORE_OLD_COPY` (exit 6) until a
  person runs `komando doctor --accept-old-copy`. When the keychain does
  not answer in time, komando reads but changes nothing
  (`KEYCHAIN_SLOW`).
- **Windows:** komando builds and runs natively on Windows, with the vault
  key in Windows Credential Manager, a native "Allow once" window that
  counts only a real mouse or keyboard, and `.zip` releases.

### Removed

- OpenVPN OS mode (`vpn add --os-mode`), which ran the `openvpn` program
  with sudo and changed your computer's routes, is gone; komando's own
  OpenVPN client does the work without sudo. A VPN saved with it is never
  run another way: `komando vpn up` stops with `VPN_OS_MODE_REMOVED` until
  you add it again with `komando vpn add NAME openvpn --config FILE.ovpn
  --check HOST:PORT --overwrite`.
- `job wait --wait-timeout` is gone: use `--timeout` (still 10m when not
  given). The hidden `--target` flag of `komando list` and `host export` is
  gone too: give the target as the argument.
- `komando test` results no longer carry `name`: read `host`, as with
  `facts` and `exec`.
- A server saved with the 0.1.0 field `jump` is no longer moved to `via`
  on load.
- The files of before as a way of working: `state.json`, `vault.json`,
  `vault.key`, `known_hosts`, `audit.jsonl` and key files under `keys/` are
  only read, by `komando seal`. `key gen --overwrite` is no longer needed
  (keys komando makes live in the store) and does nothing.

### Security

- **Built with Go 1.27.4.** It fixes GO-2026-6859 in the standard
  `net/http` package. Building from source now needs Go 1.27.4 or newer.
- **No more ways to lock yourself out.** Stopping or disabling the SSH
  service is blocked on Debian and Ubuntu too (`ssh.service`, with any
  systemctl options), and `user lock`/`user rm` refuse root and the user
  komando logs in as.
- **`net http` takes only http:// and https:// URLs.** A URL that started
  with `-` reached curl as an option.
- **`tunnel start -R` on a protected server needs a person's yes,** like
  every other change there.
- **Every blocked attempt is in the audit log** (exit 6 stops, including
  safety settings and secrets sent somewhere), so `audit --failed` shows
  them. `guide install` is audited too.
- **An AI agent cannot run `secret keychain`;** it needs a person, as
  `secret passphrase` already did. It used to wait on the keychain prompt.

### Changed

- `komando host ssh-command` on a sealed folder gives OpenSSH a private
  copy of the pinned host keys (for a person only; an AI agent gets
  `NEEDS_PERSON`). A key komando made lives sealed in the store and is
  never written to a file: `host ssh-command` gives it to the running
  ssh-agent (`SSH_AUTH_SOCK`) for one hour and the line picks it by its
  public key; with no ssh-agent it stops with `SSH_AGENT_NEEDED`. Keys
  made by `komando key gen` have no file any more (`key show` names them
  `sealed:<id>`).
- On a sealed folder, `komando status --short` (the shell prompt line)
  counts what runs instead of naming it: `vpn:2 tun:1`, not
  `vpn:office,lab`. It reads only process numbers kept beside the sealed
  store, so no VPN name sits in a plain file and the prompt never opens
  the keychain on each Enter.
- Running VPN sessions, server logins, jobs and tunnels live in
  `runtime.json` (sealed), apart from the inventory in `store.db`; `config
  show` lists it. A background VPN marking itself used no longer rewrites
  the inventory.
- **One command for each job.** Shortcuts that stay now run the same code
  as the main command, with the same flags:
  - `cp`, `storage upload` and `storage download` are `upload` and
    `download`.
  - `svc logs` and `docker logs` are `logs --unit` and `logs --container`.
- **Old names for one release.** These still work, print
  `komando: use X now`, and go away in the next release:
  - `script TARGET FILE` is now `exec TARGET --script FILE`.
  - `host import` is `import ssh-config` or `import komando`, and
    `host export` is `export` (`export kind:host` for servers only).
  - `prompt` is `status --short`.
  - `db query --csv`/`--tsv` are `db query -o csv`/`-o tsv`. An export
    has every row; one larger than `--max-output` fails instead of being
    cut.
- **Removed:** the aliases `ops`, `snippet`, `snippets` and `diag` (use
  `recipe`), `inspect` for `facts`, `systemd` for `svc`, the hidden
  `policy allow` (use `policy rm`), and the built-in recipes that a
  command already does (`recipe run ports` now names `net ports`).
- **One error code, one exit code.** Codes that exited differently in
  different places now always use the exit in `komando schema`:
  `DB_AUTH`, `QUEUE_AUTH`, `STORAGE_AUTH` and `DB_CONNECT` exit 4;
  `DB_PRIVILEGE`, `PERMISSION_DENIED`, `QUEUE_ERROR`, `TOOL_FAILED` and
  `UNSAFE_PATH` exit 5; `NOT_A_FOLDER` exits 8. A vault that cannot be
  opened for a server's password gives `VAULT_LOCKED`/`VAULT_KEY`/
  `VAULT_DECRYPT` instead of `SECRET_UNRESOLVED`.
- **`list` and `ls` work for every list.** Each command that lists takes
  both words.
- **A list for a TARGET that picks nothing of its kind fails** with
  `NO_MATCHING_TARGETS` (exit 3) instead of an empty success
  (`vpn list web1`, `host list kind:db`).
- **`db add`, `cache add` and the other family adds refuse another
  family's URL** (`WRONG_KIND`), and `cluster add k8s://...` asks for the
  kubeconfig it needs.
- **The names aws, gcp and azure are kept for `komando login`;** a server
  cannot take them.
- **`policy` rule ids come from the pattern** (`custom-1a2b3c4d`), so
  removing one rule no longer renumbers the others.
- **`registry rm` needs a tag or digest;** it used to pick `:latest`.

### Known limits

- Any program of your user can read the store's key from the keychain
  (macOS through `/usr/bin/security`, Windows Credential Manager, an
  unlocked Linux keychain), and on macOS can lower the change count. An
  agent running as your user is such a program. See "What the keychain
  does not protect against" in docs/features/settings.md.
- On macOS a program with Accessibility permission can click "Allow once".
  Use the approval code, or keep that permission away from agent terminals.

### Fixed

- **Over 150 bugs found by a hands-on review of every command.** The main
  ones:
  - **Dry runs:** a previewed edit says "would change", not "changed";
    `sync --delete`, `guide uninstall` and `vpn up` say what the real run
    would need; `registry copy --dry-run` checks both registries; a
    `--write --dry-run` on a missing SQLite file no longer creates it;
    Windows servers show the Windows command.
  - **Errors:** "not found" names the right kind ("web1 is a server") and
    never suggests the name you typed; hints name your real server or
    service instead of `NAME`; an AI agent reading text output gets the
    same advice as in JSON; a stray argument says the command takes none.
  - **Files and commands:** `fs cat --tail` on a big file reads its end;
    `cp` and `sync` accept `tag:`, `label:` and `kind:` and keep the port
    of `user@addr:port`; `--env KEY=a,b` keeps the comma; a script whose
    `#!` line uses `env -S` runs the right interpreter; uploading a file
    that holds a `[hidden]` value is refused everywhere;
    `upload CONN DIR -r` puts the folder under its own name.
  - **Databases and caches:** memcached keys with a TTL over 30 days no
    longer expire at once; `PRAGMA journal_mode=DELETE` is not called a
    mass delete; statements that load code (`CREATE EXTENSION`, `LOAD`)
    count as destructive; `cache run "SET a 1"` in one argument works;
    `XREAD` is a read; `MONITOR`/`SUBSCRIBE` are refused instead of
    hanging.
  - **Clusters:** `--timeout` now bounds every cluster and registry call
    (an unreachable cluster no longer hangs for minutes); `import
    kubeconfig` reads `$KUBECONFIG`, resolves relative certificate paths
    from the kubeconfig's folder and no longer gives one context's name to
    another; `cluster status` checks StatefulSets and DaemonSets.
  - **Servers:** `docker logs --sudo` uses sudo; `reboot` refuses Windows
    servers before it starts; `cert check` no longer fails at random on
    servers that reject post-quantum key shares; `pkg update` refuses
    package names it would have ignored.
  - **VPNs and settings:** `vpn up` that fails is audited as failed;
    `vpn mv` moves the VPN's own secrets to the new name, and adding a VPN again after `vpn rm` reuses them; `vpn edit`
    can change `--portal`; `config show` JSON lists every setting;
    `doctor` notices an agent guard that points to a missing program;
    `guide uninstall` checks first, then removes, so a stop changes
    nothing.
  - **Menu and forms:** Add something > Database no longer crashes;
    `komando db add` alone opens the database form; "Protect or unprotect"
    can unprotect; the review shows exactly the command that runs; Check
    everything runs `doctor` even when a server fails; a group's tasks
    leave out one-server tasks; risky tasks (`fs rm`, `docker prune`,
    `user rm`) get the "cannot be undone" warning.

- **Running now is what runs on this computer.** It lists and counts
  VPNs, logins and port forwards only. Background jobs run on the servers
  and keep going without this computer, so they sit under "Background
  jobs" (the same list as on a server) and are not counted; its count
  leaves out jobs that ended: komando remembers a job ended whenever it checks it (`job status`,
  `wait`, `list --refresh`, `rm`) and leaves out jobs whose server left
  your list. "Check which jobs still run" asks every server.

## [0.11.0] - 2026-11-11

### Highlights

- **A simpler menu: pick a thing, then what to do with it.** `komando`
  now shows your servers, databases and services, and VPNs first, then
  Add something, Check everything, History and undo, and Settings and
  help. Picking a server shows plain tasks such as Read logs, Restart a
  service or Edit a file. "All features" is gone; every feature is still
  reachable, and a test keeps it that way.
- **Undo for file edits:** `komando fs restore HOST PATH` puts the backup
  back, and `fs replace`/`fs write --backup` print the undo line.
- **Errors for people:** text output starts with what happened and that
  nothing was changed, then the hint, then the code. JSON is unchanged.
- **Plain words:** `db add`, `cache add`, `queue add`, `storage add`,
  `cluster add` and `registry add` open the same form as `conn add`, and
  "conn" no longer appears in menus, forms or messages.

## [0.10.0] - 2026-11-10

### Highlights

- **GlobalProtect with a browser sign-in,** including Prisma Access with
  the Cloud Authentication Service: `vpn up` opens a browser window for
  the password and one-time code, then picks the best gateway from the
  portal's list.
- **GlobalProtect sessions last the whole login.** They no longer drop
  after about 18 minutes: the tunnel is kept alive and set up again by
  itself.
- **Old flag names are gone** (`--jump`, `--force`, `--param`, `--lines`,
  and others kept since 0.1 to 0.3). See Removed for the new names.

### Added

- **GlobalProtect with a browser sign-in.** `komando vpn up` now logs in to
  GlobalProtect portals that use a web sign-in (SAML, or Palo Alto's Cloud
  Authentication Service, as Prisma Access does): it opens a window of
  Chrome, Edge, Brave or Chromium with an empty temporary profile, you sign
  in there with your password and one-time code, and komando reads the
  result and connects. It also reads the portal's list of gateways and
  takes the best one for your region; before, the portal address had to be
  the gateway itself. Add such a VPN with only `--portal`. A gateway
  with a sign-in of its own is shown in the same window. Tried against a
  real Prisma Access gateway. Not built yet: gateways behind a load
  balancer (the error names the portal's other gateways) and the device
  report (HIP).

### Removed

- Old flag names kept as aliases since 0.1 to 0.3 are gone. Use the new
  names: `--via` (was `--jump`), `--overwrite` (was `--force`), `recipe run
  --var` (was `--param`), `logs -n`/`--limit` (was `--lines`), `fs cat
  --line-numbers` (was `--number`), `job logs --max-bytes` (was `--limit`),
  `--target` (was `--host`), `host mv` and `conn mv` (was `host edit
  --rename` and `conn edit --rename`). `recipe add --mutating` is gone too:
  a recipe counts as a change unless you save it with `--read-only`.

### Fixed

- A GlobalProtect VPN no longer drops after about 18 minutes. komando
  now sends the keepalive the gateway expects, sets the tunnel up again
  before the gateway's own tunnel timeout, and after a drop reconnects
  with the same login (for up to 5 minutes) instead of ending the session.
- `vpn add` no longer says a VPN needs `openconnect` and `ocproxy` when
  komando's own client is the one that will run it.
- A second `komando vpn up NAME` that waits for another one (which may be
  waiting for a sign-in) now says so instead of standing still.

## [0.9.0] - 2026-11-10

### Highlights

- **Every feature as plain questions:** type `komando`, pick Add or All
  features, and answer one question at a time. Add has a form for every
  kind of server, database, cache, queue, storage, cluster, registry and
  VPN, and the last screen shows the exact commands before anything runs.
- **Windows servers,** over OpenSSH or WinRM: `test`, `exec`, `script`,
  `facts`, files, services and `shell` run PowerShell there, with Windows
  forms of the destructive rules.
- **`komando queue`: message queues.** Kafka, RabbitMQ, NATS JetStream,
  Amazon SQS and Google Cloud Pub/Sub: look at topics, queues and lag, peek
  at messages without removing any, send, create, and delete only with
  `--allow-dangerous`.
- **Five more databases:** SQL Server, Oracle, ClickHouse, Snowflake and
  BigQuery work with `db query`, `schema`, `explain`, `info` and the rest,
  read-only unless you add `--write`.
- **Windows (SMB) shares as storage,** with komando's own SMB 2 and 3
  client.
- **Azure and Google logins in more places:** `azure-kv:` reads secrets
  from Azure Key Vault, and registry conns for Azure Container Registry,
  Google Artifact Registry and Container Registry log in with your cloud
  login.

### Added

- **Every feature as questions, for people at a terminal.** Type `komando`,
  pick Add or All features, and answer one plain question at a time (a
  name, an address, a user ...), each with an example, a default Enter
  takes, and a check before the next question. Add has a form for every
  kind: Linux and Windows servers (OpenSSH or WinRM), PostgreSQL, MySQL,
  SQL Server, Oracle (service name or SID), MongoDB, ClickHouse, Snowflake
  (key pair or token), BigQuery (your Google login), SQLite, Redis,
  Memcached, Kafka, RabbitMQ, NATS, Amazon SQS, Google Pub/Sub, S3 (AWS,
  MinIO, R2, Wasabi, Spaces, B2), SFTP, FTP, Google Cloud Storage, Azure
  Blob, WebDAV, Windows shares (SMB), Kubernetes, container registries
  (also Amazon ECR, Azure and Google with their own logins) and every VPN
  kind.
  All features lists every command by area and asks for what it needs,
  picking servers, databases and VPNs from your list. The last screen shows
  the exact command lines before anything runs, and offers **Try it first**
  (`--dry-run`) for a change. Forms never hold a password (the command asks
  for it hidden) and never add `--yes`, `--allow-dangerous` or `--reveal`.
  A password pasted with an address is taken out before it is shown.
- `komando host add`, `conn add` and `vpn add` typed alone at a terminal ask
  the same questions; with any argument or flag, or for an AI agent, they
  work as before.
- `vpn add --ask-password` and `--ask-psk`: type the VPN login password or
  the pre-shared key (l2tp, ipsec, ikev2) once, hidden, as with `host add`;
  they are stored as `secret:NAME-pass` and `secret:NAME-psk`. AI agents get
  `NEEDS_PERSON`.
- **Windows servers over OpenSSH:** `komando host add win1
  Administrator@10.0.0.9 --os windows` marks a Windows server. komando then
  runs PowerShell there: `test`, `exec`, `script`, `facts` (Windows version
  and support dates, updates, pending reboot, ports), `fs ls/stat/cat/write`,
  `upload`, `download`, `cp` (single files), `svc
  status/list/start/stop/restart/enable/disable` and `shell` work; other
  commands stop with `NOT_SUPPORTED` and a hint before anything runs. See
  docs/features/windows.md.
- **Windows servers over WinRM:** `komando host add win2
  winrm://Administrator@10.0.0.9 --ask-password` reaches a Windows server
  through WinRM (what Ansible uses) with komando's own client: HTTPS on
  port 5986 with the certificate checked (`?ca=secret:NAME` for a private
  CA, `?tls=skip-verify` only when asked), NTLM login (`?auth=basic` for
  local accounts), `--via` bastions and VPNs. The same Windows commands
  work as over OpenSSH.
- `os:windows` and `os:linux` target selectors.
- **Windows (SMB) shares as storage conns:** `smb://alice@fileserver/team/reports?domain=CORP`
  (or `cifs://`, or `CORP;alice@` for the domain) reaches a Windows file
  server, Samba, a NAS or Azure Files with the same `storage ls`, `cat`,
  `download`, `upload` and `rm` as the other kinds, also `--via` an SSH host
  or a VPN. komando speaks SMB 2 and 3 itself (no `smbclient` needed), logs
  in with the password from `--password-ref`, signs every message and
  encrypts when the server asks for it. A guest login is refused, a key
  cannot climb out of the conn's folder with `..` (between `/` or `\`), an upload
  replaces a file only once the new one is complete, and `storage link`
  answers `NOT_SUPPORTED`. `komando doctor` warns about SMB conns that cross
  the network, since their encryption depends on the server.
- `azure-kv:VAULT/NAME[#JSON_KEY]` reads a secret from Azure Key Vault,
  everywhere a `--password-ref` or another secret reference is taken
  (`azure-kv:shop-vault/db-password`, or `.../NAME/VERSION` for an older
  version). komando signs in to Azure itself, without the `az` program: with
  a service principal (`AZURE_TENANT_ID`, `AZURE_CLIENT_ID`,
  `AZURE_CLIENT_SECRET`), a workload identity on AKS, a token the Azure CLI
  saved while it lasts, or the managed identity on Azure. The token goes
  only to Key Vault hosts, and komando keeps no token.
- A registry conn for Azure Container Registry
  (`registry://myregistry.azurecr.io`) without `--password-ref` logs in with
  your Azure login, as `az acr login` does: komando trades an Azure token for
  a fresh registry login each time, like it already does for Amazon ECR. It
  uses the same Azure logins as `azure-kv:`. Without one, the error is
  `AZURE_LOGIN_REQUIRED`. The Azure token is good for the whole
  subscription, so it goes only over https with the registry's certificate
  checked: a conn with `?tls=false` or `?tls=skip-verify` needs
  `--password-ref`.
- Registry conns for Google Artifact Registry (`REGION-docker.pkg.dev`) and
  Container Registry (`gcr.io`, `eu.gcr.io`, `us.gcr.io`, `asia.gcr.io`)
  without `--password-ref` log in with your Google login: komando gets a
  fresh access token each time and logs in as `oauth2accesstoken`, as
  `gcloud auth configure-docker` does, with the credentials it already uses
  for `gs://` storage and `gcp-sm:`. With no Google login at all, public
  images are read without one; an expired login, or a key file that is set
  but missing or broken, gives `GCP_LOGIN_REQUIRED`.
  The token goes only over https with the registry's certificate checked.
- **`komando queue`: message queues, starting with Apache Kafka** (and
  what speaks its protocol: Redpanda, Amazon MSK, Confluent Cloud). Add a
  cluster as a conn, `kafka://USER@BROKER1:9092,BROKER2:9092?tls=true&sasl=scram-sha-512`
  (SASL PLAIN or SCRAM with `--password-ref`, a private CA with
  `?ca=secret:NAME`, `--via` an SSH server or a VPN like any conn).
  `queue info`, `ls`, `describe`, `groups` and `lag` read the brokers,
  topics, partitions and consumer groups; `queue peek` reads the newest or
  oldest messages without joining a consumer group, so no application's
  position moves. `queue send` and `queue create` change; `queue rm` and
  `queue purge` delete messages and need `--allow-dangerous`. Every change
  has a real `--dry-run` (`create` asks the brokers to check the topic
  only). Design: docs/design/queue.md; guide: docs/features/queues.md.
- **RabbitMQ in `komando queue`:** add a server as a conn,
  `amqps://USER@HOST:5671/VHOST` (or `amqp://` --via an SSH server; the
  path is the vhost, `%2F` for `/`), with `?management=15671` to also use
  the management HTTP API. `queue info` and `describe` work over AMQP
  alone; `queue ls`, `queue peek`, the nodes and the cluster totals need
  the management API. `queue peek` takes the first messages of a queue and gives every
  one back, so nothing is removed (RabbitMQ marks them redelivered); on a
  quorum queue each peek counts as a delivery, so peek stops with
  `DELIVERY_LIMIT_NEAR` before a message gets close to its delivery limit.
  `queue send` publishes a persistent message and waits for the server's
  confirm; `queue create --type classic|quorum|stream` makes a durable
  queue (`--config x-max-length=1000` for its arguments); `rm` and `purge`
  need `--allow-dangerous`. `amqp://` straight over the network is refused
  like `redis://` unless `?insecure=1`. New error codes `QUEUE_NOT_FOUND`,
  `QUEUE_EXISTS` and `DELIVERY_LIMIT_NEAR`. Built on
  github.com/rabbitmq/amqp091-go (BSD-2).
- **NATS JetStream in `komando queue`:** add a server as a conn,
  `tls://USER@HOST:4222,HOST2:4222` (or `nats://` --via an SSH server),
  logging in with a user and `--password-ref`, a token (a password
  reference without a user), or a `.creds` file kept in the vault
  (`?creds=secret:NAME`); `?domain=` for a leaf node's JetStream.
  `queue ls` lists streams, `describe` shows a stream with its limits,
  cluster and consumers, `groups` and `lag` show consumers (pending, ack
  pending, waiting). `queue peek` reads messages by their sequence number,
  the newest or (`--oldest`) the first ones, with no consumer and no
  acknowledgement, so nothing is removed, also from a work-queue stream.
  `queue send` takes a subject, checks that a stream keeps it, and waits
  for the stream's acknowledgement; `queue create` makes a stream
  (`--config subjects='orders.>' --config max_age=7d`, `--replicas`);
  `rm` and `purge` need `--allow-dangerous`. `nats://` straight over the
  network is refused like `redis://` unless `?insecure=1`. New error codes
  `STREAM_NOT_FOUND`, `STREAM_EXISTS` and `CONSUMER_NOT_FOUND`. Built on
  github.com/nats-io/nats.go and github.com/nats-io/nkeys (Apache-2.0).
- **Amazon SQS in `komando queue`:** add a region as a conn,
  `sqs://eu-west-1`, logging in like komando's other AWS clients: the
  conn's `--option aws_profile=NAME` (SSO included, renewed with `komando
  login aws`), an access key ID in the URL (`sqs://AKIA...@eu-west-1`)
  with the secret key from `--password-ref`, or the usual AWS chain
  (variables, default profile, the server's role). `?endpoint=` for a VPC
  endpoint or an emulator (LocalStack, moto), `?account=` for queues
  another account shares. `queue ls` and `describe` show the waiting,
  in-flight and delayed messages, settings, dead-letter queue and tags.
  `queue peek` receives a sample with a visibility timeout of 0 and never
  deletes, so every message stays and stays visible; since each receive
  counts toward a dead-letter queue's `maxReceiveCount`, peek stops with
  `DELIVERY_LIMIT_NEAR` before a message runs out of receives. `queue
  send` sends text with `--header` values as message attributes (`--key`
  is a FIFO queue's message group); `queue create` makes a standard or
  (name.fifo) FIFO queue from SQS settings (`--config
  VisibilityTimeout=60`); `rm` and `purge` need `--allow-dangerous`. An
  `http://` endpoint straight over the network is refused unless
  `?insecure=1`. komando speaks the SQS API itself, signed with the AWS
  SDK's SigV4 signer it already had: no new dependency.
- **Google Cloud Pub/Sub in `komando queue`:** add a project as a conn,
  `pubsub://my-project`, logging in like gs:// storage: a service account
  key in `--password-ref`, or else gcloud's application default login; the
  emulator (`?endpoint=http://localhost:8085`) needs none, and a login is
  only ever sent over HTTPS. You send to a topic; `queue peek` and `purge`
  take a subscription, where the messages wait, and `queue groups` lists
  the subscriptions. `queue peek` pulls without acknowledging and gives
  every message straight back (ack deadline 0), so nothing is removed;
  with a dead-letter topic it stops with `DELIVERY_LIMIT_NEAR` before a
  message runs out of deliveries. `queue describe` shows a topic with its
  subscriptions, or one subscription; `queue create subscriptions/NAME
  --config topic=TOPIC` makes a subscription, with Pub/Sub's own setting
  names (`ackDeadlineSeconds=60`, `messageRetentionDuration=7d`);
  `purge` (a seek to now) and `rm` need `--allow-dangerous`, and `rm`
  deletes a subscription only when written `subscriptions/NAME`. Pub/Sub
  does not count messages, so the counts are -1 and the text says so. New
  error codes `SUBSCRIPTION_NOT_FOUND` and `SUBSCRIPTION_EXISTS`. komando
  speaks the Pub/Sub REST API itself: no new dependency.
- **SQL Server conns** (`sqlserver://app@db.internal:1433/sales?encrypt=true`,
  also `mssql://`): `db query`, `schema`, `explain` (SHOWPLAN; `--analyze`
  measures), `info`, `activity`, `locks`, `sizes`, `kill --session`, users
  and grants, `db shell` and `conn test`, through `--via` and VPNs, with
  `?ca=secret:NAME` and `tls=skip-verify`. New conns that cross the network
  get `encrypt=true`. SQL Server has no read-only transaction, so without
  `--write` komando rolls the SQL back and checks its own transaction after
  each statement; T-SQL gets stricter checks (a change anywhere in the text
  counts, a bare procedure name runs it, `BEGIN`/`COMMIT` are refused
  anywhere, and numbers are read as SQL Server reads them, so `1eDROP` is
  `1e DROP`). A URL option given twice (`encrypt=true&Encrypt=disable`) is
  refused. `db dump` and `restore` say `NOT_SUPPORTED` for now. Built in
  with go-mssqldb (BSD-3-Clause), pure Go.
- **Oracle conns** (`oracle://app@db.internal:1521/ORCLPDB1?tls=true`, the
  path is the service name; `?sid=` for old databases): `db query`,
  `schema`, `explain` (EXPLAIN PLAN and DBMS_XPLAN),
  `info`, `activity`, `locks`, `sizes`, `kill`, users and grants, `db shell`
  and `conn test`, through `--via` and VPNs, with TCPS (`tls=true`,
  `tls=skip-verify`) and `?ca=secret:NAME`. New conns that cross the network
  get `tls=true`. Without `--write` every run is `SET TRANSACTION READ ONLY`,
  checked after each statement. DDL commits on its own in Oracle, so it
  always needs `--write` and runs alone; PL/SQL blocks, calls to stored
  functions (which can commit on their own), database links and inline
  external tables need `--write` and `--allow-dangerous`; `COMMIT` and autonomous transactions are refused
  anywhere; `q'[...]'` quotes and `/` lines are read as Oracle does. `db
  dump` and `restore` say `NOT_SUPPORTED` (Data Pump runs on the server).
  Built in with go-ora (MIT), pure Go.
- **ClickHouse conns** (`clickhouse://app@ch.internal:8443/analytics?tls=true`)
  over ClickHouse's HTTP interface, with komando's own small client (no
  driver library): `db query` with `{p1:String}` placeholders, `schema`
  (engines, keys, skipping indexes), `explain` (`EXPLAIN indexes = 1`),
  `info`, `activity`, `sizes` (from `system.parts`), `kill` (by the `pid`
  `db activity` makes from the query id), users and grants, `db shell` and
  `conn test`, through `--via` and VPNs, with `tls=true`, `tls=skip-verify`
  and `?ca=secret:NAME`. New conns that cross the network get `tls=true`
  (port 8123 becomes 8443); the native ports 9000 and 9440 are refused with
  a hint. ClickHouse has no transactions: without `--write` every request
  carries the server's own `readonly=1` (also every query with rows), and a
  statement that is not a read needs `--write`, goes alone, and a dry run
  only reports it. Table functions and engines that reach other servers,
  files or programs (`url()`, `s3()`, `remote()`, `file()`,
  `executable()`, ...) need `--allow-dangerous`; `$$` heredocs and
  unquoted non-ASCII are refused. A user whose profile is read-only gets no
  settings it would refuse. `db user add` sends a salted SHA-256 hash
  komando computes, never the password. `db dump`, `restore` and `locks`
  say `NOT_SUPPORTED`.
- **Snowflake conns**
  (`snowflake://APP_RO@myorg-myaccount/ANALYTICS/PUBLIC?warehouse=W&role=R`,
  the account in place of a host) over Snowflake's SQL API, with komando's
  own small client (no driver library): `db query` with `?` placeholders,
  `schema`, `explain`, `info`, `activity` (running queries from
  `QUERY_HISTORY`), `sizes`, `kill` (`SYSTEM$CANCEL_QUERY`; `--session`
  ends the session), `db user ls` and `db grants` (read only), `db shell`
  and `conn test`, through `--via` and VPNs, always HTTPS with the
  certificate checked, and `?ca=secret:NAME` for a proxy's CA. Login is a
  private key from the vault (komando signs the key-pair token itself) or a
  programmatic access token; the SQL API takes no passwords, and browser
  SSO is not supported. Snowflake has no read-only mode, so komando's
  check is the guard: without `--write` only reads are sent, each request
  runs exactly one statement, and a statement that is not a read needs
  `--write`, goes alone, and a dry run only reports it; the docs give the
  SQL for a read-only role. `CREATE OR REPLACE`, `SYSTEM$` functions that
  change things, stage files, `CALL` and `EXECUTE IMMEDIATE` need
  `--allow-dangerous`; `//` comments, `$$` text and `\'` are read as
  Snowflake reads them. A run that times out cancels the statement on the
  server. `db dump`, `restore`, `locks`, `user add`/`passwd`/`rm` and
  `grant`/`revoke` say `NOT_SUPPORTED`. Not yet run against a real
  account: see docs/design/snowflake.md.
- **BigQuery conns** (`bigquery://my-project/analytics?location=EU`, the
  project jobs run in and a default dataset) over BigQuery's REST API, with
  komando's own small client (not the Google Cloud SDK): `db query` with `?`
  placeholders, `schema` (datasets, tables and columns from the API),
  `explain` (the dry run), `info`, `activity` (jobs that are not done, from
  `INFORMATION_SCHEMA.JOBS`), `sizes`, `kill` (`jobs.cancel`), `db shell`
  and `conn test`, through `--via` and VPNs, HTTPS with the certificate
  checked and `?ca=secret:NAME` for a proxy's CA. The login is the same as
  for `gs://` conns: gcloud's application default credentials (sent only to
  `*.googleapis.com`), or a service account key in `--password-ref`. Every
  statement goes to BigQuery as a dry run first: without `--write` only
  what BigQuery itself calls a `SELECT` runs, and a query that would read
  more than the new `--max-bytes` (default 10GB) stops with the new error
  `DB_BYTES_LIMIT`; each job also carries that cap (`maximumBytesBilled`),
  and each result says `bytes_processed`. `--dry-run` is BigQuery's own dry
  run, for reads too. A write needs `--write` and goes alone; `EXPORT DATA`,
  `EXTERNAL_QUERY`, remote functions, `CREATE OR REPLACE`, `LOAD DATA
  OVERWRITE`, row access policies, reservations, `CALL` and `EXECUTE
  IMMEDIATE` need `--allow-dangerous`. Scripts are refused; `#` comments,
  triple-quoted and raw strings and `` `names` `` are read as BigQuery reads
  them. A run that times out cancels its job. `db dump`, `restore`, `locks`,
  `db user` and `grant`/`revoke`/`grants` say `NOT_SUPPORTED`. Not yet run
  against a real project: see docs/design/bigquery.md.

### Changed

- The menu's Add asks one question at a time instead of one line
  (`web1 deploy@10.0.0.5`), and the main menu has **All features** in place
  of Audit (Audit is under All features, Safety and audit).
- Every JSON error now has an `error.hint`: an error without a hint of its
  own gets a general next step for its exit code.
- `komando schema` lists 16 more error codes (among them `CERT_PROBLEMS`,
  `NXDOMAIN` and `SECRET_DESTINATION`), and each code's example and hint now
  come from the same place in the code, so the hint fits the code.
- The `sql-remote` rule's reason names what it covers now (dblink, an
  Oracle database link, ClickHouse `url()` or `s3()`), not only dblink.

### Fixed

- The docs no longer claim more than the code does: secrets are hidden from
  agents komando recognises, and several design docs named flags, commands
  and error codes that do not exist.

### Security

- Windows forms of the destructive rules: a recursive delete of the system
  drive or a system folder, formatting disks, `Stop-Computer`,
  `Restart-Computer`, stopping SSH or WinRM, blocking all incoming traffic,
  deleting users, hidden (`-EncodedCommand`) or downloaded scripts,
  deleting shadow copies, and deleting a registry hive need
  `--allow-dangerous`. `exec --read-only` and `script --read-only` on
  Windows servers fail closed: they accept only a small subset of
  PowerShell that komando reads exactly (pipelines of listed read cmdlets
  with literal arguments and safe parameters, and simple `Where-Object`
  and `ForEach-Object` blocks) and refuse everything else, such as `$`,
  backticks, `@`, `&`, redirection, comments, .NET calls, keywords and
  characters outside ASCII. See docs/features/windows.md.
- A command komando cannot run on Windows is refused for every Windows
  server, so a sh script is never sent to PowerShell.
- WinRM refuses Basic login over plain HTTP (the password would travel
  unencrypted) and warns about `tls=off` and `tls=skip-verify`.

## [0.8.0] - 2026-11-09

### Highlights

- **SSH logins ask a person, as `ssh` does:** at a terminal, komando asks
  for a missing password and for the one-time code of a two-factor login,
  so `komando shell`, the menu and every other command reach two-factor
  servers. AI agents are never asked; they send the user to their own
  terminal.
- **New database and cache conns check TLS by default:** a conn that
  crosses the network gets `sslmode=verify-full` (Postgres) or `tls=true`
  (MySQL), and a plain `redis://` there is refused unless you say
  `?insecure=1`. Saved conns keep their URL.
- **Fewer ways for an AI agent to reach a secret:** `secret set` and
  `--ask-password` from an agent stop with `NEEDS_PERSON`, `vpn add` no
  longer overwrites another entry's secret, a VPN password or a new VPN
  address needs a person's yes, and `docker exec --read-only` and `cluster
  exec --read-only` are checked like `exec --read-only`.
- **Easier first steps:** `--ask-password` stores a password in one step,
  `host add`, `conn add` and `vpn add` say what to run next, the menu grows
  with your inventory, and more hints now name a whole command you can run.
- **Easier to move and to leave:** a whole `export` carries your deny rules
  and settings and names the keys it needs, `import` keeps servers whose
  key is not here yet, and `komando guide uninstall` takes komando out of
  your AI agents again.
- **For AI agents and their people:** `komando schema` lists every error
  code with its next step, `doctor` checks each agent's skill, and `audit
  --actor NAME` shows what one person or agent did.
- **A new vault keeps its key in the OS keychain**, so a backup or a synced
  copy of `~/.komando` no longer opens it. Vaults you have keep their key
  where it is; `komando secret keychain` moves it.
- **`komando ssh-gate` gives a phone's SSH key komando and nothing else:**
  no shell, one komando command at a time, run as for an AI agent, and
  read-only if you choose.
- **`komando login HOST` lets an AI agent reach a two-factor server:** a
  person answers the code once, and komando keeps that login for 8 hours.

### Added

- **`komando ssh-gate`: an SSH key that runs komando and nothing else.**
  For a phone (the Komando app) or another computer that reaches komando
  over SSH: `komando ssh-gate line --name phone KEY` prints the line for
  `~/.ssh/authorized_keys` (`restrict,command="/full/path/komando ssh-gate
  --name phone" ...`). For that key, sshd runs ssh-gate, which takes only
  one komando command: split into words like a shell, but with no shell and
  no expansion, so `;`, `|`, `$(...)` and other programs are refused
  (`SSH_GATE_SYNTAX`, `SSH_GATE_REFUSED`). komando then runs as for an AI
  agent, whatever the client says it is: secrets stay hidden, `--reveal`,
  `--allow-dangerous` and commands for a person at a terminal are refused,
  and `--yes` on a protected target needs a person on the komando computer.
  `--read-only` keys run only what `komando schema` counts as a read
  (`SSH_GATE_READ_ONLY`). No key writes on the komando computer: downloads,
  dumps and copies to a folder here, changes to komando's own setup, and
  every command on a target that is this computer (a sqlite conn,
  `localhost`, loopback) or not in the inventory (`u@HOST`) are refused;
  a change komando adds later is refused until it is known to act on
  servers only. Every command a key runs or is refused is in
  `komando audit`, with the key's name, the address it came from and why,
  even with the audit setting off; what the key sent is shown escaped.
  See [Safety](docs/features/safety.md#a-key-that-runs-komando-and-nothing-else).
- `KOMANDO_KEYCHAIN=off` keeps komando away from the keychain (CI runners,
  containers, test runs): a new vault then keeps its key in `vault.key`.
- `komando login HOST`: a person logs in to a server once, answering its
  password and two-factor code, and komando keeps that login in the
  background for the new `login_for` setting (8h). Every command to that
  server, an AI agent's too, uses it without a code; rules, approvals and
  audit stay the same. A login to a jump host serves every server behind
  it. `komando logout HOST` (or `--all`) ends it, and `komando status`
  lists kept logins. Making `login_for` longer needs a person's yes.
- `audit --actor NAME`: what one person, AI agent or computer account did
  (`komando audit --actor budi --since 30d`). A new page, [Rotate keys and
  passwords](docs/features/rotate.md), gives the steps in order for an SSH
  key, a server or database password, and for when someone leaves.
- `komando schema` lists every error code (`error_codes`, over 200): its
  exit code, an example message and the usual next step. It is made from the
  source, and a test keeps it in step. The troubleshooting table names the
  common codes that were missing (`HOSTKEY_UNKNOWN`, `DNS_ERROR`,
  `HOST_NOT_FOUND`, `VAULT_*`, `IMPORT_INCOMPLETE`).
- `komando guide uninstall` takes the skill and komando's guard entries out
  of Claude Code, Codex, Cursor and Gemini CLI, keeping everything else in
  those files (a changed file is kept as `.bak`). An AI agent needs a
  person's yes to remove its own guard.
- A whole `export` carries your own deny rules and settings. `import
  komando` adds the deny rules and lists the settings that differ with the
  `komando config set` command for each; it changes none.
- `doctor` checks AI agents: whether they have komando's skill, whether it
  is this version's (after an update, `komando guide install` again), and
  whether Claude Code runs with komando's guard.
- `--ask-password` on `host add`, `host edit`, `conn add` and `conn edit`: a
  person types the password once (hidden) and it is stored as
  `secret:NAME-pass` and used as the reference, in one step instead of
  three. It never replaces a secret something else uses, asks first on a
  protected entry, and takes back a new secret when the add fails. An AI
  agent gets `NEEDS_PERSON`.
- `host add`, `conn add` and `vpn add` end with `next:` (`komando test
  web1`, `komando vpn up office`). A `--password-ref secret:NAME` whose
  secret is not in the vault yet is a warning at once, with the command
  that stores it. `host rm`, `conn rm` and `vpn rm` name the secrets nothing
  uses any more (`secrets_unused`) with the `secret rm` command; komando
  does not remove them by itself.
- The installer says when another komando earlier in your PATH would run
  instead, tells an update to run `komando guide install` again, and shows
  how to turn on tab completion; README has a Tab completion section.
- **The menu grows with you.** Add stays once there is a server (after the
  actions) and also adds a conn from a name and a URL (`app-db
  postgres://...`). VPN connects or disconnects: an up VPN says `up (Enter
  disconnects)` and the header counts the VPNs that are up. Import shows
  while `~/.ssh/config` names servers komando does not know, and AI agent
  (`komando guide install`) while no agent has komando's skill, when the
  number keys still reach them (9 rows at most). `?` shows what komando
  does, by task, instead of `komando --help`.
- `db shell`: `\write` allows changes for the rest of the shell after a
  yes, and connects again read-write (`\write` again goes back); a
  destructive statement asks for the conn's name instead of refusing.
- **SSH logins ask a person, as `ssh` does.** At a terminal, komando asks
  for a server's password when none is stored, and for the one-time code
  of a two-factor login, with the server's name (`web1: Verification
  code:`), hidden unless the server lets the answer show; servers that log
  in at once ask one at a time, and Ctrl-C stops the login (`CANCELLED`).
  `komando shell`, the menu and every other command now reach two-factor
  servers. A stored password still goes out once, only to a hidden password
  question. AI agents, scripts and background processes are never asked:
  the `AUTH_FAILED` hint sends a person to run the command in their own
  terminal, no longer to `ssh`.
- `export` names the keychain keys its servers use (`keys_needed`) and
  their files (`key_files`), which an export file never holds.

### Changed

- **A new vault keeps its key in the OS keychain** (the macOS keychain, or
  the Secret Service through `secret-tool` on Linux), no longer in
  `vault.key` beside the vault, so a backup or a synced copy of
  `~/.komando` does not open it. komando makes the key at the first secret
  and counts on it only once it reads back. A key the keychain already
  holds for that folder (a vault moved aside) is used, never replaced.
  Where the keychain cannot keep it (no `secret-tool`, no desktop session,
  a locked keychain over SSH), the key goes into `vault.key` as before and
  `komando doctor` warns. Existing vaults keep their key where it is: move
  it with `komando secret keychain`.
- `AUTH_FAILED` and `NO_AUTH` for an AI agent or a script now name
  `komando login HOST` as the way a person lets it reach a two-factor
  server.
- Hints name whole commands: `komando fs ls TARGET FOLDER`, `komando
  cluster history CONN deployment/NAME`, `komando net check web1
  HOST:443` instead of a bare command that fails as typed. `DNS_ERROR`,
  `CONNECT_TIMEOUT`, `CONNECT_FAILED`, `WAIT_TIMEOUT` and `JOB_LOST` name
  the command to run next. A typo's hint never shows an example with
  `--yes`, `--allow-dangerous` or `--reveal`; SQLite `db restore` keeps its
  own hint.
- A vault that cannot be opened says why, with the step: `VAULT_LOCKED`
  (no passphrase given), `VAULT_KEY` (key file missing or broken),
  `VAULT_DECRYPT` (wrong passphrase), instead of `REMOTE_ERROR`. A server's
  unreadable password reference names the exact `secret set` (or what the
  reference needs). `test` on one target ends with that target's own hint.
- An import that refuses some servers still brings the rest in, but ends
  with `IMPORT_INCOMPLETE` (exit 1) instead of `ok`; names that exist
  already are still skipped quietly, so importing again is safe.
- Docs: one story for moving to another computer (export without
  passwords, or the whole folder once the vault has a passphrase), uninstall
  with `guide uninstall` and the keychain item, and "Undo a change" for files.
- For AI agents, the approval hint says "komando asks the user in a
  window" only where a flag opens one: not for `--write` or leaving out
  `--read-only` (komando does not ask; the agent asks the user first), and
  not for stops no flag lifts (komando's own folder, an unsafe backup line,
  an `.ovpn` script line). `READ_ONLY_VIOLATION` no longer says to add
  `--yes` on a server that is not protected.
- `VPN_DOWN` and `TUNNEL_TIMEOUT` put the last lines of the log in the
  message and name a command to try, instead of sending an agent to a file
  in `~/.komando` it may not read.
- Text for people says what happened first: `stored app-db-pass`, `added
  the deny rule "rm -rf /srv" (2 custom rules now)`, `removed app-db`,
  `saved 2 servers, 1 conn to FILE (no passwords)`; `false` fields after
  such a headline are left out. JSON is unchanged (fields were only added).
- `komando list` on an empty inventory also shows how to add a database,
  and `SECRET_NOT_FOUND` for a conn names the secret to set.
- A person at a terminal confirms `fs rm --recursive`, removing a top-level
  path, `sync --delete` and removing an essential package by typing the
  target's name, as `exec` and `db query` already ask, instead of being
  sent back to add `--allow-dangerous`. One typed name covers the same
  targets for the rest of the command, so a step two checks catch is asked
  once.
- An approval window nobody answers closes after 2 minutes and the agent is
  told nobody answered, no longer that the user clicked Deny.
- An AI agent that runs `secret set NAME` with no value gets `NEEDS_PERSON`:
  ask the user to run `komando secret set NAME` in their own terminal. It
  used to get a `USAGE` error whose hint was the same command. `komando
  guide` and the skill say never to ask for a password in the chat.
- `import komando` adds a server whose keychain key is not on this computer,
  leaves the key out and says how to bring it (`key add`, then `host edit
  --key`), as it does for an identity file. It used to leave the server out.
- `rename --prefix --notes` replaces only what clearly means an entry:
  server, conn, VPN and secret names, `@group`, and a pattern such as
  `shop-db-*` that matches the same entries afterwards (before, it did not
  follow). The old prefix without its `-`, group names without `@`, key
  names, and names that are also the user, host, bucket or database in a
  conn URL stay, and are listed under `kept` with the reason. Before, `db
  shop` and `bucket shop-dev` became `acme-shop…` too.
- `rename --prefix` lists every label value that names an old entry (such
  as a conn's `host=` label, which `doctor` reads), and `--labels` replaces
  them by the same rules. Without `--notes`, a warning counts the notes
  that still name old entries.

### Fixed

- Last gaps from the user-journey review: the features index no longer
  says SQLite restores; the tunnel page says how a person copies the
  database password; README says Codex asks once in `/hooks` and what
  `secret keychain` needs on Linux; `komando schema` describes every `meta`
  field; the proxy-command and credential-plugin stops name
  `--allow-dangerous`; `KEYCHAIN_FAILED` says a person unlocks the keychain.
- A flag a group gives all its sub-commands (`cron --user`, `cron --sudo`,
  `docker --sudo`, `pkg --no-sudo`) now shows in the sub-command's `--help`
  and in `komando schema <command>`, where agents look before using one.
- Docs: examples that broke the rules or skipped a step (`psql` and
  `pg_dump` over `exec`, a `policy check` example that is not blocked,
  `secret:` references with no `secret set`, conn names an import does not
  make, a key file from the cloud provider); the `tunnel start` usage line
  (`-L/-R/-D` are optional for a conn); "keychain" now means only the
  system keychain (komando's SSH keys are its key list); the env variable
  table, ID examples and the Go version.
- AI agents read komando's hints whole again. The secret masker hid the
  command after words such as "password:" (`save its password: [hidden]
  secret set web1-pass`) in `NO_AUTH`, `KEY_PASSPHRASE_REQUIRED`, `komando
  guide` itself and `guide install --help`. A value that starts with a
  `` `komando `` command is now kept, and a test runs the masker over every
  hint that names one, the guide and the skill. Kebab-case flags such as
  `--host-key-policy=strict` are no longer hidden, and a few messages (a
  locked vault, a missing `secret-tool`, a registry CA reference, a failing
  credential helper) were reworded so they arrive whole.
- `db dump` and `db restore` of an archive failed for a conn with a
  private CA (`?ca=secret:NAME`) when `pg_dump` or `pg_restore` ran on a
  server (`--on HOST` or `--via`): libpq refused the `ca` option. The tools
  now get the CA in a file on that server, removed when they end, and
  check the certificate fully against it, as komando does: libpq with
  `sslrootcert=` and `sslmode=verify-full`, `mysqldump` with `--ssl-ca`.

### Security

- With `host_key_policy strict`, an AI agent's first pin (`host trust`)
  needs a person's yes; the window shows each fingerprint to compare.
  `HOSTKEY_UNKNOWN` now says which fingerprint the server shows.
- **New conns check TLS by default.** `conn add` and `conn edit --url` of a
  conn that crosses the network on its own (no `--via`, not this computer)
  add `sslmode=verify-full` (Postgres) or `tls=true` (MySQL) when the URL
  says nothing, and say so in `warnings`. A plain `redis://` or
  `memcached://` there is refused (`INSECURE_PROTOCOL`) unless the URL
  has `?insecure=1`, which an AI agent needs a person's yes for. Saved
  conns keep their URL. `pg_dump` and `pg_restore` 16 or newer get
  `sslrootcert=system` for such a URL, so `db dump --on` checks the
  certificate against the system's CAs as komando does; an older one
  needs the CA in `~/.postgresql/root.crt` and stops with a hint
  (`DB_CONNECT`).
- An AI agent that adds a VPN with a password or pre-shared key reference,
  or points a VPN at another server or address, needs `--yes` and a
  person's yes (`SECRET_DESTINATION`); the window names the references and
  the server (for OpenVPN, its profile's `remote` lines). `vpn add` now
  takes `--legacy-crypto` and `--allow-pap` (a person's yes, as on
  `vpn edit`) and shows an OpenVPN profile's warnings.
- `vpn up` hands `KOMANDO_VAULT_PASS` to its background `vpn serve` on
  stdin instead of in its environment, as `tunnel start` does.
- `docker exec --read-only` and `cluster exec --read-only` are checked as
  `exec --read-only` is: a command that clearly changes something is
  refused (`READ_ONLY_VIOLATION`), and on a protected target only commands
  komando knows read skip `--yes`. Before, the flag alone skipped it.
- JSON answers list the SSH host keys a command trusted for the first time
  in `meta.host_keys_pinned`, so an agent can show the fingerprints.
- `vpn add NAME wireguard` and `vpn add NAME openvpn` no longer replace a
  vault secret named `NAME-key`, `NAME-psk` or `NAME-config` that is not
  that VPN's own (`SECRET_EXISTS`, nothing saved). Before, `vpn add prod
  ...` silently overwrote a secret `prod-key` that a server used, and an
  AI agent could put a value it chose there. `--overwrite` still reuses
  the secrets of the VPN it replaces when nothing else uses them.

## [0.7.0] - 2026-11-09

### Highlights

- **Rename a whole project in one step:** `komando rename --prefix shop-
  acme-shop-` renames every server, conn, VPN, secret, key and group that
  starts with `shop-`, and every reference follows. It needs one `--yes`
  (one approval window) for all the protected ones, and it changes
  everything or nothing.
- **`komando update` updates komando itself:** it installs the newest
  release (`sudo komando update` for /usr/local/bin), checked like the
  install line; `komando update --dry-run` says whether there is one.
- **An encrypted key in ssh-agent logs in, as with `ssh`:** a server whose
  `--identity` (from `import ssh-config`) or `--key` is encrypted now uses
  the agent's copy of that key, so a usual macOS setup works with
  `komando test` as it does with `ssh`.
- **The stored password is never sent as a two-factor code.** Before, every
  question the server asked got the password, and each try could count as
  a failed login and lock the account.
- **A person decides where an AI agent sends a secret:** `{{secret:NAME}}`,
  `--env K=secret:NAME` and a password on a new or moved server or conn
  need `--yes` and a yes in komando's window, which names the secret and
  the place (`SECRET_DESTINATION`). Agents that use `fs replace ...
  {{secret:NAME}}` now ask first.
- **Safer connections by default:** vault values for `-e` stay off the
  remote command line, the first trusted SSH host key is shown with its
  fingerprint, IKEv1 no longer offers 3DES or small DH groups, L2TP never
  sends the password with PAP, and `komando doctor` prints the fix for
  every database or cache without checked TLS.
- **Customer data stays out of the AI model:** on protected servers and
  conns, an AI agent sees email addresses, phone numbers, card numbers and
  IBANs as `[hidden: email]` and so on, and columns you name as
  `[hidden: column]`.
- **More places to reach:** MongoDB, Redis Cluster and Sentinel, databases
  and caches with a private CA (`?ca=secret:NAME`), and Google Cloud
  Storage, Azure Blob and WebDAV storage, all also through `--via`.
- **Many clusters at once, Helm without helm:** `cluster status`, `ls`,
  `events` and `helm ls` read every cluster a selector picks, and
  `cluster helm` reads Helm releases straight from Kubernetes.
- **Company proxies:** kube, registry and SSL VPN traffic follows
  `HTTPS_PROXY`, and an HTTP proxy can be a `--via` path (VPN kind
  `proxy`).

### Added

- **`komando secret passphrase`** re-encrypts every secret under a new
  passphrase, so `KOMANDO_VAULT_PASS` can change without losing the vault.
  It also gives a passphrase to a vault whose key is in `vault.key` or the
  keychain (the old key is removed once the new vault is saved and read
  back), and `--off --yes` goes back to a random key in `vault.key`. Every
  secret is decrypted first; when one cannot be, nothing changes. A person
  at a terminal only (`NEEDS_PERSON` for AI agents and scripts).
  `komando doctor` now fails when `KOMANDO_VAULT_PASS` does not open the
  vault and warns about a leftover `vault.key`.
- **`komando rename --prefix OLD NEW`** renames every server, conn, VPN,
  secret, key and group whose name starts with OLD. When OLD ends in `-`,
  the name without it is renamed too (group `shop` for `--prefix shop-`).
  Every reference follows: `--via` paths (also a server in the middle of
  one), password, sudo, key, preshared key and passphrase references,
  `secret:NAME` options in conn URLs, the key a server uses, group
  membership, jobs and tunnels. A key komando made moves its files. The
  protected mark, labels, notes and creation time stay, and names inside
  URLs (a bucket, a database user) do not change. The inventory and the
  vault are each written once; a name that is taken, or two old names with
  one new name, stops it before anything changes (`NAME_TAKEN` lists every
  clash). Protected servers and conns need `--yes` once, and an AI agent's
  window says how many it covers. `--dry-run` shows the old and new names
  per kind and every reference that would change. `--kind` renames only
  some kinds, and `--notes` also replaces the old names in notes, as whole
  words. When the new prefix starts with the old one, a second run changes
  nothing.
- **`komando key mv OLD NEW`** renames a key; the servers that use it follow,
  and a key komando made moves its private and `.pub` files in
  `~/.komando/keys`.
- **`komando group mv OLD NEW`** renames a group on every server, conn and
  VPN in it; with a protected member it needs `--yes` once. A name that is
  another group already is refused (`GROUP_EXISTS`).
- `komando audit --since` and `--until` pick a time window: how long ago
  (`2h`, `7d`), `today`, `yesterday`, or a time (`2026-11-07`,
  `'2026-11-07 14:30'`, `2026-11-07T14:30:00Z`; without a zone, this
  computer's). With either, every match is shown, not only the newest 50,
  unless `-n` is given. They work with `--target`, `--command` and
  `--failed`.
- A company HTTP proxy is a VPN of kind `proxy`
  (`komando vpn add office proxy --address proxy.corp:3128`, its login with
  `--user` and `--password-ref`): `--via office` tunnels servers (SSH),
  databases, caches and file servers through it (CONNECT), as `socks` VPNs
  do for SOCKS proxies. `host ssh-command` gives OpenSSH the same path.
- Personal data is hidden from AI agents in what they read from protected
  servers and conns: `[hidden: email]`, `[hidden: phone]` (international
  form), `[hidden: card]` (card network prefix, length and check digit) and
  `[hidden: iban]` (check digits). It covers `db query`, `cache get` and
  `run`, `storage cat` and `ls`, `fs cat`, `exec`, `logs` and the other
  commands that show data from a target; komando's own inventory is never
  hidden. `komando config set mask_personal all` hides it everywhere, `off`
  nowhere (showing more needs `--yes`). A conn can ask for it with
  `--option mask_personal=on`, and a database conn hides whole columns with
  `--option 'mask_columns=name address'`. `--reveal`, which a person
  allows, shows the values. A `db query --write`, `cache set` or
  `cache run --write` that still holds a hidden value stops with
  `HIDDEN_VALUE`, as file writes already did.

- `komando cluster status`, `cluster ls`, `cluster events` and
  `cluster helm ls` read every cluster a selector picks (`@prod`,
  `kind:k8s`, `all`) at the same time: one row per cluster in
  `data.results` with `data.summary`, and a cluster that cannot be read
  fails alone (`PARTIAL_FAILURE`). One cluster gives the same output as
  before; commands that change a cluster stay on one.
- `komando cluster helm ls|status|history|values` read the Helm releases
  stored in a Kubernetes cluster, without the `helm` program: name,
  revision, status, chart and app version, the notes, every stored
  revision, and the values (`--all` with the chart's defaults,
  `--revision N` for an older one). It only reads; install and upgrade
  stay with helm.
- Storage conns for **Google Cloud Storage** (`gs://bucket/folder`, logged
  in like gcloud or with a service account key), **Azure Blob Storage**
  (`azblob://ACCOUNT@container/folder`, with the account key or a SAS
  token) and **WebDAV** (`webdavs://user@host/path`: Nextcloud, ownCloud, a
  NAS). `storage ls`, `cat`, `upload`, `download`, `rm`, `sync` and
  `conn test` work on them as on S3, also through `--via`. `storage link`
  makes a signed link for Google Cloud (with a service account key) and
  Azure (with the account key). Big Azure uploads go up in blocks, with no
  temporary file; WebDAV makes missing folders. Emulators take
  `?endpoint=URL`.
- **MongoDB** conns (`mongodb://`, `mongodb+srv://`, replica sets, Atlas):
  `db query` takes a command document in JSON (`{"find": ...}`,
  `{"aggregate": ...}`, `{"update": ...}`), rated before it is sent like
  SQL, so changes need `--write`, and an empty-filter delete, `drop`, user
  changes and `shutdown` need `--allow-dangerous`. `db schema` lists
  collections, or the fields of a sample with their types; `db info` gives
  version, role and sizes; `conn test` logs in. Every member is reached
  through `--via`, and `?ca=` checks a private CA.
- Redis Cluster and Sentinel: a `redis://` or `rediss://` conn with
  `?cluster=1` works on the whole cluster from one node's address
  (`cache keys` scans every master, `cache info` adds them up with the
  cluster's state), and one with `?sentinel=MASTER` reaches the master the
  Sentinels name (more Sentinels with `sentinels=`, their login with
  `sentinel_auth=same`). Valkey, ElastiCache and MemoryDB clusters work
  the same way.
- Databases and caches whose certificate comes from a private CA (a
  company CA, Amazon RDS, Azure, ElastiCache) are checked against it:
  `?ca=secret:NAME` on a `postgres://`, `mysql://`, `rediss://` or
  `memcacheds://` conn names the vault secret that holds the CA (PEM), as
  registries already allowed. The check is a full one (signed by that CA,
  naming the server), also with `sslmode=require`, and a Postgres conn then
  never goes on without TLS.
- `komando` alone opens a menu for a person at a terminal: choose Shell,
  Test, Facts, Database, VPN, List, Audit or Doctor with the arrow keys and
  Enter (`?` for help), then a server, conn or VPN from a list you can
  filter by typing. Only what has something to act on is shown; with no
  server yet, Add (and Import, when there is a `~/.ssh/config`) comes
  first. It runs the same command you could type and shows it first. AI
  agents, scripts and `komando` with any flag still get the first steps
  (or, when piped, a `USAGE` error).
- **`komando update`** replaces komando with the newest release, checked
  against the release's `checksums.txt` like the install line, and tried
  once before it takes the old program's place. `komando update --dry-run`
  says whether there is a newer version; `komando update v0.6.0` installs
  that version (going back needs a person's yes, since an older komando may
  lack safety checks; without a VERSION it never goes back). In a folder
  only root may change it stops with `NOT_WRITABLE` and gives the `sudo`
  command to run. Run as you, the update goes into the audit log; as root
  it writes nothing in `~/.komando`, so no file there ends up belonging to
  root. It tries again when GitHub answers 5xx. A komando built from source
  is not replaced (`SOURCE_BUILD`).

### Changed

- `komando import` says `nothing to import from FILE` first when it adds
  nothing, and a note about a server it did add (such as a missing
  identity file) no longer reads `not imported:`. `import ssh-config` on a
  computer with no `~/.ssh/config` says so and shows how to add a server.
- The README, Settings, Safety and SECURITY.md now agree on how to protect
  the vault: `komando secret keychain` is the recommended setup (before or
  after the first secret), and `KOMANDO_VAULT_PASS` is optional. A new
  vault takes the passphrase at its first secret; setting the variable later
  does nothing to an existing vault (`komando secret passphrase` does), which
  the docs did not say.

### Fixed

- Behind a company proxy, Kubernetes clusters, registries and the
  AnyConnect, Fortinet, GlobalProtect, F5 and Pulse VPNs could not be
  reached: they ignored `HTTPS_PROXY`, while `kubectl` and `docker` use
  it. They now go through `HTTPS_PROXY` (`HTTP_PROXY` for `http://`)
  except what `NO_PROXY` names, like storage and the secret stores already
  did. That includes `cluster exec`, `cluster forward` and `cluster shell`,
  and a kubeconfig's `proxy-url` wins for its cluster. A target reached
  with `--via` still goes out through its path. See "Behind a company
  proxy" in [Private servers and tunnels](docs/features/tunnels.md).
- `komando db query --csv` and `--tsv` printed values an AI agent should
  not see: unlike the JSON and text output, they skipped the masking of
  secrets and vault values. They are masked the same way now.
- A `rediss://` conn reached through `--via` could not connect: the Redis
  client leaves TLS out when it is given its own dialer, so it spoke plain
  Redis to the TLS port. komando's dialer now adds TLS itself, checking
  each server's own name.
- `komando host import --overwrite` deleted an existing server when the
  imported copy with the same name was refused (for example, its `--via`
  host does not exist). The server it would have replaced now stays.
- `komando import dbeaver` told you to set a password with the conn's
  name from DBeaver, even when that name was taken and the conn was added
  as `shop-2`: following it pointed your existing `shop` conn at the new
  password. The note now names the conn as it was added, and only a
  connection that was added gets one.
- An encrypted `--identity` or `--key` with no passphrase ref failed with
  `KEY_PASSPHRASE_REQUIRED` even when ssh-agent (or the macOS Keychain)
  held it. komando now finds the agent's copy by its public key (from the
  key file, `PATH.pub` or the keychain) and offers it first, as OpenSSH
  does. The error stays (`KEY_PASSPHRASE_REQUIRED`, exit 2) when the agent
  does not hold the key, and its hint names commands that work:
  `ssh-add PATH`, or `komando secret set`, `komando key add ... --passphrase-ref`,
  then `komando host edit HOST --key NAME --unset identity` (for a `--key`
  key, `komando key edit` with its real name). Before, it named
  `komando key edit <name>`, which fails for an identity file.
- The stored password goes out at most once per login, and only to a
  hidden question that asks for a password. A question about a one-time
  code, token, OTP, passcode or verification, a shown question, or the
  password asked a second time gets no answer: the login stops with
  `AUTH_FAILED` (exit 4), and the message quotes the server's question,
  cleaned, for example `web1 asks "Verification code:" (two-factor login)`.
  The hint says to log in once at a terminal with the command
  `komando host ssh-command web1` prints. `komando shell` uses the same
  login.
- Clearer login hints; codes, exit codes and JSON fields are unchanged.
  `NO_AUTH` says `ssh-add ~/.ssh/id_ed25519` when that key is encrypted and
  the agent is empty, `ssh-add` when the agent is empty, and otherwise how
  to save a password (`komando secret set web1-pass`, then
  `komando host edit web1 --password-ref secret:web1-pass`); it says
  "start ssh-agent" only when `SSH_AUTH_SOCK` is not set. `AUTH_FAILED`
  no longer suggests `komando key deploy`, which logs in the same way and
  fails too; a password-only server is told how to store a changed
  password. The sudo hint names the server instead of a literal `<host>`.
- `HOSTKEY_MISMATCH` shows the full SHA256 fingerprint the server offers
  now, next to the pinned one. A person at a terminal gets a hint worded
  for them: if you rebuilt the server, compare the fingerprint with the one
  on its console, then run `komando host trust NAME --reset`. AI agents
  and scripts keep the hint that tells them to report it.
- Ctrl-C at a question ends it. Before, a `[y/N]` question or a hidden
  prompt went on waiting and Ctrl-C showed nothing. Now Ctrl-C at a
  `[y/N]` question or a typed name is a no (`cancelled: ...`, `nothing was
  changed`, exit 6), and at a hidden prompt (`secret set`, `secret check`,
  a VPN password) the command stops with `CANCELLED`, exit 1, with echo on
  again. Later questions in the same command are not asked. Ctrl-D at a
  `[y/N]` question is a no and ends the line.
- A paste of more than one line at a hidden prompt stores nothing. Before,
  only the first line was read and the shell ran the others as commands
  once komando ended, showing the secret and saving it in the shell's
  history. Now the other lines are thrown away and komando stops with a
  `USAGE` error (exit 2) that points to `komando secret set NAME < FILE`.
- VPN logins with komando's own clients (AnyConnect, Fortinet,
  GlobalProtect, F5, Pulse, OpenVPN, IPsec) ask the same way: Ctrl-C
  works, a paste of more than one line is refused, and the prompt text a
  VPN server sends keeps its lines but loses control characters. A Pulse
  realm or region choice shows numbered lines, takes the number or the
  name, and asks again after a typo (up to 3 times) instead of ending the
  login. The Pulse sign-in notice asks `Accept the sign-in notice? [y/N]`
  and takes y or yes in any case.

### Security

- **`--read-only` on a protected server or conn is now an allowlist, not a
  denylist.** Before, a protected target let any command komando did not
  recognise skip `--yes`, so an unknown program that changes things could
  pass. Now `--read-only` skips the confirmation only for commands komando
  knows read (`cat`, `ls`, `tail`, `df`, `ps`, `grep`, `journalctl` and
  `systemctl status`, `docker ps`/`logs`, `kubectl get`/`describe`, `find`
  without `-delete`/`-exec`, and the like); anything else takes the normal
  `--yes` path with a person's approval. Unprotected targets are unchanged.
  Affects `exec`, `script`, `job start` and read-only recipes.
- **An `--os-mode` OpenVPN profile is now rewritten into a canonical form
  and handed to `openvpn` on its input, never written to a file.** komando
  parses the `.ovpn`, refuses anything its checker and OpenVPN could read
  differently (backslash escapes, stray quotes, over-long lines, odd inline
  tags, control characters), and passes `openvpn` only the directives it
  checked, with `--script-security 1` on the command line so the root
  process runs no user programs. A profile komando accepted before may now
  be refused if it relies on one of those tricks.
- **`komando update` follows release redirects only while they stay on
  HTTPS**, so the download can never be pulled over plain HTTP.
- An AI agent that sends a secret somewhere needs `--yes`, and komando's
  window names the secret and the place (`SECRET_DESTINATION`, exit 6):
  `{{secret:NAME}}` in `fs write` and `fs replace`, `exec --env
  K=secret:NAME` and `job start --env`, `db user add` and `db user passwd`,
  and a password reference (`secret:`, `env:`, `file:`, ...) that `host
  add`, `host edit`, `conn add`, `conn edit`, `import csv` or another import
  attaches to a server or conn, or a server or conn with one that moves to
  another address, port, `--via` path or proxy command. Before, an agent
  could put a vault value on a server it controls, where it can come back
  in a form masking does not know. People and scripts are not asked. An
  agent's dry run reads no secret: it keeps `{{secret:NAME}}` as written.
- No password reference and no `{{secret:NAME}}` reads the approval code's
  key (`RESERVED_SECRET`), for anyone. Before, only the `secret` commands
  refused it.
- An AI agent that adds a conn whose URL turns its network protection down
  (`sslmode=disable`, `allow` or `prefer`; MySQL `tls=false`, `preferred`
  or `skip-verify`; `tls=false` or `tls=skip-verify` for a registry or
  FTPS; FTP `insecure=1`), or edits a conn so that it does (also
  `rediss://` to `redis://`), needs `--yes` and a person's yes
  (`SAFETY_SETTING`).
- An AI agent's command with a `KOMANDO_HOME` other than `~/.komando`
  needs `--yes` and a person's yes, every time (`SAFETY_SETTING`): in a new
  folder komando knew none of the protected servers, deny rules or host
  keys, and wrote the audit log elsewhere. A link to `~/.komando` counts as
  the usual folder. The guard (`komando guide install`) now also stops
  shell lines that set, export or unset `KOMANDO_HOME`.
- The vault key in the OS keychain is read with `/usr/bin/security` on
  macOS and with `secret-tool` from `/usr/bin`, `/bin` or `/usr/local/bin`
  on Linux, never through `PATH`, as the approval window's tools already
  were.
- `tunnel start` hands `KOMANDO_VAULT_PASS` to its background process on
  stdin instead of in its environment, where any program of the user could
  read it for as long as the tunnel runs.
- For an AI agent, audit records add `os_user` (the computer account, read
  from the system) and `actor_claimed: true` when the name comes from
  `KOMANDO_ACTOR`, which the agent's environment can set to anything.
  `komando audit -o text` shows such a line as `Claude Code (as NAME)`.
- `fs replace --regex` with `{{secret:NAME}}` writes a `$` in the secret
  as it is; before, `$1` in a password was read as a group.
- A vault value given to a remote command (`-e DB_PASS=secret:NAME`, or a
  server's `--env` with `secret:`) reaches the command on its input, not
  on its command line. Before, every user of the server could read it in
  `ps` while the command ran, and with `--sudo` it was written to sudo's
  log. Other values are unchanged. A vault value longer than 4000
  characters cannot go through `--pty` and is refused there. `job start`
  now writes the job's environment file from its input too; before, the
  values were on the command line while the job was set up.
- The first time komando trusts a server's SSH host key
  (`host_key_policy accept-new`, the default), it says so on stderr with
  the SHA256 fingerprint and how to compare it with the server's own, and
  writes it to the audit log (`host.key-pinned`). The servers page shows
  how to check keys before the first connection.
- IKEv1 (`l2tp`, `ipsec`) offers only AES with SHA-256 or SHA-1 and DH
  groups 14 and 19, and the server may only choose what was offered.
  Before, komando also offered 3DES and DH groups 2 and 5, and accepted a
  suite it had not offered. A server that only speaks those old ciphers
  now stops with an error whose hint names
  `komando vpn edit NAME --legacy-crypto`, which allows them for that VPN
  again (after the strong ones) and needs a person's yes. Cisco-style
  IPsec with a group name (aggressive mode) gets a warning in the session
  log and in `komando doctor`: anyone who sees that login can guess the
  group password offline.
- L2TP no longer sends your password with PAP when the server asks for
  it: komando asks for MS-CHAPv2 instead, and a server that insists on
  PAP stops with an error that says why.
  `komando vpn edit NAME --allow-pap` allows PAP for that VPN; it needs a
  person's yes.
  `komando doctor` lists VPNs with either setting on.
- komando's OpenVPN client wants the server's certificate to be marked for
  a server (serverAuth, or nsCertType server) even when the profile has no
  `remote-cert-tls server`, so another user's certificate from the same CA
  cannot pretend to be the server. A profile can name the server with
  `verify-x509-name` instead; the error shows the line to add. A profile
  without either check gets a warning in the session log.
- `komando doctor` explains why each database or cache conn without
  checked TLS is at risk (for example, the MySQL 8 login over a plain
  connection can be tricked into giving away the password) and prints the
  `komando conn edit NAME --url ...` line that adds `sslmode=verify-full`,
  `tls=true`, `rediss://` or `memcacheds://`. Saved conns keep working as
  they are. When TLS stops a connection, the hint names what to do and
  the weaker setting with its cost.

## [0.6.0] - 2026-11-08

### Highlights

- **Lists are sorted by name, as one list:** servers, conns and VPNs share
  one A-Z order in `list` and `test`, and lists a server sends (`fs ls`,
  `docker ps`, `registry ls` and more) are sorted too. Scripts that relied
  on servers coming first see a new order.

### Changed

- Lists are sorted by name, as one list. `list` (and `host`, `conn` and
  `vpn list`) and `test` put servers, conns and VPNs in one A-Z order
  instead of all servers first; the KIND column tells them apart.
  `recipe list` puts your saved recipes among the built-in ones (the
  category still says `saved`), `group list` shows groups and tags
  together, and `policy list` sorts the rules of each kind by ID. Lists a
  server sends in its own order are sorted too: `fs ls`, `storage ls` on
  SFTP and FTP, `user list`, `svc list`, `docker ps`, `docker stats`,
  `docker images` (docker puts the newest first) and `registry ls`. Lists
  without names keep their order: `job list` and `tunnel list` by start
  time, `cron list` as in the crontab.

## [0.5.0] - 2026-11-08

### Highlights

- **`?resolve=IP` for registry and S3 conns**, like `curl --resolve`: reach
  a registry whose public DNS is wrong or missing straight from your
  computer, without `--via` a server that has the right `/etc/hosts`.
- **Secrets named in a conn URL count as used** (`?ca=secret:NAME`):
  `secret rm` no longer deletes them, and `secret mv` and `export` follow.
- **`doctor` finds untidy conns:** a shared protected password, duplicate
  conns, and an unprotected conn of a protected server.
- **`sudo sh install.sh` installs komando owned by root.**

### Added

- Registry and S3 conns take `?resolve=IP` (or `IP:PORT`), like
  `curl --resolve`: komando connects to that address instead of the one DNS
  gives for the name. TLS keeps using the name in the URL, so
  `?ca=secret:NAME` and `?tls=skip-verify` work as they do without it. This
  helps when a registry's public DNS is wrong or missing: before, the only
  way was `--via` a server whose `/etc/hosts` had the right address. With
  `--via`, the last server connects to the IP. `komando test` and `tunnel`
  use it too, and so does `cert check` for an S3 conn. A value that is not
  an IP address is refused with `USAGE`.

### Changed

- `doctor` warns about conns worth a look: an unprotected conn that shares
  its password secret with a protected server or conn, two conns with the
  same kind, URL and `--via`, and an unprotected conn with the label
  `host=SERVER` of a protected server. Each warning says the command that
  fixes it.
- `host show @group` (or another selector where one name is expected) says
  that the command takes one name and points at `komando list @group` and
  `komando export @group`, instead of a bare "not found".

### Fixed

- A secret that only a conn URL names, such as a registry's
  `?ca=secret:NAME`, counts as used: `secret list` shows the conn under
  `used_by`, `secret rm` refuses it (`SECRET_IN_USE`), `secret mv` changes
  the URL too, `export` lists it in `secrets_needed`, and `doctor` warns
  when it is not in the vault. Before, `secret rm` deleted it and broke the
  conn, and `secret mv` left the URL on the old name.
- A database that times out in the checks right after connecting (a slow
  VPN) said `connecting to  timed out`, without the address. The message
  names the address, and the `--via` path when there is one:
  `connecting to 10.0.0.5:5432 via office-vpn timed out`.
- `sudo sh install.sh` installed komando owned by uid 1001, the user that
  built the release, instead of root. It now extracts with
  `--no-same-owner`. If you installed with sudo, fix the owner once:
  `sudo chown root:wheel /usr/local/bin/komando` (Linux: `root:root`).

## [0.4.0] - 2026-11-07

### Highlights

- **Clearer for people at a terminal:** `komando` alone shows three first
  steps instead of the full help, typos get "did you mean", and results
  of a change say what happened ("added web2") instead of a list of fields.
- **FTP and FTPS keep going** when the server drops a connection in the
  middle of a command: komando logs in again once and repeats it.
- **For scripts and agents:** piped `komando` alone, or a group such as
  `komando db` without its sub-command, now fails with `USAGE` (exit 2),
  and `komando test` on one target gives that target's own error code.
- **BREAKING exit codes:** `NO_AUTH` exits 4 (was 2) and
  `SECRET_UNRESOLVED` exits 3 everywhere; scripts that check them must be
  updated.

### Added

- Release archives include `THIRD_PARTY_LICENSES`: the license texts and
  NOTICE files of the Go modules and the Go standard library built into
  komando (`make licenses` writes it alone).
- `install.sh` installs one version with `KOMANDO_VERSION=vX.Y.Z`.
- The README has Update, Uninstall and "Something wrong?" sections, and
  says how to protect the vault key (`komando secret keychain`).
- The docs say how to get the AI agent seatbelts (secrets hidden in output,
  a person allows `--yes`) for agents komando does not know by name: set
  `KOMANDO_AGENT=1` in the agent's environment.

### Changed

- **BREAKING: exit codes.** Scripts and agents that check komando's exit
  codes must be updated. `NO_AUTH` (a server with no key, identity or password) now
  exits 4 like `AUTH_FAILED`, not 2. `SECRET_UNRESOLVED` (a password
  reference that cannot be read) exits 3 everywhere; it was 2 for servers
  and 1 for conns and registry CAs. The agent guide's error table now says
  `PARTIAL_FAILURE` exits with the worst code among the failed servers.
- `komando` with no arguments prints the first steps; `komando --help`
  still lists every command.
- A mistyped command or flag says what was meant, on one line:
  `unknown command "exce"; did you mean exec?`,
  `unknown flag: --tiemout; did you mean --timeout?`. The hint points at
  the help of the command meant.
- A usage error without its own hint now shows the command's example and
  its `--help`, instead of the same hint for every command.
- Text output of a change starts with what happened (`added web2`,
  `changed web2`, `web2: nothing to change`, `would add web2 (dry run)`),
  then the record without its timestamps. Records show `name` first, and
  times in local time with the zone instead of UTC RFC3339. JSON is
  unchanged.
- Counts read as words: "1 server", "3 servers", "both failed",
  "all 5 failed", instead of "server(s)" and "2 of 2 failed".
- `komando test` on one target fails with that target's own error code
  (for example `CONNECTION_REFUSED`), as `exec` already did, instead of
  `PARTIAL_FAILURE`.
- `komando list` shows `yes` or `-` under PROTECTED instead of
  `true`/`false`.
- Every command has at least one example in `--help`; a test checks that
  each example uses commands and flags that exist.
- `komando --help` fits 80 columns: shorter one-line descriptions (the
  full sentence stays in the command's own `--help`) and shorter global
  flag texts.
- A sub-command's `--help` lists the four global flags that matter
  (`--dry-run`, `-o`, `--timeout`, `--yes`) instead of all eleven;
  `komando --help` still lists every one.
- `config set` says what changed: `parallel: 10 → 5`, or
  `parallel: already 5`. JSON is unchanged.
- `policy list -o text` is a table of what each rule stops, with the note
  that the rules are guardrails, not a security boundary; the regular
  expressions stay in `-o json`.
- Piped (JSON) output for `komando` alone, or a group such as `komando db`
  without its sub-command, is a `USAGE` envelope (exit 2) that names the
  sub-commands, instead of help text. In a terminal nothing changed.
- Hints that were questions now say what to do: a refused SSH connection
  suggests checking sshd and `komando host show NAME`.

### Fixed

- `komando export -o text` showed `secrets_needed: [hidden]` for an empty
  list: names of secrets and `-` are not secret values.
- FTP and FTPS (`storage`, `upload`, `download`, `sync` on an `ftp://` or
  `ftps://` conn): when the server drops a connection in the middle of a
  command (EOF, reset), komando logs in again once and repeats the command,
  instead of stopping with `STORAGE_CONNECT`. It never repeats after an FTP
  error reply, a TLS error or a timeout, nor a download that already wrote
  bytes, nor an upload from a source that cannot start over (a pipe). A
  `rm` whose repeat finds the file gone counts as done.
- `install.sh` no longer installs into `~/.local/bin` when
  `KOMANDO_INSTALL_DIR` is set but cannot be written: it creates the
  folder, or stops with a message.

### Security

- Downloads by an AI agent (`download`, `sync`, `storage download`, also
  to stdout) save text files the way `fs cat` shows them, with secret
  values as `[hidden]`. Before, they gave the agent the real file.
- `upload` and `sync` refuse a file that still holds `[hidden]` or
  `[secret:NAME]`, as `fs write` does, so a masked copy never replaces the
  real values.
- `fs cat` and `fs replace` now hide Redis passwords (`requirepass`,
  `masterauth`, ACL rules) as other output does. Before, `fs replace`
  could confirm a guessed password and `fs cat` returned the file's hash.
- `exec --read-only` checks the SQL in `psql -c`, `mysql -e` and SQL fed in
  with `--stdin-file` (the same rules as `db query`), and the commands in
  `redis-cli`, `valkey-cli` and `keydb-cli` (the same as `cache run`). It
  also catches `sort -o`, `uniq IN OUT`, `split`, `openssl -out`, `date -s`,
  `hostname NAME`, `dmesg -C` and `less +CMD`.
- The danger check now stops `bash --rcfile FILE -c ...`, `ufw --force
  reset`, `iptables -P INPUT DROP`, `cp`, `mv`, `tee`, `truncate` or `dd`
  onto `/etc/passwd`, `/etc/shadow` or `/etc/sudoers`, `echo '...' | sh`
  (the text is checked like `sh -c`) and `base64 -d | sh`.
- `secret set` checks that `KOMANDO_VAULT_PASS` opens the secrets already
  stored; a mistyped passphrase no longer saves a secret under a second key.
  A missing `vault.key` is no longer replaced by a new one while secrets
  need it: komando asks you to restore it.

## [0.3.1] - 2026-11-07

### Highlights

- **Rebuilt a group of servers?** `komando host trust @group --reset --yes`
  accepts all their new keys after one yes, instead of one per server.
- **New servers that are still starting:** `komando test @new --wait 5m`
  waits until they answer, instead of a sleep loop.
- **AI agents read output more simply:** the guide tells them to use `-o
  text` when they only want to read what a command printed.

### Added

- `komando host trust TARGET` takes many servers (`@group`, `tag:`,
  `'web*'`, `a,b`): after a rebuild of a whole group, `--reset` replaces
  every changed key after ONE yes that names each server with its new
  fingerprint, instead of one yes per server. `data.results` has each
  server's `fingerprint` and `old_fingerprints`. A changed key is still
  refused without `--reset`; `host trust NAME` answers as before.

- `komando test TARGET --wait 5m` waits for new servers: it tests again
  every few seconds until every target passes or the time is up (right
  after creating or rebuilding cloud servers, instead of a sleep loop).
  It does not wait out a changed host key or a refused login: those fail at
  once. `data.waited_ms` says how long it waited.

### Changed

- `komando host rm` says which servers' pinned host keys it keeps
  (`host_keys_kept`, `note`): a server added again at the same address must
  show the same key, so `rm` plus `add` is no way around
  `HOSTKEY_MISMATCH`.

- The agent guide (`komando guide`), the skill and the output docs say
  when to use `-o text`: to read a command's output, instead of pulling
  `stdout` out of the JSON. JSON stays the default for branching on each
  server's exit code or error.

### Fixed

- `--help` examples for `cluster` commands now use `--namespace`; `-n` is
  `--limit` in komando, so the old examples failed when copied. `import
  --help` no longer shows "(default -)", and `komando --help` and `conn
  --help` now say that clusters and registries are conns too.

## [0.3.0] - 2026-11-07

### Highlights

- **New license.** komando is now under the AGPL-3.0, with a commercial
  license for closed-source use. It stays free to use for any purpose.
- **More VPNs built in.** L2TP/IPsec, Cisco-style IPsec (XAUTH) and IKEv2
  work without strongSwan, OS VPN settings or admin rights.
- **Patch rounds.** `pkg security` installs only security updates, one
  server at a time, and checks each server before and after. `cert check`
  shows when certificates expire, `docker prune` previews what it would
  delete, and `reboot` restarts servers one at a time and waits for them.
- **Safer for AI agents.** A full security review brought fixes for SQL,
  database restores, Redis passwords, clusters and `--read-only`.
- **Easier inventory.** Rename servers, conns, VPNs and secrets (`mv`),
  import servers from a spreadsheet (`import csv`) and edit many at once.

### Changed

- **License: komando is now under the GNU Affero General Public License
  v3.0 (AGPL-3.0)** instead of MIT. You can still use it for free, for any
  purpose. If you change komando and give it to others, or let them use it
  over a network, you must share your version's source code under the same
  license. A [commercial license](COMMERCIAL-LICENSE.md) is available for
  closed-source use. Contributors now sign a short
  [Contributor License Agreement](CLA.md) once. v0.1.0 and v0.2.0 stay
  under MIT.

- The built-in recipes `cert-expiry`, `certbot-certs` and `docker-prune`
  are gone: `komando cert check` and `komando docker prune` do the same
  better (`docker-prune` skipped the preview and the `--allow-dangerous`
  question). Running one of those names says which command to use; a
  saved recipe of the same name still works.

- `komando facts` and `komando pkg security` read the server's state with
  the same check, so they agree: `facts` now also sees a newer kernel that
  needrestart reports (`reboot_required`, `reboot_packages: ["kernel"]`)
  and, on dnf/yum servers, the services that need a restart (from
  `needs-restarting -s`). `pkg security` now has `os_support` and warns on
  an OS past end of life, where an empty list does not mean the server is
  safe.

- `komando vpn status`: `last_end` now says when the session ended and how
  long it ran. When an L2TP server ends the session, it also says how long
  the link had no traffic (a server idle timeout?), and the log shows the
  server's own reason (StopCCN/CDN result, LCP Terminate text).

- Servers behind the same jump hosts share one connection to them within a
  command: `exec -P 10` through a bastion logs in to it once (OpenSSH's
  ControlMaster), staying under its `MaxStartups`. A broken shared path is
  opened again once.

- A protected server stays protected under another name: before any
  change, komando also compares the IP addresses names resolve to on this
  computer, so `db.internal` is the protected `10.0.0.5` (hosts and conns,
  same port). Names only a jump host knows are compared as text.

- A person is asked about a safety change (for example a recipe replaced by
  a read-only one) before komando locks its state file, so other komando
  commands do not wait for the answer.

- `cache run` text output shows map entries as `name: value` (was `name =>
  value`). For agents, a RESP2 `HGETALL` reply is shown as a map, so
  secret-named fields are hidden as over RESP3.

- When a script command times out, the hint no longer says to raise
  `--timeout`; it says the script may still be running and names `SCRIPT
  KILL` or `FUNCTION KILL`.

- Approval window: line breaks, tabs, control characters, long runs of
  spaces, blank-drawing letters (U+3164 ...) and combining marks show as
  $'...' escapes, so multi-line `fs replace` edits on protected hosts can be
  approved; bidi and zero-width characters are still refused.

- Error and hint lines show colour/conceal escapes and carriage returns as
  \e and \r.

- A saved read-only recipe that no longer passes the read-only check runs as
  a change (protected servers ask for --yes) instead of being blocked.

- `--backup` copies add up next to the file; clean them up with `fs rm`.

- An SSH connection that stops answering (for example a VPN that dropped
  silently) is closed after about a minute without an answer, so commands
  report the loss instead of waiting until `--timeout`.

- `host edit --rename` and `conn edit --rename` are deprecated in favour of
  `host mv` / `conn mv`.

- The approval window for protected changes says which protected entries the
  command touches.

- Imports refuse a server whose `key` is not in komando's keychain.

- The hidden `secret set` prompt drops text typed or pasted before it
  appeared, and says so; it strips bracketed-paste marks.

- `komando facts` reports values it cannot read as `null` instead of
  `0`/`false`: `reboot_required` is `null` where it cannot be checked, and
  an unsupported OS shows `updates.security: null` with a warning.

### Added

- `komando schema` says what each command does: `kind` is `read`,
  `change` or `depends`, and `kind_note` says on what for `depends`
  (`exec` changes things unless `--read-only`, `db query` only reads
  unless `--write`). Agents can see it before they run a command.

- `make e2e` also runs `facts`, `pkg security` (with a real `--apply`) and
  `pkg` against Rocky Linux 9 (dnf) and Amazon Linux 2 (yum) servers, and
  compares every answer with the native `dnf`/`yum`/`rpm` on the same
  server (`test/e2e/rhel`, `test/e2e/checks/rhel.sh`).

- Registry conns (`registry://`, `oci://`) take TLS options:
  `?ca=secret:NAME` trusts a private CA (PEM in the vault), or pins the
  registry's own certificate when the CA is not at hand, and keeps the
  certificate check on; `?tls=skip-verify` uses HTTPS without the check
  (like Docker's `insecure-registries`; `komando doctor` warns about it,
  also with `--via`). A refused certificate is now `REGISTRY_TLS` (not
  `REGISTRY_UNREACHABLE`), with a hint that names `ca=` first. Unknown
  registry URL options and `tls=` values are refused instead of ignored.
  With `--via`, the last server looks the registry's name up (its
  `/etc/hosts` applies); the certificate check and `Host` stay on the name.

- L2TP/IPsec (`l2tp`), Cisco-style IPsec with a group name and XAUTH login
  (`ipsec`, also `cisco`) and IKEv2 (`ikev2`, pre-shared key or EAP-MSCHAPv2
  login with the server's certificate checked) are built into komando:
  komando's own IKEv1, IKEv2, ESP-in-UDP, L2TP and PPP, so they need no
  strongSwan, no OS VPN settings and no admin rights, and the computer's
  network stays as it is. New `vpn add`/`vpn edit` flags: `--server`,
  `--psk-ref`, `--id`, `--remote-id`, `--ca`. Tested against strongSwan 5.9
  and xl2tpd, rekeys included (`make e2e-ipsec`). Before, these kinds were
  only a name for `system`.

- `komando vpn status` shows why a VPN's last session ended (`last_end`),
  and for `l2tp`, `ipsec` and `ikev2` the last lines of its log
  (`last_log`), so an agent can tell why without reading `~/.komando`.

- `db dump --on HOST` runs pg_dump or mysqldump on a server you choose,
  whatever the conn's own path (for example a conn through a VPN), so
  `--format custom` works there too. It runs at low priority (nice, ionice),
  keeps the password in the tool's environment and streams the backup back
  over SSH; `runs_on` and `low_priority` in the answer and the audit say
  where and how. `db restore --on HOST` loads a PostgreSQL archive with
  pg_restore there, behind the same `--allow-dangerous` gate.

- New errors with hints: `TOOL_TOO_OLD` (pg_dump older than the database
  server, or pg_restore older than the archive) and `CONN_UNREACHABLE` (the
  tool cannot reach the database from that server, with how to add a
  127.0.0.1 conn through it).

- `komando reboot TARGET`: reboots servers one at a time, waits for each to
  answer again and checks it really started anew (boot id). A server that
  does not come back stops the rest. Destructive: needs `--allow-dangerous`.

- `komando registry prune CONN REPO --keep N [--older-than 30d] [--match RE]`:
  deletes old images, never one a kept tag points at (`latest` always
  stays). `registry inspect` now gives a multi-platform image's build date.

- `komando import aws`: one S3 storage conn per bucket of each profile in
  `~/.aws/config` (and the credentials file). The conns use the profile, so
  no key is copied and SSO or roles keep working.

- memcached conns (`memcached://`, `memcacheds://` for TLS, the text
  protocol's login): `cache get`, `set`, `rm`, `keys`, `info` and `run` work
  like they do for Redis, with the same safety rules (`flush_all` needs
  `--allow-dangerous`). komando speaks the protocol itself.

- `komando db user ls|add|passwd|rm`, `db grant`, `db revoke` and `db grants`
  for PostgreSQL and MySQL/MariaDB. Passwords come from a secret reference
  and are never shown or audited; PostgreSQL gets a SCRAM-SHA-256 verifier
  computed by komando, so the password never reaches the server.

- `komando config set audit_syslog tls://HOST:6514` (or `udp://`, `tcp://`):
  each audit record also goes to a log server or SIEM, as RFC 5424 syslog.
  Changing it needs `--yes`.

- `komando secret keychain`: the vault key moves from `vault.key` into the
  OS keychain (macOS keychain, Linux Secret Service), so a backup of
  `~/.komando` no longer opens the vault. `--off --yes` moves it back.
  `doctor` names it.

- `komando config approval-code`: komando's "Allow once" window then also
  asks for the 6-digit code from your authenticator app (TOTP), a second
  factor for an AI agent's `--yes`, `--allow-dangerous` and `--reveal`. Only a
  person at a terminal can turn it on; turning it off needs that code too.

- The guard that keeps AI agents away from secret files on this computer now
  also works for Cursor, Gemini CLI and Codex: `komando guide install` adds
  it to `.cursor/hooks.json`, `.gemini/settings.json` and `.codex/hooks.json`
  when those folders exist (Codex asks you to approve it once in `/hooks`).

- `komando svc daemon-reload TARGET`: reloads unit files after you write
  one, and names units that still need a reload.

- `komando job wait` takes several job IDs and waits for all of them, with
  one result per job and a summary; the exit code is the worst one.

- `komando job start --sudo` works on servers whose sudo needs a password
  (`--sudo-ref`). The password is sent as input, never on a command line,
  and the job deletes it as soon as it starts.

- `komando host mv OLD NEW`, `conn mv` and `vpn mv` rename an entry and
  update every reference to it (`--via` paths, jobs, tunnels) in one step;
  renaming a protected entry needs `--yes`.

- `komando host edit` takes several names and targets (`host edit @ubuntu
  --sudo-ref secret:ubuntu-sudo`); one `--yes` and one approval window,
  which lists every server and which are protected, cover the whole command.

- `komando import csv FILE` adds servers from a spreadsheet; every row is
  checked before anything is written.

- `komando secret mv OLD NEW` renames a secret and every server, conn, key
  and VPN reference to it, without showing the value. `secret cp OLD NEW`
  copies one inside the vault.

- `komando secret check NAME`: a person compares a value with the stored one
  without seeing either; refused for AI agents (`NEEDS_PERSON`).

- `secret set` and `secret get` warn when a value starts or ends with a
  space or tab, ends with a line break, or holds control characters.

- `komando facts` reports whether the OS still gets security updates
  (`os_support`: supported, extended through Ubuntu Pro ESM or Debian LTS,
  unsupported, unknown), pending and security updates with the package index
  age, reboot-required packages, services needing a restart, passwordless
  sudo, Docker version, Swarm role and running containers, PM2 daemons and
  apps, listening ports with their programs, hand-made systemd units, and
  `warnings`. It also has a short text view.

- `komando pkg security TARGET` lists pending security updates with each
  server's state (running containers, failed units, pending updates, reboot
  required, services needing a restart). `--apply` installs only security
  updates, one server at a time, compares each server before and after and
  stops the round on an unexpected change (`UNEXPECTED_CHANGE`;
  `--keep-going` to continue). It never reboots.

- `komando cert check TARGET...` shows when TLS certificates expire: on
  servers (certbot, nginx, haproxy, apache, `--path`; only the certificate
  part of a file is read) and for websites and TLS conns (directly or
  through `--via`, with a trust check), plus certbot renewal state. `--warn`
  (default 30d) flags certificates expiring soon; problems exit 1 with
  `CERT_PROBLEMS`.

- `komando docker prune TARGET` with `--older-than`, `--all` and
  `--volumes`. `--dry-run` lists the stopped containers, images, volumes and
  build cache that would be removed, with sizes and a total. The real run
  needs `--allow-dangerous`.

- komando's own restore of plain SQL skips pg_dump 17's `SET
  transaction_timeout` on PostgreSQL servers older than 17, so such backups
  restore there.

### Security

- Updated `github.com/klauspost/compress` to v1.20.2 (GO-2026-6865: a
  crafted compressed frame could crash komando during a VPN session).

Fixes from the full security review of 2026-11-04.

- komando db refuses SET NAMES, SET CHARACTER SET, client_encoding and
  character_set_client changes (SQL_STRING_RULES), and refuses a connection
  whose client character set can hide a backslash (SJIS, GBK, BIG5, GB18030,
  UHC, JOHAB, cp932).

- MySQL `--` before 0x7f is read as a comment the way the server reads it;
  `--` before a non-ASCII byte is refused (SQL_HIDDEN_CODE).

- In MySQL only known transactional statements (SELECT, INSERT, UPDATE,
  DELETE, REPLACE, WITH, VALUES, TABLE, SHOW, DESCRIBE, EXPLAIN, HELP, USE,
  DO, HANDLER, SET) run inside komando's transaction; everything else,
  including CHECK TABLE, CACHE INDEX, replication START/STOP/CHANGE, IMPORT
  TABLE, CLONE, BACKUP STAGE and XA, must be sent alone, needs --write, and
  a dry run reports it without running it.

- A dry run no longer executes statements a rollback does not undo (ending
  sessions, COPY ... PROGRAM, server files, dblink, server config,
  set_config with a computed name, DO, CALL, EXECUTE, setval); they are
  reported as skipped.

- `db query --write --dry-run` runs nothing when the real run would be
  blocked (destructive SQL without --allow-dangerous, or a protected conn
  without --yes); it shows the plan and meta.would_be_blocked.

- Postgres COMMIT AND CHAIN hidden from the classifier is now caught
  (SQL_TX_CONTROL) before the next statement runs.

- `db dump --table` refuses values that start with `-`; mysqldump read them
  as options on the --via server (e.g. --result-file could overwrite files).

- `db restore` names SQL that runs programs, touches server files, changes
  server config or privileges, or cannot be inspected (sql-program,
  sql-server-file, sql-server-config, sql-privileges, sql-opaque,
  sql-remote, sql-kill) next to db-restore in the approval and
  POLICY_BLOCKED, with the line where each first appears.

- `cache run` now needs `--write --allow-dangerous` for read-only scripts
  (`EVAL_RO`, `EVALSHA_RO`, `FCALL_RO`) and for module code (`TFCALL`,
  `TFCALLASYNC`, `RG.PYEXECUTE`, `RG.TRIGGER`, `RG.TRIGGERONKEY`), because
  each can block the server or run code komando cannot inspect.

- `FUNCTION LOAD REPLACE`, `TFUNCTION LOAD REPLACE`, `TFUNCTION DELETE` and
  `RG.UNREGISTER` count as `redis-scripts` (destructive).

- AI agents no longer see Redis passwords: `CONFIG GET` and `SENTINEL CONFIG
  GET` values of requirepass, masterauth, primaryauth, tls-*-pass and
  sentinel-pass, and the password hashes in `ACL LIST` and `ACL GETUSER`,
  show as `[hidden]`, also when the password is a word like `yes`.

- Output masking now also hides Redis passwords written the Redis way
  (`requirepass pw`, `sentinel auth-pass mymaster pw`, ACL `>pw` and
  `#hash`), as seen through `fs read` of redis.conf or users.acl, grep, or
  redis-cli `CONFIG GET` over `exec`.

- Cluster run: an AI agent's `get secret -o yaml|json` is a read, since the
  values show as hidden; it no longer asks the person for --allow-dangerous.

- Cluster run / cluster apply: a file that still holds a value komando hid
  ([hidden], (hidden)) is refused with HIDDEN_VALUE before anything is sent,
  so a get-edit-apply round trip cannot overwrite a password with the
  marker.

- Cluster run: an AI agent cannot send komando's own folder, or files that
  are secrets by name (unless --reveal), to the cluster through -f,
  --from-file or cp (SENSITIVE_FILE).

- Cluster run: an empty object name (delete pod/, delete pod "",
  metadata.name: "") is refused instead of deleting the whole collection.

- Cluster run cp: never writes into a .git folder; copied files keep their
  exec bit like kubectl cp, never setuid, setgid or world-write.

- Swarm: --mount read as CSV, host-folder volumes (volume-opt device, volume
  create --opt device=), --volumes-from, --network/--net host, --cgroupns
  host, --pid container:, --device-cgroup-rule, credential folders even
  read-only (/root, /home/USER, .ssh, /etc/kubernetes, /var/lib/kubelet,
  shadow, etcd, rancher), /opt and /var/spool, and plugin create|enable|set
  now need --allow-dangerous.

- Kubeconfig login programs: a kubeconfig a person imported (or allowed) is
  trusted for its program and server, so agents no longer get a window on
  every read; a change in the vault asks again.

- Approval window: names the program a kubeconfig login runs, and a yes
  given for something else does not cover it.

- Cluster exec/shell/forward --dry-run report the login-program stop the
  real run would meet.

- komando counts an AI agent's variable as present even when it is empty,
  and the agent guard now also stops env flag clusters, GNU long-option
  prefixes and env -S, exec -c, read/printf -v/mapfile/for loops that set
  the variables, brace/glob/$-computed names, statements that start with a
  keyword, more wrappers (timeout, setsid, stdbuf, chrt, busybox, ...),
  `sudo komando` without -E, `bash -lc`/`sh -ec` scripts and quoted heredocs
  fed to a shell.

- An AI agent's local reads, file: references and the guard catch
  ~/.KOMANDO-style case variants on macOS and Windows, hard links to
  komando's data or private keys, and any /proc/.../environ path (refused
  even with --reveal).

- `komando sync` of a folder checks each file for an AI agent, as `cp -r`
  does; komando's own data is never uploaded, even with --reveal.

- The agent guard stops recursive reads and archives of a folder that holds
  komando's data (grep -r ~, rg, tar -C ~, zip -r, cp -r, find -exec, the
  Grep tool in the home folder), follows tar/git -C, sees through $(echo
  ...) substitutions and expands ~user.

- `--read-only` now reads shell scripts the way bash does: options after
  `-c` (`bash -c -- '...'`), arguments a script gets (`sh -c '...' "$0"`),
  comments, here-documents, `case` inside `$( )` and brace expansion
  (`{rm,-rf,/x}`). A command it cannot read (an unclosed quote) is refused.

- Under `--read-only`, an argument that is only known when the command runs
  (`find /data $X`, `xargs find`) is refused for commands whose arguments
  decide what they do. `-e` values are filled in first.

- Under `--read-only`, setting a variable that runs code (BASH_ENV, PS4,
  PROMPT_COMMAND, LD_PRELOAD, PAGER, GIT_SSH_COMMAND, BASH_FUNC_*) is
  refused, whether inline, through env or sudo, through export, or with -e.

- `--read-only` now catches more commands that write or run commands: git
  -c, sed e/w, gawk --source and @f(), tar --checkpoint-action and extract,
  psql \! and \o, mysql system and tee, vim, script, sg, hash -p,
  gzip/xz/unzip/patch on files, curl -o/-O/-d/-X POST, wget saving a file,
  sqlite3, crontab FILE, docker/kubectl exec, and git branch/tag/config
  changes. Subcommands are now found after global options (`kubectl -n prod
  delete`, `iptables -t nat -A`). New wrappers: chrt, taskset, numactl,
  prlimit, fakeroot, faketime.

- `pkg rm` now treats openssh-server.x86_64, sudo.noarch and other name.arch
  spellings (also after a version) as essential, and apt patterns such as
  `openssh.server` that would pick an essential package. All need
  --allow-dangerous.

- Package names may no longer end in '-' (apt reads it as 'remove this
  package', even for `pkg install` and `pkg upgrade`) or '.'; a local
  package file gets a message pointing to `komando upload` + `komando exec`.

- On apt servers, `pkg rm` of a package whose removal would take an
  essential package with it (libssl3 takes openssh-server) now stops with
  POLICY_BLOCKED before anything is removed. Other package managers are not
  checked this way yet (known gap).

- An AI agent's `--dry-run --reveal` no longer shows hidden values; a dry
  run always keeps masking on and reports `REVEAL_NEEDS_PERSON` in
  `meta.would_be_blocked`.

- `fs replace` refuses (HIDDEN_VALUE) an agent's edit that would uncover a
  hidden value, such as renaming `DB_PASSWORD=` or cutting off `postgres://`
  or `Bearer `.

- For AI agents, `fs replace`, `fs write --if-changed` and `would_change` no
  longer reveal whether new text equals a hidden value, and `fs cat`/`fs
  replace`/`fs write` leave out the sha256 of a file with hidden values.

- `fs cat --head/--tail` masks the whole file before cutting it; the end of
  a private key without its BEGIN line is hidden too.

- VPN (OpenVPN): verify-x509-name now compares the server certificate's
  subject attribute by attribute. A crafted value such as O="Corp, CN=vpn"
  or CN="vpn " can no longer pass as the pinned server.

- VPN (OpenVPN): remote-cert-ku accepts the 0x prefix, as OpenVPN does.
  remote-cert-eku accepts the IPsec usage names (IPSec End System, IPSec
  Tunnel, IPSec User).

- VPN (OpenVPN): a client-side rekey no longer cuts off a renegotiation the
  server already started, which could drop the session.

- VPN: only SOCKS clients that log in keep a VPN session from going idle.
  Running out of file descriptors no longer ends the session.

### Removed

- `op://` no longer falls back to the closed-source `op` CLI, as announced
  in 0.2.0: it reads 1Password Connect only. Without Connect it says so and
  names the alternatives (`bw://`, `kdbx:`, a komando secret).

### Fixed

- `komando vpn up` printed the session's local SOCKS password; it now shows
  `[hidden]`.

- `komando db dump` works again on PostgreSQL 12 and 13: it no longer reads
  catalog columns that only newer servers have (`prosqlbody`, `tgparentid`).

- The Bitwarden device id file (`bitwarden-device`) is kept in
  `KOMANDO_HOME`, like every other state file, instead of always in
  `~/.komando`.

- The Postgres read-only session setting falls back for any pooler that
  rejects the startup parameter (SQLSTATE 08P01), not only PgBouncer's
  wording.

- `db restore` no longer hangs (PostgreSQL) or fails with 'Query was empty'
  (MySQL) when the last statement has no trailing `;`.

- `db restore` no longer refuses backups whose data or comments mention
  NO_BACKSLASH_ESCAPES or standard_conforming_strings, MySQL routines with a
  line starting with a column such as `source`, names ending in a backslash
  in backticks, or non-Latin PostgreSQL dollar-quote tags.

- `db restore` refuses computed changes to standard_conforming_strings
  (set_config) and sql_mode (CONCAT, variables), and DELIMITER lines it
  cannot follow; the check and the restore now read DELIMITER the same way.

- MySQL restore no longer sends a comment-only chunk in front of the next
  statement on the same line.

- Dry-run and result `runs_on` say `local` when komando itself runs the dump
  or restore through the --via path.

- The agent guard no longer treats quoted regexes and sed scripts as file
  globs (`grep -o '.*' f`, `sed 's/.*//' f`), no longer checks find's -name
  patterns, and allows `du -sh ~/*/*`.

- `komando import kubeconfig|pgpass|mycnf|env|docker` works for AI agents
  again (the secrets go into the vault, which agents never see).

- `--dry-run --host-key-policy off` keeps the policy for people and scripts;
  only an AI agent's preview connects with identity checks on.

- Read-only shell scripts with a `#!` line now work with `script
  --read-only` and `exec --read-only --stdin-file ... -- 'bash -s'`. Script
  arguments (`--arg`, `bash -s -- ARGS`) are refused under --read-only.

- `exec --read-only --stdin-file` treats input as data unless the command is
  a shell reading its input (`bash -s`). SQL sent to `psql` with `n > 5`
  works again; `\!` and `system` in that SQL are refused.

- `awk '/systemd/'`, `awk '/a|b/'`, `node -v`, `php -v`, `perl -v`, `bash
  --version` and `exec 2>&1` are read-only again.

- A streamed line that only mentions a private key header no longer holds
  `logs --follow` or `exec --stream` output for 256 KiB. After 16 KiB the
  output is released with the header hidden.

- Connecting through a jump host that never answers the channel open (or
  waits for a firewalled target) now fails with CONNECT_TIMEOUT after
  --connect-timeout, where it used to hang.

- A slow SSM or proxy-command start no longer makes the ssh-agent's
  signature time out into a false AUTH_FAILED.

- `host import` and `komando import` resolve each name once, in parallel and
  outside the inventory lock, when checking imported hosts against protected
  servers.

- `host trust --dry-run` says how the key would be fetched (directly,
  through a VPN, a proxy command or jump hosts).

- Re-running a secret rotation (`--old 'NAME=[hidden]' --new
  'NAME={{secret:VAULT}}'`) on a host where it is already done returns
  changed:false again, not NO_MATCH.

- Writes work again on SFTP servers that do not allow setting file modes,
  when their new files are no more open than requested; the result reports
  the mode the file got.

- A broken or empty state file now fails with `STATE_CORRUPT` and a hint on
  how to recover.

- Moving the vault key to or from the keychain waits for other komando
  processes changing the vault.

- `komando exec` (and `script`, `logs`, module commands) no longer reports a
  bare exit -1 when the connection breaks mid-command: the server's result
  has error code `CONNECTION_LOST` (exit 4), keeps the output received so
  far, and says the command may still be running or may have finished.

- Renaming a protected host or conn with `--rename` no longer skips the
  `--yes` check, and renaming a conn updates the tunnels that point to it.

- `secret rm` and `used_by` count `secret:` references in a server's
  environment variables.

- The approval code's key can no longer be set, moved, copied or removed
  with `komando secret` (`RESERVED_SECRET`).

- `komando test` results carry `host`, like `facts` and `exec`. `name` stays
  for existing scripts; use `host`.

## [0.2.0] - 2026-11-04

### Highlights

- **More than servers.** One list now holds databases (PostgreSQL, MySQL,
  SQLite), caches (Redis, Valkey), storage (S3, FTPS, SFTP),
  Kubernetes and Docker Swarm clusters and container registries, each with
  its own safe command: `db`, `cache`, `storage`, `cluster`, `registry`.
- **VPNs built in.** WireGuard, OpenVPN, AnyConnect and Tailscale connect by
  themselves when a target needs them, several at once, with nothing else
  to install.
- **Passwords from where you keep them.** komando's own vault, or HashiCorp
  Vault, AWS and Google secret managers, Bitwarden, KeePass and 1Password.
- **Secrets stay away from AI agents.** Passwords, keys and tokens show as
  `[hidden]`, and changes that need a person open a window on their screen.
- **Know what is running.** `komando status` and `komando prompt` show the
  VPNs, tunnels and jobs that are still up.

### Built in: secret managers and AWS logins (no vault, aws or gcloud CLI)

- `vault:` references read HashiCorp Vault or OpenBao themselves (KV v1 and
  v2, namespaces, `VAULT_CACERT`, `~/.vault-token`).
- `aws-sm:` reads AWS Secrets Manager, and `gcp-sm:` Google Secret Manager,
  with the credentials already on the computer.
- Conns with `aws_profile` (S3, ECR) read `~/.aws` themselves: SSO,
  assumed roles, temporary keys. New `komando login aws [--profile]` does
  the SSO sign-in that `aws sso login` did, into the same cache.
- New error codes `AWS_PROFILE_NOT_FOUND` and `AWS_FAILED`;
  `AWS_CLI_MISSING` no longer happens.

### Built in: OpenVPN and AnyConnect (no Docker, openvpn or openconnect)

- `openvpn` VPNs (and Pritunl profiles) run on komando's own OpenVPN client
  in user space: UDP and TCP, tls-auth and tls-crypt, AES-128/256-GCM,
  ChaCha20-Poly1305 and AES-CBC with HMAC, TLS key export or the older PRF,
  pushed options, keepalive and key renegotiation. No Docker container,
  no openvpn program, no admin rights; the computer's routes stay as they
  are. Profiles with options it does not support, or with compression
  (VORACLE), are refused at `vpn add` (`OVPN_UNSUPPORTED`). `--os-mode` is
  deprecated.
- `anyconnect` VPNs (Cisco AnyConnect, ocserv) run on komando's own client:
  the XML login (with one-time codes asked at `vpn up`) and the CSTP tunnel.
  The login happens at the terminal; the session's process gets only the
  session cookie.
- Experimental: komando's own Fortinet (form login with token codes, PPP
  over TLS), GlobalProtect (gateway login with challenges, GPST tunnel) and
  F5 BIG-IP (APM login, PPP over TLS) clients. They are used when
  openconnect is not installed, or with
  `KOMANDO_EXPERIMENTAL_VPN=fortinet,globalprotect,f5`; they have not yet
  been tried against the vendors' own servers.
- Experimental: komando's own Pulse Secure / Ivanti Connect Secure client
  (IF-T/TLS with EAP: realm choice, password, one-time codes asked at
  `vpn up`, the DSID session cookie, packets over TLS). Same rule: used
  when openconnect is not installed, or with `KOMANDO_EXPERIMENTAL_VPN=pulse`.
  Client certificates (EAP-TTLS) and Host Checker are refused with a clear
  error.
- AnyConnect uses DTLS (UDP) when the server offers it, with the key taken
  from the TLS connection (ocserv's PSK-NEGOTIATE); packets move back to
  TLS when UDP stops answering. Tested against ocserv.
- Hosts added with `--ssm` reach EC2 through komando's own AWS Session
  Manager client when the aws CLI or its session-manager-plugin is missing
  (or with `KOMANDO_EXPERIMENTAL=ssm`). KMS-encrypted sessions work: komando
  asks KMS for the session's data key and encrypts the stream with it.
- Every VPN session's local SOCKS port now needs a random per-session login
  (WireGuard and Tailscale too), so other users of the computer cannot use
  it.

### Built in: komando's own dump and restore

- `db dump` and `db restore` work without pg_dump, psql, mysqldump or mysql
  for direct conns, VPN conns and servers without those tools: komando
  writes and reads plain SQL itself (PostgreSQL: extensions, schemas, types,
  functions, sequences, tables with identity, generated columns and
  partitions, data via COPY, constraints, indexes, views, materialized
  views, triggers, row-level security, comments; MySQL: tables, data,
  views, triggers, routines). Objects it cannot write stop the dump by name
  (`DUMP_UNSUPPORTED`). Through a server that has the tools, they are still
  used. `tool` in the answer says which ran.

### Built in: komando's own kubectl and SQL shell

- `cluster run` no longer needs kubectl: komando understands the kubectl
  commands itself and prints what kubectl prints (server-side tables, wide,
  name, json, yaml, jsonpath, custom-columns, watch) for get, describe,
  logs, events, top, explain, version, api-resources, api-versions,
  cluster-info, auth, wait, rollout, apply, diff, create, replace, delete,
  patch, label, annotate, scale, set image, cordon, uncordon, drain, taint,
  run, exec, cp, debug, certificate and config. The read-only default and
  the risk checks are unchanged; port-forward and `exec -it` point at
  `cluster forward` and `cluster shell`.
- `db shell` is komando's own SQL shell for PostgreSQL, MySQL/MariaDB and
  SQLite (no psql, mysql or sqlite3): each statement gets db query's checks
  and is audited; `\d`, `\l`, `\dn`, `\du`, `\x`, `\G`, `\timing`, `\i`.
  `TOOL_MISSING` and `TLS_THROUGH_FORWARD` no longer happen for it.

### Built in: Kubernetes exec, shell and port-forward (no kubectl)

- `cluster exec` and `cluster forward` speak Kubernetes' streaming
  protocols over WebSocket themselves, and over SPDY on clusters before
  Kubernetes 1.30 (tried when the WebSocket is refused, as kubectl does;
  tested against Kubernetes 1.29). `cluster forward svc/NAME` maps the
  service port to the pod's target port (by number or name), like kubectl.
- New `cluster shell TARGET POD|TYPE/NAME [-- COMMAND]`: an interactive
  terminal in a pod for people, with the status lines and the protected
  question of `komando shell`.
- EKS and GKE tokens (`aws eks get-token`, `aws-iam-authenticator`,
  `gke-gcloud-auth-plugin` in a kubeconfig) are made by komando.
- `cluster exec --dry-run` and `cluster forward --dry-run` describe the
  call without "kubectl" in `would_run`, and add `pod`, `command`, `local`.

### Built in: Bitwarden, KeePass, 1Password Connect

- New `bw://ITEM/FIELD` for Bitwarden and Vaultwarden: komando logs in,
  syncs once per run and decrypts on this computer (personal, item-key and
  organization items), like Bitwarden's own clients.
- New `kdbx:FILE#GROUP/ENTRY[#FIELD]` for KeePass and KeePassXC files.
- `op://` reads a 1Password Connect server (`OP_CONNECT_HOST`,
  `OP_CONNECT_TOKEN`). Without Connect it still calls the `op` CLI, which is
  deprecated: komando ships only open-source parts, and the 1Password SDK's
  core is a prebuilt WebAssembly module.

### Built in: Tailscale and Headscale (no tailscaled)

- `tailscale` VPNs run inside komando with Tailscale's own Go library
  (`tsnet`), in user-space: no `tailscale` or `tailscaled` to install, no
  admin rights, the computer's network unchanged. Without an auth key,
  `komando vpn up` opens the login page once; the node then stays logged in.

### `komando prompt`: VPNs and tunnels in your shell prompt

- `komando prompt` prints `vpn:office tun:2`, or nothing, for zsh (also
  oh-my-zsh), bash or starship; the docs have the line to add. It only
  reads the state file: no network, no writes, no other programs, never an
  error, and it does not keep an idle VPN alive.

### `komando status`: what is still running

- One command lists what komando left running: VPN sessions (with when
  they close if unused), tunnels and jobs. It contacts nothing, so it is
  quick and works offline; `job list --refresh` still asks the servers
  whether a job runs.

### Where am I? Status lines for people

- `shell`, `db shell`, `cluster forward` and `logs --follow` (servers,
  Kubernetes, Swarm) print one line before they connect: what, where, as
  whom, the way there (`via vpn office → bastion1`) and `PROTECTED`
  (red; `NO_COLOR` turns colour off). `shell` and `db shell` also say how
  the session ended: `left web1 (exit 0, 12m)` or `connection to web1 lost`.
- A command that connects a VPN by itself says the VPN stays up, for how
  long, and how to stop it.
- Only for a person at a terminal, on stderr: agents, scripts, pipes and
  JSON output are unchanged. Names and addresses are printed without
  control characters, so they cannot rewrite the terminal.
- `db shell`'s line moved before connecting and uses the same format
  (was `komando: psql session on app-db (read-only)`).

### Safer `komando shell` (`ssh`, `connect`)

- `--dry-run` no longer opens a real shell: it shows the host, address,
  user, `--via` path and whether it is protected, and connects nothing.
- A protected server asks `[y/N]` before the shell opens, like `db shell`
  on a protected conn; `--yes` skips the question.
- AI agents are refused even when they run in a pseudo-terminal, and the
  error code is now `NEEDS_TERMINAL` (was `NOT_A_TTY`), the same as
  `db shell`. Like `db shell`, it also needs stderr to be a terminal.
### Clearer errors

- Every error now has a hint with the next step; a test keeps it that way.
- A file missing on this computer reads "./x does not exist on this
  computer" instead of Go's "stat ./x: no such file or directory".
- `cp ./missing web1:/tmp/` no longer suggests renaming the destination; that
  hint is only for a target komando does not know.
- A failure on one server no longer names it twice ("web1: … for web1").
- In text, an error from many servers shows its code too
  (`error [PARTIAL_FAILURE]: …`), like any other error.
- An unexpected file error is `FILE_ERROR`, not `REMOTE_ERROR`.

### Feels like the native tools (an end-to-end round over every command)

- `--dry-run` is never stopped by a safety rule: it shows the plan, and
  `meta.would_be_blocked` (in text: "without --dry-run this stops here")
  names the stop the real run would hit. Text dry runs start with
  "dry run: nothing was changed".
- A typo in a subcommand (`komando host lst`) fails with exit 2 and "did you
  mean list?" instead of printing help and exiting 0. Missing or extra
  arguments show the usage line and an example, and `-o text` now applies
  to these errors too.
- A person who answers no at a `[y/N]` prompt sees "cancelled … nothing was
  changed" instead of advice to re-run with `--yes`.
- A protected server or conn stays protected under another spelling of its
  address (upper case, a trailing dot).
- Text output shows server and database content safely: colours stay, but
  other terminal escape sequences (window title, clipboard writes) and
  control characters are shown as `\e` and `\xNN`.
- Many skipped targets print as one line; `KOMANDO_OUTPUT` with a wrong
  value names the variable; negative `-P`, `--timeout`, `--max-output` are
  refused.
- Masking for AI agents no longer hides settings and plain values
  (`max_tokens: 4096`, `password_min_length=12`, URLs, paths, YAML
  structure such as `secretKeyRef: {...}`), and a token never runs into the
  next line.
- cron: IDs are matched exactly (an ID with a dot could delete other
  entries), a newline in COMMAND is refused, schedules are checked here,
  `%` is escaped, crontab read errors are reported instead of shown as an
  empty list, `--user` uses sudo, `cron rm` says how many it removed.
- pkg: package names that start with `-` or hold patterns are refused
  (option injection), removing essential packages (openssh-server, sudo,
  systemd, libc ...) needs `--allow-dangerous`, `pkg installed` returns
  rows with installed true/false, `upgradable --refresh`, dnf/yum
  `upgradable` no longer fails when nothing is pending, and output and the
  audit log show `pkg install tree` instead of a long script.
- user: `user list` works on Debian and Alpine, `user unlock`, `--pubkey` is
  checked, `--shell` applies to existing users.
- net: `net check` fails (exit 5) on a closed port like `nc -z`, accepts
  `[IPv6]:port` and checks the port range; `net http` reports no answer as
  NO_RESPONSE and takes `--expect 200` or `2xx`; `net dns` fails with
  NXDOMAIN (exit 3) when a name does not resolve.
- The agent guard no longer blocks setting komando's variables, quoted
  heredocs, or `|` inside quotes; reading through them still is.
- Servers and files: `fs write`/`replace` follow symlinks and write the
  target (`--no-follow` refuses); `fs mv` never overwrites without
  `--overwrite`; diffs are real unified diffs; `--read-only` is checked
  (a command that writes is READ_ONLY_VIOLATION); remote `~` and `host:`
  mean the home folder like scp; `SRC/` copies the contents and re-runs
  never nest; symlinks that are skipped are listed; sync keeps modes and
  times, refuses a missing source, and never deletes when the source is
  empty; recursive downloads go on past unreadable files and report them;
  `download --sudo`; `script --arg` works for perl, python, ruby and node.
- Text output for people: each failed server shows `[FAILED exit=3]` with
  its own error and hint, stderr stays inside its server's block,
  truncated output says so, streamed output is not printed twice, and a
  `--timeout` that ends a follow (`logs -f`, `cluster logs -f`,
  `cluster run -- get -w`, `cluster forward`) is a normal end. Tables for
  `fs ls`, jobs, recipes, tunnels, keys, secrets, audit, config, db
  activity/locks/sizes, cache info, cluster ls and docker ps.
- Jobs: `job kill` records the kill and is safe to repeat, `job rm` refuses
  a running job (`--kill` first), `job wait --timeout`.
- Inventory: protected entries need `--yes` for any change, an alias of a
  protected server is protected too, hosts are validated when saved (port,
  user, --via, identity file), `host rm @group` / `conn rm 'tmp-*'` take
  selectors, `group rm GROUP` deletes a group, `config get`, `doctor`
  checks the inventory, audit records every inventory and settings change,
  `host ssh-command` prints commands that work through jump hosts, `import`
  vets proxy commands, an empty inventory says how to start, and "did you
  mean" everywhere.
- Policy: `rm -rf //`, `find / -delete`, `chmod -R ... /`, `iptables
  --flush` are caught; `grep mkfs notes` is not; `policy check` exits 6
  when blocked; `policy allow` explains built-in rules.
- Databases, caches, storage: dates and times print as psql/mysql do (no
  invented `Z`, MySQL zero dates kept); MariaDB `explain --analyze`;
  placeholder count checked before sending; `db query --csv/--tsv`; cache
  output reads like redis-cli and `cache info` gives a summary; downloads
  never write in a dry run; a key ending in `/` means into that folder;
  `--to DIR/` and `--to -`; folder markers are skipped; missing databases
  and folders exit 3; `db shell` explains how to install the client on
  this computer.
- Clusters and docker: Swarm output has the same shape as Kubernetes
  (`items`, `healthy`, `problems`); TYPE NAME and TYPE/NAME work in every
  verb; `-A`; rollouts that time out name the stuck pods and why; rollback
  skips the revision that failed; `apply` diffs Secrets without showing
  them and says created/configured/unchanged; `docker exec` passes words as
  given and keeps the exit code; `docker raw`/`compose` can no longer slip
  past the policy with a leading flag; a missing container exits 3.
- System modules and VPNs: hosts without systemd say NO_SYSTEMD, unknown
  units UNIT_NOT_FOUND; `svc restart --wait`; pkg install/rm report what
  changed and PACKAGE_NOT_FOUND; `pkg upgrade --dry-run` lists what would
  change; `net dns --type MX`; `net ports` with process and pid; `vpn
  status` dials SOCKS and system VPNs; `vpn up` checks a WireGuard tunnel
  really answers; `vpn edit`; VPN errors keep their own code through SSH.
- `facts` knows containers (init, virt, IPs without /len).
- `job wait` survives a dropped SSH connection (a NAT or firewall closing
  an idle one): it connects again and keeps waiting until the job ends or
  the timeout passes. Before, a 25-minute install's wait could stop after
  ~10 minutes with the job still running.
- The agent guard no longer mistakes `.../environments` for a process
  environment or a jq filter `.key` for a key file, and reads `\"` the way
  the shell does (fuzzing found a way around it).
- `cluster forward TARGET svc/x :80` picks any free local port, like kubectl.
- `vpn rm` takes several names, like `host rm`; `svc logs` as a user who may
  not read the system journal says to add `--sudo`.
- e2e: WireGuard end to end (a user-space peer), and svc/logs against the
  real systemctl and journalctl on a server with systemd as PID 1.
- e2e: AWS SSM end to end with a stand-in `aws` CLI (login, commands and
  files through `aws ssm start-session`), and an expired SSO login.
- `storage link --endpoint https://PUBLIC-NAME` signs a link for the address
  people use when komando reaches the storage through `--via`.
- `docker logs` shows times only with `--timestamps`, like docker and
  kubectl; a failing command on one server states its error once.
- e2e: every one of the 195 commands now runs at least once
  (`test/e2e/checks/`), and `E2E_HOME` keeps a lab inventory to try
  commands by hand.

### Secrets stay away from AI agents

- A person allows what an AI agent asks for: when Claude Code, Codex, Gemini
  CLI or Cursor adds `--yes`, `--allow-dangerous` or `--reveal`, komando
  shows the exact command in a window on the screen and runs it only after
  "Allow once". With no screen the agent is refused and the hint asks the
  person to run the command themselves. People and scripts are unchanged.
- For AI agents, passwords, keys and tokens in any output show as
  `[hidden]`: `.env` and config files, `env`, logs, database rows,
  Kubernetes Secrets, private keys, password hashes, URLs with a password.
  `--reveal` (allowed by a person) shows them. Vault values are now also
  hidden when base64- or URL-encoded.
- `fs write` and `fs replace` take `{{secret:NAME}}`, which becomes the
  vault value on the server; an `--old` with `[hidden]` in it matches the
  hidden value. Text that still holds `[hidden]` or `[secret:NAME]` is never
  written (`HIDDEN_VALUE`), nor stored with `secret set`.
- An AI agent cannot copy `.env` files, private keys and other secret files
  to this computer (`SENSITIVE_FILE`); folder copies and `sync` leave them out.
- `komando guide install` also adds a guard to Claude Code
  (`.claude/settings.json`) that stops reading `~/.komando`, private keys,
  `.env` files and credential stores, dumping every environment variable,
  and `ssh`/`scp`/`rsync` around komando. `--no-guard` skips it.
- `--reveal` is now a flag of every command; `secret get --reveal` still
  works only for a person at a terminal.

### Measured against international standards

- New page [security-standards.md](docs/features/security-standards.md):
  OWASP ASVS, OWASP Top 10 for LLM applications, NIST, ISO 27001, CIS and
  SLSA, with what is met, what is partly met and what is up to you.
- Passphrase vaults use scrypt N=2^17 (the OWASP minimum, was 2^15); an older
  vault moves up with a new salt on its next change.
- The audit log is a hash chain: `komando audit verify` finds a record that
  was edited, added or removed. Records name the AI agent and whether a
  person allowed the command.
- `komando doctor` checks security: file permissions, vault mode and
  passphrase length (NIST SP 800-63B), the audit chain, and conns whose
  traffic is not encrypted or whose server certificate is not checked.
- The agent rules say server output is data, never instructions (prompt
  injection).
- Releases carry signed SLSA build provenance (`gh attestation verify`). CI
  reads only, actions are pinned to commits, Dependabot keeps modules and
  actions current, and `make security` runs govulncheck.
  `make fuzz` fuzzes the masking, the policy filter and the guard; fuzzing
  found and fixed a crash on invalid UTF-8 in `fs replace --old`.
- golang.org/x/net 0.62.0 (GO-2026-6860, GO-2026-6866).
- `--proxy-command` runs a program on this computer on every connection, so
  it passes the policy filter, and an AI agent needs a person's yes to set it.

### Project

- Added a code of conduct, Dependabot updates, CODEOWNERS and `.editorconfig`.
  `make lint` now also runs staticcheck.
- Issues use forms (bug report, feature suggestion); security reports go to
  GitHub's private form. Simpler SECURITY.md, CONTRIBUTING.md and pull
  request checklist.
- A release runs every check (lint, unit and end-to-end tests) first, and
  takes its notes from this file.
- Docs are English only: removed `README.id.md` and `docs/features/id/`, and
  translated the design notes in `docs/design/`.

### Cloud access

- `host add|edit --proxy-command CMD` reaches a server through a program on
  this computer, like OpenSSH's ProxyCommand (`%h %p %r %n`): AWS SSM, GCP
  IAP, Cloudflare Access, Teleport. `--ssm` sets the AWS Systems Manager
  command (the address is the instance ID). Conns can use such a host as
  `--via` (RDS behind SSM). `import ssh-config` keeps ProxyCommand; imports
  of export files drop it.
- S3 conns can log in with an AWS CLI profile (`--option aws_profile=NAME`):
  SSO, assumed roles and temporary keys work as configured in the aws CLI.
  An expired SSO login answers `AWS_LOGIN_REQUIRED`.
- Amazon ECR registries get a fresh login from the aws CLI each time
  (logins last 12 hours), with the same `aws_profile` option.

### Day-to-day database care

- `db info` (version, uptime, size, connections, primary or replica and
  replay lag), `db activity [--all]`, `db locks` (who waits on whom),
  `db sizes` (databases, biggest tables and indexes) for PostgreSQL and
  MySQL/MariaDB; `db info` and `db sizes` for SQLite too.
- `db kill CONN PID` cancels a running query; `--session` ends the
  connection and needs `--allow-dangerous`. `--dry-run` shows the session.
- `db schema TABLE` shows foreign keys, checks and unique constraints.
- `db dump --format custom` writes a PostgreSQL archive; `db restore`
  recognises it and uses pg_restore (in one transaction). `--table` and
  `--schema-only` narrow a dump (PostgreSQL and MySQL).

### Bulk transfer

- `komando sync SRC DST` keeps a folder in step between this computer and
  servers (many at once) or storage, sending only new and changed files.
  `--exclude` skips names and paths; `--delete` removes what the source no
  longer has (needs `--allow-dangerous`); `--dry-run` lists every file.
- Storage: `upload -r` sends a folder, `download -r` fetches a prefix
  (existing local files stay unless `--overwrite`), `storage cat` reads a
  text object (`--head`, `--tail`), and `storage rm --prefix [--older-than
  30d]` cleans up old objects with a list first and a `--limit`.
- Uploads to servers stream the file: a backup of any size no longer has to
  fit in memory.
- `key revoke KEY TARGET` removes a public key from authorized_keys on many
  servers (`--user` for another account); revoking the key komando logs in
  with needs `--allow-dangerous`.

### Cluster deploy cycle

- `cluster deploy TARGET TYPE/NAME --image IMAGE [--wait]` puts out a new
  image on Kubernetes (deployment, statefulset, daemonset) or Swarm.
- `cluster status TARGET TYPE/NAME [--wait]` tells whether a rollout has
  finished, and waits for it (`ROLLOUT_FAILED`, `ROLLOUT_TIMEOUT`).
- `cluster history` lists a deployment's revisions with their images;
  `cluster rollback [--to N] [--wait]` goes back (Swarm: to the previous
  version).
- `cluster status TARGET` names every problem: CrashLoopBackOff and other
  container waits, deployments short of replicas, nodes not ready or under
  pressure (`healthy`, `problems`).
- `cluster describe` (state, conditions, containers or pods, events) and
  `cluster events [--warnings] [--for TYPE/NAME]`.
- `cluster ls -l SELECTOR`, and useful columns for ingresses, volume claims
  and volumes, jobs, cron jobs, autoscalers, config maps, events and
  namespaces.
- `cluster logs` reads a workload (`deploy/api`) or a label (`-l app=api`)
  across its pods, and follows with `-f` (Kubernetes and Swarm).
- `cluster exec` runs a command in a pod with the destructive-command
  check (`--read-only` for looks); `cluster forward` reaches a pod or
  service port on 127.0.0.1.

### Secrets stay out of sight; dry runs show the change

- Vault secrets are hidden in everything komando prints: a remote `.env`,
  a log line or `env` output shows `[secret:NAME]` instead of the value
  (values of 6 characters or more). `secret get --reveal` still shows it
  to a person.
- `--env KEY=secret:NAME` (exec, script, job, host `--env`) fills the value
  in from the vault on the way to the server, so an agent never handles it.
  Jobs get their exports from a private file that is deleted at start, not
  on a command line other users can see.
- `cluster apply --dry-run` shows each object's change (`create`, `change`
  or `none`) as a diff; Secret values stay hidden.
- `registry rm` lists every tag that goes with the image, in the dry run
  too.

### Promises kept

- The audit log fails closed: when it cannot be written, commands that
  could change something are refused (`AUDIT_UNAVAILABLE`); `doctor`
  checks it.
- `komando test` logs in to databases, caches and registries (and reports
  the server version) instead of only opening the port.
- Shell completion fills in server, conn and VPN names, `@groups`, `tag:`
  and saved names from the inventory.
- `komando schema` lists every selector (`kind:`, servers and conns) and
  every secret reference form.
- `import ssh-config` reports what it did not carry over (Match blocks,
  ProxyCommand, ...) instead of dropping it silently.
- `conn edit --option statement_timeout=10s` is used by `db query` and
  `db schema`.
- docs/design/vision.md shows the real status of every family.

### Safer file edits, downloads and tunnels

- `fs write|replace --validate CMD` checks the new file before it goes
  into place (`%s` is its path, e.g. `visudo -cf %s`, `sshd -t -f %s`). If
  the check fails the old file stays (`VALIDATION_FAILED`).
- `fs write --dry-run` shows the change as a diff.
- Downloads from servers never replace a file on this computer
  (`FILE_EXISTS`; `--overwrite` to replace), are written under a temporary
  name first, and refuse server paths that lead outside the destination.
- `tunnel start` asks for `--yes` before listening on anything but
  loopback (`OPEN_BIND`), as docs/design/network.md promised.

### Secrets and risk ratings

- `secret get --reveal` works only for a person at a terminal
  (`REVEAL_NEEDS_HUMAN` for agents and scripts); commands refer to secrets
  as `secret:NAME` instead.
- `secret rm` refuses a secret that a server, conn, key or VPN still uses
  (`SECRET_IN_USE`) and is written to the audit log.
- `host add|edit --password-ref/--sudo-ref` refuse a password typed where a
  reference belongs; before, it was stored and printed as plain text.
- `cluster run -- get secret ... -o yaml|json|jsonpath` needs
  `--allow-dangerous`: those formats print the secret values. The default
  table (names and key counts) stays a read.
- `docker raw` and `docker rm` are rated like `cluster run` on a Swarm
  manager: reads stay reads, and `rm`, `volume rm`, `prune`, `run`, `exec`
  need `--allow-dangerous`; so does `docker compose down -v/--rmi`.
- `cache run`: `GETDEL`, `RENAME` and `EXPIRE` to zero or the past delete
  keys, so they need `--allow-dangerous` like `DEL`. Read commands of
  RedisJSON, RediSearch, RedisTimeSeries and RedisBloom count as reads;
  `ACL LOG RESET` is a write.
- `db query`: passwords in `CREATE/ALTER USER|ROLE ... PASSWORD`,
  `IDENTIFIED BY` and `SET PASSWORD` are replaced with `'***'` in the audit
  log.
- `svc logs -f` and `docker logs -f` stream like `logs -f` (they waited for
  the timeout before).
- `registry ls` follows every page of the repository list (it read only the
  first).

### Safety fixes from a full review

- `--dry-run` now changes nothing on every command. Inventory commands
  (`host`, `conn`, `group`, `key`, `policy`, `config`, `recipe`) show the
  result without saving it, and `job kill`, `job rm`, `tunnel stop`,
  `key gen`, `key rm --delete-file`, `secret set` and `secret rm` only
  report what they would do. Before, some of them made the change while
  the answer and the audit log said `dry_run: true`.
- `.ovpn` profiles may not use `setenv opt ...`: OpenVPN runs the rest of
  that line as an option, which got past the allowlist (for example
  `setenv opt up /bin/sh`).
- The destructive-command policy checks each line of a script, so a
  `reboot` on its own line is caught. It also catches `/sbin/reboot`,
  `nohup reboot`, `rm -rf "/"`, `rm -rf -- /`, `rm --recursive --force /`,
  `rm -rf /etc/*` and `rm -rf /var/lib`.
- `--env` names must be shell variable names (`A-Z`, `0-9`, `_`). A name
  like `X;reboot;Y` used to run as a command, past the policy check.
- `svc restart|start|reload` quotes unit names in its `journalctl` call.
- The sudo password (`--sudo-ref`) is sent only when sudo asks for it.
  When sudo did not ask (NOPASSWD, or a recent sudo), the password went to
  the command's stdin, and `script` printed it in its error output.
- `db query` on MySQL: `--` starts a comment only before white space, as
  in MySQL itself, so `SELECT 1 --1, LOAD_FILE(...)` is no longer rated a
  read. `SET TRANSACTION`, `SET SESSION CHARACTERISTICS`,
  `transaction_read_only` and `SET autocommit` are refused, because they
  switch off or end the read-only transaction.
- `fs write|replace|upload --sudo` reads the existing file mode as root.
  Before, a file the SSH user could not see (`/etc/sudoers.d`, `/root`)
  became 0644. The staged copy in `/tmp` is now private (0600) and is
  removed when the connection fails.
- `fs write --append` refuses files over 64 MiB (FILE_TOO_LARGE) instead
  of cutting them to 64 MiB.

### VPN clients tested against real servers

- `make e2e-vpnclients` runs, all in Docker: ocserv (the AnyConnect
  protocol, the path the whole openconnect family uses) and Headscale with
  a Tailscale node. komando connects on demand, `--mfa` VPNs ask for a
  person, the Tailscale auth key is on no command line, and `vpn down`
  stops the clients.
- Session checks read the process name from /proc on Linux (small images
  have no `ps`, which made every session look dead).

### Subnet clashes

- `vpn up` for VPNs that change the computer's routes (OpenVPN
  `--os-mode`, system VPNs with `--service`) compares the routing table
  before and after and warns when the new routes overlap ones another
  interface already had (two networks claiming the same addresses). The
  other kinds never touch the computer's routes, so they cannot clash.

### Output contract 1

- Every JSON answer carries `meta.contract: 1`, and `komando schema` says
  `contract: 1`. Within a contract, field names, error codes and exit codes
  are only added, never renamed or removed (docs/design/ux.md, section 13).

### Agent skill

- `komando guide install` adds the komando skill (`SKILL.md`, the Agent
  Skills format) to `~/.claude/skills` (Claude Code) and `~/.agents/skills`
  (Codex, Cursor, Gemini CLI). Agents then reach for komando by themselves
  on server, database, cache and storage tasks. `--project` installs into
  the current folder; a changed file is kept as `SKILL.md.bak`. The same
  skill lives in `skills/komando/` for `npx skills add sgnd/komando`.

### Logs and files

- `komando logs ... --follow` (`-f`) keeps printing new lines until Ctrl-C;
  in a terminal they show as plain lines (marked by server when there are
  several), for agents as NDJSON events.
- `fs rm --recursive` needs `--allow-dangerous`, like `storage rm`.

### More import sources

- `komando import filezilla` (SFTP sites, passwords to the vault), `rclone`
  (SFTP remotes) and `dbeaver` (PostgreSQL, MySQL/MariaDB and SQLite
  connections).

### Fixes from the second review

- OpenVPN container: the entrypoint parsed again (a comment had swallowed
  `fi`; a test now checks every embedded script), the SOCKS port listens
  only on the container's network and needs a random per-connection
  login, the container runs with only the capabilities it needs and
  no-new-privileges, and config/login files are removed also when
  connecting fails. Tested against a real OpenVPN server
  (`make e2e-openvpn`).
- .ovpn inline blocks end the way OpenVPN ends them, so text after `</ca>`
  can no longer smuggle in directives; an unclosed block is refused.
- `cluster run` refuses flags that would send the conn's credentials to
  another cluster or identity (`--server`, `--kubeconfig`, `--token`,
  `--context`, `--as` ...) and user `--dry-run` values; `config view` (it
  can print credentials), `edit`, `apply --prune`, scaling to 0, role
  bindings, privileged `run`, and docker `exec`/`run`/`cp`, `--prune` and
  node drains are rated dangerous.
- VPN sessions: stops take the VPN's lock and check it is still the same
  session; sessions in use (a long `logs --follow`) stay fresh; containers
  are tracked by ID and labelled with their komando home; OS-mode OpenVPN
  writes its pid to /var/run and logs to syslog.
- Imports keep a secret reference only when that secret really does not
  exist (not when the vault is locked).

### Fixes from review

- `cluster run` must start with the command (a leading flag could hide a
  delete behind a "get"); kubectl and docker commands are rated by verb and
  subcommand (`auth reconcile`, `service rm`, `system prune` ...), the
  destructive-command policy sees them unquoted, and `--dry-run=server` goes
  right after the verb (never into `exec ... --`).
- `import komando` drops references to secrets or files that already exist
  on this computer and imports recipes as changes, so a file from someone
  else cannot send your passwords to their server or skip `--yes`.
- OpenVPN configs pass only an allowlist of client settings, with keys
  inline; nothing that runs programs or reads/writes files by path.
- KOMANDO_VAULT_PASS is removed from the environment at start, so kubectl,
  credential plugins, VPN clients and docker never inherit it.
- VPN sessions: a reused pid is never signalled, a failed stop (sudo) is
  reported and the session kept, idle sessions close at the next komando
  command, two commands cannot start the same VPN twice, config and login
  files are deleted once connected, the Tailscale auth key no longer shows
  in `ps`, and `vpn up/down/rm --dry-run` change nothing.
- `label:KEY` without a value picks targets that have the label (it picked
  those without it). kubectl secrets are hidden in the audit log;
  `cluster rm`/`registry rm --dry-run` report what would be blocked.

### OpenVPN without touching your computer's network

- `openvpn` (and `pritunl`) VPNs run in a small Docker container, built
  once from files inside komando, and are reached through a local SOCKS
  port, like the other VPN kinds: several at once, no sudo, no route
  changes. `--os-mode` keeps the old way (sudo, system routes).

### Password managers

- `--password-ref` also takes `op://...` (1Password), `vault:PATH#FIELD`
  (HashiCorp Vault), `aws-sm:NAME[#KEY]` (AWS Secrets Manager) and
  `gcp-sm:NAME[@PROJECT]` (Google Secret Manager). komando runs that tool's
  CLI when it needs the value and never stores it.
### Registry copy

- `komando registry copy SRC:IMAGE DST:[IMAGE]` copies an image between
  registries or repositories with every platform, keeping the digest.
  Layers already at the destination are skipped, layers within one registry
  are mounted, credentials never go to another host (e.g. an upload
  redirect), and only the destination is guarded (`--yes` when protected).

### Database shell

- `komando db shell CONN` opens psql, mysql or sqlite3 on this computer,
  connected through the conn's `--via` path, with the password in the
  client's environment. Read-only unless `--write` (PostgreSQL
  default_transaction_read_only, MySQL session READ ONLY, sqlite3
  -readonly); protected conns need `--yes` for `--write`. PostgreSQL keeps
  verifying the certificate's host name through the forward (PGHOSTADDR).
  For people only: without a terminal it refuses with NEEDS_TERMINAL.

### File servers in storage

- `komando storage` also works with FTPS (`ftps://`, TLS on control and data
  connections), SFTP (`sftp://`, for shell-less accounts; host keys checked
  like SSH hosts) and FTP (`ftp://`, refused without `?insecure=1` because
  it sends the password unencrypted). ls, download, upload and rm behave as
  for buckets; uploads go to a temporary name and are renamed into place,
  creating missing folders; keys cannot leave the conn's folder. All of it
  works through `--via` bastions and VPNs.

### Container registries

- `komando registry ls|inspect|rm` for Docker Hub, GHCR, GitLab, Harbor,
  ECR and registry:2 over the OCI Distribution API (basic and token auth),
  through `--via` paths and VPNs. `rm` deletes by digest and needs
  `--allow-dangerous`. `komando import docker` reads
  `~/.docker/config.json`, including credential helpers.

### Clusters

- `komando cluster` for Kubernetes (a k8s conn) and Docker Swarm (a manager
  server) with the same verbs: `status`, `ls`, `get` (Secret values hidden),
  `logs`, `apply` (server-side; `--dry-run` asks the server), `restart`,
  `scale` (to 0 needs `--allow-dangerous`), `rm` (needs `--allow-dangerous`)
  and `run` for any kubectl or docker command (read-only unless `--write`).
  The Kubernetes API is called directly (no client-go), through `--via`
  paths and VPNs; `cluster run` gives kubectl a private kubeconfig and a
  local tunnel. `komando import kubeconfig` adds one conn per context and
  keeps each context's credentials in the vault.

### VPNs

- `komando vpn add NAME wireguard|socks|system`. A VPN goes first in a
  `--via` path (`--via office,bastion`) for servers, conns and tunnels.
  WireGuard runs inside komando for that command only: several VPNs at
  once, overlapping subnets, no admin rights, no change to the computer's
  network. Keys go to the vault. `system` checks an OS VPN is connected
  (`VPN_DOWN` if not). `list`, `test`, targets (`kind:vpn`), groups and
  `export`/`import` include VPNs; a VPN in use cannot be removed.

### One command per job

- `--via` for servers too: `host add db1 ... --via bastion` (chains like
  `--via bastion,db1`). `--jump` still works; state files move `jump` to
  `via` on load. Conns take `--via` chains as well, and a host on anyone's
  `--via` path cannot be removed (`HOST_IN_USE`).
- `komando upload` and `komando download` work for servers (SFTP, many at
  once) and storage conns. `cp` and `storage upload/download` are the same
  commands spelled the old way.
- `komando recipe` is one list of built-in and saved commands. `ops` and
  `snippet` are other names for it; saved recipes cannot reuse built-in
  names, and marking an existing recipe read-only needs `--yes`.
- `host list/test` and `conn list/test` are `komando list/test` limited to
  servers or conns (new selector `kind:conn`); `svc logs` and `docker logs`
  are `komando logs` with `--unit` or `--container`.
- `komando import SOURCE` brings in `ssh-config`, `pgpass`, `mycnf`, `env`
  (.env URLs) and `komando` export files; passwords go to the vault, re-imports
  change nothing, and what cannot be imported is listed. `komando export`
  saves servers, conns and recipes (no passwords) to move computers.
- `komando tunnel start CONN` opens a local port to a conn through its
  `--via` path, for apps like TablePlus or psql (`--port` to choose it).

- `komando conn`: an inventory of databases (PostgreSQL, MySQL, SQLite) next
  to hosts. Add, edit, list, show, remove and test them; reach private ones
  through a host with `--via`. Passwords are refused in URLs and live in the
  vault. First step toward `komando db` (see `docs/design/resources-and-db.md`).
- Hosts and conns share one name space. Removing a host that a conn uses
  with `--via` is refused (`HOST_IN_USE`); renaming a host updates its conns.
- `komando audit --host` also matches conn names.
- `komando db query/schema/explain` for PostgreSQL and SQLite. Read-only by
  default (the database enforces it); `--write` to change data, `--write
  --dry-run` to try it and roll back. Destructive SQL (DROP, TRUNCATE,
  DELETE/UPDATE without WHERE, ...) needs `--allow-dangerous`; protected
  conns need `--yes`. Results are structured rows, safe for JSON.
- `komando storage` (alias `s3`) for S3 and S3-compatible storage (MinIO, R2,
  Wasabi, Spaces, B2, Garage): `ls`, `download` (to a file, never
  overwriting), `upload`, `rm` (exact keys only, needs `--allow-dangerous`),
  and `link` for temporary download links. Keys stay inside the conn's folder.
- `komando policy list` shows the SQL and Redis rules; `komando policy check
  --for KIND` rates a SQL query or Redis command.
- MySQL and MariaDB conns for `komando db`.
- `komando db dump` and `db restore`: backups to and from a file on this
  computer, using pg_dump/psql or mysqldump/mysql on the `--via` server (or
  locally). The password never appears on a command line; files are 0600 and
  never overwritten; restores need `--allow-dangerous` and refuse files with
  client commands (`\!`, `system`). MySQL `tls=` settings carry over.
- `komando config set audit_sql full|hash|off` controls how SQL text is kept
  in the audit log.
- `komando cache` for Redis/Valkey: `get` (any type, with TTL), `keys` (SCAN,
  never KEYS), `info`, `set`, `rm`, and `run` for any command, read-only
  unless `--write`. Deleting, flushing, blocking, scripts and
  server-reconfiguring commands need `--allow-dangerous`.

### Everything in one place

- Targets pick servers and conns together: `@prod` is everything in the
  `prod` group. Each command uses what it can work with and lists the rest
  in `meta.skipped`; when nothing fits, `NO_MATCHING_TARGETS` names the right
  command. New selector `kind:` (`kind:host`, `kind:db`, `kind:postgres`, ...).
  Typos get a "did you mean" hint. Unknown names now report
  `TARGET_NOT_FOUND` from commands that take both kinds.
- `komando list [TARGET]` and `komando test TARGET` show and check servers
  and conns together. `group add/rm` and `group list` include conns.

### Safety

- Snippets count as changes, so protected servers need `--yes`, unless saved
  with `--read-only`. Snippets saved before this release are treated as
  changes too. `snippet add --mutating` is no longer needed.
- `komando secret set NAME VALUE` is refused (`SECRET_IN_ARGS`): a value on
  the command line lands in shell history. Type it, pipe it, or use
  `--from-env`.
- Removing, replacing (`add --overwrite`) or unprotecting a protected server
  or conn needs `--yes`.
- Protection follows the address: an ad-hoc `user@address`, a second host
  name for the same address and port, or a second conn to the same database
  server, file or bucket counts as protected too.
- Turning off the audit log or `audit_sql`, loosening host key checks
  (setting, or `--host-key-policy off`), and removing a deny rule need `--yes`
  (`SAFETY_SETTING`). `config set audit` accepts only on/off values.
- A person typing in a terminal is asked instead of getting an error: `[y/N]`
  for protected targets, and typing the target's name for dangerous
  commands. Agents and scripts still need `--yes` / `--allow-dangerous`.
- Names ignore upper and lower case (`Web1` and `web1` cannot both exist),
  and `all` cannot be a name. `host import` skips invalid names.

### One way to say each thing

Old names keep working for one release and print a note.

- `rm` everywhere: `group remove`, `pkg remove` and `user delete` are now
  `rm`; every `rm` also accepts `remove`, `delete` and `del`.
- `--overwrite` replaces `--force` (`host add`, `conn add`, `snippet add`).
- `--var` replaces `--param` (`ops run`).
- `--target` replaces `--host` (`audit`, `job list`) and takes any target.
- `-n, --limit` replaces `--lines` (`logs`, `svc logs`, `docker logs`).
  `fs cat -n` (line numbers) is now `--line-numbers`; `job logs --limit`
  (bytes) is now `--max-bytes`.
- `-r` is the only short flag for `--recursive` (`fs ls` used `-R`).
- `logs --file` and `--grep` lose their short flags: `-g` now means only
  `--group`, and `-f` in `logs` is kept free for a future `--follow`.
- `pkg` and `user` accept `--no-sudo`.
- Usage lines say `TARGET` everywhere (was `HOST` in `fs`, `shell`, `tunnel`).

## [0.1.0] - 2026-11-02

First release.

- Server list with groups, tags, labels, jump hosts and `~/.ssh/config` import
- SSH keys and an encrypted password vault
- Run commands and scripts on many servers in parallel; long-running jobs
- Safe file reading and editing, upload and download
- Background tunnels (local, remote, SOCKS)
- Health checks and 39 ready-made recipes; services, logs, Docker, packages, network, users, cron
- Safety: dangerous-command filter, protected servers, dry run, server identity check, audit log
- Readable text in a terminal, JSON for AI agents

[Unreleased]: https://github.com/sgnd/komando/compare/v0.13.0...HEAD
[0.13.0]: https://github.com/sgnd/komando/compare/v0.12.0...v0.13.0
[0.12.0]: https://github.com/sgnd/komando/compare/v0.11.0...v0.12.0
[0.11.0]: https://github.com/sgnd/komando/compare/v0.10.0...v0.11.0
[0.10.0]: https://github.com/sgnd/komando/compare/v0.9.0...v0.10.0
[0.9.0]: https://github.com/sgnd/komando/compare/v0.8.0...v0.9.0
[0.8.0]: https://github.com/sgnd/komando/compare/v0.7.0...v0.8.0
[0.7.0]: https://github.com/sgnd/komando/compare/v0.6.0...v0.7.0
[0.6.0]: https://github.com/sgnd/komando/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/sgnd/komando/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/sgnd/komando/compare/v0.3.1...v0.4.0
[0.3.1]: https://github.com/sgnd/komando/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/sgnd/komando/compare/v0.2.0...v0.3.0
[0.2.0]: https://github.com/sgnd/komando/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/sgnd/komando/releases/tag/v0.1.0
