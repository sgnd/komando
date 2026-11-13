# Error codes

Every error code komando gives, with its exit code, an example message and
the usual next step. The error's own `hint` says what to do in your case.
This page is made from the code (`komando schema` lists the same under
`error_codes`). [Results and errors](output.md) explains the common ones.
[All docs](README.md)

| Code | Exit | Example message | Usual next step |
|------|------|-----------------|-----------------|
| `AMBIGUOUS_MATCH` | 8 | --old matches … times in … | add surrounding context to --old so it is unique (read the file with `komando fs cat SERVER PATH`), or pass --all |
| `AUDIT_TAMPERED` | 1 | the audit log chain is broken at line … | keep a copy of the file and find out who changed it; komando keeps adding records after it |
| `AUDIT_UNAVAILABLE` | 1 | the store, which keeps the audit log, cannot be written: … | fix the file or folder permissions (`komando doctor` checks them); nothing was run |
| `AUTH_FAILED` | 4 | … asks … (two-factor login); only a person can answer it, and none is at a terminal here | run `komando login SERVER` in a terminal: komando asks you for the code once and keeps the login, so later commands (an AI agent's too) need no code; an AI agent asks the user to run it |
| `AWS_FAILED` | 4 | AWS profile …: … | check the profile in ~/.aws/config |
| `AWS_LOGIN_REQUIRED` | 4 | AWS profile …: … | a person runs `komando login aws --profile …` once, then run it again |
| `AWS_PROFILE_NOT_FOUND` | 3 | there is no AWS profile … | add the profile to ~/.aws/config (or fix --option aws_profile) |
| `AZURE_FAILED` | 4 | …: … | check that this computer reaches login.microsoftonline.com |
| `AZURE_LOGIN_REQUIRED` | 4 | …: … | set AZURE_TENANT_ID, AZURE_CLIENT_ID and AZURE_CLIENT_SECRET for a service principal, run komando on Azure with a managed identity, or a person runs `az login` |
| `BACKUP_FAILED` | 5 | could not make a backup of …: …; the file was not changed | check free space with `komando exec TARGET --read-only -- df -h`, or run without --backup |
| `BACKUP_NOT_FOUND` | 3 | no backup of … found (looked for ….bak) | komando keeps a backup only when you edit with --backup; give another copy with --copy PATH |
| `BAD_CA` | 2 | registry CA …: … | store the registry's CA certificate (PEM) with `komando secret set NAME < ca.crt` |
| `BAD_FILE` | 2 | cannot read backup: … | the file is not readable text SQL |
| `BAD_RELEASE` | 1 | … is … bytes, more than komando accepts; nothing was changed | report it at …/issues |
| `BAD_SECRET` | 2 | the password for … contains a line break | store the password again without line breaks (`komando secret set NAME`) |
| `BINARY_FILE` | 1 | … is a binary file; fs cat shows text only | save it with `komando download … …` |
| `BUCKET_NOT_FOUND` | 3 | bucket does not exist | check the bucket name in the conn URL (`komando conn show NAME`) |
| `BUILTIN_RULE` | 2 | … is a built-in rule and cannot be removed | built-in rules always apply (see them with `komando policy list`); for one intended command, confirm with the user and pass --allow-dangerous |
| `CACHE_AUTH` | 4 | memcached refused the login: … | check the user in the URL and the password reference (`komando conn show NAME`) |
| `CACHE_CONNECT` | 4 | cannot connect to …: … | the server's certificate could not be checked against this computer's CAs: give the CA that signed it with ?ca=secret:NAME (`komando secret set NAME < ca.pem`), or reach the server --via an SSH server with the plain scheme (redis://, memcached://) instead (`komando conn edit NAME --via HOST --url ...`) |
| `CACHE_ERROR` | 5 | this memcached cannot list keys: … | start memcached with the LRU crawler on (the default since 1.5); `cache get` works without it |
| `CANCELLED` | 1 | interrupted | it stopped before the end (Ctrl-C or a signal); check what it left, then run it again |
| `CERT_PROBLEMS` | 1 | … of … targets need attention: … | renew or replace the certificates marked expiring, expired or not_trusted; see each result |
| `CHECKSUM_MISMATCH` | 1 | … does not match checksums.txt of its release; nothing was changed | run it again, and report it at …/issues if it happens again |
| `CHMOD_FAILED` | 5 | cannot set mode … on …: …; the file was not changed | this SFTP server does not allow setting file modes, and its new files are more open than asked for; if the server has a shell and sudo, retry with --sudo |
| `CODE_WRONG` | 2 | that code does not match; nothing was changed | check the phone's clock and run it again |
| `COMMAND_FAILED` | 5 | exit code … | read the error output (stderr) for the reason |
| `COMMAND_NOT_FOUND` | 3 | no command … | run `komando schema --compact` to see every command |
| `CONFIRM_REQUIRED` | 6 | deleting group … takes … entries out of it | check with --dry-run, ask the user; once they agree, run it again with --yes (komando then asks them in a window on their screen) |
| `CONNECTION_LOST` | 4 | the connection to … broke while reading the job's status | run it again; the job keeps running on the server |
| `CONNECTION_REFUSED` | 4 | the server refused the connection: nothing listens on that port | check that sshd runs on the server and listens on this port: `komando host show …` |
| `CONNECT_FAILED` | 4 | cannot reach …: … | check the name and port; if the site is only reachable from a server or VPN, add --via NAME |
| `CONNECT_TIMEOUT` | 7 | connecting to … timed out | a firewall drops the connection, or the server is private: check the address with `komando host show …`, reach it through a bastion or VPN (`komando host edit … --via NAME`), or raise --connect-timeout on a slow link |
| `CONN_EXISTS` | 8 | … … already exists | use `komando … edit` or pass --overwrite to replace it |
| `CONN_NOT_FOUND` | 3 | no conn named … | see them with `komando conn list` |
| `CONN_UNREACHABLE` | 4 | cannot reach …: … | check the address and port; if it is only reachable from a server, set `komando conn edit … --via SERVER` |
| `CONSUMER_GROUP_NOT_FOUND` | 3 | no consumer group named … | list consumer groups with `komando queue groups CONN` |
| `CONSUMER_NOT_FOUND` | 3 | no consumer named … | list consumers with `komando queue groups CONN`; name one as STREAM/CONSUMER |
| `CONTAINER_NOT_FOUND` | 3 | no container named … | its containers: … |
| `CRONTAB_UNREADABLE` | 5 | cannot read the crontab (exit …) | check the user name; reading another user's crontab needs sudo |
| `DB_AUTH` | 4 | bigquery: the stored key is not a service account key: … | the --password-ref of a bigquery conn holds a service account key (the JSON file from the console), or leave it out to use gcloud's login |
| `DB_BYTES_LIMIT` | 6 | the query would read …, more than --max-bytes …, so it did not run | BigQuery bills by the bytes a query reads: select fewer columns, filter on the partition or cluster columns, or, if that cost is intended (ask the user), raise --max-bytes |
| `DB_CONNECT` | 4 | cannot open …: … | check the file path in the conn URL (`komando conn show NAME`) |
| `DB_ERROR` | 5 | … (SQLSTATE …) | fix the SQL; `komando db schema CONN TABLE` shows columns and types |
| `DB_NOT_FOUND` | 3 | … failed on … (exit …): … | check the database name at the end of the conn URL (`komando conn show …`) |
| `DB_PRIVILEGE` | 5 | … (error …) | the conn's user lacks this right; ask an admin to grant it, or use a conn with an admin user |
| `DB_USER_EXISTS` | 8 | user … already exists | change its password with `komando db user passwd CONN … --password-ref secret:NAME` |
| `DB_USER_IN_USE` | 8 | the database user owns objects or has sessions, so it is not removed | end its sessions first: find them with `komando db activity CONN --all`, then `komando db kill CONN PID --session` |
| `DB_USER_NOT_FOUND` | 3 | no database user named … | list users with `komando db user list CONN` |
| `DECLINED` | 6 | not run: the person said no; nothing was changed | run it again to be asked again |
| `DELETE_FAILED` | 1 | cannot delete …: … | check the file's permissions |
| `DELIVERY_LIMIT_NEAR` | 8 | subscription … moves a message to its dead-letter topic after … deliveries, and peek would count as one | do not peek this subscription: every delivery counts, and a message delivered too often goes to the dead-letter topic. Peek a subscription of the dead-letter topic instead, or raise maxDeliveryAttempts |
| `DEPLOY_FAILED` | 5 | key deploy could not add the key to the server's authorized_keys (the server's words follow) | check that ~/.ssh is writable there: `komando fs stat SERVER ~/.ssh` |
| `DIG_MISSING` | 3 | … records need dig, which is not installed on this server | install dig (Debian/Ubuntu: dnsutils, Alpine: bind-tools, RHEL: bind-utils), for example `komando pkg install TARGET dnsutils`; A and AAAA work without it |
| `DNS_ERROR` | 4 | the server's name does not resolve on this computer | the name does not resolve here: check it with `komando host show …` and fix it with `komando host edit … --address ADDRESS`; a name only a VPN resolves needs --via that VPN |
| `DOCKER_ERROR` | 5 | docker on the server answered with an error | check that Docker runs there: `komando exec TARGET --read-only -- docker info` |
| `DOCKER_MISSING` | 3 | docker not found | install Docker on the server, or pick another server |
| `DOCKER_PERMISSION` | 5 | the login user may not use docker on the server (add --sudo, or the docker group) | add --sudo, or add the login user to the docker group |
| `DOCTOR_FAILED` | 1 | some checks failed | fix the checks marked ✗ (ok: false in -o json), then run `komando doctor` again |
| `DRY_RUN_UNSUPPORTED` | 2 | this change cannot be previewed; run it without --dry-run to make it | run it again without --dry-run to make the change |
| `DUMP_FAILED` | 5 | the backup stopped before the end; no partial file is left | check the conn with `komando test …`; with --run-on HOST, pg_dump or mysqldump on that server runs instead |
| `DUMP_UNSUPPORTED` | 2 | komando's own dump cannot write an object (the message names it) | run pg_dump on a server that has it and can reach the database (--run-on HOST), or dump the other tables with --table |
| `ERROR` | 1 | an error with no more specific code (read the message) | read the message; `komando doctor` checks this computer's setup |
| `FAILED` | 5 | kubectl exited … | read the error output (stderr) for the reason; `komando cluster events TARGET --warnings` shows the cluster's recent problems |
| `FILE_ERROR` | 1 | a file on this computer cannot be read or written | check that the folder exists and is writable |
| `FILE_EXISTS` | 8 | … already exists on this computer | choose another --to, remove the file, or pass --overwrite |
| `FILE_NOT_FOUND` | 3 | identity file …: … | give the path of a private key file, or register it with `komando key add NAME FILE` and use --key |
| `FILE_TOO_LARGE` | 8 | …:… is more than …; komando holds a copy from a pod in memory, and stopped | copy a smaller part, or pack it smaller in the pod first: `komando cluster run TARGET --write -- exec POD -- gzip PATH` |
| `FOLDER_NOT_FOUND` | 3 | no folder named … | add -p/--parents to create it |
| `GCP_LOGIN_REQUIRED` | 4 | …: … | a person runs `gcloud auth application-default login` again, or set GOOGLE_APPLICATION_CREDENTIALS to a service account key file; on Google Cloud the machine's service account is used |
| `GROUP_EXISTS` | 8 | group … exists | pick another name; to merge them, run `komando group add … @…` and then `komando group rm …` |
| `GROUP_NOT_FOUND` | 3 | no group named … | run `komando group list` to see groups |
| `HELM_RELEASE_NOT_FOUND` | 3 | no Helm release named … in namespace … | see the releases with `komando cluster helm list TARGET -A`, and name the namespace with --namespace |
| `HELM_REVISION_NOT_FOUND` | 3 | … has no revision … | see the revisions with `komando cluster helm history TARGET RELEASE` |
| `HIDDEN_VALUE` | 2 | …/… holds a value komando hid from you ([hidden] or (hidden)); sending it would write that text over the real value | leave the hidden entries out of the file (or use valueFrom.secretKeyRef), or change only what you need with `cluster run TARGET --write -- set image\|patch ...` |
| `HOSTKEY_MISMATCH` | 4 | host key for … changed: the server was rebuilt, or someone is intercepting the connection | possible man-in-the-middle: report this to the user and do not re-trust the key yourself; once they have checked the new fingerprint another way, they can run `komando host trust … --reset` |
| `HOSTKEY_REVOKED` | 4 | … shows the revoked host key … | this key is on komando's list of revoked host keys: treat the server as compromised, tell its owner, and do not re-trust it with `komando host trust`; nothing was sent |
| `HOSTKEY_UNKNOWN` | 4 | host key for … is not trusted yet (host keys are strict) | compare the fingerprint with what the server's owner sees, then run `komando host trust …` (an AI agent asks the user: its pin needs their yes) |
| `HOSTKEY_UNREADABLE` | 4 | the pinned host key for … cannot be read | a person checks the server's key and runs `komando host trust` for it in their own terminal |
| `HOST_EXISTS` | 8 | … … already exists | use `komando … edit` or pass --overwrite to replace it |
| `HOST_IN_USE` | 8 | server … is on the --via path of … | change them first: … (or --via OTHER), or remove them in the same command |
| `HOST_NOT_FOUND` | 3 | no server named … | see them with `komando host list` |
| `IMPORT_INCOMPLETE` | 1 | … not imported (see skipped) | fix them in the source and import again: the rest is in, and importing again skips it |
| `INSECURE_PROTOCOL` | 2 | …:// crosses the network to … without TLS, so the password and the data travel unencrypted | use the URL's TLS form if the server has TLS (rediss://, memcacheds://, amqps://, nats tls://, kafka tls=true, an https:// endpoint, ftps://, webdavs://), or reach it --via an SSH server (`--via HOST`); otherwise add ?insecure=1 to accept that the login and the data travel unencrypted |
| `IS_A_DIRECTORY` | 2 | … is a folder, not a file | list it with `komando fs list TARGET …` |
| `IS_A_SYMLINK` | 8 | … is a symbolic link (--no-follow) | drop --no-follow to write the file it points to |
| `JOB_FAILED` | 5 | job exited with … | read its output with `komando job logs … --limit 50` |
| `JOB_KILLED` | 5 | job … was killed (…) | it was stopped with `komando job kill` |
| `JOB_LOST` | 5 | job … lost | it stopped without an exit code (killed, or the server restarted): `komando job logs … --limit 50` shows how far it got; start it again with `komando job start … -- …` if needed |
| `JOB_NOT_FOUND` | 3 | no job named … | see them with `komando job list` |
| `JOB_RUNNING` | 8 | job … is still running | stop it first with `komando job kill …`, or pass --kill to stop and remove it |
| `JOB_START_FAILED` | 5 | could not start job: … | check that /bin/sh and nohup work there: `komando test TARGET` |
| `JOURNAL_PERMISSION` | 5 | this user may not read the system journal | add --sudo, or add the login user to the systemd-journal group |
| `K8S_CONFLICT` | 8 | the object changed or exists already (the cluster's words follow) | the object changed meanwhile or exists already: look at it with `komando cluster get TARGET TYPE/NAME`, then run it again |
| `K8S_ERROR` | 5 | the Kubernetes API answered with an error (its words follow) | read the cluster's words; `komando cluster events TARGET --warnings` shows what went wrong lately |
| `K8S_FORBIDDEN` | 4 | listing Helm releases: … | Helm keeps releases as Secrets: the kubeconfig's user needs to list secrets there (or name one namespace with --namespace) |
| `K8S_INVALID` | 2 | the cluster refused the request as written (its words follow) | the cluster refused it as written: check the label selector (-l) or the object's YAML |
| `K8S_NOT_FOUND` | 3 | … has no running pod | check them with `komando cluster list TARGET pods` |
| `K8S_UNREACHABLE` | 4 | the Kubernetes API did not answer (address, --via path or VPN) | check the conn with `komando test TARGET` (and its --via path) |
| `KEYCHAIN_FAILED` | 5 | …; the store still uses store.key, nothing was lost | a person unlocks the keychain (an AI agent asks the user), then run it again; on Linux it needs secret-tool and a keyring |
| `KEYCHAIN_SLOW` | 1 | nothing was changed: the keychain did not answer in time, so komando could not check that … is the newest copy | run it again in a moment; if it keeps happening, run `komando doctor` |
| `KEYCHAIN_TAKEN` | 8 | …; the store still uses store.key, nothing was lost | put back the vault you moved aside, or once no vault needs that key, a person deletes the keychain item (an AI agent asks the user), then run it again |
| `KEYSCAN_FAILED` | 4 | cannot fetch host key from …: … | check the address and port with `komando host show …` |
| `KEY_EXISTS` | 8 | key … already exists | choose another name, or `komando key rm …` first |
| `KEY_INVALID` | 2 | cannot parse …: … | give an OpenSSH or PEM private key file |
| `KEY_IN_USE` | 8 | server … still uses this key | give the server another key first: `komando host edit … --key OTHER` |
| `KEY_NOT_FOUND` | 3 | no SSH key named … | see them with `komando key list` |
| `KEY_PASSPHRASE_REQUIRED` | 2 | key … is encrypted and … | load the key into ssh-agent with `ssh-add PATH`, or store its passphrase with `komando secret set NAME` (the hint gives the whole commands) |
| `KEY_UNREADABLE` | 4 | cannot read key …: … | check the key path (`komando key list` shows the keys komando knows) |
| `KILL_FAILED` | 5 | the server did not stop session … | you may lack the right to stop another user's session |
| `KUBECONFIG` | 2 | conn …: … | import it again with `komando import kubeconfig` |
| `LOGIN_FAILED` | 4 | the login to … ended early (…) | the whole log is … (for a person to read) |
| `MIXED_OS` | 2 | the target picks Windows servers (…) and other servers (…) | a command is written for one shell: run it twice, once with TARGET,os:windows (PowerShell) and once with TARGET,!os:windows (sh) |
| `NAME_TAKEN` | 8 | the rename clashes: …; nothing was renamed | pick other names, or rename or remove what is in the way first |
| `NEEDS_PERSON` | 6 | setting up the approval code shows its secret, so only a person at a terminal can do it | a person runs `komando config approval-code` in their own terminal |
| `NEEDS_TERMINAL` | 2 | cluster shell needs a person at a terminal | agents and scripts use `komando cluster exec` |
| `NOTHING_TO_RENAME` | 3 | no … starts with … | check OLD with `komando list` and `komando secret list`; names are matched from the start, as written |
| `NOT_A_FOLDER` | 8 | … is a file, not a folder | give a folder path, not a file |
| `NOT_FOUND` | 3 | INFO … returned nothing | this server has no such section; try `komando cache info CONN --all` |
| `NOT_SUPPORTED` | 2 | … waits for data that keeps coming, so cache run would never return | cache run sends one command and prints its one reply; drop BLOCK from XREAD, and use redis-cli for MONITOR or SUBSCRIBE |
| `NOT_SWARM_MANAGER` | 3 | … is not a Swarm manager (docker not found) | Swarm commands run on a manager: `komando exec … --read-only -- docker node ls` shows whether it is one |
| `NOT_TEXT` | 2 | … is not text | download it with `komando storage download CONN OBJECT` |
| `NOT_WRITABLE` | 8 | cannot replace …: …: …; nothing was changed | make … writable, or install komando in another folder with the install line (KOMANDO_INSTALL_DIR=DIR) |
| `NO_AUTH` | 4 | no authentication method available for …: it has no key or password, and … | start ssh-agent, then run … |
| `NO_CERTIFICATE` | 5 | … sent no certificate | check that … is the TLS port of the site |
| `NO_FOLDER` | 1 | cannot find the folder: … | set HOME, or run it from the project folder |
| `NO_JOURNAL` | 3 | journald has no log files on this server | the service may log to a file: `komando logs TARGET --file /var/log/...` |
| `NO_MATCH` | 8 | --old text not found in … | read the file with `komando fs cat TARGET …` and copy the exact text (whitespace matters) |
| `NO_MATCHING_TARGETS` | 3 | nothing to check | give a server, a TLS conn or a website (https://NAME): `komando cert check URL` |
| `NO_PACKAGE_MANAGER` | 3 | no supported package manager on this server | komando knows apt, dnf, yum, apk, zypper and pacman |
| `NO_PASSPHRASE` | 2 | the vault has no passphrase to take away | the vault keeps its key in store.key or the OS keychain already; the hint says which |
| `NO_PUBLIC_KEY` | 2 | komando does not have the public key of … | place ….pub next to the key, then `komando key rm …` and add it again |
| `NO_RECORDS` | 3 | … has no … records (or does not exist) from this server | check the name and type, and the server's DNS (/etc/resolv.conf) |
| `NO_RESPONSE` | 4 | no HTTP answer from … | check the URL, and that the server can reach it: `komando net check … ADDRESS:443` |
| `NO_SYSTEMD` | 3 | systemd is not running on this server | this server runs without systemd (a container?); read logs with `komando logs TARGET --file PATH` or `komando docker logs` |
| `NO_TUNNEL_NEEDED` | 2 | … has no --via, so it is reachable without a tunnel | connect to … directly |
| `NXDOMAIN` | 3 | … does not resolve from this server | check the name, and the server's DNS (/etc/resolv.conf) |
| `OBJECT_NOT_FOUND` | 3 | … not found | list files with `komando storage list CONN [PREFIX]` |
| `OPEN_BIND` | 6 | the tunnel would listen on … of …, open to its network (the default 127.0.0.1 keeps it to that computer) | check with --dry-run, ask the user; once they agree, run it again with --yes (komando then asks them in a window on their screen) |
| `OPTION_LIKE_VAR` | 2 | the value of … may not start with '-' (… would be read as an option) | for a path that starts with -, write ./… |
| `OUTPUT_TRUNCATED` | 1 | the rows are more than the output size cap (--max-output) allows; nothing was printed | raise --max-output (bytes, for example --max-output 104857600), or narrow the SQL with WHERE or LIMIT; a whole database copies with `komando db dump` |
| `OVPN_UNSUPPORTED` | 2 | the OpenVPN profile has an option komando's own client does not support (the message names it) | change the profile, or report the option you need at …/issues |
| `PACKAGE_NOT_FOUND` | 3 | …: no such package in the server's package index | check the name; refresh the index with `komando pkg update TARGET` if the package is new |
| `PARTIAL_FAILURE` | 1 | some targets failed and some worked (see each result) | see each result's error and hint |
| `PARTIAL_TRANSFER` | 5 | … could not be copied; the other files were copied | fix the listed ones (permissions?) and run it again |
| `PARTITION_NOT_FOUND` | 3 | topic … has no partition … (it has …) | partitions are numbered from 0; see them with `komando queue describe CONN …` |
| `PASSPHRASE_MISMATCH` | 2 | the two passphrases you typed differ; nothing was changed | run it again |
| `PATH_NOT_FOUND` | 3 | … does not exist (or holds no files) | check the source path; nothing was changed |
| `PERMISSION_DENIED` | 5 | cannot read … | add --sudo |
| `PKG_FAILED` | 5 | pkg … failed (exit …) | read the error output (stderr) for the package manager's message |
| `POLICY_BLOCKED` | 6 | the command matches destructive rules [rm-rf]: deletes files recursively | check with --dry-run, ask the user; once they agree, run it again with --allow-dangerous (komando then asks them in a window on their screen) |
| `PORT_CLOSED` | 5 | cannot connect to … | check the address, firewall or service on the other side |
| `PORT_IN_USE` | 8 | cannot listen on 127.0.0.1:…: … | pick another LOCAL port (`komando tunnel list` shows the ones komando holds) |
| `POWERSHELL_FAILED` | 5 | the login check in PowerShell failed on … (exit …): … | komando runs every command on Windows in Windows PowerShell (powershell.exe): check that it is on the PATH of the login user, and read the message |
| `PROTECTED_HOST` | 6 | this changes protected server …: … | check with --dry-run, ask the user; once they agree, run it again with --yes (komando then asks them in a window on their screen) |
| `PROTECTED_TARGET` | 6 | a change action on protected conn …: … | check with --dry-run, ask the user; once they agree, run it again with --yes (komando then asks them in a window on their screen) |
| `PROXY_FAILED` | 4 | proxy command for …: … | check the program in --proxy-command is installed |
| `PROXY_NOT_FIRST` | 2 | … has a proxy command but is reached through another hop | a proxy command can only start a path; put that server first in --via |
| `QUEUE_AUTH` | 4 | the brokers refused the login: … | check the user in the URL, the sasl= option and the password reference (`komando conn show NAME`) |
| `QUEUE_CONNECT` | 4 | cannot connect to …: … | run `komando test TARGET` to check reachability, or reach the server --via an SSH server that can |
| `QUEUE_DENIED` | 5 | the server refused the vhost …: … | check the vhost in the URL's path (%2F is the default vhost "/") and that the user has permissions on it |
| `QUEUE_ERROR` | 5 | …: could not give back the messages peek pulled: …; nothing is lost | Pub/Sub gives the messages out again once the subscription's ack deadline has passed |
| `QUEUE_EXISTS` | 8 | queue … already exists | pick another name, or see it with `komando queue describe CONN …` |
| `QUEUE_NOT_FOUND` | 3 | no queue named … | list queues with `komando queue list CONN` (it needs ?management=PORT in the conn's URL); the vhost is the URL's path |
| `READ_FAILED` | 5 | cannot read …: … | run it again; the output was cut (raise --max-output?) |
| `READ_ONLY_VIOLATION` | 6 | --read-only, but the command changes something (…) | it changes something, so it is not --read-only: tell the user what it changes, then run it without --read-only (a protected server also needs --yes) |
| `REBOOT_FAILED` | 5 | the reboot command failed (exit …): … | read the error output (stderr); without sudo rights a reboot is refused |
| `REBOOT_TIMEOUT` | 7 | … did not come back within … | check the server's console; komando did not reboot the servers after it |
| `RECIPE_BUILTIN` | 8 | … is a built-in recipe | pick another name; see `komando recipe list` |
| `RECIPE_CHANGED` | 8 | recipe … changed while komando was starting | run it again |
| `RECIPE_EXISTS` | 8 | recipe … exists | see it with `komando recipe show NAME`, or pass --overwrite to replace it |
| `RECIPE_NOT_FOUND` | 3 | no recipe named … | see them with `komando recipe list` |
| `REGISTRY_AUTH` | 4 | the registry refused to list its repositories: … | the login may read images but not list every repository: name one with `komando registry list CONN REPO`; else check the user in the conn URL and its --password-ref |
| `REGISTRY_ERROR` | 5 | the registry did not say the image's digest | run it again; if it keeps failing, the registry may not support this image format |
| `REGISTRY_NOT_FOUND` | 3 | no repository named … | list the repositories with `komando registry list CONN` |
| `REGISTRY_RATE_LIMIT` | 5 | the registry turned the request down: too many requests (Docker Hub's pull limit) | the registry limits how many requests it takes (Docker Hub: pulls per 6 hours, fewer without a login); wait and run it again |
| `REGISTRY_TLS` | 4 | the registry's TLS certificate is for another name: … | use the host name the certificate is for in the conn URL; with --via the server on the path looks the name up (its /etc/hosts applies) |
| `REGISTRY_UNREACHABLE` | 4 | the registry did not answer (address, TLS or --via path) | check the conn with `komando test TARGET` |
| `REGISTRY_UNSUPPORTED` | 5 | … has no list of every repository | name the repository: `komando registry list CONN REPO` (on Docker Hub, nginx means library/nginx) |
| `RELEASES_UNREACHABLE` | 4 | cannot reach komando's releases: … | check this computer's internet connection (and HTTPS_PROXY), then run it again |
| `REMOTE_ERROR` | 1 | an error from outside komando with no more specific code (its words follow) | run it again with -o json for the details; `komando doctor` checks this computer's setup |
| `RENAME_FAILED` | 1 | the vault cannot rename the VPN's secrets: …; nothing was renamed | check that the vault opens (`komando secret list`, KOMANDO_VAULT_PASS) |
| `RESERVED_SECRET` | 2 | secret … belongs to komando's approval code | a person manages it with `komando config approval-code` |
| `RESTORE_FAILED` | 5 | the restore stopped at a line: PostgreSQL changed nothing (one transaction), MySQL kept the statements before it | fix the file, then restore it again: `komando db restore … --from …` |
| `RESTORE_UNSUPPORTED` | 2 | line … switches to another database: … | the file switches databases (pg_dump --create or pg_dumpall); dump the one database without --create and restore that into this conn |
| `REVEAL_NEEDS_HUMAN` | 6 | --reveal only works for a person at a terminal | ask a person to run `komando secret show … --reveal` in a terminal; to use the secret in a command, reference it (secret:…) instead |
| `REVEAL_NEEDS_PERSON` | 6 | --reveal needs the user's yes | values stay [hidden] in a dry run; run it without --dry-run to ask the user in a window on their screen |
| `REVISION_NOT_FOUND` | 3 | no earlier revision to go back to | see the revisions with `komando cluster history TARGET TYPE/NAME` |
| `REVOKE_FAILED` | 5 | the key could not be removed from a server's authorized_keys | run it again; to look at the file: `komando fs cat SERVER ~/.ssh/authorized_keys` |
| `ROLLOUT_FAILED` | 5 | pods stuck for … | see why with `komando cluster describe TARGET …`; `komando cluster rollback` goes back |
| `ROLLOUT_TIMEOUT` | 7 | not rolled out after … (replicas …)… | see the tasks with `komando cluster describe … service/…` |
| `RULE_NOT_FOUND` | 3 | no custom deny rule named … | see the custom rules and their ids with `komando policy list` |
| `SAFETY_SETTING` | 6 | … weakens komando's safety checks | check with --dry-run, ask the user; once they agree, run it again with --yes (komando then asks them in a window on their screen) |
| `SECRET_DESTINATION` | 6 | an AI agent asked to send …; that needs a person's yes | check with --dry-run, ask the user; once they agree, run it again with --yes (komando then asks them in a window on their screen) |
| `SECRET_EXISTS` | 8 | secret … is used by … already; --ask-password and --ask-psk do not replace it | use it with --… …, or store this one under another name: `komando secret set NAME`, then --… secret:NAME |
| `SECRET_INPUT_INVALID` | 2 | … the value of a secret in komando's vault; an AI agent never sends one (this was written to the audit log) | never type a secret's value: put {{secret:NAME}} where komando takes it (fs write, fs replace, -e), or ask the user to keep the value with `komando secret set NAME` and use that name |
| `SECRET_IN_ARGS` | 2 | refusing a secret value on the command line: it would be saved in shell history | run `komando secret set …` and type it (hidden), use --from-env VAR, or pipe it in (stdin) |
| `SECRET_IN_USE` | 8 | secret … is used by … | point them at another secret first, for example `…`, or rename it with `komando secret rename` |
| `SECRET_MISMATCH` | 1 | the value is not the one stored in … | if the stored one is wrong, store the right one with `komando secret set …` |
| `SECRET_NOT_FOUND` | 3 | no secret named … | see them with `komando secret list` |
| `SECRET_UNRESOLVED` | 3 | registry CA …: … | store the CA certificate with `komando secret set NAME < ca.crt` |
| `SECURITY_UNSUPPORTED` | 3 | komando picks security updates on apt and dnf/yum servers only; … uses … | use `komando pkg upgrade TARGET` on these servers |
| `SELF_NOT_FOUND` | 1 | cannot find the komando program that is running: … | run komando by its full path, for example /usr/local/bin/komando update |
| `SENSITIVE_FILE` | 6 | … is …; komando does not read it for an AI agent | ask the user for the one value you need |
| `SESSION_NOT_FOUND` | 3 | no session … | list sessions with `komando db activity CONN --all` |
| `SFTP_UNAVAILABLE` | 4 | sftp: … | enable the sftp subsystem in sshd_config |
| `SHARED_FOLDER_CONFLICT` | 8 | … can be changed by …, not only by root and the SSH user: as root, komando does not write … there (that user could swap it for a link while root writes) | write it as … instead, for example `komando exec TARGET --sudo-user … --stdin-file FILE -- sh -c 'cat > "$0"' …` |
| `SKIPPED` | 1 | skipped: another server failed first, and --fail-fast is on | run without --fail-fast to reach every server |
| `SOURCE_BUILD` | 8 | this komando was built from source (version …), so update does not replace it | build it again (git pull, then make build), or install a release with the install line: https://github.com/sgnd/komando#install |
| `SOURCE_EMPTY` | 3 | … has no files to sync, so --delete would remove everything in … | check the source path; nothing was deleted |
| `SQL_HIDDEN_CODE` | 2 | -- is followed by a non-ASCII byte | put a space after -- to start a comment: whether this one starts a comment depends on the server's character set |
| `SQL_STRING_RULES` | 6 | this user's queries are read as …, not ClickHouse SQL | komando checks ClickHouse SQL; use a user whose settings profile keeps dialect = 'clickhouse' |
| `SQL_TX_CONTROL` | 2 | … is not allowed in komando db | leave transactions to komando: without --write it runs a read-only transaction, with --write one transaction that --dry-run rolls back |
| `SSH_AGENT_NEEDED` | 2 | a key komando made is sealed in its store and never written to a file, so OpenSSH gets it from a running ssh-agent, and none was found (SSH_AUTH_SOCK) | start one with `eval "$(ssh-agent)"` and run this again, or use `komando shell SERVER`, which logs in with the key itself |
| `SSH_AGENT_REFUSED` | 1 | the ssh-agent did not take key …: … | check the ssh-agent, or use `komando shell SERVER` |
| `SSH_GATE_PATH` | 1 | komando cannot tell its own full path, which the line needs | run komando by its full path, for example /usr/local/bin/komando ssh-gate line ... |
| `SSH_GATE_READ_ONLY` | 6 | komando … is refused for a read-only key: … | this key was added with --read-only and runs only commands that read; use a key that may change things, or the komando computer itself |
| `SSH_GATE_REFUSED` | 6 | komando … needs a person at a terminal on this computer; a key cannot run it | a person runs it in a terminal on the komando computer itself |
| `SSH_GATE_SYNTAX` | 2 | an ssh-gate key sent more than one komando command, or a character a shell would expand (the message names it) | send one komando command; put an argument with ; \| & $ or backquotes in single quotes ($ and backquotes are refused even in double quotes) |
| `SSM_FAILED` | 4 | AWS Session Manager could not open a session to the instance | check the instance ID, its SSM agent and your AWS login (`komando login aws`) |
| `STATE_CORRUPT` | 1 | … does not open with the store's key | the file holds only running VPN sessions, logins, jobs and tunnels: move it away, then connect again (a VPN started before the store's key changed is ended by `komando vpn down`) |
| `STORAGE_AUTH` | 4 | an azblob conn needs the storage account's key or a SAS token | store the account key or a SAS token with `komando secret set NAME` and pass --password-ref secret:NAME |
| `STORAGE_CONNECT` | 4 | komando could not reach the bucket or file server | run `komando test TARGET` to check reachability |
| `STORAGE_ERROR` | 5 | the file is in use | another program has the file open; close it there and run it again |
| `STORAGE_TLS` | 4 | the storage server's TLS certificate does not verify: … | if the server uses a self-signed certificate you trust, add ?tls=skip-verify to the conn URL |
| `STORE_BUSY` | 8 | komando's store stayed busy for …, so the server's host key could not be checked: … | another komando process is writing komando's store, or one is stuck (`komando status` lists what runs): wait for it to finish, then run it again |
| `STORE_KEY_CHANGED` | 1 | …: … | run it again: another komando changed the store's key while this one ran |
| `STORE_NEWER` | 1 | … was made by a newer komando | a newer komando made or changed this store; update this one: `komando update` |
| `STORE_OLD_COPY` | 6 | … …: servers, rules, secrets or pinned host keys may be old | if the komando folder was restored from a backup on purpose, a person runs `komando doctor --accept-old-copy` in their own terminal; otherwise find out who put an old copy back or changed the keychain |
| `STREAM_EXISTS` | 8 | stream … already exists | pick another name, or see it with `komando queue describe CONN …` |
| `STREAM_NOT_FOUND` | 3 | no stream named … | list streams with `komando queue list CONN` |
| `SUBSCRIPTION_EXISTS` | 8 | subscription … already exists | pick another name, or see it with `komando queue describe CONN subscriptions/…` |
| `SUBSCRIPTION_NOT_FOUND` | 3 | no subscription named … | list subscriptions with `komando queue groups CONN`; `komando queue describe CONN TOPIC` shows a topic's own |
| `SVC_FAILED` | 5 | systemctl daemon-reload failed (…) | read the error output (stderr) for systemd's reason; a unit file with a mistake is named there |
| `SWARM_ERROR` | 5 | Docker Swarm answered with an error | check that Docker runs there: `komando exec TARGET --read-only -- docker info` |
| `SYMLINK_LOOP` | 8 | …: too many levels of symbolic links | a link points back to itself; look at it with `komando fs stat SERVER PATH` |
| `TABLE_NOT_FOUND` | 3 | no table named … | run `komando db schema CONN` to list tables |
| `TARGET_EMPTY` | 3 | target … matched nothing | run `komando list` to see servers, conns, groups and tags |
| `TARGET_NOT_FOUND` | 3 | no server, conn or VPN named … | run `komando list` to see servers, conns and VPNs |
| `TIMEOUT` | 7 | redis did not answer in time | raise --timeout |
| `TLS_HANDSHAKE_FAILED` | 4 | TLS handshake with … failed: … | the server ended the TLS handshake; run it again, and check that … is the TLS port (not plain HTTP) |
| `TOOL_FAILED` | 5 | a program komando ran on the server failed (its words follow) | check that … is installed and works: `komando doctor` |
| `TOOL_MISSING` | 3 | curl is not installed | install curl on the server |
| `TOOL_TOO_OLD` | 5 | … failed on … (exit …): … | pg_dump … is older than the server (…): install postgresql-client-… where the tool runs, or name a server that has it with --run-on HOST |
| `TOO_MANY` | 8 | … objects match, more than --max-remove … | narrow --prefix or --older-than, or raise --max-remove above … after checking the list |
| `TOO_MANY_TAGS` | 2 | … has more than … tags | komando prunes a repository of at most 10000 tags, and --match does not change that (every tag is read, so a kept tag protects its image): delete some first with `komando registry rm CONN IMAGE` |
| `TOPIC_EXISTS` | 8 | topic … already exists | pick another name, or see it with `komando queue describe CONN …` |
| `TOPIC_NOT_FOUND` | 3 | no topic named … | list topics with `komando queue list CONN` |
| `TUNNEL_FAILED` | 4 | the server refused the port forwarding (AllowTcpForwarding, address) | check that the server allows forwarding (AllowTcpForwarding in sshd_config) and that the address is right |
| `TUNNEL_NOT_FOUND` | 3 | no tunnel named … | see them with `komando tunnel list` |
| `TUNNEL_TIMEOUT` | 7 | tunnel did not become ready… | check that … answers: `komando test …`; the whole log is … (for a person to read) |
| `UNEXPECTED_CHANGE` | 8 | … changed after patching: … | check the server (`komando docker ps …`, `komando svc list … --failed`); servers after it were not patched: run it again with --keep-going to patch them anyway |
| `UNEXPECTED_STATUS` | 5 | HTTP …, expected … | check the URL and the service behind it |
| `UNIT_NOT_ACTIVE` | 5 | not active after …s: … | read why with `komando logs TARGET --unit UNIT -n 50` |
| `UNIT_NOT_FOUND` | 3 | no unit named … | check the name with `komando svc list TARGET` |
| `UNKNOWN_SETTING` | 2 | komando has no setting named … | see the settings with `komando config show`: … |
| `UNKNOWN_VAR` | 2 | recipe … has no blank named … (…) | see the recipe with `komando recipe list` |
| `UNSAFE_BACKUP` | 6 | line … is a client command, not SQL: … | the file contains a client command that could run programs or read files where the restore runs; remove that line if the file is not from a trusted dump |
| `UNSAFE_PATH` | 5 | server sent the path …, which leads outside …; nothing outside the folder was written | check the server for odd file names |
| `UNSUPPORTED_PLATFORM` | 8 | there is no komando release for … | build komando from source: https://github.com/sgnd/komando#install |
| `UPLOAD_NOT_RENAMED` | 5 | could not rename the upload into place: …; the old file was removed | the new content is on the server as …: rename it by hand |
| `URL_HAS_PASSWORD` | 2 | a conn URL holds no password | remove the password from the URL, store it with `komando secret set NAME`, then pass --password-ref secret:NAME |
| `USAGE` | 2 | --… and --unset … contradict each other | pass one of them |
| `USER_NOT_FOUND` | 3 | no user named … | list the accounts with `komando user list TARGET --all` |
| `VALIDATION_FAILED` | 8 | --validate rejected the new file: …; the file was not changed | fix the content and run it again |
| `VAULT_CHANGED` | 8 | …; nothing was changed | run it again |
| `VAULT_DECRYPT` | 1 | password for … (…): … | KOMANDO_VAULT_PASS is not the passphrase this vault was saved with: set the right one (`komando doctor` says which vault mode is in use); nothing was lost |
| `VAULT_KEY` | 1 | password for … (…): … | restore ~/.komando/store.key from a backup, or move the key back with `komando secret keychain` on the computer whose keychain holds it; `komando doctor` checks the vault |
| `VAULT_LOCKED` | 1 | password for … (…): … | the person who set the passphrase exports KOMANDO_VAULT_PASS in the shell that runs komando (an AI agent asks the user; it never sees the passphrase) |
| `VERSION_NOT_FOUND` | 3 | komando … has no download for … | pick another version from …/releases |
| `VIA_CYCLE` | 2 | server … is in its own --via path | --via names the servers (or VPN) in front of this one, not the server itself |
| `VIA_NOT_FOUND` | 3 | no server or VPN named … | --via takes server and VPN names; see them with `komando list` |
| `VIA_ORDER` | 2 | …: the --via path reaches VPN … after another step | a path can use one VPN, as its first step |
| `VPN_CLIENT_MISSING` | 3 | … VPNs need the … program, which is not installed | install the program the message names (macOS: `brew install NAME`; Linux: its package) |
| `VPN_CONFIG` | 2 | …: … | check the file is a WireGuard (wg-quick) config |
| `VPN_DOWN` | 4 | VPN … did not start: … | the message ends with its log; `komando vpn test …` tries again, and the whole log is … (for a person to read) |
| `VPN_EXISTS` | 8 | … … already exists | use `komando … edit` or pass --overwrite to replace it |
| `VPN_IN_USE` | 8 | VPN … is on the --via path of … | change their --via first: `komando host edit TARGET --via OTHER` |
| `VPN_LOGIN_REQUIRED` | 4 | VPN … is not connected and needs a person to log in | ask a person to run `komando vpn up …` (it needs their login); then run it again |
| `VPN_NOT_FOR_OPENSSH` | 2 | VPN … (…) runs inside komando; OpenSSH cannot use it | use `komando shell SERVER` (it opens the VPN itself), or connect the VPN on this computer and leave it out of --via |
| `VPN_NOT_FOUND` | 3 | no VPN named … | see them with `komando vpn list` |
| `VPN_OS_MODE_REMOVED` | 2 | VPN … uses OpenVPN OS mode (--os-mode), which komando no longer has | add it again with komando's own client: `komando vpn add … openvpn --config FILE.ovpn --check HOST:PORT --overwrite` (plus --user and --password-ref if it logs in) |
| `VPN_STOP_FAILED` | 1 | could not disconnect …: … | run `komando vpn down …` again; if it still fails, end process … yourself |
| `WAIT_TIMEOUT` | 7 | job … still running after … | it is still running: `komando job wait …` waits again, `komando job logs … --limit 50` shows its output so far |
| `WEAK_PASSPHRASE` | 2 | …; nothing was changed | run it again with another passphrase |
| `WINRM_ERROR` | 5 | …: … | read the message; `winrm quickconfig` on the server sets WinRM up, and the user needs the right to use it (an administrator, or the Remote Management Users group) |
| `WINRM_INSECURE` | 2 | Basic login over plain HTTP sends the password unencrypted | use HTTPS (leave tls=off out), or NTLM (leave auth=basic out), which never sends the password |
| `WINRM_NOT_HTTPS` | 4 | …: … | the server speaks plain HTTP there: use port 5986 for HTTPS, or ?tls=off if it truly has no HTTPS (commands then travel unencrypted) |
| `WINRM_TLS` | 4 | …: the WinRM server's certificate cannot be trusted: … | if the server's certificate comes from your own CA, store it with `komando secret set NAME < ca.crt` and add ?ca=secret:NAME to its winrm:// address (`komando host edit … --address winrm://...`) |
| `WINRM_UNREACHABLE` | 4 | cannot reach … over WinRM: … | check the address and that WinRM listens there (port 5986 for HTTPS, 5985 for HTTP) and the firewall lets you in |
| `WRITE_FAILED` | 1 | …; nothing was changed | check that you may write to … |
| `WRITE_REQUIRES_FLAG` | 6 | … needs --write | this command may change data (or is not known to be a read); run it again with --write |
| `WRONG_KIND` | 2 | … is a … URL, not one for `komando … add` | add it with `komando … add` (or `komando conn add`) |
| `WRONG_PASSPHRASE` | 2 | that passphrase does not open the vault; nothing was changed | run it again and type the passphrase the vault has now |

## Codes shared by several things

These codes are given for more than one kind of item. `error.thing` says
which one (it is left out for the other codes). A later contract gives
each its own code; until then the code stays as it is.

| Code | `error.thing` | Codes it will split into |
|------|---------------|--------------------------|
| `KEY_NOT_FOUND` | `ssh_key`, `cache_key` | SSH_KEY_NOT_FOUND, CACHE_KEY_NOT_FOUND |
| `CONN_NOT_FOUND` | `conn`, `selector` | CONN_NOT_FOUND, TARGET_EMPTY |
| `NOT_FOUND` | `swarm_service`, `swarm_stack`, `swarm_node`, `swarm_task`, `swarm_config`, `swarm_secret`, `swarm_network`, `docker_object`, `cache_info_section` | SWARM_SERVICE_NOT_FOUND, SWARM_STACK_NOT_FOUND, SWARM_OBJECT_NOT_FOUND, DOCKER_OBJECT_NOT_FOUND, CACHE_SECTION_NOT_FOUND |
| `REGISTRY_NOT_FOUND` | `repository`, `image_tag` | REPOSITORY_NOT_FOUND, IMAGE_NOT_FOUND |
| `K8S_NOT_FOUND` | `k8s_object`, `k8s_pod`, `k8s_container` | K8S_NOT_FOUND, K8S_POD_NOT_FOUND, K8S_CONTAINER_NOT_FOUND |

## Codes that mean the same

Each row is codes that mean the same thing. All of them stay, since
scripts branch on them; new errors use the first one, and a later
contract keeps only that one.

| Codes | Use | Meaning |
|-------|-----|---------|
| `PROTECTED_TARGET`, `PROTECTED_HOST` | `PROTECTED_TARGET` | a protected item needs a person's yes (--yes); PROTECTED_HOST is the server case |
| `REVEAL_NEEDS_PERSON`, `REVEAL_NEEDS_HUMAN` | `REVEAL_NEEDS_PERSON` | --reveal needs a person; REVEAL_NEEDS_HUMAN is the case where no window can ask one, so only a person at a terminal can run it |
| `TARGET_EMPTY`, `NO_MATCHING_TARGETS`, `CONN_NOT_FOUND` | `TARGET_EMPTY` | the target picked nothing the command can use; CONN_NOT_FOUND counts only with error.thing selector |
| `CONN_UNREACHABLE`, `CONNECT_FAILED` | `CONN_UNREACHABLE` | komando could not reach the address |
| `TOOL_FAILED`, `FAILED` | `TOOL_FAILED` | a program komando ran (kubectl, a dump tool) failed; its words follow |
| `IS_A_DIRECTORY`, `USAGE` | `IS_A_DIRECTORY` | storage download of a folder without -r gives USAGE today; contract 2 gives IS_A_DIRECTORY, as fs cat does |
