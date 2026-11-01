# Servers

Add servers, log in with keys or passwords, and keep the list tidy. [All features](README.md)

## Add servers

```bash
komando host add web1 ubuntu@203.0.113.10                 # name + user@address
komando host add web2 ubuntu@203.0.113.11 --group web --tag prod
komando host add db1 admin@10.0.0.5 --jump bastion         # reached through "bastion"
komando host import --ssh-config ~/.ssh/config             # import what you already have
komando host list                                          # see them all
komando host test all                                      # can we log in everywhere?
```

Change or remove later:

```bash
komando host edit web1 --add-tag canary --port 2222
komando host edit web1 --protected        # production: changes need --yes
komando host rm web2
```

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
komando key gen deploy
komando key deploy deploy @web --set-default
```

**sudo needs a password?**

```bash
komando secret set web1-sudo
komando host edit web1 --sudo-ref secret:web1-sudo
```

References can also point to an environment variable (`env:MY_VAR`) or a
file (`file:/path`).
