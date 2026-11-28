# Clusters (Kubernetes and Docker Swarm)

See and change what runs in Kubernetes and Docker Swarm with one set of
commands. You do not need `kubectl` or `docker` on your computer: komando
speaks to the cluster itself. [All docs](README.md)

## Look at a cluster

```bash
komando import kubeconfig                  # one conn per kubeconfig context (see Add a cluster)
komando conn rename my-ctx-name prod-k8s   # give it a short name (import names it after the context)
komando test prod-k8s                      # can komando reach it and log in?
komando cluster kubernetes raw prod-k8s -- get nodes
komando cluster kubernetes raw prod-k8s -- get pods -A
```

Every cluster command is `cluster kubernetes raw` (or `cluster swarm raw`)
with the native command after `--`. See
[Anything else kubectl or docker can do](#anything-else-kubectl-or-docker-can-do).

## Add a cluster

### Kubernetes

komando reads your kubeconfig (the login file `kubectl` uses, usually
`~/.kube/config`) and adds one conn per context (one cluster and user in
that file):

```bash
komando import kubeconfig --dry-run           # see what would be added
komando import kubeconfig                     # reads $KUBECONFIG, else ~/.kube/config
komando conn edit prod-k8s --via bastion      # API server on a private network? reach it like anything else
```

Typed alone at a terminal, `komando cluster kubernetes add` asks for your
kubeconfig file.

How the login works:

- komando keeps each context's kubeconfig in the vault.
- It makes the EKS and GKE logins itself (`aws eks get-token`,
  `aws-iam-authenticator`, `gke-gcloud-auth-plugin`), so you do not need
  those programs. That login is made from this computer's AWS or Google
  Cloud login and sent to the kubeconfig's server, so an AI agent needs a
  person's yes (`--yes`) to import such a kubeconfig. It goes only over
  https with the server's certificate checked: a server at `http://`, or
  `insecure-skip-tls-verify` with no CA, stops with a usage error.
- Any other login program the kubeconfig names runs on this computer, so
  an AI agent needs a person's yes (`--yes`) to import it, as with a
  server's `--proxy-command`.
- Your own import records which file that program is (its full path) and
  the `PATH` of the import. An AI agent's command runs that file with that
  `PATH`, your real home folder and only a few plain variables (user,
  language, screen, temp folder) of its own environment: what the program
  needs beyond those goes in the kubeconfig's `env`. If the file is one
  that programs of your user can replace (Homebrew's `bin`,
  `~/.local/bin`, or on Windows a folder under Program Files that an
  installer let every user write) and its contents changed, for example after an update,
  agents are asked again until you import the kubeconfig again.
- An import an AI agent made with your yes trusts nothing for later: its
  cluster commands ask you each time, and after your yes the program runs
  with the system's `PATH`. Import the kubeconfig yourself to trust it.
- When that program is missing, cluster commands stop with `TOOL_MISSING`
  (exit 3) and the kubeconfig's own `installHint`. When it runs but cannot
  log in (it may want a person to sign in first), they stop with
  `LOGIN_FAILED` (exit 4).
- Once a person imported (or allowed) a kubeconfig, agents use the conn
  without asking. If the kubeconfig in the vault changes to another program
  or anything in its cluster block (the server, its CA, `tls-server-name`,
  `proxy-url`, `insecure-skip-tls-verify`; `secret set`), or reads its
  token from a local file (`tokenFile`), every agent command asks again,
  reads included, until a person imports it again. This holds for the EKS
  and GKE logins too.

komando checks the API server's certificate against the kubeconfig's CA.
A context with `insecure-skip-tls-verify` and no CA skips that check, as
kubectl does; the import names it in its notes, because its login goes
to whoever answers at that address. With a CA, the certificate is always
checked, even if `insecure-skip-tls-verify` is set too.

To add one cluster by hand, store its kubeconfig in the vault first, then
name it with `cluster kubernetes add` (the same as `conn add`, but it refuses a URL
that is not a cluster):

```bash
komando secret set prod-kubeconfig < prod.kubeconfig
komando cluster kubernetes add prod-k8s k8s://api.cluster.example:6443 --credential prod-kubeconfig
```

### Docker Swarm

A Swarm is reached through a manager server: add the manager as a server
and give it the tag `swarm`:

```bash
komando host add swarm1 admin@10.0.0.10 --tag swarm
komando host edit swarm1 --add-tag swarm     # a manager already in your list
```

`komando cluster swarm raw swarm1 -- ...` runs a docker command on that
manager (see [Run anything else](#anything-else-kubectl-or-docker-can-do)). The other `cluster
swarm` verbs (add, edit, list, remove, rename, show, test) wait for the
Swarm entry that the stored-data move gives (row C483).

### Remove a cluster from komando

```bash
komando conn rm prod-k8s                 # komando forgets it; the cluster is not touched
komando secret rm prod-kubeconfig        # its kubeconfig, once nothing uses it
```

`conn rm` lists the vault secrets nothing uses any more
(`secrets_unused`). It does not touch the cluster.

## Read and change what runs

```bash
komando cluster kubernetes raw prod-k8s -- get pods -n shop
komando cluster kubernetes raw prod-k8s -- get deploy -A
komando cluster kubernetes raw prod-k8s -- get pods -l app=api -n shop
komando cluster kubernetes raw prod-k8s -- describe deployment/api -n shop
komando cluster kubernetes raw prod-k8s -- get events -n shop --field-selector type=Warning
komando cluster kubernetes raw prod-k8s -- logs deploy/api -n shop --tail 100
komando cluster kubernetes raw prod-k8s --write -- set image deployment/api api=ghcr.io/acme/api:1.4.3 -n shop
komando cluster kubernetes raw prod-k8s -- rollout status deployment/api -n shop
komando cluster kubernetes raw prod-k8s --write -- rollout undo deployment/api -n shop
komando cluster kubernetes raw prod-k8s --write -- scale deployment/api --replicas=3 -n shop
komando cluster kubernetes raw prod-k8s --write -- rollout restart deployment/api -n shop
komando cluster kubernetes raw prod-k8s --write -- apply -f app.yaml --dry-run=server

komando cluster swarm raw swarm1 -- service ls
komando cluster swarm raw swarm1 -- service ps web
komando cluster swarm raw swarm1 --write -- service scale web=3
```

- On a protected cluster a change asks a person at a terminal; an AI agent
  or a script adds `--yes` after a person agrees (`PROTECTED_TARGET`,
  exit 6, without it).
- Delete, drain and scaling to 0 also need `--allow-dangerous`. komando no
  longer asks a person to type the object's name: the flag is the extra
  yes.
- The words after `--` are kubectl's (or docker's), so `-n` there is
  kubectl's namespace flag. Without it, kubectl's own default applies: the
  namespace of the kubeconfig context, else `default`. Change it for good
  with `komando conn edit prod-k8s --option namespace=shop`.
- A raw command runs on one cluster at a time. For several, run it on each.

### Helm releases (read-only)

The Helm releases of a cluster are Secrets labelled `owner=helm` that hold
the release as gzipped JSON. Read through raw, a Secret is masked, so two
built-in snippets decode them instead, without the helm program:

| Snippet | What it gives |
|---------|---------------|
| `helm-list` | the releases of the conn's namespace (the newest revision of each): name, namespace, revision, status, chart, app version. `--var namespace=NAME` names another one, `--var all-namespaces=1` reads every namespace |
| `helm-release` | one release (`--var release=NAME`, `--var namespace=NAME`, `--var revision=N`): status, notes, history of revisions and the values it was installed with (`values`, and `values_all` with the chart's defaults) |

Both only read; install, upgrade and rollback stay with `helm`. The
kubeconfig's user needs the right to list Secrets there (`K8S_FORBIDDEN`
otherwise). The ready-made snippets are off until the v0.18.0 cut turns them
on.

## Work inside a pod

```bash
komando cluster kubernetes exec prod-k8s deploy/api --namespace shop --read-only -- cat /app/config.yml
komando cluster kubernetes exec prod-k8s api-7d9f-x2 -c api --namespace shop -- php artisan cache:clear
komando cluster kubernetes tunnel start prod-k8s svc/api 8080:80 --namespace shop   # 127.0.0.1:8080 until Ctrl-C
komando cluster kubernetes shell prod-k8s deploy/api --namespace shop          # interactive, for people
```

- `cluster kubernetes exec` runs one command (not interactive). The
  dangerous-command filter checks it, as with `exec` on servers.
  `--read-only` says it only looks, checked as for `exec`: only a
  command komando knows only reads runs (`cat`, `ls`, `printenv` ...);
  anything else is refused (`READ_ONLY_VIOLATION`; see [Commands](commands.md#protected-servers-and---read-only)).
- `cluster kubernetes tunnel start` makes a pod or service port reachable on this
  computer only (127.0.0.1). For a service, the service port is forwarded to
  the pod port behind it. Ctrl-C or `--timeout` ends it normally. What goes
  through it skips komando's checks, so a protected cluster asks first
  (`--yes`), and the audit log records the forward.
- `cluster kubernetes shell` opens a terminal in the pod (bash, else sh) for a
  person, and asks first on a protected cluster. Agents get
  `NEEDS_TERMINAL` and use `cluster kubernetes exec` instead.
- komando speaks Kubernetes' exec and port-forward protocols itself:
  WebSocket, and SPDY on clusters older than Kubernetes 1.30, as kubectl
  does. A pod or service that does not exist is "not found" (exit 3).

## Anything else kubectl or docker can do

```bash
komando cluster kubernetes raw prod-k8s -- get pods -A -o wide
komando cluster kubernetes raw prod-k8s --write -- rollout undo deployment/api -n shop
komando cluster swarm raw swarm1 -- service ps web
```

On Kubernetes, `cluster kubernetes raw` is komando's own kubectl. It understands kubectl
commands and prints what kubectl prints, through the conn's `--via` path,
with no kubectl installed. On Swarm the command goes to docker on the
manager. The words after `--` are kubectl's (or docker's), so `-n` there
is kubectl's namespace flag.

- It only reads unless you add `--write`. Delete, drain, scaling to 0 and
  similar also need `--allow-dangerous`.
- A file (`apply -f`, `create -f`) is rated by
  what is in it. One that gives out rights (a Role, ClusterRole or their
  bindings, a webhook configuration, an APIService, a service account
  token Secret, EKS's `aws-auth` ConfigMap) or opens a node to a pod
  (`hostPID`, `hostNetwork`, `hostIPC`, a privileged container, added
  capabilities, a `hostPath` volume, a pod in `kube-system` that runs as
  one of its service accounts) also needs `--allow-dangerous`, like
  `create clusterrolebinding` and `run --privileged` do. So does an
  object a controller installs with its own rights: a k3s `HelmChart`, an
  Argo CD `Application`, `ApplicationSet` or `AppProject`, a Flux
  `Kustomization` or `HelmRelease`. The same holds for a Swarm stack file
  whose service is privileged, adds capabilities or devices, shares the
  server's namespaces, or mounts `/`, the docker socket, system or
  credential folders. komando reads each file once, so the file that was
  rated is the file that is sent.
- `label` that sets `pod-security.kubernetes.io/enforce=privileged` on a
  namespace, or removes that label, and `set serviceaccount` need
  `--allow-dangerous` too. A Namespace in a manifest (`apply -f`,
  `run -- apply|create -f`) with that label is read by the same rule.
  A Namespace that sets other `pod-security.kubernetes.io/` labels but
  leaves `enforce` out counts as removing it: `apply` drops a label the
  last apply set. A Namespace with no pod-security labels is not rated,
  because komando cannot see the live labels and such manifests are
  common. Lowering `enforce` to `baseline` is not rated, as with `label`.
- `-k` (`--kustomize`) is refused: komando checks every manifest it sends
  and does not render kustomize. Render it first (`kubectl kustomize DIR >
  app.yaml`) and pass `-f app.yaml`.
- A compose or stack file already on the server (`stack deploy -c FILE`,
  `docker compose -f FILE up`, or compose's own file names when there is
  no `-f`, with their override files) is read there first (at most
  1 MiB, without sudo) and rated the same way. These count as dangerous
  too, because komando cannot check what they lead to: a file it cannot
  read, `include:`, `extends:` with another `file:`, `privileged` left to
  a variable, and a `COMPOSE_FILE` in the folder's `.env`.
- The rating reads the file a moment before docker does. Someone who can
  change that file on the server can swap it in between: the rating stops
  an agent's mistake and a file that was dangerous already, not a person
  who can already write there.
- `--dry-run` sends a change to the server as a server-side dry run
  (`apply`, `create`, `delete`, `scale`, `patch`, ...). A command the server
  cannot dry-run (`exec`, `cp`, `create token`, `config view`, `get` of
  Secret values for a person) is only shown, not run.
- For AI agents, Secret values and env values named like secrets
  (`DB_PASSWORD`) show as hidden in `get` output, so
  `get secret -o yaml` is a read for them. `apply`, `create` and `replace`
  refuse a file that still holds a hidden value (`HIDDEN_VALUE`): change
  one field with `set image` or `patch` instead.
- For AI agents, files of this computer that would go to the cluster
  (`-f`, `--from-file`, `cp` to a pod) may not be secrets by their name
  (`.env`, keys) unless the person allows `--reveal`, and never komando's
  own folder (`SENSITIVE_FILE`).
- `delete -f FILE` deletes each object in the namespace its file names,
  and refuses a `-n` that says otherwise. An empty name is refused.
- `cp POD:SRC DST` writes only inside DST, never into a `.git` folder, and
  skips links and devices, like kubectl cp. It brings at most 512 MiB
  (`FILE_TOO_LARGE`): komando checks every name before it writes any, so
  it holds the copy in memory. For an AI agent it copies as `download`
  does: a file that is a secret by its name (`.env`, a private key) is
  refused (`SENSITIVE_FILE`; when SRC itself is named so, before komando
  reads the pod), a text file is written with its secret
  values `[hidden]`, and a binary or larger file that holds a vault value
  is refused; nothing is written when any file is refused.
- On Swarm, `docker run`, `create` and `service create|update` that give a
  container the server (`--privileged`, `--cap-add`, devices, the host's
  network or processes, `--volumes-from`, a bind of `/`, the docker socket,
  system or credential folders) also need `--allow-dangerous`, as do
  `plugin install|create|enable|set` and a `volume create` that is a host
  folder.
- It stops at `--timeout` (default 5 minutes). A watch (`get -w`) or follow
  (`logs -f`) that ends there ends normally. `logs -f` prints lines as they
  come and follows all selected pods at once (`--max-log-requests`, 5 by
  default).
- A Swarm stack file goes to the manager as a file that is already there:
  put it on the manager, then `stack deploy -c FILE` reads it there. Raw
  cannot send a file over standard input.
- Sessions have their own commands: `cluster kubernetes tunnel start` (port-forward) and
  `cluster kubernetes shell` (`exec -it`).
- A command it does not know gets a "did you mean". The commands it knows
  are in [Reference](#reference).

## Limits

- `cluster kubernetes raw` knows kubectl's own commands, not kubectl plugins (krew).
  `edit` is refused (get the YAML, change it, then `apply -f`), and of
  `config` only `current-context` and `get-contexts` work.
- komando cannot tell which service accounts outside `kube-system` have
  strong rights (an operator's own namespace, `argocd`, `flux-system`),
  nor that a kubeconfig's default namespace is `kube-system`.
- Helm: komando reads releases only; install, upgrade and rollback stay
  with `helm`.

## Troubleshooting

| Code | What it means | What to do |
|------|---------------|------------|
| `TOOL_MISSING` (exit 3) | the login program the kubeconfig names is not installed | install it; the error shows the kubeconfig's `installHint` |
| `LOGIN_FAILED` (exit 4) | the login program ran but could not log in | a person signs in with that program, then run it again |
| `CONN_UNREACHABLE` (exit 4) | the API server did not answer | `komando test prod-k8s`, and check its `--via` path or VPN |
| `K8S_FORBIDDEN` (exit 4) | the kubeconfig's user may not do this (Helm: list Secrets) | give the user the right, or name one namespace with `--namespace` |
| `K8S_INVALID` (exit 2) | the cluster refused the request or the file as written | read the cluster's words in the message; fix the YAML or the `-l` selector |
| `K8S_POD_NOT_FOUND` (exit 3) | the workload has no running pod to read or run in | `komando cluster kubernetes raw prod-k8s -- get pods -n shop` |
| `NOT_SWARM_MANAGER` (exit 3) | the server is not a Swarm manager | name a manager; `komando exec swarm1 --read-only -- docker node ls` shows whether it is one |
| `ROLLOUT_FAILED` (exit 5), `ROLLOUT_TIMEOUT` (exit 7) | the new version did not come up | `komando cluster kubernetes raw prod-k8s -- describe deployment/api -n shop`, then `-- rollout undo` |
| `HIDDEN_VALUE` (exit 2) | the file holds a value komando hid from an AI agent | leave hidden entries out, or change one field with `cluster kubernetes raw ... --write -- set image` or `patch` |
| `NEEDS_TERMINAL` (exit 2) | `cluster kubernetes shell` needs a person | agents and scripts use `cluster kubernetes exec` |

## Reference

Kubectl commands `cluster kubernetes raw` knows:

| Group | Commands |
|-------|----------|
| Read | `get` (server tables, `-o wide\|name\|json\|yaml\|jsonpath=...\|custom-columns=...`, `-w`, `-l`, `-A`), `describe`, `logs`, `events`, `top`, `explain`, `version`, `api-resources`, `api-versions`, `cluster-info`, `auth can-i`, `auth whoami`, `wait` |
| Roll out | `rollout status\|history\|undo\|restart\|pause\|resume`, `set image`, `scale` |
| Change | `apply`, `diff`, `create` (`-f`, namespace, configmap, secret, deployment, job, cronjob, service, role, rolebinding, token), `replace`, `delete`, `patch`, `label`, `annotate` |
| Nodes | `cordon`, `uncordon`, `drain`, `taint` |
| Pods | `run`, `exec`, `cp`, `debug` |
| Other | `certificate approve\|deny`, `config` |
