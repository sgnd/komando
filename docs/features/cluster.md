# Clusters (Kubernetes and Docker Swarm)

See and change what runs in Kubernetes and Docker Swarm with one set of
commands. You do not need `kubectl` or `docker` on your computer: komando
speaks to the cluster itself. [All docs](README.md)

A cluster command is `komando cluster PROVIDER VERB NAME`: the provider is
`kubernetes` or `swarm`, and NAME is the cluster's name in komando's list.
Looking, deploying and changing all go through one verb, `raw`: the words
after `--` are kubectl's (or docker's), and komando checks them before it
sends them. Only `exec`, `shell` and `tunnel` are komando's own verbs, on
`cluster kubernetes`.

## Check a cluster's health

```bash
komando cluster kubernetes list                                 # your Kubernetes clusters
komando test prod-k8s                                           # can komando reach it and log in?
komando cluster kubernetes raw prod-k8s -- get nodes
komando cluster kubernetes raw prod-k8s -- get pods -A --field-selector=status.phase!=Running
```

Typed alone at a terminal, `komando cluster kubernetes raw` asks which
cluster, with a list of yours to pick from, then what to run.

```text
NAMESPACE  NAME                  READY  STATUS            RESTARTS  AGE
shop       api-7d9f-x2           0/1    CrashLoopBackOff  14        2d
```

The first command shows the nodes, the second the pods that are not
running. On Swarm, the same questions are `node ls` and `service ls`:

```bash
komando cluster swarm raw swarm1 -- node ls                     # nodes that are down or drained
komando cluster swarm raw swarm1 -- service ls                  # services short of replicas
```

komando no longer builds a one-page health summary of a cluster. The
questions above are the way to ask it.

## Add a cluster

### Kubernetes

komando keeps the cluster's kubeconfig (the login file `kubectl` uses) as
a credential and an entry points at it. The kubeconfig is never typed on a
command line, and there is no import of a kubeconfig file. One entry holds
one context (one cluster and user in that file):

```bash
komando credential token add prod-kubeconfig                    # the kubeconfig, prod.kubeconfig
komando cluster kubernetes add prod-k8s --kubeconfig-credential prod-kubeconfig --context prod
komando cluster kubernetes edit prod-k8s --via bastion          # API server on a private network? reach it like anything else
```

TODO(cut): how a kubeconfig file is given to `credential token add` waits
on the `Options` of that leaf (PR B).

Typed alone at a terminal, `komando cluster kubernetes add` asks for each
part step by step.

How the login works:

- komando keeps each context's kubeconfig in a credential.
- It makes the EKS and GKE logins itself (`aws eks get-token`,
  `aws-iam-authenticator`, `gke-gcloud-auth-plugin`), so you do not need
  those programs. That login is made from this computer's AWS or Google
  Cloud login and sent to the kubeconfig's server, so an AI agent needs a
  person's yes (`--yes`) to add such a cluster. It goes only over
  https with the server's certificate checked: a server at `http://`, or
  `insecure-skip-tls-verify` with no CA, stops with a usage error.
- Any other login program the kubeconfig names runs on this computer, so
  an AI agent needs a person's yes (`--yes`) to add it, as with a
  server's `--proxy-command`.
- A cluster you add records which file that program is (its full path) and
  the `PATH` of the command. An AI agent's command runs that file with that
  `PATH`, your real home folder and only a few plain variables (user,
  language, screen, temp folder) of its own environment: what the program
  needs beyond those goes in the kubeconfig's `env`. If the file is one
  that programs of your user can replace (Homebrew's `bin`,
  `~/.local/bin`, or on Windows a folder under Program Files that an
  installer let every user write) and its contents changed, for example after an update,
  agents are asked again until you add the cluster again.
- A cluster an AI agent added with your yes trusts nothing for later: its
  cluster commands ask you each time, and after your yes the program runs
  with the system's `PATH`. Add the cluster yourself to trust it.
- When that program is missing, cluster commands stop with `TOOL_MISSING`
  (exit 3) and the kubeconfig's own `installHint`. When it runs but cannot
  log in (it may want a person to sign in first), they stop with
  `LOGIN_FAILED` (exit 4).
- Once a person added (or allowed) a cluster, agents use the entry
  without asking. If the kubeconfig in its credential changes to another
  program or anything in its cluster block (the server, its CA,
  `tls-server-name`, `proxy-url`, `insecure-skip-tls-verify`), or reads its
  token from a local file (`tokenFile`), every agent command asks again,
  reads included, until a person adds the cluster again. This holds for the
  EKS and GKE logins too.

komando checks the API server's certificate against the kubeconfig's CA.
A context with `insecure-skip-tls-verify` and no CA skips that check, as
kubectl does; the add names it in its notes, because its login goes
to whoever answers at that address. With a CA, the certificate is always
checked, even if `insecure-skip-tls-verify` is set too.

### Docker Swarm

A Swarm is reached through a manager server, and it is its own entry under
the provider `swarm`:

```bash
komando cluster swarm add swarm1
komando test swarm1
```

Typed alone at a terminal, `komando cluster swarm add` asks for each part
step by step.

TODO(cut): how a Swarm entry names its manager server (today a server
tagged `swarm`) waits on O-41.

### Remove a cluster from komando

```bash
komando cluster kubernetes remove prod-k8s       # komando forgets it; the cluster is not touched
komando credential token remove prod-kubeconfig  # its kubeconfig, once nothing uses it
```

`remove` takes the cluster off komando's list only. Deleting an object
inside the cluster is `delete` through `raw`.

## Name objects

Every command names objects the way kubectl does: `TYPE NAME` or
`TYPE/NAME` (`deployment api`, `deploy/api`, `deployment.apps/api`). If you
mistype a kind, the error suggests the one you probably meant.

- Name a namespace (see [Glossary](glossary.md)) with kubectl's `-n` after
  the `--`. Without it, komando uses the cluster's usual namespace: the one
  its kubeconfig context names, else `default`. Change it for good with
  `komando cluster kubernetes edit prod-k8s --option namespace=shop`.
- `-A` (`--all-namespaces`) is kubectl's too: `get pods -A`.
- Swarm kinds are `service` (`svc`), `task`, `node` and `stack`. Swarm
  has no namespaces.

TODO(cut): the komando-side cluster flags (`--namespace`,
`--all-namespaces`, `--selector`, `--revision`) wait on the `Options` of
each leaf in the table (PR C).

## Look around

```bash
komando cluster kubernetes raw prod-k8s -- get pods -n shop
komando cluster kubernetes raw prod-k8s -- get deploy -A                     # every namespace
komando cluster kubernetes raw prod-k8s -- get pods -n shop -l app=api       # only objects with these labels
komando cluster kubernetes raw prod-k8s -- describe deployment/api -n shop   # images, strategy, pods, events
komando cluster kubernetes raw prod-k8s -- get events -n shop --field-selector type=Warning --sort-by=.lastTimestamp
komando cluster kubernetes raw prod-k8s -- get deploy/api -n shop -o yaml    # the whole object (Secret values hidden)

komando cluster swarm raw swarm1 -- service ls
komando cluster swarm raw swarm1 -- service ps web                           # tasks of a service
komando cluster swarm raw swarm1 -- service inspect web --pretty             # image, replicas, update state
```

```text
$ komando cluster kubernetes raw prod-k8s -- get deploy -n shop
NAME   READY   UP-TO-DATE   AVAILABLE   AGE
api    3/3     3            3           12d
web    2/2     2            2           40d
```

In text mode the tables look like kubectl's. In JSON the reply is under
`data`.

`raw` takes one cluster (NAME). To look at several, run it once for each.

### Helm releases

komando does not run the `helm` program. Helm keeps each release as a Secret
in the cluster, so the releases and their revisions are listed with
kubectl:

```bash
komando cluster kubernetes raw prod-k8s -- get secrets -A -l owner=helm
komando cluster kubernetes raw prod-k8s -- get secrets -n shop -l name=shop-api,owner=helm
```

The kubeconfig's user needs to list Secrets in that namespace
(`K8S_FORBIDDEN` otherwise). Install, upgrade and rollback of a release
stay with `helm`. To change what runs from komando, set a new image or
apply manifests, for example the output of `helm template`: see
[Deploy a new version](#deploy-a-new-version-and-roll-back).

TODO(cut): reading a release's values, status and history waits on the
decision whether `raw` runs `helm` words (the replaced `cluster helm`
commands of the cut plan, section 1.6).

## Read logs

```bash
komando cluster kubernetes raw prod-k8s -- logs api-7d9f-x2 -n shop --since=10m --tail=100   # one pod
komando cluster kubernetes raw prod-k8s -- logs deploy/api -n shop -f                        # a workload, following
komando cluster kubernetes raw prod-k8s -- logs -l app=api -n shop --tail=50                 # every pod with a label
komando cluster kubernetes raw prod-k8s -- logs api-7d9f-x2 -n shop --previous               # the run before the last restart
komando cluster swarm raw swarm1 -- service logs web -f --tail 100                           # a Swarm service
```

```text
GET /health 200 1ms
GET /orders 500 32ms
```

- `-f` keeps reading new lines. Ctrl-C or `--timeout` ends it normally.
- `--since` takes a duration (`10m`, `2h`) or a time (`2026-01-02T10:00:00Z`).
- `--timestamps` starts each line with its time; `-c` picks a container.
- `logs -f` prints lines as they come and follows all selected pods at once
  (`--max-log-requests`, 5 by default).

## Deploy a new version, and roll back

```bash
komando cluster kubernetes raw prod-k8s --write -- set image deployment/api api=ghcr.io/acme/api:1.4.3 -n shop
komando cluster kubernetes raw prod-k8s -- rollout status deployment/api -n shop    # has it rolled out?
komando cluster kubernetes raw prod-k8s -- rollout history deployment/api -n shop   # revisions and their images
komando cluster kubernetes raw prod-k8s --write -- rollout undo deployment/api -n shop                  # back to the previous one
komando cluster kubernetes raw prod-k8s --write -- rollout undo deployment/api --to-revision=3 -n shop  # back to revision 3

komando cluster swarm raw swarm1 --write -- service update --image nginx:1.27 web
komando cluster swarm raw swarm1 --write -- service rollback web
```

Typed alone at a terminal, `komando cluster kubernetes raw` asks for the
cluster, then the command.

`set image` takes `CONTAINER=IMAGE`, so with several containers in a pod
it names the one that gets the image. `rollout status` stays until every
replica runs the new version and ends with kubectl's own words when it does
not; `--timeout` (global, default 5 minutes) stops the wait.

`rollout undo` without `--to-revision` goes to the previous revision. With
`--to-revision` it goes to that one.

Run a change with `--dry-run` first: komando sends it to the server as a
server-side dry run, and it never blocks.

## Change the cluster

```bash
komando cluster kubernetes raw prod-k8s --write --dry-run -- apply -f app.yaml   # the server checks it; nothing changes
komando cluster kubernetes raw prod-k8s --write -- apply -f app.yaml             # created / configured / unchanged per object
komando cluster kubernetes raw prod-k8s --write -- rollout restart deployment/api -n shop
komando cluster kubernetes raw prod-k8s --write -- scale deployment/api --replicas=3 -n shop
komando cluster kubernetes raw prod-k8s --write -- delete pod/api-7d9f-x2 -n shop

komando cluster swarm raw swarm1 --write --dry-run -- stack deploy -c compose.yml shop
komando cluster swarm raw swarm1 --write -- stack deploy -c compose.yml shop
komando cluster swarm raw swarm1 --write -- service scale web=4
```

- `apply` sends the file to the server as a dry run first with
  `--dry-run`. If the cluster refuses one object (a typo, an unknown field
  or kind), it stops there and nothing in the file is applied
  (`K8S_INVALID`).
- A field another tool owns (an autoscaler's replicas, a `kubectl edit`)
  stops `apply` with `K8S_CONFLICT`, which names that tool and the fields,
  and nothing is applied. Leave those fields out of the file, or add
  `--force-conflicts` after the `--` to take them over (as
  `kubectl apply --server-side --force-conflicts` does). It is still a
  change: a protected cluster needs a person's yes, as without it.
- A dry run of `apply` shows what would be created or changed. Secret
  values never show for an AI agent.
- An object whose namespace in the file differs from `-n` is refused, as
  kubectl does.
- A protected cluster needs a person's yes before any change.
- Scaling to 0 and `delete` stop things. An AI agent or a script adds
  `--allow-dangerous` after a person agrees; without it, it gets
  `POLICY_BLOCKED` (exit 6). See [Safety](safety.md#what-needs-a-yes).
  One loss to know: through `raw`, a person at a terminal is asked only for
  `--allow-dangerous`, no longer to type the object's name. For a cluster
  that matters, mark it protected (`komando cluster kubernetes edit
  prod-k8s --protected`), which adds a person's yes to every change.

## Work inside a pod

```bash
komando cluster kubernetes exec prod-k8s deploy/api -n shop --read-only -- cat /app/config.yml
komando cluster kubernetes exec prod-k8s api-7d9f-x2 -c api -n shop -- php artisan cache:clear
komando cluster kubernetes tunnel start prod-k8s svc/api 8080:80 -n shop   # 127.0.0.1:8080 until Ctrl-C
komando cluster kubernetes shell prod-k8s deploy/api -n shop                # interactive, for people
```

- `exec` runs one command (not interactive). The
  dangerous-command filter checks it, as with `exec` on servers.
  `--read-only` says it only looks, checked as for `exec`: only a
  command komando knows only reads runs (`cat`, `ls`, `printenv` ...);
  anything else is refused (`READ_ONLY_VIOLATION`; see [Commands](commands.md#protected-servers-and---read-only)).
- `cluster kubernetes tunnel start` makes a pod or service port reachable on this
  computer only (127.0.0.1). For a service, the service port is forwarded to
  the pod port behind it. Ctrl-C or `--timeout` ends it normally. What goes
  through it skips komando's checks, so a protected cluster asks first
  (`--yes`), and the audit log records the tunnel.
- `shell` opens a terminal in the pod (bash, else sh) for a
  person, and asks first on a protected cluster. Agents get
  `NEEDS_TERMINAL` and use `exec` instead.
- komando speaks Kubernetes' exec and port-forward protocols itself:
  WebSocket, and SPDY on clusters older than Kubernetes 1.30, as kubectl
  does. A pod or service that does not exist is "not found" (exit 3).

## Anything else kubectl or docker can do

`raw` sends any kubectl command. It only reads unless you add `--write`:

```bash
komando cluster kubernetes raw prod-k8s -- get pods -A -o wide
komando cluster kubernetes raw prod-k8s --write -- rollout undo deployment/api -n shop
komando cluster swarm raw swarm1 -- service ps web
```

On Kubernetes, `raw` is komando's own kubectl. It understands kubectl
commands and prints what kubectl prints, through the entry's `--via` path,
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
  `create -f`) with that label is read by the same rule.
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
  it holds the copy in memory. For an AI agent it copies as `komando copy`
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
  (`logs -f`) that ends there ends normally.
- Sessions have their own commands: `cluster kubernetes tunnel start`
  (port-forward) and `cluster kubernetes shell` (`exec -it`).
- A command it does not know gets a "did you mean". The commands it knows
  are in [Reference](#reference).

## Limits

- `raw` knows kubectl's own commands, not kubectl plugins (krew).
  `edit` is refused (get the YAML, change it, then `apply -f`), and of
  `config` only `current-context` and `get-contexts` work.
- komando cannot tell which service accounts outside `kube-system` have
  strong rights (an operator's own namespace, `argocd`, `flux-system`),
  nor that a kubeconfig's default namespace is `kube-system`.
- komando does not run Helm: install, upgrade and rollback stay with
  `helm`.

## Troubleshooting

| Code | What it means | What to do |
|------|---------------|------------|
| `TOOL_MISSING` (exit 3) | the login program the kubeconfig names is not installed | install it; the error shows the kubeconfig's `installHint` |
| `LOGIN_FAILED` (exit 4) | the login program ran but could not log in | a person signs in with that program, then run it again |
| `CONN_UNREACHABLE` (exit 4) | the API server did not answer | `komando test prod-k8s`, and check its `--via` path or VPN |
| `K8S_FORBIDDEN` (exit 4) | the kubeconfig's user may not do this (Helm: list Secrets) | give the user the right, or name one namespace with `-n` |
| `K8S_INVALID` (exit 2) | the cluster refused the request or the file as written | read the cluster's words in the message; fix the YAML or the `-l` selector |
| `K8S_POD_NOT_FOUND` (exit 3) | the workload has no running pod to read or run in | `komando cluster kubernetes raw prod-k8s -- get pods -n shop` |
| `NOT_SWARM_MANAGER` (exit 3) | the server is not a Swarm manager | name a manager; `komando host ssh exec swarm1 --read-only -- docker node ls` shows whether it is one |
| `HIDDEN_VALUE` (exit 2) | the file holds a value komando hid from an AI agent | leave hidden entries out, or change one field with `raw --write -- set image` or `patch` |
| `NEEDS_TERMINAL` (exit 2) | `shell` needs a person | agents and scripts use `exec` |
| `USAGE` (exit 2) | the words for the cluster came without `--` | put `--` before kubectl's words |

## Reference

Kubectl commands `raw` knows:

| Group | Commands |
|-------|----------|
| Read | `get` (server tables, `-o wide\|name\|json\|yaml\|jsonpath=...\|custom-columns=...`, `-w`, `-l`, `-A`), `describe`, `logs`, `events`, `top`, `explain`, `version`, `api-resources`, `api-versions`, `cluster-info`, `auth can-i`, `auth whoami`, `wait` |
| Roll out | `rollout status\|history\|undo\|restart\|pause\|resume`, `set image`, `scale` |
| Change | `apply`, `diff`, `create` (`-f`, namespace, configmap, secret, deployment, job, cronjob, service, role, rolebinding, token), `replace`, `delete`, `patch`, `label`, `annotate` |
| Nodes | `cordon`, `uncordon`, `drain`, `taint` |
| Pods | `run`, `exec`, `cp`, `debug` |
| Other | `certificate approve\|deny`, `config` |
