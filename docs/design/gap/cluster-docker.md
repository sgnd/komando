# Feature gap analysis: Kubernetes, Docker Swarm, Docker/Compose on hosts

> **Snapshot of `feat/v0.3` (commit 4784fc9), 2026-11-02.** Many MISSING and
> PARTIAL rows below were done in Phases 1–5 and the built-in work, and no
> feature needs kubectl, psql, the aws CLI or openvpn any more (only Pulse
> VPNs still use openconnect).
> Current status: [README.md](README.md#still-open).

Scope: `komando cluster` (Kubernetes + Swarm), `komando docker` (one host /
fleet over SSH), `komando logs --container`, container-related `ops` recipes.
Compared with kubectl, kubectx/kubens, k9s, stern/kail, helm, kustomize,
kubeseal, Lens, krew (neat, tree, who-can), popeye, kube-capacity, velero,
Docker CLI, docker compose, lazydocker, ctop, dive, Docker Swarm, Portainer,
Nomad, Podman.

Sources of evidence: `internal/cli/cluster.go`, `internal/kube/kube.go`,
`internal/cli/modules.go` (docker part), `internal/cli/ops.go` (recipes),
`internal/policy/policy.go`, `internal/cli/exec.go`/`common.go` (guards),
`docs/features/cluster.md`, `docs/features/system.md`, `docs/design/vision.md`,
`docs/design/ux.md`, and `bin/komando --help`.

## Legend

- **PRESENT**: there is a first-class, structured command/flag with risk classification.
- **PARTIAL**: it exists, but something is lacking (missing flag, unstructured output,
  only through a workaround, or inconsistent safety).
- **MISSING**: there is no first-class command. If there is a workaround
  (`cluster run -- <kubectl>`, `cluster run -- <docker>` on a Swarm manager,
  `docker raw`, `exec`), it is named in the notes column.
- **NON-GOAL**: deliberately not built, according to `docs/design/vision.md`
  ("Non-goals"). One exception: "Impersonation `--as`" is deliberately rejected
  by the code for safety (not from vision.md), but it is still counted here
  because it is not a gap.
- Priority: **P1** daily need / safety / agent blocker;
  **P2** used often but there is a reasonable workaround; **P3** rare/niche.

Non-goal quotes used (vision.md, "Non-goals"):

- NG-1: "Replacing full tools (`psql`, `kubectl`, `terraform`, `helm`).
  komando handles 80% of daily work safely. The rest can still be
  done through `exec` on the host or the original tool."
- NG-2: "Infrastructure as Code, cloud provisioning, or GitOps."
- NG-3: "GUI, TUI, plugin system, or daemon/server. komando stays a pure CLI."
- NG-4: "Monitoring or alerting that runs continuously."

Important notes about workarounds:

- `cluster run TARGET -- ARGS` runs **local kubectl** (temporary kubeconfig
  from the vault, through `--via`) or **docker on the Swarm manager**.
  Read-only unless `--write`; risky verbs (`delete`, `drain`, `exec`, `cp`,
  `port-forward`, `debug`, `patch`, `edit`, `taint`, `cordon`...) also need
  `--allow-dangerous` (`classifyKubectl`/`classifyDocker`, cluster.go:843-895).
  JSON output is only `{stdout, stderr, exit_code}` (raw text), not structured
  data. The flags `--context/--kubeconfig/--as/--token/--dry-run` are rejected (cluster.go:811-813).
  **There is no workaround for helm** (only kubectl).
- `docker raw TARGET -- ARGS` runs any docker command on the host, **always
  treated as mutating** (modules.go:387) with no read/write/destructive classification;
  only the global policy pattern (`docker-prune-all`) blocks anything.

---

## 1. Connection, context, and target

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Import kubeconfig, one conn per context | kubectl config, Lens | PRESENT | `komando import kubeconfig [--dry-run]`; kubeconfig per context into the vault (`importKubeconfig`, cluster.go:1066) | - |
| Switch cluster/context | kubectx, `kubectl config use-context` | PRESENT | The concept is replaced by a conn name per command (`cluster ls prod ...`); there is no "active context" state that can be wrong | - |
| List contexts | `kubectl config get-contexts` | PRESENT | `komando list kind:conn` / `conn list`; `cluster run -- config get-contexts` is classified read | - |
| Default namespace per cluster (change) | kubens, `kubectl config set-context --namespace` | PARTIAL | The default namespace is taken from the kubeconfig context at import (`importKubeconfig` stores it as the `namespace` option, cluster.go:1096-1097; fallback `default`, kube.go:240-243); `--namespace` per command. The default **can** be changed without re-importing: `conn edit prod --option namespace=shop` (conn.go:75/214), used by `kubeClient` (cluster.go:78). What is lacking: `cluster run` (kubectl) ignores that option and uses the namespace from the kubeconfig in the vault (`runKubectl`, cluster.go:985); this option is also not documented in docs/features/cluster.md | P3 - the path already exists; only `cluster run` consistency and docs remain |
| Exec auth plugin (EKS/GKE/AKS token) | kubectl | PRESENT | `bearer()` runs the exec plugin (kube.go:256); docs/features/cluster.md | - |
| Private API server through bastion/VPN | kubectl + manual ssh tunnel, Lens | PRESENT | `conn edit prod --via bastion`; kubectl in `cluster run` goes through a local tunnel (`forwardLocal`) with the real TLS server name | - |
| Docker Swarm as target | `docker context`, Portainer | PRESENT | The manager server is used directly as the target (`resolveCluster`) | - |
| Remote Docker host | `docker context`, `DOCKER_HOST=ssh://` | PRESENT | All `komando docker ... TARGET` go over SSH; supports the `@group` selector (parallel fleet) | - |
| One command to many clusters at once | k9s (no), kubectl (no), Lens (catalog) | MISSING | `resolveCluster` rejects >1 cluster: "this command works on one" (cluster.go:59). For `docker`, fleet works | P2 - vision: universal `@prod` selector; `cluster status @prod` for a summary of all clusters |
| Check cluster connection | `kubectl cluster-info`, `kubectl version` | PRESENT | `cluster status` (version through `/version`, cluster.go:226, which also tests login); `komando test <conn>` only checks TCP to the API server (`testConn`, conn.go:490-501), not authentication | - |
| Podman as engine | podman CLI, podman-remote | MISSING | The `docker` command is hardcoded (modules.go); only the `podman-docker` alias on the host or `exec -- podman ...` | P3 - small market on servers; possible through `exec` |
| Nomad as orchestrator | nomad CLI | MISSING | vision.md:95 "later: nomad" (planned, not yet built) | P3 - few users, already planned |
| Local k3s/kind/minikube | kubectl | PRESENT | generic k8s conn (vision.md:95) | - |
| OpenShift (`oc`), Rancher | oc, rancher CLI | PARTIAL | The generic k8s API works (CRD discovery); special verbs (`oc login`, project, route) do not | P3 - niche |

## 2. Viewing objects and status (get/describe/insight)

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List objects of any type (including CRDs, shortnames) | `kubectl get`, k9s | PRESENT | `cluster ls TARGET TYPE` with discovery + shortNames (kube.go:353-412); `--namespace`, `--all-namespaces`, `-n/--limit` | - |
| Short columns per kind (pods, deploy, sts, ds, svc, node, secret) | `kubectl get` | PRESENT | `summarize()` (cluster.go:273): status, ready, restarts, node, ports, version | - |
| Columns for other kinds (ingress, pvc, pv, job, cronjob, hpa, configmap, event, namespace) | `kubectl get` (server-side printer columns) | PARTIAL | Other kinds get only `name/namespace/age`. Does not use the `Table` API (`Accept: application/json;as=Table`), which gives kubectl columns for all kinds including CRDs | P1 - the agent must `get` one by one to learn the status of a PVC/Job/Ingress |
| `-o wide` (pod IP, node, nominated) | `kubectl get -o wide` | PARTIAL | Pod: node is there, pod IP is not; workaround `cluster run -- get pods -o wide` (text) | P3 |
| Label filter `-l app=api` | `kubectl get -l`, k9s filter | MISSING | `cluster ls` has no `--selector`; only `cluster run -- get pods -l app=api` (raw text) | P1 - the main way to pick pods of a deployment; important for agents |
| Field filter (`status.phase!=Running`, `spec.nodeName=`) | `kubectl get --field-selector` | MISSING | Only used internally in `cluster status`; workaround `cluster run` | P2 |
| Pagination / continue | `kubectl get --chunk-size` | PARTIAL | `--limit` + `truncated: true`, but no `--continue` for the next page | P3 |
| Full object (YAML/JSON) | `kubectl get -o yaml` | PRESENT | `cluster get TARGET TYPE NAME`; `managedFields` removed; Secrets redacted | - |
| "Clean" object for re-apply | kubectl-neat | PARTIAL | `managedFields` removed, but `status`, `uid`, `resourceVersion`, `creationTimestamp`, the `last-applied` annotation stay | P3 |
| Describe (object + related events, human summary) | `kubectl describe`, k9s `d`, Lens | MISSING | `cluster get` does not include events; workaround `cluster run -- describe pod X` (read, text) | P1 - first debug step (ImagePullBackOff, FailedScheduling, OOMKilled) |
| Cluster/namespace events, time-sorted, Warning only | `kubectl events --types=Warning`, `get events --sort-by` | PARTIAL | `cluster ls prod events` works through discovery, but only name/age (no reason/message/object, no sort, no Warning filter) | P1 - core of "what is wrong" diagnosis for agents |
| Cluster health summary | Lens overview, k9s pulses, popeye | PARTIAL | `cluster status`: version, ready nodes, "not running" pods based on **phase** only (fieldSelector `status.phase!=Running,status.phase!=Succeeded`, cluster.go:235). A `CrashLoopBackOff` pod has phase `Running` → missed; `ImagePullBackOff` (phase `Pending`) is listed but with no reason; deployments with `ready < desired`, node pressure (Memory/Disk/PID), Pending PVCs, failed Jobs, Warning events are not reported | P1 - the command promises "what is not healthy"; agents rely on it |
| Swarm health summary | Portainer, `docker service ls` | PARTIAL | `cluster status swarm1` only returns raw JSON of `docker info/node ls/service ls`; does not count services with replicas `1/3`, Down/Drain nodes, failed tasks | P2 |
| Config lint/sanitizing (no limits, latest tag, missing probes) | popeye, kube-score, Polaris | MISSING | - | P3 - "nice to have", not 80% daily work |
| Ownership tree (Deployment→RS→Pod) | kubectl-tree, Lens | MISSING | - | P3 |
| Pod & node CPU/mem usage | `kubectl top`, k9s, Lens | MISSING | Workaround `cluster run -- top pods -A` (read, needs metrics-server, text) | P2 - daily question "who is eating memory" |
| Capacity: request/limit vs allocatable per node | kube-capacity, Lens | MISSING | Workaround `cluster run -- describe nodes` | P2 |
| List resource types | `kubectl api-resources` | PARTIAL | Discovery exists internally (kube.go:353) but is not exposed; `cluster run -- api-resources` (read) | P3 |
| Field documentation | `kubectl explain` | PARTIAL | Only `cluster run -- explain deploy.spec` (read) | P3 |
| Watch changes (`-w`) | `kubectl get -w`, k9s | MISSING | Not a non-goal: vision.md does not mention watch, and short-lived streaming already exists in komando (`logs --follow`, ux.md:108 `-f`); NG-4 is only about continuous monitoring/alerting. The workaround `cluster run -- get pods -w` (read) is only useful in text mode (JSON mode holds output, cluster.go:1032-1036) | P3 - rarely needed by agents; `rollout status`/`wait` matter more |
| Interactive dashboard | k9s, Lens, lazydocker, Portainer UI | NON-GOAL | NG-3: "GUI, TUI ... komando stays a pure CLI" | - |

## 3. Logs

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Log of one pod, tail N, since, timestamps | `kubectl logs --tail --since --timestamps` | PRESENT | `cluster logs TARGET POD -n --since` (timestamps always) | - |
| Pick container, previous run | `kubectl logs -c`, `--previous` | PRESENT | `--container/-c`, `--previous` | - |
| Follow (`-f`) pod | `kubectl logs -f`, stern | MISSING | `cluster logs` has no `--follow`, even though ux.md:108 promises `-f` for follow and `komando logs --follow` already exists for hosts. Workaround `cluster run -- logs -f POD` (text mode only; JSON mode holds output until done) | P1 - daily need during deploys; consistency of the `logs` verb |
| Log by workload (`deploy/api`, `svc/x`) | `kubectl logs deploy/api` | MISSING | The path is always `pods/<name>` (cluster.go:507); you must find the pod name first | P1 - random pod names change on every rollout; agent needs 2 steps |
| Logs of many pods via selector / name regex | stern, kail, `kubectl logs -l` | MISSING | No `--selector`; `cluster run -- logs -l app=api --prefix` as a workaround | P1 - multi-replica services: the error can be in any replica |
| All containers in a pod | `kubectl logs --all-containers` | MISSING | Workaround `cluster run` | P2 - sidecars (istio, cloudsql-proxy) |
| Filter log content (grep) | stern `--include/--exclude` | MISSING | `komando logs` (host) has `--grep`, `cluster logs` does not | P2 - consistency with `logs --grep` |
| `--until` / time range | journalctl, docker logs `--until` | MISSING | The k8s API does not support until; can be filtered client-side | P3 |
| Swarm service log (tail, since) | `docker service logs` | PRESENT | `cluster logs swarm1 web -n --since` (`--no-trunc --timestamps`) | - |
| Follow Swarm service log | `docker service logs -f` | MISSING | No `--follow`; `cluster run swarm1 -- service logs -f web` (buffered until timeout) | P2 |
| Container log on host (tail/since/until/grep/follow) | `docker logs`, lazydocker | PRESENT | `logs TARGET --container C` with `-f/--follow`, `--grep`, `--since`, `--until`, `-n` (modules.go:173-256; follow through `followLogs`, modules.go:272-273). Note: the alias `docker logs TARGET C` accepts `-f` but calls `runOne`, not `followLogs` (modules.go:320-323) → output is held until timeout; small bug, correct follow is through `komando logs --container` | - |
| Container logs on many hosts at once | ctop (no), Portainer (per env) | PRESENT | `komando logs @web --container api` (fleet) | - |
| Compose project log (all services) | `docker compose logs --tail -f` | PARTIAL | `docker compose TARGET -- logs --tail 50` (text); `-f` through runOne is buffered until timeout | P3 |

## 4. Access and debugging of workloads

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Exec command in pod (non-interactive) | `kubectl exec POD -- cmd` | PARTIAL | Only `cluster run --write --allow-dangerous -- exec POD -- cmd`. No first-class exec with `--read-only` like `docker exec --read-only`; even read commands (`cat /etc/app.conf`, `env`) need `--allow-dangerous` | P1 - daily debugging; forces the agent to use `--allow-dangerous`, which should be rare (rule 7 AGENTS.md) |
| Interactive exec (`-it` shell) | `kubectl exec -it`, k9s `s`, Lens | PARTIAL | `cluster run ... -- exec -it POD -- sh` works in text mode (stdin connected, cluster.go:1035); no first-class command | P2 - for humans; agents do not need it |
| Copy files to/from pod | `kubectl cp` | PARTIAL | `cluster run --write --allow-dangerous -- cp`; no integration with `komando cp TARGET:PATH` | P2 |
| Port-forward to pod/service | `kubectl port-forward`, k9s, Lens | PARTIAL | `cluster run --write --allow-dangerous -- port-forward svc/x 8080:80` blocks in the foreground; not integrated with `komando tunnel start` (which supports db/host conns, not k8s services) | P1 - access to DBs/internal admin UIs in the cluster; agent needs background + local address like `tunnel start` |
| `kubectl proxy` | kubectl | PARTIAL | `cluster run ... -- proxy` (destructive); rarely needed | P3 |
| Ephemeral debug container / node debug | `kubectl debug` | PARTIAL | Only through `cluster run --write --allow-dangerous`; cannot `--dry-run` (cluster.go:1025-1026) | P3 |
| Temporary pod (busybox/netshoot) | `kubectl run --rm -it` | PARTIAL | `cluster run --write -- run tmp --image=busybox --rm -it` (text) | P3 |
| Attach | `kubectl attach` | PARTIAL | `cluster run` (destructive) | P3 |
| Exec in container (host) | `docker exec` | PRESENT | `docker exec TARGET C -- cmd` with `--read-only`, policy checked on the inner command (modules.go:352) | - |
| Interactive container exec (host, `-it`) | `docker exec -it`, lazydocker | PARTIAL | `docker exec` uses `-i` without a TTY; no `--pty` (while `komando exec` has `--pty`) | P2 - shell into a container for humans |
| Copy files host<->container | `docker cp` | PARTIAL | `docker raw -- cp` (mutating, not considered destructive); no `cp TARGET:container:/path` | P3 |
| Exec in Swarm task / container on another node | `docker exec` on the node | MISSING | You must find the task's node and then `docker exec` on that node; no help | P3 |

## 5. Deploy, rollout, and object changes (Kubernetes)

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Apply multi-document YAML, server-side apply | `kubectl apply --server-side` | PRESENT | `cluster apply TARGET --file F` (stdin `-`), field manager `komando` | - |
| Server dry-run | `kubectl apply --dry-run=server` | PRESENT | Global `--dry-run` → `dryRun=All` | - |
| Diff before apply | `kubectl diff`, Argo/helm-diff | MISSING | ux.md:332 says "`apply` always with a diff and `--dry-run=server` first", but `cluster apply --dry-run` only returns a list of object names (cluster.go:708-710), with no diff. Workaround `cluster run -- diff -f app.yaml` (read) | P1 - safety: humans/agents must see what changes before writing |
| Field manager conflicts | `kubectl apply --server-side` (no force by default) | PARTIAL | Always `force=true` (cluster.go:691): takes over fields owned by other managers (HPA, other controllers) without warning | P2 - safety; better not to force unless asked |
| Apply directory / many files / URL | `kubectl apply -f dir/ -R` | MISSING | `--file` is one file; workaround `cat *.yaml \| ... --file -` | P2 |
| Kustomize | `kubectl apply -k`, kustomize | MISSING | Workaround `kustomize build \| komando cluster apply --file -` or `cluster run --write -- apply -k` | P2 - common in app repos; but can be piped |
| CRD then CR order in one file | kubectl (re-discovery) | PARTIAL | Discovery is cached once (kube.go:353); a CR whose CRD was just created in the same file fails with "does not serve" | P3 |
| Non-preferred apiVersion (e.g. `autoscaling/v1`) | kubectl | PARTIAL | `ResourceFor` only knows the preferred version of each group (kube.go:395) → manifests with an old version that is still served are rejected | P2 - confusing error for old YAML |
| Prune objects that are not in the file | `kubectl apply --prune`, ApplySet | NON-GOAL | NG-2 (GitOps); `--prune` is classified destructive in `cluster run` | - |
| Change image (deploy a new version) | `kubectl set image`, k9s | MISSING | Workaround `cluster run --write -- set image deploy/api api=repo:tag`; Swarm `cluster run --write -- service update --image` | P1 - most common deploy action; worth making first-class with an old→new image audit and a rollback hint |
| Rollout status / wait until done | `kubectl rollout status`, `kubectl wait` | MISSING | `cluster restart`/`scale`/`apply` return right away without waiting; workaround `cluster run -- rollout status deploy/api --timeout 5m` (read) | P1 - the agent needs to know whether the change succeeded before reporting |
| Rollout history | `kubectl rollout history` | PARTIAL | `cluster run -- rollout history` (read, text); `cluster ls replicasets` without revision/image | P2 |
| Rollback (undo) | `kubectl rollout undo`, helm rollback | MISSING | Only `cluster run --write -- rollout undo` (shown as an example in the docs); not first-class, no summary of the target revision | P1 - the most important way back when a deploy fails; AGENTS.md rule 11 asks for a rollback method |
| Pause/resume rollout | `kubectl rollout pause/resume` | PARTIAL | `cluster run --write` | P3 |
| Rolling restart | `kubectl rollout restart` | PRESENT | `cluster restart TARGET deployment/api` (deploy/sts/ds), server dry-run | - |
| Scale | `kubectl scale` | PRESENT | `cluster scale TARGET TYPE/NAME N`; 0 → `--allow-dangerous` | - |
| Conditional scale (`--current-replicas`) | `kubectl scale --current-replicas` | MISSING | No check of the starting value; output does not mention the previous replicas (useful for rollback) | P2 - safety/rollback |
| Autoscale (HPA) create/view | `kubectl autoscale`, `get hpa` | PARTIAL | `cluster ls hpa` only name/age; create through `cluster run --write -- autoscale` or YAML | P3 |
| Patch | `kubectl patch` | PARTIAL | `cluster run --write --allow-dangerous -- patch` (patch is considered destructive) | P3 |
| Edit in editor | `kubectl edit`, k9s `e` | PARTIAL | `cluster run` (destructive, text mode); the suggested safe flow: `cluster get` → edit file → `cluster apply --dry-run` | P3 |
| Label/annotate | `kubectl label/annotate` | PARTIAL | `cluster run --write -- label ...` | P3 |
| Create Secret/ConfigMap from file/literal | `kubectl create secret generic --from-literal`, `create configmap` | PARTIAL | `cluster run --write -- create secret ... --from-literal=k=v`: audit is safe (`redactArgs`, cluster.go:1110-1129, hides values of arguments that contain literal/password/token/secret, in both `=` and space form), but the value still goes through the argv of local kubectl; no integration from `komando secret` (vault) → k8s Secret | P2 - vision manages secrets; safe path from vault to cluster |
| Delete object | `kubectl delete` | PRESENT | `cluster rm TARGET TYPE NAME --allow-dangerous`, server dry-run | - |
| Delete many / by selector, `--cascade`, `--grace-period` | `kubectl delete -l`, `--force` | MISSING | `cluster rm` is one object; the rest is `cluster run --allow-dangerous` | P3 |
| Replace | `kubectl replace` | PARTIAL | `cluster run` (destructive) | P3 |
| Run a Job from a CronJob now | `kubectl create job --from=cronjob/x` | PARTIAL | `cluster run --write -- create job ...` | P2 - common ops action (manual backup, migration) |
| Suspend/resume CronJob | `kubectl patch cronjob -p '{"spec":{"suspend":true}}'` | PARTIAL | `cluster run --allow-dangerous -- patch` | P3 |
| Wait for condition (`wait --for=condition`) | `kubectl wait` | PARTIAL | `cluster run -- wait` (read) | P2 |
| Helm-style template/values | helm template, kustomize | NON-GOAL | NG-1 (not a helm replacement) and NG-2 (IaC) | - |

## 6. Nodes and capacity (Kubernetes)

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List nodes + Ready status + version | `kubectl get nodes` | PRESENT | `cluster ls prod nodes` (status, kubelet version); `cluster status` ready nodes | - |
| Node conditions (MemoryPressure, DiskPressure), taints, role, IP | `kubectl describe node`, k9s | PARTIAL | Only in `cluster get node X` (full JSON); not summarized in ls/status | P2 |
| Cordon/uncordon | `kubectl cordon/uncordon` | PARTIAL | `cluster run --write --allow-dangerous -- cordon NODE` | P2 - routine node maintenance |
| Drain | `kubectl drain --ignore-daemonsets --delete-emptydir-data` | PARTIAL | `cluster run --write --allow-dangerous -- drain`; no summary of the pods that will move or of the PDBs that block; server `--dry-run` is supported by kubectl | P2 - maintenance; worth making safe and structured |
| Taint | `kubectl taint` | PARTIAL | `cluster run --allow-dangerous` | P3 |
| Pods per node | `kubectl get pods --field-selector spec.nodeName=` | PARTIAL | `cluster ls pods -A` has a node column; no filter | P3 |
| Shell into node | `kubectl debug node/x`, ssh | PARTIAL | If the node is registered as a komando host: `komando exec/shell`; `kubectl debug node` through `cluster run` | P3 |

## 7. RBAC, security, and secrets (Kubernetes)

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Secret values hidden | Lens (hidden by default) | PARTIAL | `cluster get` redacts Secrets (cluster.go:327), `cluster ls` shows only the key count. **But** `cluster run -- get secret X -o yaml` or `-o jsonpath='{.data}'` is classified read and prints the values (base64) without redaction; `get pods -o yaml` also shows inline env | P1 - safety/rule 9 AGENTS.md: the agent can leak secrets through a read-only workaround |
| See one Secret value on human request | `kubectl get secret -o jsonpath \| base64 -d` | MISSING | No equivalent of `secret get --reveal` for k8s Secrets (other than the leaky workaround above) | P2 - consistent with `komando secret get --reveal` |
| Check permissions (`can-i`, `whoami`) | `kubectl auth can-i --list`, `auth whoami` | PARTIAL | `cluster run -- auth can-i ...` (read); no first-class permission check before an action | P2 - the agent could check before trying |
| Who can do X | kubectl-who-can, rbac-lookup | MISSING | - | P3 |
| Sealed Secrets | kubeseal | MISSING | - | P3 - GitOps (NG-2) tends to be out of scope |
| Approve CSR / certificates | `kubectl certificate approve` | PARTIAL | `cluster run --allow-dangerous` | P3 |
| Impersonation `--as` | kubectl | NON-GOAL (deliberately rejected) | `kubectlForbidden` rejects `--as`, `--as-group`, `--as-uid`, `--token`, `--context` (cluster.go:811-813): identity is set by the conn. Not listed in "Non-goals" of vision.md; this is a safety decision in the code, not a gap | - |
| Audit every change | kubectl (no), Lens (no) | PRESENT | `withKube`/`runKubectl` write an audit for risk > read; `komando audit` | - |
| Protected cluster (confirmation) | - | PRESENT | Conn `--protected` → changes need `--yes` (docs/features/cluster.md) | - |

## 8. Helm and the package ecosystem

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| List releases (`helm list -A`) | helm, Lens | MISSING | No helm workaround (`cluster run` is kubectl only); releases are visible as `sh.helm.release.v1.*` Secrets via `cluster ls secrets` | P2 - read-only, asked often; can be read from Secrets without the helm binary |
| Release status/history | `helm status`, `helm history` | MISSING | - | P2 - diagnosis of "which chart version is running" |
| Values used by a release | `helm get values` | MISSING | - | P3 |
| Release rollback | `helm rollback` | MISSING | - | P2 - standard way back for helm-based clusters |
| Install/upgrade/uninstall chart | `helm upgrade --install` | NON-GOAL | NG-1: "Replacing full tools (... `helm`)" - use the real helm | - |
| Template, repo add/update, plugins | `helm template`, `helm repo` | NON-GOAL | NG-1 / NG-2 | - |
| Kustomize build | kustomize | NON-GOAL | NG-1 (replacing full tools; vision.md does not name kustomize explicitly, but rendering manifests = the job of the original tool); can be piped into `cluster apply --file -`. Applying the result is recorded separately in section 5 ("Kustomize", MISSING) | - |
| Cluster backup/restore | velero | NON-GOAL | NG-1 (another full tool) / NG-2; `cluster get` per object can serve as a manual backup | - |
| krew plugins | krew | NON-GOAL | NG-3: "plugin system" | - |

## 9. Docker Swarm

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Swarm status | `docker info`, `node ls`, `service ls` | PARTIAL | `cluster status swarm1` (raw JSON, no "what is not healthy" analysis) | P2 |
| List services/nodes/stacks/tasks | `docker service ls`, `node ls`, `stack ls`, `service ps` | PRESENT | `cluster ls swarm1 services\|nodes\|stacks\|tasks` | - |
| Tasks of one service / one stack | `docker service ps web`, `docker stack ps shop` | PARTIAL | `tasks` = all services (loop); no filter per service/stack; workaround `cluster run -- service ps web` (read) | P2 - diagnosis of "why did the task fail" |
| Failed tasks + error message (`--no-trunc`) | `docker service ps --no-trunc --filter desired-state=...` | PARTIAL | `tasks` returns the Error column but truncated (no `--no-trunc`) | P2 |
| Inspect service/node/secret/config/network | `docker X inspect` | PRESENT | `cluster get swarm1 service web` (any type is passed through) | - |
| List secrets/configs/networks/volumes | `docker secret ls`, `config ls`, `network ls` | PARTIAL | `cluster ls` rejects types other than services/nodes/tasks/stacks (cluster.go:381); workaround `cluster run -- secret ls` (read) | P2 |
| Service log | `docker service logs` | PRESENT | `cluster logs swarm1 web -n --since` (no follow, see section 3) | - |
| Update service image | `docker service update --image` | MISSING | Workaround `cluster run --write -- service update --image repo:tag web` | P1 - daily deploy on Swarm |
| Service rollback | `docker service rollback` / `update --rollback` | MISSING | Workaround `cluster run --write -- service rollback web` | P1 - way back when a deploy fails |
| Restart (force update) | `docker service update --force` | PRESENT | `cluster restart swarm1 service/web` (`--detach`) | - |
| Wait for update convergence | `docker service update` (without `--detach`) | MISSING | restart/scale/apply are always `--detach`; no convergence status | P1 - the agent does not know whether the rollout succeeded (parallel to k8s rollout status) |
| Scale | `docker service scale` | PRESENT | `cluster scale swarm1 service/web 4`; 0 → `--allow-dangerous` | - |
| Deploy stack from compose file | `docker stack deploy -c` | PRESENT | `cluster apply swarm1 --file compose.yml --stack shop` (sent through stdin) | - |
| Stack deploy with registry auth | `docker stack deploy --with-registry-auth` | MISSING | The flag does not exist; private images can fail on workers. Integration with the `registry` conn is also not there yet | P2 - common for private images (GHCR/ECR) |
| Relative files in compose (env_file, configs, secrets file) | `docker stack deploy` from a local directory | PARTIAL | The file is sent via stdin; relative paths are resolved on the manager, not on the laptop → fails unless the files already exist on the manager. Not documented | P2 - surprise on the first deploy |
| Stack diff / dry-run | Portainer (preview) | PARTIAL | `--dry-run` only shows the command that will run; Swarm has no server-side dry-run | P3 |
| Delete service/stack | `docker service rm`, `stack rm` | PRESENT | `cluster rm swarm1 service\|stack NAME --allow-dangerous` | - |
| Node drain/active/pause | `docker node update --availability drain` | PARTIAL | `cluster run --write --allow-dangerous -- node update --availability drain N` (destructive, classifyDocker) | P2 - node maintenance |
| Promote/demote, node labels | `docker node promote/update --label-add` | PARTIAL | `cluster run --write`; demote is destructive | P3 |
| Create Swarm secret/config | `docker secret create`, `config create` | PARTIAL | `cluster run --write -- secret create NAME FILE` (FILE must already exist on the manager): Swarm `cluster run` does not pass stdin (`runOne` with nil stdin, cluster.go:953; exec.go:318-321), so `secret create NAME -` cannot be used; no path from the `komando secret` vault | P2 - app secrets on Swarm; the value should come from the vault, not from an argument |
| Init/join swarm, join token | `docker swarm init/join-token` | PARTIAL | `cluster run` (`swarm` is always destructive); `swarm join-token` prints the token without redaction | P3 |
| Create/delete overlay network | `docker network create -d overlay` | PARTIAL | `cluster run --write` | P3 |

## 10. Docker on hosts (Docker CLI, lazydocker, ctop, dive, Portainer)

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Structured ps (all containers) | `docker ps -a`, lazydocker, ctop | PRESENT | `docker ps TARGET` (JSON lines, fleet `@web`) | - |
| ps filter (status, label, name, health) | `docker ps --filter` | MISSING | `docker ps` is always `ps -a` without `--filter`; workaround `docker raw -- ps --filter health=unhealthy` | P2 - "which containers are unhealthy on all hosts" |
| Unhealthy container / restart loop | lazydocker, Portainer, recipe | PARTIAL | recipe `docker-overview` (ops.go:134) text; no structured restart count/health field | P2 |
| Structured CPU/mem stats | `docker stats --no-stream`, ctop | PRESENT | `docker stats TARGET` | - |
| Processes in a container | `docker top` | PARTIAL | `docker raw -- top C` (considered mutating) | P3 |
| Inspect | `docker inspect` | PARTIAL | `docker inspect TARGET NAME` (JSON). Env with passwords is shown without redaction (unlike `cluster get`, which redacts Secrets) | P2 - safety: the agent reads inspect to debug and leaks `DB_PASSWORD` |
| Start/stop/restart | `docker start/stop/restart` | PRESENT | `docker start\|stop\|restart TARGET NAME...` (mutating, protected host → `--yes`, `--dry-run`) | - |
| Delete container | `docker rm` | PARTIAL | `docker rm TARGET NAME` is only "mutating"; `-f`/`-v` (delete anonymous volumes) pass without `--allow-dangerous`. Not consistent with `cluster rm`, which needs `--allow-dangerous` | P1 - safety; the rule "rm needs --allow-dangerous" must be the same in every family |
| Kill, pause/unpause, rename, update (limits) | `docker kill/pause/update` | PARTIAL | `docker raw` (mutating, no classification) | P3 |
| Run/create new container | `docker run -d` | PARTIAL | `docker raw -- run -d ...`; no guard for `--privileged`, `-v /:/host`, `--pid=host` (in k8s `cluster run`, `run --privileged` is destructive) | P2 - safety: `docker raw` classification on par with `classifyDocker` |
| Structured images | `docker images` | PRESENT | `docker images TARGET` | - |
| Pull image | `docker pull` | PRESENT | `docker pull TARGET IMAGE` | - |
| Pull with registry credentials from the vault | `docker login` + pull | MISSING | The `registry` conn (vault) is not used to log in on the host; you must `docker login` manually on the host | P2 - vision: one vault for everything; private images are common |
| Tag/push image | `docker tag/push` | PARTIAL | `docker raw`; between registries without a host: `komando registry copy` (PRESENT) | P3 |
| Delete image (rmi) | `docker rmi`, `image rm` | PARTIAL | `docker raw -- rmi` (only mutating); registry: `registry rm --allow-dangerous` | P3 |
| Build image on host | `docker build`, buildx | PARTIAL | `docker raw -- build` (needs the context on the host; no context upload). Local builds are out of scope | P3 - CI/CD, not daily ops |
| Image layer analysis | dive | MISSING | `registry inspect` gives size/platform, not layer contents | P3 |
| Network ls/inspect/create/rm | `docker network` | PARTIAL | `docker raw`; even `network ls` is considered mutating (protected host asks for `--yes`) | P2 - `docker raw` must tell reads apart |
| Volume ls/inspect/rm | `docker volume` | PARTIAL | `docker raw`; `volume rm` is not blocked by policy (only `volume prune --all`) → data loss without `--allow-dangerous` | P1 - safety: volume = data |
| Disk usage | `docker system df` | PARTIAL | recipe `docker-overview` (text) / `docker raw -- system df` | P3 |
| Safe prune | `docker system prune` | PRESENT | recipe `docker-prune` (no volumes, mutating); `prune -a/--volumes` blocked by the `docker-prune-all` policy | - |
| Events | `docker events --since` | PARTIAL | `docker raw -- events --since 1h --until now` (needs `--until` so it does not hang) | P3 |
| Copy container files | `docker cp` | PARTIAL | see section 4 | P3 |
| Registry login | `docker login` | PARTIAL | `komando import docker` imports `~/.docker/config.json` into a registry conn (local); login on a remote host does not exist | P3 |
| Docker context | `docker context` | PRESENT | komando targets/hosts replace contexts | - |
| `docker raw` with risk classification | (komando concept) | PARTIAL | `docker raw` is always mutating (modules.go:387): reads (`ps`, `network ls`) are treated as writes, while `volume rm`, `rm -f`, `run --privileged` are not treated as destructive. `classifyDocker` (cluster.go:877) already exists but is only used in `cluster run` | P1 - safety & agent ergonomics; cheap fix (reuse `classifyDocker`, a `--write` flag like `cluster run`) |
| Fleet: docker actions on many hosts | Portainer (multi-env) | PRESENT | All `docker` subcommands accept `@group` (runFleet, parallel `-P`) | - |
| TUI dashboard | lazydocker, ctop, Portainer UI | NON-GOAL | NG-3 | - |

## 11. Docker Compose on hosts

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Compose passthrough with file/dir | `docker compose -f -p` | PRESENT | `docker compose TARGET --dir D --file F -- ARGS` | - |
| up -d / pull / restart / exec | `docker compose up/pull/restart/exec` | PRESENT | Through passthrough; considered mutating (protected → `--yes`), `--dry-run` shows the command | - |
| Structured ps | `docker compose ps --format json` | PARTIAL | Text output (`2>&1` merged); `-- ps --format json` is possible but the result is not parsed | P2 - the agent needs structured compose service status |
| `ls` projects on host | `docker compose ls` | PRESENT | passthrough `-- ls` (considered read) | - |
| Down | `docker compose down` | PARTIAL | Only mutating; `down -v` (delete volumes = data) and `down --rmi all` do not need `--allow-dangerous`; the policy has no compose pattern | P1 - safety: `down -v` deletes the database |
| Config (render) | `docker compose config` | PARTIAL | Considered read, but prints env/secrets interpolated from `.env` without redaction | P2 - safety: secrets leak to the agent |
| Read-only detection | - | PARTIAL | `HasPrefix(sub,"ps"/"logs"/"config"/"ls")` (modules.go:376): `top`, `images`, `version`, `events` are considered mutating | P3 |
| Logs follow | `docker compose logs -f` | PARTIAL | See section 3 (buffered until timeout) | P3 |
| Edit compose file/env on host | editor + ssh | PRESENT | `komando fs replace ... --backup`, `cp` (host section) | - |
| Deploy flow: pull → up → check health | Portainer stacks, watchtower | PARTIAL | Can be chained by hand; no health check after `up` | P2 - post-deploy verification for agents |
| Automatic image updates | watchtower | NON-GOAL | NG-3/NG-4 (daemon, runs continuously) | - |

## 12. Cross-cutting: agent contract and safety

| Capability | Compared tools | komando status | Evidence/notes | Priority |
|---|---|---|---|---|
| Structured JSON output for first-class commands | kubectl `-o json` | PRESENT | Contract `{ok, command, data, error, meta}`; `cluster ls/get/status`, `docker ps/stats/images` | - |
| Structured output for workarounds | kubectl `-o json` | PARTIAL | `cluster run` returns raw stdout; the agent can add `-o json` itself, but `docker raw`/`compose` are not parsed | P3 |
| Streaming in JSON mode (follow, rollout status, port-forward) | - | PARTIAL | `runKubectl` holds output until the process ends in JSON mode (cluster.go:1032-1036); long commands need `job start` | P2 |
| Long commands in the background | - | PARTIAL | `komando job start` exists for hosts (can be used for `docker ...` on a Swarm manager); for Kubernetes there is none: `cluster run` runs local kubectl in the foreground (cluster.go:1031-1037) and `job` only works over SSH | P2 - rollout/drain can take > 2 minutes (AGENTS.md rule 6) |
| Consistent risk classification across families | - | PARTIAL | k8s: rm/scale 0/drain/exec → `--allow-dangerous`. Docker host: `rm`, `volume rm`, `compose down -v`, `raw` → mutating is enough | P1 - the "secure by default" principle must be uniform |
| Dry-run on all changes | kubectl `--dry-run=server` | PARTIAL | k8s: server dry-run; Swarm/docker: only shows the command. Swarm `cluster rm` without `--allow-dangerous` blocks before the dry-run can show the plan (cluster.go:782) | P3 |
| Rollback hint after a change | - | MISSING | `cluster scale/apply/set image` do not return the previous value (old replicas, old image, revision) for rollback | P2 - AGENTS.md rule 11 |
| `@group` selector for clusters | - | MISSING | See section 1 | P2 |

---

## Count summary

Counted per capability row across all tables (183 rows):

| Status | Count |
|---|---|
| PRESENT | 46 |
| PARTIAL | 83 |
| MISSING | 43 |
| NON-GOAL | 11 |

Gap priority (PARTIAL + MISSING): P1 = 23, P2 = 49, P3 = 54.
(After per-row verification: "Watch changes" moved from NON-GOAL to
MISSING/P3, and "Default namespace per cluster" went down from P2 to P3.)
(The "Impersonation `--as`" row is counted as NON-GOAL because it is deliberately rejected for safety.)

## Top 10 P1 gaps (by impact)

1. **Docker risk classification on hosts is inconsistent**: `docker rm -f/-v`,
   `docker raw -- volume rm`, `docker compose down -v`, `docker raw -- run
   --privileged` are only "mutating"; `docker raw` does not tell reads apart. Reuse
   `classifyDocker` + `--write`/`--allow-dangerous` like `cluster run`.
2. **Secret leak through `cluster run -- get secret -o yaml`** (classified
   read, not redacted).
3. **`cluster status` misses CrashLoopBackOff** (phase `Running`),
   incomplete deployments, node pressure (phase only); ImagePullBackOff
   is listed (phase `Pending`) but with no reason.
4. **No diff before `cluster apply`** (even though ux.md:332 promises it).
5. **No rollout status / wait for convergence** (k8s and Swarm; all
   changes are `--detach`).
6. **No first-class rollback** (`rollout undo`, `service rollback`).
7. **No first-class set image** (k8s `set image`, Swarm `service update --image`).
8. **`cluster logs`: no `--follow`, no logs per workload (`deploy/api`) and
   per multi-pod selector (stern)**.
9. **No useful describe/events** (events only name/age; `cluster
   ls` without `--selector` and columns for other kinds via the Table API).
10. **Exec into a pod needs `--allow-dangerous` even for reads; port-forward to a
    service is not integrated with `tunnel start`** (background + local address).

## Per-row verification

Re-checked 2026-11-02 against the code on branch `feat/v0.3` (`internal/cli/cluster.go`,
`internal/cli/modules.go`, `internal/cli/exec.go`, `internal/cli/common.go`, `internal/cli/conn.go`,
`internal/kube/kube.go`, `internal/policy/policy.go`, `internal/cli/ops.go`) and `bin/komando <cmd> --help`
(without connecting to a server). "Correct" = status, evidence and priority match the code.

| # | Capability (short) | Final status | Check result | Evidence in code |
|---|---|---|---|---|
| 1 | Import kubeconfig | PRESENT | Correct | cluster.go:1066-1106 `importKubeconfig`; `import --help`: source `kubeconfig` |
| 2 | Switch cluster/context | PRESENT | Correct | cluster.go:40-60 `resolveCluster` (conn name per command) |
| 3 | List contexts | PRESENT | Correct | `conn --help`: `list` = `list kind:conn`; cluster.go:850-853 `config get-contexts` read |
| 4 | Default namespace per cluster | PARTIAL P3 | Corrected: wrong evidence (`conn edit --option namespace=` exists); P2→P3 | conn.go:75/214 `--option`; cluster.go:78 used by `kubeClient`; cluster.go:985 `runKubectl` ignores it |
| 5 | Exec auth plugin | PRESENT | Correct | kube.go:256-284 `bearer()`; docs/features/cluster.md:16-17 |
| 6 | Private API server | PRESENT | Correct | cluster.go:64 `openAccess`; cluster.go:989-1006 `forwardLocal` + TLSServerName |
| 7 | Docker Swarm as target | PRESENT | Correct | cluster.go:54-55 (`clusterTarget{host}`) |
| 8 | Remote Docker host | PRESENT | Correct | modules.go:284-391 via `runOne`/`probe` → `resolveTargets` (exec.go:191-200, 325-332) |
| 9 | Many clusters at once | MISSING P2 | Correct | cluster.go:59 "this command works on one" |
| 10 | Check cluster connection | PRESENT | Corrected: evidence (`test` is TCP only) | cluster.go:224-227 `/version`; conn.go:490-501 `testConn` only dials TCP |
| 11 | Podman | MISSING P3 | Correct | grep podman: only ops.go:32 (tool detection in facts); modules.go hardcodes `docker` |
| 12 | Nomad | MISSING P3 | Correct | grep nomad in internal: 0 results; vision.md:95 "later: nomad" |
| 13 | k3s/kind/minikube | PRESENT | Correct | driver.go:71 generic kind `k8s`; vision.md:95 |
| 14 | OpenShift, Rancher | PARTIAL P3 | Correct | kube.go:353-399 generic discovery; grep `oc login`/route: 0 results |
| 15 | List objects of any type | PRESENT | Correct | cluster.go:352-424; kube.go:353-411 (shortNames 376) |
| 16 | Short columns per kind | PRESENT | Correct | cluster.go:273-323 `summarize` |
| 17 | Columns for other kinds | PARTIAL P1 | Correct | cluster.go:277-281 (default name/ns/age); grep `as=Table`: 0 results |
| 18 | `-o wide` | PARTIAL P3 | Correct | cluster.go:283-299 (node present, podIP not) |
| 19 | Label filter | MISSING P1 | Correct | grep `labelSelector`: 0 results; `cluster ls --help` has no selector |
| 20 | Field filter | MISSING P2 | Correct | fieldSelector only at cluster.go:235 (internal status) |
| 21 | Pagination | PARTIAL P3 | Correct | cluster.go:394-416 (`limit`, `truncated`); no continue flag |
| 22 | Full object | PRESENT | Correct | cluster.go:426-463; managedFields 454-456; `redact` 453 |
| 23 | Clean object | PARTIAL P3 | Correct | cluster.go:454-456 only removes managedFields; last-applied is only removed for Secrets (338-342) |
| 24 | Describe | MISSING P1 | Correct | grep describe in cli: only cluster.go:855 (classify read) |
| 25 | Events | PARTIAL P1 | Correct | cluster.go:277-281 (kind Event → name/ns/age only) |
| 26 | Cluster health summary | PARTIAL P1 | Corrected: evidence (ImagePullBackOff/Pending is listed; line 233→235) | cluster.go:235 fieldSelector phase; 244-250 |
| 27 | Swarm health summary | PARTIAL P2 | Correct | cluster.go:220-223 (`swarmRead` raw JSON) |
| 28 | Lint/sanitizing | MISSING P3 | Correct | grep popeye/kube-score/lint in internal: 0 results |
| 29 | Ownership tree | MISSING P3 | Correct | grep ownerReferences/tree in cluster.go/kube: 0 results |
| 30 | Pod & node CPU/mem | MISSING P2 | Correct | `top` only in classify (cluster.go:855); grep metrics.k8s.io: 0 results |
| 31 | Capacity | MISSING P2 | Correct | grep allocatable in internal: 0 results |
| 32 | List resource types | PARTIAL P3 | Correct | kube.go:353 `discover` not exposed; cluster.go:855 `api-resources` read |
| 33 | Field documentation | PARTIAL P3 | Correct | cluster.go:855 `explain` read |
| 34 | Watch changes | MISSING P3 | Corrected: NON-GOAL→MISSING (P3) | vision.md:221-228 does not mention watch; ux.md:108 `-f`; grep watch in internal: 0 results |
| 35 | Interactive dashboard | NON-GOAL | Correct | vision.md:227 (NG-3) |
| 36 | Log of one pod | PRESENT | Correct | cluster.go:491-511 (tailLines, timestamps=true, sinceSeconds) |
| 37 | Pick container, previous | PRESENT | Correct | cluster.go:516-519 |
| 38 | Follow pod | MISSING P1 | Correct | cluster.go:515-519 without `--follow`; grep follow in cluster.go: 0 results; ux.md:108 |
| 39 | Log by workload | MISSING P1 | Corrected: line 503→507 | cluster.go:507 path `/pods/<nama>/log` |
| 40 | Log via selector | MISSING P1 | Correct | grep selector in cluster.go: only :235 |
| 41 | All containers | MISSING P2 | Correct | grep `all-containers`: 0 results |
| 42 | Filter log content (grep) | MISSING P2 | Correct | cluster.go:515-519 without `--grep`; modules.go:182 (host has it) |
| 43 | `--until` | MISSING P3 | Correct | cluster.go:515-519 without `--until` |
| 44 | Swarm service log | PRESENT | Correct | cluster.go:484-489 |
| 45 | Follow Swarm log | MISSING P2 | Correct | cluster.go:485-489 `runOne` (buffer); no follow |
| 46 | Container log on host | PRESENT | Corrected: evidence (`docker logs -f` does not stream) | modules.go:272-273 `followLogs`; modules.go:320-323 alias `docker logs` uses `runOne` |
| 47 | Container logs on many hosts | PRESENT | Correct | modules.go:258-276 `logs` + `resolveTargets` (exec.go:196) |
| 48 | Compose project log | PARTIAL P3 | Correct | modules.go:361-377 passthrough `runOne` (buffer) |
| 49 | Exec in pod (non-interactive) | PARTIAL P1 | Correct | cluster.go:862-864 `exec` destructive; 941-951 needs `--write` + `--allow-dangerous` |
| 50 | Interactive exec -it | PARTIAL P2 | Corrected: line 1032→1035 | cluster.go:1034-1036 (stdin in text mode) |
| 51 | Copy pod files | PARTIAL P2 | Correct | cluster.go:863 `cp` destructive; grep `komando cp`↔pod integration: 0 results |
| 52 | Port-forward | PARTIAL P1 | Correct | cluster.go:863 destructive; tunnel.go has no k8s type (`tunnel start --help`) |
| 53 | kubectl proxy | PARTIAL P3 | Correct | cluster.go:863 `proxy` destructive |
| 54 | Debug container | PARTIAL P3 | Corrected: line 1015→1025-1026, needs `--write` | cluster.go:863, 1025-1026 |
| 55 | Temporary pod | PARTIAL P3 | Correct | cluster.go:869-872 `run` = write (except --privileged/--overrides) |
| 56 | Attach | PARTIAL P3 | Correct | cluster.go:863 `attach` destructive |
| 57 | Exec in container (host) | PRESENT | Corrected: line 350→352 | modules.go:343-359; guard 352; `--read-only` 359 |
| 58 | Interactive container exec (host) | PARTIAL P2 | Correct | modules.go:356 `docker exec -i` without TTY; grep pty in modules.go: 0 results |
| 59 | Copy host<->container | PARTIAL P3 | Correct | modules.go:382-388 `docker raw` (mutating) |
| 60 | Exec in Swarm task | MISSING P3 | Correct | cluster.go: no first-class Swarm exec |
| 61 | Apply multi-document SSA | PRESENT | Correct | cluster.go:655-718; 691 fieldManager komando; 726-758 splitYAML |
| 62 | Server dry-run | PRESENT | Correct | cluster.go:692-694 `dryRun=All` |
| 63 | Diff before apply | MISSING P1 | Correct | cluster.go:708-710 names only; ux.md:332; `diff` read in cluster.go:856 |
| 64 | Field manager conflicts | PARTIAL P2 | Correct | cluster.go:691 `force=true` |
| 65 | Apply directory | MISSING P2 | Correct | cluster.go:668 `readFileOrStdin` one file |
| 66 | Kustomize (apply -k) | MISSING P2 | Correct | grep kustomize in internal: 0 results |
| 67 | CRD then CR order | PARTIAL P3 | Correct | kube.go:354-356 discovery cached once |
| 68 | Non-preferred apiVersion | PARTIAL P2 | Correct | kube.go:394-397 only PreferredVersion; 414-421 |
| 69 | Prune objects | NON-GOAL | Correct | vision.md:226 (NG-2 GitOps); cluster.go:865 `--prune` destructive |
| 70 | Change image | MISSING P1 | Correct | grep `set image` in internal: 0 results (examples only); cluster.go:872 `set` = write |
| 71 | Rollout status / wait | MISSING P1 | Correct | cluster.go:562/631/684 `--detach`; 581/647/710 return right away; 860 rollout status read |
| 72 | Rollout history | PARTIAL P2 | Correct | cluster.go:860 read; 300-302 RS without revision/image |
| 73 | Rollback (undo) | MISSING P1 | Correct | docs/features/cluster.md:56; cluster.go:872 rollout undo = write |
| 74 | Pause/resume rollout | PARTIAL P3 | Correct | cluster.go:872 (default write) |
| 75 | Rolling restart | PRESENT | Correct | cluster.go:540-587 |
| 76 | Scale | PRESENT | Correct | cluster.go:598-653; 624-626 0 → destructive |
| 77 | Conditional scale | MISSING P2 | Correct | grep `current-replicas`: 0 results; cluster.go:647 without old replicas |
| 78 | Autoscale (HPA) | PARTIAL P3 | Correct | cluster.go:277-281 (hpa name/age); autoscale = write |
| 79 | Patch | PARTIAL P3 | Correct | cluster.go:862 destructive |
| 80 | Edit in editor | PARTIAL P3 | Correct | cluster.go:862 destructive |
| 81 | Label/annotate | PARTIAL P3 | Correct | cluster.go:872 write |
| 82 | Create Secret/ConfigMap | PARTIAL P2 | Corrected: evidence (redactArgs coverage checked) | cluster.go:1110-1129 `redactArgs`; grep vault→k8s Secret integration: 0 results |
| 83 | Delete object | PRESENT | Correct | cluster.go:760-806 |
| 84 | Delete many / selector | MISSING P3 | Correct | cluster.go:767 `ExactArgs(3)`; no selector |
| 85 | Replace | PARTIAL P3 | Correct | cluster.go:862 destructive |
| 86 | Job from CronJob | PARTIAL P2 | Correct | cluster.go:867/872 create job = write |
| 87 | Suspend/resume CronJob | PARTIAL P3 | Correct | cluster.go:862 patch destructive |
| 88 | Wait for condition | PARTIAL P2 | Correct | cluster.go:856 `wait` read |
| 89 | Helm-style template | NON-GOAL | Correct | vision.md:223-226 (NG-1 helm, NG-2) |
| 90 | List nodes | PRESENT | Correct | cluster.go:313-316; 238-243 |
| 91 | Node conditions | PARTIAL P2 | Correct | cluster.go:313-316 only Ready/version |
| 92 | Cordon/uncordon | PARTIAL P2 | Correct | cluster.go:862 destructive |
| 93 | Drain | PARTIAL P2 | Correct | cluster.go:862 destructive; 1022-1028 `--dry-run=server` added |
| 94 | Taint | PARTIAL P3 | Correct | cluster.go:862 destructive |
| 95 | Pods per node | PARTIAL P3 | Correct | cluster.go:299 node column; no filter |
| 96 | Shell into node | PARTIAL P3 | Correct | cluster.go:863 debug destructive; `shell`/`exec` for hosts |
| 97 | Secret values hidden | PARTIAL P1 | Correct | cluster.go:327-343, 453; 855 `get` read without stdout redaction (1055) |
| 98 | See Secret value | MISSING P2 | Correct | grep reveal in cluster.go: 0 results |
| 99 | Check permissions | PARTIAL P2 | Correct | cluster.go:858 can-i/whoami read |
| 100 | Who can | MISSING P3 | Correct | grep who-can/rbac-lookup: 0 results |
| 101 | Sealed Secrets | MISSING P3 | Correct | grep kubeseal/sealed: 0 results |
| 102 | Approve CSR | PARTIAL P3 | Correct | cluster.go:862 `certificate` destructive |
| 103 | Impersonation --as | NON-GOAL | Corrected: evidence (not from vision.md; line 810→811-813) | cluster.go:811-813 `kubectlForbidden`; vision.md:221-228 does not mention it |
| 104 | Audit every change | PRESENT | Correct | cluster.go:140-142, 1046-1048; exec.go:309 (Swarm) |
| 105 | Protected cluster | PRESENT | Correct | common.go:214-224 `guardConns`; docs/features/cluster.md:49 |
| 106 | List helm releases | MISSING P2 | Correct | grep helm in internal: 0 results |
| 107 | Release status/history | MISSING P2 | Correct | grep helm: 0 results |
| 108 | Release values | MISSING P3 | Correct | grep helm: 0 results |
| 109 | Release rollback | MISSING P2 | Correct | grep helm: 0 results |
| 110 | Install/upgrade chart | NON-GOAL | Correct | vision.md:223 (NG-1 names `helm`) |
| 111 | Helm template, repo, plugins | NON-GOAL | Correct | vision.md:223-226 (NG-1/NG-2) |
| 112 | Kustomize build | NON-GOAL | Corrected: evidence NG-2→NG-1 (kustomize not named explicitly) | vision.md:223-225 NG-1; grep kustomize: 0 results |
| 113 | Cluster backup/restore | NON-GOAL | Correct | vision.md:223-226 (NG-1 full tools) |
| 114 | krew plugins | NON-GOAL | Correct | vision.md:227 (NG-3 plugin system) |
| 115 | Swarm status | PARTIAL P2 | Correct | cluster.go:220-223 |
| 116 | List services/nodes/stacks/tasks | PRESENT | Correct | cluster.go:372-382 |
| 117 | Tasks of one service/stack | PARTIAL P2 | Correct | cluster.go:377 loops over all services |
| 118 | Failed tasks --no-trunc | PARTIAL P2 | Correct | cluster.go:377 without `--no-trunc` (only in logs :485) |
| 119 | Swarm inspect | PRESENT | Correct | cluster.go:441-442 |
| 120 | List secrets/configs/networks | PARTIAL P2 | Correct | cluster.go:379-381 |
| 121 | Service log | PRESENT | Correct | cluster.go:484-489 |
| 122 | Update service image | MISSING P1 | Correct | cluster.go:894 `service update` = write; no first-class command |
| 123 | Service rollback | MISSING P1 | Correct | cluster.go:894 default write; no first-class command |
| 124 | Restart (force update) | PRESENT | Correct | cluster.go:561-562 |
| 125 | Wait for convergence | MISSING P1 | Correct | cluster.go:562/631/684 `--detach` |
| 126 | Swarm scale | PRESENT | Correct | cluster.go:627-631 |
| 127 | Deploy stack | PRESENT | Correct | cluster.go:680-684 |
| 128 | Stack deploy registry auth | MISSING P2 | Correct | grep with-registry-auth: 0 results |
| 129 | Relative compose files | PARTIAL P2 | Correct | cluster.go:684 `-c -` through stdin; grep docs relative/env_file: 0 results |
| 130 | Stack diff / dry-run | PARTIAL P3 | Correct | exec.go:212-228 dry-run shows the command only |
| 131 | Delete service/stack | PRESENT | Correct | cluster.go:777-785 |
| 132 | Node drain/active/pause | PARTIAL P2 | Correct | cluster.go:891 node update --availability destructive |
| 133 | Promote/demote, labels | PARTIAL P3 | Correct | cluster.go:888 demote destructive; the rest write |
| 134 | Create Swarm secret/config | PARTIAL P2 | Corrected: evidence (stdin is not passed) | cluster.go:953 `runOne` nil stdin; exec.go:318-321 |
| 135 | Init/join swarm | PARTIAL P3 | Correct | cluster.go:889 `swarm` destructive; output not redacted |
| 136 | Overlay network | PARTIAL P3 | Correct | cluster.go:894 (network create = write) |
| 137 | Structured ps | PRESENT | Correct | modules.go:302 `ps -a` + parseJSONLines |
| 138 | ps filter | MISSING P2 | Correct | modules.go:302 no filter flag |
| 139 | Unhealthy container | PARTIAL P2 | Correct | ops.go:134 `docker-overview` (text) |
| 140 | Stats | PRESENT | Correct | modules.go:303 |
| 141 | Processes in container | PARTIAL P3 | Correct | modules.go:387 raw mutating |
| 142 | Inspect (host) | PARTIAL P2 | Correct | modules.go:328-341 without redaction |
| 143 | Start/stop/restart | PRESENT | Correct | modules.go:304-314 (mutating=true) |
| 144 | Delete container | PARTIAL P1 | Correct | modules.go:304-311 `rm` mutating; policy.go:34 only prune |
| 145 | Kill/pause/update | PARTIAL P3 | Correct | modules.go:387 |
| 146 | Run/create container | PARTIAL P2 | Correct | modules.go:387; cluster.go:869 (guard only in cluster run) |
| 147 | Images | PRESENT | Correct | modules.go:303 |
| 148 | Pull | PRESENT | Correct | modules.go:304 |
| 149 | Pull with vault credentials | MISSING P2 | Correct | grep `docker login` in internal: 0 results |
| 150 | Tag/push image | PARTIAL P3 | Correct | modules.go:387; `registry copy` exists |
| 151 | Delete image | PARTIAL P3 | Correct | modules.go:387; `registry rm` needs --allow-dangerous |
| 152 | Build image | PARTIAL P3 | Correct | modules.go:387 |
| 153 | Layer analysis | MISSING P3 | Correct | `registry inspect` (help: digest/size/platform) |
| 154 | Docker network | PARTIAL P2 | Correct | modules.go:387 mutating=true |
| 155 | Docker volume | PARTIAL P1 | Correct | modules.go:387; policy.go:34 only `volume prune -a` |
| 156 | Disk usage | PARTIAL P3 | Correct | ops.go:134 |
| 157 | Safe prune | PRESENT | Correct | ops.go:143 `docker-prune`; policy.go:34 |
| 158 | Docker events | PARTIAL P3 | Correct | modules.go:387 |
| 159 | Copy container files | PARTIAL P3 | Correct | modules.go:387 |
| 160 | Registry login | PARTIAL P3 | Correct | `import --help`: docker source; grep remote login: 0 results |
| 161 | Docker context | PRESENT | Correct | exec.go:196 `resolveTargets` |
| 162 | docker raw classification | PARTIAL P1 | Correct | modules.go:387 mutating=true; cluster.go:877 `classifyDocker` only used at :927 |
| 163 | Docker fleet | PRESENT | Correct | exec.go:191-262 `runFleet`/`fanout` |
| 164 | TUI dashboard | NON-GOAL | Correct | vision.md:227 (NG-3) |
| 165 | Compose passthrough | PRESENT | Correct | modules.go:361-381 |
| 166 | up/pull/restart/exec | PRESENT | Correct | modules.go:376-377 mutating; exec.go:212-228 dry-run |
| 167 | Structured compose ps | PARTIAL P2 | Correct | modules.go:375 `2>&1`, no parsing |
| 168 | ls projects | PRESENT | Correct | modules.go:376 prefix `ls` = read |
| 169 | Compose down | PARTIAL P1 | Correct | modules.go:376-377 mutating; policy.go has no compose pattern |
| 170 | Compose config | PARTIAL P2 | Correct | modules.go:376 `config` read, without redaction |
| 171 | Read-only detection | PARTIAL P3 | Correct | modules.go:376 |
| 172 | Compose logs follow | PARTIAL P3 | Correct | modules.go:377 `runOne` (buffer) |
| 173 | Edit compose file | PRESENT | Correct | `fs` (help: replace) and `cp` |
| 174 | Deploy flow + health | PARTIAL P2 | Correct | modules.go:361-379 no health check |
| 175 | Automatic image updates | NON-GOAL | Correct | vision.md:227-228 (NG-3/NG-4) |
| 176 | First-class JSON output | PRESENT | Correct | cluster.go:146 `out.P.Print`; modules.go:298 |
| 177 | Workaround output | PARTIAL P3 | Correct | cluster.go:1055; modules.go:375/387 |
| 178 | JSON mode streaming | PARTIAL P2 | Corrected: line 1028-1033→1032-1036 | cluster.go:1032-1036 |
| 179 | Long commands in background | PARTIAL P2 | Corrected: evidence ("unclear"→not supported for k8s) | cluster.go:1031-1037 foreground; job.go SSH only |
| 180 | Consistent risk classification | PARTIAL P1 | Correct | cluster.go:624-626, 787, 862; modules.go:311/377/387 |
| 181 | Dry-run on all changes | PARTIAL P3 | Correct | cluster.go:782-783 blocks before dry-run; exec.go:212 |
| 182 | Rollback hint | MISSING P2 | Correct | cluster.go:581/647/710 without old values |
| 183 | @group selector for clusters | MISSING P2 | Correct | cluster.go:59 |
