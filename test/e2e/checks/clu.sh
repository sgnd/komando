# shellcheck shell=bash
# Clusters, Swarm, docker and registry: shapes, names, errors and safety.
# Uses namespace t-e2eclu, Swarm service t-e2eclu-web and image tag
# t-e2eclu/busybox:2; everything is removed at the end.
CLU_K8S_IMG=${CLU_K8S_IMG:-rancher/mirrored-pause:3.6}
CLU_IMG=${CLU_IMG:-busybox:1.37}
set +e

# each part runs in the area that has its containers (run.sh)
if in_area k8s; then
# Kubernetes
cat > "$TMP/clu.yaml" <<YAML
apiVersion: v1
kind: Namespace
metadata: { name: t-e2eclu }
---
apiVersion: v1
kind: Secret
metadata: { name: creds, namespace: t-e2eclu }
stringData: { password: one }
---
apiVersion: apps/v1
kind: Deployment
metadata: { name: web, namespace: t-e2eclu }
spec:
  replicas: 1
  selector: { matchLabels: { app: web } }
  template:
    metadata: { labels: { app: web } }
    spec: { containers: [ { name: web, image: "$CLU_K8S_IMG" } ] }
YAML
check "apply --dry-run creates into a namespace the file makes" "create create create" \
  "$($K cluster apply lab-k3s --file "$TMP/clu.yaml" --dry-run | jget '" ".join(c["action"] for c in d["data"]["changes"])')"
check "apply --namespace must match the file" USAGE "$($K cluster apply lab-k3s --file "$TMP/clu.yaml" --namespace other | jget 'd["error"]["code"]')"
check "apply --stack is for Swarm" USAGE "$($K cluster apply lab-k3s --file "$TMP/clu.yaml" --stack x | jget 'd["error"]["code"]')"
check "apply says created" "created created created" "$($K cluster apply lab-k3s --file "$TMP/clu.yaml" | jget '" ".join(o["action"] for o in d["data"]["objects"])')"
check "apply again says unchanged" "unchanged unchanged unchanged" "$($K cluster apply lab-k3s --file "$TMP/clu.yaml" | jget '" ".join(o["action"] for o in d["data"]["objects"])')"
printf 'apiVersion: v1\nkind: ConfigMap\nmetadata: {name: t-ok, namespace: t-e2eclu}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: Bad_Name, namespace: t-e2eclu}\n' >"$TMP/half.yaml"
check "apply: a refused object stops the whole file" "K8S_INVALID True K8S_NOT_FOUND" \
  "$($K cluster apply lab-k3s --file "$TMP/half.yaml" >"$TMP/o"; jget 'd["error"]["code"] + " " + str("nothing was applied" in d["error"]["message"])' <"$TMP/o") $($K cluster get lab-k3s cm t-ok --namespace t-e2eclu | jget 'd["error"]["code"]' || true)"
sed 's/password: one/password: two/' "$TMP/clu.yaml" > "$TMP/clu2.yaml"
check "a changed Secret value is a change, still hidden" "change True" \
  "$($K cluster apply lab-k3s --file "$TMP/clu2.yaml" --dry-run | jget 'd["data"]["changes"][1]["action"] + " " + str("two" not in json.dumps(d) and "(hidden, changed)" in d["data"]["changes"][1]["diff"])')"
$K cluster status lab-k3s deployment/web --namespace t-e2eclu --wait --timeout 90s >/dev/null
check "TYPE NAME, TYPE/NAME and group-qualified kinds" "web web web" \
  "$($K cluster get lab-k3s deployment web --namespace t-e2eclu | jget 'd["data"]["metadata"]["name"]') $($K cluster get lab-k3s deploy/web --namespace t-e2eclu | jget 'd["data"]["metadata"]["name"]') $($K cluster get lab-k3s deployment.apps/web --namespace t-e2eclu | jget 'd["data"]["metadata"]["name"]')"
check "status takes TYPE NAME" True "$($K cluster status lab-k3s deployment web --namespace t-e2eclu | jget 'd["data"]["rolled_out"]')"
check "-n is --namespace on cluster get" web "$($K cluster get lab-k3s deploy web -n t-e2eclu | jget 'd["data"]["metadata"]["name"]')"
check "-A lists every namespace" True "$($K cluster ls lab-k3s deploy -A | jget 'any(i["namespace"]=="t-e2eclu" for i in d["data"]["items"])')"
check "ls text is a table" True "$($K cluster ls lab-k3s deploy --namespace t-e2eclu -o text | head -1 | grep -q '^NAME  *READY  *UP-TO-DATE  *AVAILABLE  *AGE' && echo True)"
check "unknown kind suggests one" True "$($K cluster ls lab-k3s deploymnt | jget '"did you mean \"deployment\"" in d["error"]["message"]')"
check "status --namespace filters" t-e2eclu "$($K cluster status lab-k3s --namespace t-e2eclu | jget 'd["data"]["namespace"]')"
check "describe shows images and selector" "True app=web" "$($K cluster describe lab-k3s deploy/web --namespace t-e2eclu | jget 'str(d["data"]["summary"]["images"].startswith("web=")) + " " + d["data"]["summary"]["selector"]')"
# Helm: two revisions stored the way helm stores them (a Secret per revision,
# base64 of gzipped JSON), made with kubectl, as komando needs no helm program
kc() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s kubectl "$@"; }
for v in 1 2; do
  st=superseded; [ "$v" = 2 ] && st=deployed
  rel=$(python3 -c "
import base64, gzip, json, sys
v, st = int(sys.argv[1]), sys.argv[2]
r = {'name': 'demo', 'namespace': 't-e2eclu', 'version': v,
     'info': {'first_deployed': '2026-01-01T00:00:00Z', 'last_deployed': '2026-01-0%dT00:00:00Z' % v,
              'description': 'Upgrade complete' if v == 2 else 'Install complete', 'status': st, 'notes': 'demo notes'},
     'chart': {'metadata': {'name': 'demo', 'version': '1.%d.0' % v, 'appVersion': '2.%d' % v}, 'values': {'replicas': 1, 'image': 'demo'}},
     'config': {'replicas': 3}}
print(base64.b64encode(gzip.compress(json.dumps(r).encode())).decode())" "$v" "$st")
  kc -n t-e2eclu create secret generic "sh.helm.release.v1.demo.v$v" --type=helm.sh/release.v1 --from-literal=release="$rel" >/dev/null
  kc -n t-e2eclu label secret "sh.helm.release.v1.demo.v$v" owner=helm name=demo status=$st version=$v >/dev/null
done
check "helm ls shows the deployed revision" "demo 2 deployed demo-1.2.0" "$($K cluster helm ls lab-k3s --namespace t-e2eclu | jget '" ".join(str(x) for x in (lambda r: (r["name"], r["revision"], r["status"], r["chart"]))(d["data"]["releases"][0]))')"
check "helm status shows the notes" True "$($K cluster helm status lab-k3s demo --namespace t-e2eclu | jget '"demo notes" in json.dumps(d)')"
check "helm history lists both revisions, oldest first" "1 2" "$($K cluster helm history lab-k3s demo --namespace t-e2eclu | jget '" ".join(str(r["revision"]) for r in d["data"]["revisions"])')"
check "helm values: what was set" 3 "$($K cluster helm values lab-k3s demo --namespace t-e2eclu | jget 'd["data"]["values"]["replicas"]')"
check "helm values --all: with the chart's defaults" "3 demo" "$($K cluster helm values lab-k3s demo --namespace t-e2eclu --all | jget 'str(d["data"]["values"]["replicas"]) + " " + d["data"]["values"]["image"]')"
check "scale to the same count is unchanged" "True 1" "$($K cluster scale lab-k3s deploy/web 1 --namespace t-e2eclu | jget 'str(d["data"]["unchanged"]) + " " + str(d["data"]["previous_replicas"])')"
check "scale refuses pods" USAGE "$($K cluster scale lab-k3s pod/x 1 --namespace t-e2eclu | jget 'd["error"]["code"]')"
check "a bad label selector is a usage error" 2 "$($K cluster ls lab-k3s pods -l 'app in (' --namespace t-e2eclu >/dev/null; echo $?)"
check "rollback --revision a missing revision lists them" True "$($K cluster rollback lab-k3s deploy/web --revision 99 --namespace t-e2eclu | jget '"revision 99 not found; revisions: 1" in d["error"]["message"]')"
check "rollback to the current revision is unchanged" True "$($K cluster rollback lab-k3s deploy/web --revision 1 --namespace t-e2eclu | jget 'd["data"]["unchanged"]')"
check "exec in a missing pod is not found" 3 "$($K cluster exec lab-k3s nopod --namespace t-e2eclu --read-only -- ls >/dev/null 2>&1; echo $?)"
check "logs of a missing container is not found" 3 "$($K cluster logs lab-k3s deploy/web --namespace t-e2eclu -c nope >/dev/null; echo $?)"
check "logs of a workload name the object and its pods" "deploy/web 1" "$($K cluster logs lab-k3s deploy/web --namespace t-e2eclu | jget 'd["data"]["object"] + " " + str(len(d["data"]["pods"]))')"
check "cluster run ends a watch at --timeout" 0 "$($K cluster run lab-k3s --timeout 3s -- get pods -n t-e2eclu -w >/dev/null; echo $?)"
# :80 takes any free local port (like kubectl), so the check never meets a port in use;
# kubectl's words stay in $TMP/fw.err to show why if it fails
check "forward ends normally at --timeout" "0 True" "$($K cluster forward lab-k3s deploy/web :80 --namespace t-e2eclu --timeout 5s >"$TMP/o" 2>"$TMP/fw.err"; echo $?) $(jget 'd["ok"]' <"$TMP/o")"
[ "$(jget 'd["ok"]' <"$TMP/o")" = True ] || { echo "  forward stderr:"; head -5 "$TMP/fw.err"; }
# Ctrl-C ends a forward cleanly: exit 0, the local port is closed again
$K cluster forward lab-k3s deploy/web 18096:80 --namespace t-e2eclu >"$TMP/fwi.out" 2>/dev/null &
FW=$!
for _ in $(seq 1 40); do (exec 3<>/dev/tcp/127.0.0.1/18096) 2>/dev/null && break; sleep 0.5; done
kill -INT "$FW"; wait "$FW"; RC=$?
check "forward: Ctrl-C ends it normally" "0 True" "$RC $(jget 'd["data"]["stopped"]' <"$TMP/fwi.out")"
check "forward: the local port is closed after Ctrl-C" closed "$( (exec 3<>/dev/tcp/127.0.0.1/18096) 2>/dev/null && echo open || echo closed)"
# a person deletes by typing the object's name; the cluster's name is not enough
ptty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; }
O=$(ptty 'lab-k3s\n' cluster rm lab-k3s deployment web --namespace t-e2eclu); RC=$?
check "person: cluster rm asks for the object's name" 1 "$(grep -c 'Type the name web to continue' <<<"$O")"
check "person: the cluster's name deletes nothing" "6 web" "$RC $($K cluster get lab-k3s deploy web --namespace t-e2eclu | jget 'd["data"]["metadata"]["name"]')"
O=$(ptty 'web\n' cluster rm lab-k3s deployment web --namespace t-e2eclu); RC=$?
check "person: the object's name deletes it, asked once" "0 1 K8S_NOT_FOUND" "$RC $(grep -c 'Type the name' <<<"$O") $($K cluster get lab-k3s deploy web --namespace t-e2eclu | jget 'd["error"]["code"]' || true)"
q $K cluster rm lab-k3s namespace t-e2eclu --allow-dangerous
fi

if in_area swarm; then
# Docker Swarm
check "Swarm status has the Kubernetes shape" "True True" "$($K cluster status swarm1 | jget 'str("healthy" in d["data"]) + " " + str(isinstance(d["data"]["problems"], list))')"
check "not a Swarm manager says so" "3 NOT_SWARM_MANAGER" "$($K cluster status direct >"$TMP/o"; echo $?) $(jget 'd["error"]["code"]' <"$TMP/o")"
check "a missing service is not found" "3 True" "$($K cluster status swarm1 service/nope >"$TMP/o"; echo $?) $(jget 'd["error"]["message"] != ""' <"$TMP/o")"
check "--namespace on Swarm is refused" USAGE "$($K cluster ls swarm1 services --namespace x | jget 'd["error"]["code"]')"
# a Swarm service pulls by digest, so the tag may not be there to copy
q $K docker pull swarm1 "$CLU_IMG"
q $K docker raw swarm1 -- tag "$CLU_IMG" t-e2eclu/busybox:2
q $K cluster run swarm1 --write -- service create --detach --name t-e2eclu-web "$CLU_IMG" sleep 86400
check "Swarm service rolls out" True "$($K cluster status swarm1 svc/t-e2eclu-web --wait --timeout 90s | jget 'd["data"]["rolled_out"]')"
check "Swarm ls has items with ready" "1/1" "$($K cluster ls swarm1 svc | jget '[i["ready"] for i in d["data"]["items"] if i["name"]=="t-e2eclu-web"][0]')"
check "Swarm ls tasks -n limits" 1 "$($K cluster ls swarm1 tasks --limit 1 | jget 'len(d["data"]["items"])')"
check "Swarm describe has a summary and tasks" "$CLU_IMG True" "$($K cluster describe swarm1 service t-e2eclu-web | jget 'd["data"]["summary"]["image"] + " " + str(len(d["data"]["tasks"]) > 0)')"
check "Swarm scale to the same count is unchanged" True "$($K cluster scale swarm1 svc/t-e2eclu-web 1 | jget 'd["data"]["unchanged"]')"
check "Swarm deploy --wait" "True $CLU_IMG" "$($K cluster deploy swarm1 svc/t-e2eclu-web --image t-e2eclu/busybox:2 --wait --timeout 90s | jget 'str(d["data"]["rolled_out"]) + " " + d["data"]["previous_image"]')"
check "Swarm rollback --wait is no failure" "0 True" "$($K cluster rollback swarm1 svc/t-e2eclu-web --wait --timeout 90s >"$TMP/o"; echo $?) $(jget 'd["ok"]' <"$TMP/o")"
check "Swarm logs -f ends at --timeout" "0 True" "$($K cluster logs swarm1 t-e2eclu-web -f --timeout 3s >"$TMP/o"; echo $?) $(tail -1 "$TMP/o" | jget 'd["data"]["followed"]')"
check "Swarm apply --dry-run checks the file" 2 "$(printf 'services: [\n' | $K cluster apply swarm1 --file - --stack t-e2eclu --dry-run >/dev/null; echo $?)"
CTR=$($K docker ps swarm1 | jget '[c["Names"] for c in d["data"]["results"][0]["data"] if c["Names"].startswith("t-e2eclu-web.")][0]')
check "docker exec passes words as given" "3 out" "$($K docker exec swarm1 "$CTR" --read-only -- sh -c 'echo out; exit 3' | jget 'str(d["data"]["results"][0]["exit_code"]) + " " + d["data"]["results"][0]["stdout"].strip()')"
check "docker raw: global flags do not hide rm" POLICY_BLOCKED "$($K docker raw swarm1 -- -l debug volume rm nothing | jget 'd["error"]["code"]')"
check "docker compose: down -v behind -p is checked" POLICY_BLOCKED "$($K docker compose swarm1 --dry-run -- -p proj down -v | jget 'd["meta"]["would_be_blocked"]["code"]')"
check "docker raw refuses an unknown leading flag" USAGE "$($K docker raw swarm1 -- --weird x ps | jget 'd["error"]["code"]')"
check "docker inspect of a missing object is not found" 3 "$($K docker inspect swarm1 nope >/dev/null; echo $?)"
# a person removes a Swarm service by typing its name, not "yes"
ptty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; }
O=$(ptty 'yes\n' cluster rm swarm1 service/t-e2eclu-web); RC=$?
check "person: Swarm rm asks for the service's name" 1 "$(grep -c 'Type the name t-e2eclu-web to continue' <<<"$O")"
check "person: yes removes nothing" "6 True" "$RC $($K cluster ls swarm1 svc | jget 'any(i["name"]=="t-e2eclu-web" for i in d["data"]["items"])')"
O=$(ptty 't-e2eclu-web\n' cluster rm swarm1 service/t-e2eclu-web); RC=$?
check "person: the service's name removes it, asked once" "0 1 3" "$RC $(grep -c 'Type the name' <<<"$O") $($K cluster status swarm1 svc/t-e2eclu-web >/dev/null; echo $?)"
q $K docker raw swarm1 --allow-dangerous -- rmi t-e2eclu/busybox:2
fi

if in_area registry; then
# registry
check "a missing tag names the tags there" "3 True" "$($K registry inspect reg mirror/busybox:latest >"$TMP/o"; echo $?) $(jget '"mirror/busybox:latest not found; tags: stable" in d["error"]["message"]' <"$TMP/o")"
check "rm --dry-run names the tags that go" True "$($K registry rm reg mirror/busybox:stable --dry-run | jget '"stable" in d["data"]["would_remove_tags"]')"
check "copy without CONN: is a usage error" USAGE "$($K registry copy mirror/busybox:stable reg:x | jget 'd["error"]["code"]')"
fi

set -e
