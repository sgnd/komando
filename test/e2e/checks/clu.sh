# Clusters, Swarm, docker and registry: shapes, names, errors and safety.
# Uses namespace t-e2eclu, Swarm service t-e2eclu-web and image tag
# t-e2eclu/busybox:2; everything is removed at the end.
CLU_K8S_IMG=${CLU_K8S_IMG:-rancher/mirrored-pause:3.6}
CLU_IMG=${CLU_IMG:-busybox:1.37}
set +e

# --- Kubernetes ---------------------------------------------------------------
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
sed 's/password: one/password: two/' "$TMP/clu.yaml" > "$TMP/clu2.yaml"
check "a changed Secret value is a change, still hidden" "change True" \
  "$($K cluster apply lab-k3s --file "$TMP/clu2.yaml" --dry-run | jget 'd["data"]["changes"][1]["action"] + " " + str("two" not in json.dumps(d) and "(hidden, changed)" in d["data"]["changes"][1]["diff"])')"
$K cluster status lab-k3s deployment/web --namespace t-e2eclu --wait --timeout 90s >/dev/null
check "TYPE NAME, TYPE/NAME and group-qualified kinds" "web web web" \
  "$($K cluster get lab-k3s deployment web --namespace t-e2eclu | jget 'd["data"]["metadata"]["name"]') $($K cluster get lab-k3s deploy/web --namespace t-e2eclu | jget 'd["data"]["metadata"]["name"]') $($K cluster get lab-k3s deployment.apps/web --namespace t-e2eclu | jget 'd["data"]["metadata"]["name"]')"
check "status takes TYPE NAME" True "$($K cluster status lab-k3s deployment web --namespace t-e2eclu | jget 'd["data"]["rolled_out"]')"
check "-n NAMESPACE explains --namespace" "2 True" "$($K cluster get lab-k3s deploy web -n t-e2eclu >"$TMP/o"; echo $?) $(jget '"--namespace t-e2eclu" in d["error"]["message"]' <"$TMP/o")"
check "-A lists every namespace" True "$($K cluster ls lab-k3s deploy -A | jget 'any(i["namespace"]=="t-e2eclu" for i in d["data"]["items"])')"
check "ls text is a table" True "$($K cluster ls lab-k3s deploy --namespace t-e2eclu -o text | head -1 | grep -q '^NAME  *READY  *UP-TO-DATE  *AVAILABLE  *AGE' && echo True)"
check "unknown kind suggests one" True "$($K cluster ls lab-k3s deploymnt | jget '"did you mean \"deployment\"" in d["error"]["message"]')"
check "status --namespace filters" t-e2eclu "$($K cluster status lab-k3s --namespace t-e2eclu | jget 'd["data"]["namespace"]')"
check "describe shows images and selector" "True app=web" "$($K cluster describe lab-k3s deploy/web --namespace t-e2eclu | jget 'str(d["data"]["summary"]["images"].startswith("web=")) + " " + d["data"]["summary"]["selector"]')"
check "scale to the same count is unchanged" "True 1" "$($K cluster scale lab-k3s deploy/web 1 --namespace t-e2eclu | jget 'str(d["data"]["unchanged"]) + " " + str(d["data"]["previous_replicas"])')"
check "scale refuses pods" USAGE "$($K cluster scale lab-k3s pod/x 1 --namespace t-e2eclu | jget 'd["error"]["code"]')"
check "a bad label selector is a usage error" 2 "$($K cluster ls lab-k3s pods -l 'app in (' --namespace t-e2eclu >/dev/null; echo $?)"
check "rollback --to a missing revision lists them" True "$($K cluster rollback lab-k3s deploy/web --to 99 --namespace t-e2eclu | jget '"revision 99 not found; revisions: 1" in d["error"]["message"]')"
check "rollback to the current revision is unchanged" True "$($K cluster rollback lab-k3s deploy/web --to 1 --namespace t-e2eclu | jget 'd["data"]["unchanged"]')"
check "exec in a missing pod is not found" 3 "$($K cluster exec lab-k3s nopod --namespace t-e2eclu --read-only -- ls >/dev/null 2>&1; echo $?)"
check "logs of a missing container is not found" 3 "$($K cluster logs lab-k3s deploy/web --namespace t-e2eclu -c nope >/dev/null; echo $?)"
check "logs of a workload name the object and its pods" "deploy/web 1" "$($K cluster logs lab-k3s deploy/web --namespace t-e2eclu | jget 'd["data"]["object"] + " " + str(len(d["data"]["pods"]))')"
check "cluster run ends a watch at --timeout" 0 "$($K cluster run lab-k3s --timeout 3s -- get pods -n t-e2eclu -w >/dev/null; echo $?)"
check "forward ends normally at --timeout" "0 True" "$($K cluster forward lab-k3s deploy/web 18097:80 --namespace t-e2eclu --timeout 3s >"$TMP/o" 2>/dev/null; echo $?) $(jget 'd["ok"]' <"$TMP/o")"
q $K cluster rm lab-k3s namespace t-e2eclu --allow-dangerous

# --- Docker Swarm ---------------------------------------------------------------
check "Swarm status has the Kubernetes shape" "True True" "$($K cluster status swarm1 | jget 'str("healthy" in d["data"]) + " " + str(isinstance(d["data"]["problems"], list))')"
check "not a Swarm manager says so" "3 NOT_SWARM_MANAGER" "$($K cluster status direct >"$TMP/o"; echo $?) $(jget 'd["error"]["code"]' <"$TMP/o")"
check "a missing service is not found" "3 True" "$($K cluster status swarm1 service/nope >"$TMP/o"; echo $?) $(jget 'd["error"]["message"] != ""' <"$TMP/o")"
check "--namespace on Swarm is refused" USAGE "$($K cluster ls swarm1 services --namespace x | jget 'd["error"]["code"]')"
q $K docker raw swarm1 -- tag "$CLU_IMG" t-e2eclu/busybox:2
q $K cluster run swarm1 --write -- service create --detach --name t-e2eclu-web "$CLU_IMG" sleep 86400
check "Swarm service rolls out" True "$($K cluster status swarm1 svc/t-e2eclu-web --wait --timeout 90s | jget 'd["data"]["rolled_out"]')"
check "Swarm ls has items with ready" "1/1" "$($K cluster ls swarm1 svc | jget '[i["ready"] for i in d["data"]["items"] if i["name"]=="t-e2eclu-web"][0]')"
check "Swarm ls tasks -n limits" 1 "$($K cluster ls swarm1 tasks -n 1 | jget 'len(d["data"]["items"])')"
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
q $K cluster rm swarm1 service/t-e2eclu-web --allow-dangerous
q $K docker raw swarm1 --allow-dangerous -- rmi t-e2eclu/busybox:2

# --- registry -------------------------------------------------------------------
check "a missing tag names the tags there" "3 True" "$($K registry inspect reg mirror/busybox:latest >"$TMP/o"; echo $?) $(jget '"mirror/busybox:latest not found; tags: stable" in d["error"]["message"]' <"$TMP/o")"
check "rm --dry-run names the tags that go" True "$($K registry rm reg mirror/busybox:stable --dry-run | jget '"stable" in d["data"]["would_remove_tags"]')"
check "copy without CONN: is a usage error" USAGE "$($K registry copy mirror/busybox:stable reg:x | jget 'd["error"]["code"]')"
set -e
