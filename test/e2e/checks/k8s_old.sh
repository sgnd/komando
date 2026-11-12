# shellcheck shell=bash
# Kubernetes 1.29 (k3s-old): no WebSocket exec yet, so komando streams over
# SPDY there.
# Kubernetes 1.29 has no WebSocket exec (v5): the same commands go over SPDY
echo "==> cluster on Kubernetes 1.29 (SPDY)"
NOKUBE=(env PATH=/usr/bin:/bin)
write_tools_yaml "$TMP/tools.yaml"
echo "copied in" > "$TMP/cp-in.txt"
for _ in $(seq 1 60); do docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s-old kubectl get nodes 2>/dev/null | grep -q " Ready" && break; sleep 2; done
# a new cluster makes no pod before its default ServiceAccount exists
for _ in $(seq 1 60); do docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s-old kubectl get serviceaccount default >/dev/null 2>&1 && break; sleep 2; done
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s-old cat /etc/rancher/k3s/k3s.yaml | sed 's#https://127.0.0.1:6443#https://k3s-old:6443#; s#: default$#: lab-old#' > "$TMP/kubeconfig-old"
q $K import kubeconfig "$TMP/kubeconfig-old"
q $K conn edit lab-old --via bastion
q $K cluster apply lab-old --file "$TMP/tools.yaml"
$K cluster status lab-old deployment/tools --wait --timeout 180s >/dev/null || true
check "1.29: exec over SPDY" hello-from-pod "$("${NOKUBE[@]}" $K cluster exec lab-old deploy/tools --read-only -- cat /www/index.html | jget 'd["data"]["stdout"].strip()' || true)"
check "1.29: exec keeps stdout, stderr and the exit code" "3 out err" "$("${NOKUBE[@]}" $K cluster exec lab-old deploy/tools --read-only -- sh -c 'echo out; echo err >&2; exit 3' | jget 'str(d["data"]["exit_code"]) + " " + d["data"]["stdout"].strip() + " " + d["data"]["stderr"].strip()' || true)"
"${NOKUBE[@]}" $K cluster forward lab-old deploy/tools 18097:8080 --timeout 20s >/dev/null 2>&1 &
for _ in $(seq 1 20); do curl -sf http://127.0.0.1:18097/ >/dev/null && break; sleep 1; done
check "1.29: forward a pod port" "hello-from-pod hello-from-pod" "$(curl -sf http://127.0.0.1:18097/ || true) $(curl -sf http://127.0.0.1:18097/ || true)"
wait
POD_OLD=$("${NOKUBE[@]}" $K cluster run lab-old -- get pods -l app=tools -o 'jsonpath={.items[0].metadata.name}' | jget 'd["data"]["stdout"]' || true)
q "${NOKUBE[@]}" $K cluster run lab-old --write --allow-dangerous -- cp "$TMP/cp-in.txt" "$POD_OLD:/tmp/cp-in.txt"
q "${NOKUBE[@]}" $K cluster run lab-old --write --allow-dangerous -- cp "$POD_OLD:/tmp/cp-in.txt" "$TMP/cp-back-old.txt"
check "1.29: cp there and back (stdin ends over SPDY)" "copied in" "$(cat "$TMP/cp-back-old.txt" 2>/dev/null)"
check "1.29: cluster shell for a person" hello-from-pod "$(ptyrun 'cat /www/index.html; exit\n' env NO_COLOR=1 "$K" cluster shell lab-old deploy/tools | tr -d '\r' | grep -x hello-from-pod | head -1 || true)"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T k3s-old cat /etc/rancher/k3s/k3s.yaml | sed "s#https://127.0.0.1:6443#https://127.0.0.1:$E2E_K3S_OLD#" > "$TMP/kubeconfig-old-direct"
(cd "$ROOT" && KOMANDO_E2E_OLD_KUBECONFIG="$TMP/kubeconfig-old-direct" go test -count=1 -v -run '^TestSPDYCluster$' ./internal/kube/ >"$TMP/spdy.log" 2>&1) || true
check "1.29: every SPDY path (exec, stdin end, terminal, port-forward)" ok "$(grep -q -- '--- PASS: TestSPDYCluster' "$TMP/spdy.log" && echo ok)"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" stop k3s-old >/dev/null 2>&1 || true
