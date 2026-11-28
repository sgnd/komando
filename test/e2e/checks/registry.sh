# shellcheck shell=bash
# Container registry (registry:2 on the private network, through the
# bastion), and one with HTTPS from a private CA.
echo "==> registry"
docker pull -q busybox:1.37 >/dev/null && docker tag busybox:1.37 "127.0.0.1:$E2E_REGISTRY"/tools/busybox:1.37 && docker push -q "127.0.0.1:$E2E_REGISTRY"/tools/busybox:1.37 >/dev/null
q $K conn add reg 'registry://e2e@registry:5000?tls=false' --via bastion
check "registry catalog" True "$($K registry oci image list reg | jget '"tools/busybox" in d["data"]["repositories"]')"
check "registry tags" 1.37 "$($K registry oci image list reg tools/busybox | jget 'd["data"]["tags"][0]')"
check "registry oci image show digest" True "$($K registry oci image show reg tools/busybox:1.37 | jget 'd["data"]["digest"].startswith("sha256:")')"
q $K registry oci image copy reg:tools/busybox:1.37 reg:mirror/busybox:stable
check "registry oci image copy keeps the digest" "$($K registry oci image show reg tools/busybox:1.37 | jget 'd["data"]["digest"]')" "$($K registry oci image show reg mirror/busybox:stable | jget 'd["data"]["digest"]')"
set +e; $K registry oci image delete reg tools/busybox:1.37 >/dev/null; check "registry oci image delete needs --allow-dangerous" 6 $?; set -e
check "registry oci image delete names the tags it takes" True "$($K registry oci image delete reg tools/busybox:1.37 --allow-dangerous --dry-run | jget '"1.37" in d["data"]["tags"]')"
q $K registry oci image delete reg tools/busybox:1.37 --allow-dangerous
check "registry oci image delete removed it" IMAGE_TAG_NOT_FOUND "$($K registry oci image show reg tools/busybox:1.37 | jget 'd["error"]["code"]' || true)"
# a person deleting an image: told which tags go, then types the conn's name
rtty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; }
# its own repository: clu.sh uses mirror/busybox:stable later
q $K registry oci image copy reg:mirror/busybox:stable reg:t-person/busybox:stable
q $K registry oci image copy reg:mirror/busybox:stable reg:t-person/busybox:also
set +e
O=$(rtty 'wrong\n' registry oci image delete reg t-person/busybox:stable); RC=$?
check "person: registry oci image delete says every tag that goes" 1 "$(grep -c 'every tag on it: also, stable' <<<"$O")"
check "person: registry oci image delete asks to type the name" 1 "$(grep -c 'Type the name t-person/busybox:stable to continue' <<<"$O")"
check "person: a wrong name stops registry oci image delete (6)" 6 "$RC"
check "person: a wrong name deleted nothing" True "$($K registry oci image show reg t-person/busybox:also | jget 'd["ok"]')"
O=$(rtty 't-person/busybox:stable\n' registry oci image delete reg t-person/busybox:stable); RC=$?
check "person: the right name deletes the image" "0 1" "$RC $(grep -c 'with it went every tag on that image: also, stable' <<<"$O")"
check "person: both tags are gone" "[]" "$($K registry oci image list reg t-person/busybox | jget 'd["data"]["tags"]')"
# Next: is said only at a terminal that is not dumb (rtty's is)
check "person: registry oci image list in text says what is next" 1 "$(ptyrun '' env NO_COLOR=1 TERM=xterm CI= "$K" -o text registry oci image list reg | tr -d '\r' | grep -c 'Next: komando registry oci image list reg REPO')"
check "agent: registry names are checked first" USAGE "$($K registry oci image show reg 'tools/../_catalog:1' | jget 'd["error"]["code"]' || true)"
set -e
# prune: three images built one after the other; keepme is the same image as v1
for v in 1 2 3; do
  printf 'FROM busybox:1.37\nRUN echo %s > /build\n' "$v" | docker build -q -t "127.0.0.1:$E2E_REGISTRY/prune/app:v$v" - >/dev/null
  docker push -q "127.0.0.1:$E2E_REGISTRY/prune/app:v$v" >/dev/null; sleep 1
done
docker tag "127.0.0.1:$E2E_REGISTRY/prune/app:v1" "127.0.0.1:$E2E_REGISTRY/prune/app:keepme" && docker push -q "127.0.0.1:$E2E_REGISTRY/prune/app:keepme" >/dev/null
check "registry oci image prune needs --allow-dangerous" 6 "$($K registry oci image prune reg prune/app --keep 1 >/dev/null 2>&1; echo $?)"
check "registry oci image prune --dry-run: only v2 goes (v1 is keepme's image)" "['v2'] False" \
  "$($K registry oci image prune reg prune/app --keep 1 --match '^v' --dry-run | jget '[t for d_ in d["data"]["delete"] for t in d_["tags"]], "deleted" in d["data"]')"
q $K registry oci image prune reg prune/app --keep 1 --match '^v' --allow-dangerous
check "registry oci image prune deleted v2 and kept the rest" "['keepme', 'v1', 'v3']" "$($K registry oci image list reg prune/app | jget 'sorted(d["data"]["tags"])')"
# registry TLS: HTTPS with a private CA, at a name only bastion can look up
q $K conn add regtls 'registry://e2e@registry.lab.test' --via bastion
check "registry: a private CA is refused by default" REGISTRY_TLS "$($K registry oci image list regtls | jget 'd["error"]["code"]' || true)"
check "registry: the refusal points at ca= first" True "$($K registry oci image list regtls | jget '"?ca=credential:NAME" in d["error"]["hint"]' || true)"
docker compose -p "$PROJECT" -f "$E2E/compose.yml" exec -T regtls cat /certs/ca.crt | $K credential token add regtls-ca >/dev/null
q $K conn edit regtls --url 'registry://e2e@registry.lab.test?ca=credential:regtls-ca'
check "registry: ?ca=credential:NAME trusts the private CA (name looked up on bastion)" True "$($K registry oci image list regtls | jget 'd["ok"]')"
check "registry: conn test logs in with ca=" login "$($K conn test regtls | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "registry: ca= is not a doctor warning" False "$($K doctor | jget 'any(c["name"] == "security:conn:regtls" for c in d["data"]["security"])')"
q $K conn edit regtls --url 'registry://e2e@registry.lab.test?tls=skip-verify'
check "registry: ?tls=skip-verify works without the CA" True "$($K registry oci image list regtls | jget 'd["ok"]')"
check "registry: doctor warns about tls=skip-verify, --via too" True "$($K doctor | jget 'any(c["name"] == "security:conn:regtls" and c["warning"] for c in d["data"]["security"])')"
check "registry: an unknown tls value is refused" USAGE "$($K conn edit regtls --url 'registry://e2e@registry.lab.test?tls=insecure' | jget 'd["error"]["code"]' || true)"
q $K conn rm regtls
