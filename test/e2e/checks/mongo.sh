# shellcheck shell=bash
# MongoDB through --via bastion: login, a read, a write that needs --write,
# the destructive guard, schema, info, users and db kill. Uses the e2e_mongo database and
# drops it at the end.
set +e
MDC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
for _ in $(seq 1 60); do
  MDC exec -T mongo mongosh --quiet -u root -p mongopass --eval 'db.runCommand({ping: 1}).ok' 2>/dev/null | grep -q 1 && break
  sleep 1
done
if ! MDC exec -T mongo mongosh --quiet -u root -p mongopass --eval 'db.runCommand({ping: 1}).ok' 2>/dev/null | grep -q 1; then
  echo "  mongo is not answering; its state and last log lines:"
  MDC ps -a mongo 2>&1 | sed 's/^/    /'
  MDC logs --tail 30 mongo 2>&1 | sed 's/^/    /'
fi
echo -n mongopass | $K secret set mongo-pass >/dev/null
q $K conn add shop-mongo 'mongodb://root@mongo/e2e_mongo?authSource=admin' --via bastion --password-ref credential:mongo-pass
for _ in $(seq 1 30); do [ "$($K conn test shop-mongo | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "mongo conn test logs in through --via" login "$($K conn test shop-mongo | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "mongo insert needs --write" WRITE_REQUIRES_FLAG "$($K db query shop-mongo '{"insert": "users", "documents": [{"name": "Ada"}]}' | jget 'd["error"]["code"]')"
check "mongo insert" 2 "$($K db query shop-mongo --write '{"insert": "users", "documents": [{"name": "Ada", "plan": "pro"}, {"name": "Bob"}]}' | jget 'd["data"]["reply"]["n"]')"
check "mongo find" "['Ada']" "$($K db query shop-mongo '{"find": "users", "filter": {"plan": "pro"}}' | jget '[x["name"] for x in d["data"]["documents"]]')"
check "mongo find as text is one document a line" 2 "$($K db query shop-mongo '{"find": "users"}' -o text | grep -c '"name"')"
check "mongo delete-all is destructive" POLICY_BLOCKED "$($K db query shop-mongo --write '{"delete": "users", "deletes": [{"q": {}, "limit": 0}]}' | jget 'd["error"]["code"]')"
check "mongo schema lists the collection" "['users']" "$($K db schema shop-mongo | jget '[c["name"] for c in d["data"]["collections"]]')"
check "mongo info" standalone "$($K db info shop-mongo | jget 'd["data"]["role"]')"
check "mongo explain shows the plan" True "$($K db explain shop-mongo '{"find": "users", "filter": {"plan": "pro"}}' | jget '"queryPlanner" in d["data"]["plan"]')"
check "mongo explain --analyze has the numbers" True "$($K db explain shop-mongo --analyze '{"find": "users"}' | jget 'd["data"]["plan"]["executionStats"]["nReturned"] >= 2')"
check "mongo explain of a write is refused" USAGE "$($K db explain shop-mongo '{"delete": "users", "deletes": [{"q": {}, "limit": 0}]}' | jget 'd["error"]["code"]' || true)"
check "mongo activity lists operations" True "$($K db activity shop-mongo --all | jget 'd["data"]["count"] >= 1')"
check "mongo user list shows root, no credentials" "True False" "$($K db user list shop-mongo | jget '" ".join(str(x) for x in ["root" in [u["name"] for u in d["data"]["users"]], "SCRAM-SHA-256:" in str(d)])')"
check "mongo user show lists the roles" True "$($K db user show shop-mongo root | jget '"root" in [g["privileges"] for g in d["data"]["grants"] if g["on_type"] == "role"]')"
check "mongo user add says to use db query" NOT_SUPPORTED "$($K db user add shop-mongo app --no-login | jget 'd["error"]["code"]')"
check "mongo kill --session is refused" NOT_SUPPORTED "$($K db kill shop-mongo 42 --session | jget 'd["error"]["code"]')"
MDC exec -T mongo mongosh --quiet -u root -p mongopass e2e_mongo --authenticationDatabase admin --eval 'db.users.find({$where: "sleep(30000) || true"}).toArray()' >"$TMP/mslow.out" 2>&1 &
MSLOW=$!
OPID=
for _ in $(seq 1 50); do
  OPID=$($K db activity shop-mongo | jget '([s["pid"] for s in d["data"]["sessions"] if "sleep(30000)" in s["query"]] + [""])[0]')
  [ -n "$OPID" ] && break
  sleep 0.2
done
check "mongo activity shows the slow read" True "$([ -n "$OPID" ] && echo True || echo False)"
check "mongo kill --dry-run names the operation" "cancel query" "$($K db kill shop-mongo "$OPID" --dry-run | jget 'd["data"]["would"]')"
check "mongo kill stops it" "cancel query" "$($K db kill shop-mongo "$OPID" | jget 'd["data"]["done"]')"
wait "$MSLOW" 2>/dev/null
check "the slow read was interrupted" 1 "$(grep -c -i interrupted "$TMP/mslow.out")"
check "mongo dump says SQL only" NOT_SUPPORTED "$($K db dump shop-mongo --to "$TMP/m.dump" | jget 'd["error"]["code"]')"
q $K db query shop-mongo --write --allow-dangerous '{"dropDatabase": 1}'
q $K conn rm shop-mongo
set -e
