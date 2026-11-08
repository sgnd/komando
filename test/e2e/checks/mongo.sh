# shellcheck shell=bash
# MongoDB through --via bastion: login, a read, a write that needs --write,
# the destructive guard, schema and info. Uses the e2e_mongo database and
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
q $K conn add shop-mongo 'mongodb://root@mongo/e2e_mongo?authSource=admin' --via bastion --password-ref secret:mongo-pass
for _ in $(seq 1 30); do [ "$($K conn test shop-mongo | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "mongo conn test logs in through --via" login "$($K conn test shop-mongo | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "mongo insert needs --write" WRITE_REQUIRES_FLAG "$($K db query shop-mongo '{"insert": "users", "documents": [{"name": "Ada"}]}' | jget 'd["error"]["code"]')"
check "mongo insert" 2 "$($K db query shop-mongo --write '{"insert": "users", "documents": [{"name": "Ada", "plan": "pro"}, {"name": "Bob"}]}' | jget 'd["data"]["reply"]["n"]')"
check "mongo find" "['Ada']" "$($K db query shop-mongo '{"find": "users", "filter": {"plan": "pro"}}' | jget '[x["name"] for x in d["data"]["documents"]]')"
check "mongo find as text is one document a line" 2 "$($K db query shop-mongo '{"find": "users"}' -o text | grep -c '"name"')"
check "mongo delete-all is destructive" POLICY_BLOCKED "$($K db query shop-mongo --write '{"delete": "users", "deletes": [{"q": {}, "limit": 0}]}' | jget 'd["error"]["code"]')"
check "mongo schema lists the collection" "['users']" "$($K db schema shop-mongo | jget '[c["name"] for c in d["data"]["collections"]]')"
check "mongo info" standalone "$($K db info shop-mongo | jget 'd["data"]["role"]')"
check "mongo dump says SQL only" NOT_SUPPORTED "$($K db dump shop-mongo --to "$TMP/m.dump" | jget 'd["error"]["code"]')"
q $K db query shop-mongo --write --allow-dangerous '{"dropDatabase": 1}'
q $K conn rm shop-mongo
set -e
