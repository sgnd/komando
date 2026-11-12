# shellcheck shell=bash
# NATS with JetStream through --via bastion: conn test logs in, a stream
# is created (dry run first), messages go in, peek reads them by sequence
# and takes none away, a consumer shows in groups and lag, and purge and
# rm need --allow-dangerous.
set +e
NDC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
for _ in $(seq 1 60); do
  NDC exec -T nats wget -q -O /dev/null 'http://127.0.0.1:8222/healthz?js-enabled-only=true' >/dev/null 2>&1 && break
  sleep 1
done
echo -n natspass | $K secret set nats-pass >/dev/null
q $K conn add stream 'nats://app@nats:4222' --via bastion --password-ref secret:nats-pass
for _ in $(seq 1 30); do [ "$($K conn test stream | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "nats conn test logs in through --via" login "$($K conn test stream | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "nats info sees JetStream" True "$($K queue info stream | jget 'd["data"]["jetstream"]')"
check "nats create --dry-run makes nothing" STREAM_NOT_FOUND "$($K --dry-run queue create stream E2E_ORDERS --config 'subjects=e2e.orders.>' >/dev/null; $K queue describe stream E2E_ORDERS | jget 'd["error"]["code"]')"
check "nats create" workqueue "$($K queue create stream E2E_ORDERS --config 'subjects=e2e.orders.>' --config retention=workqueue | jget 'd["data"]["retention"]')"
check "nats create twice" STREAM_EXISTS "$($K queue create stream E2E_ORDERS | jget 'd["error"]["code"]')"
q $K queue send stream e2e.orders.new --value '{"id": 1}' --header source=e2e
check "nats send says the sequence" 2 "$($K queue send stream e2e.orders.new --value '{"id": 2}' | jget 'd["data"]["sequence"]')"
check "nats send to no stream's subject" STREAM_NOT_FOUND "$($K queue send stream nowhere --value x | jget 'd["error"]["code"]')"
check "nats peek reads the newest" "[1, 2]" "$($K queue peek stream E2E_ORDERS | jget '[m["sequence"] for m in d["data"]["messages"]]')"
check "nats peek takes nothing from a work queue" 2 "$($K queue peek stream E2E_ORDERS --oldest -n 1 >/dev/null; $K queue describe stream E2E_ORDERS | jget 'd["data"]["messages"]')"
check "nats groups lists no consumers yet" 0 "$($K queue groups stream | jget 'd["data"]["count"]')"
check "nats lag of no consumer" CONSUMER_NOT_FOUND "$($K queue lag stream E2E_ORDERS/billing | jget 'd["error"]["code"]')"
check "nats purge needs --allow-dangerous" POLICY_BLOCKED "$($K queue purge stream E2E_ORDERS | jget 'd["error"]["code"]')"
check "nats rm needs --allow-dangerous" POLICY_BLOCKED "$($K queue rm stream E2E_ORDERS | jget 'd["error"]["code"]')"
check "nats purge --dry-run counts" 2 "$($K --dry-run queue purge stream E2E_ORDERS | jget 'd["data"]["messages"]')"
check "nats peek --wait is for Kafka" NOT_SUPPORTED "$($K queue peek stream E2E_ORDERS --wait 2s | jget 'd["error"]["code"]')"
check "nats ls -n 1 is cut and says so" "1 True" "$($K queue create stream E2E_ZZ --config 'subjects=e2e.zz' >/dev/null; $K queue ls stream 'E2E_*' -n 1 | jget '"%d %s" % (d["data"]["count"], d["data"].get("truncated"))')"
pty() { ptyrun "$1" env NO_COLOR=1 TERM=dumb "$K" -o text "${@:2}" | tr -d '\r'; }
O=$(pty 'wrong\n' queue purge stream E2E_ORDERS); RC=$?
check "nats person: a wrong name stops purge (6)" "6 2" "$RC $($K queue describe stream E2E_ORDERS | jget 'd["data"]["messages"]')"
pty 'stream\n' queue purge stream E2E_ORDERS >/dev/null
check "nats person: the right name purges" 0 "$($K queue describe stream E2E_ORDERS | jget 'd["data"]["messages"]')"
pty 'stream\n' queue rm stream E2E_ZZ >/dev/null
check "nats person: the right name removes the stream" STREAM_NOT_FOUND "$($K queue describe stream E2E_ZZ | jget 'd["error"]["code"]')"
q $K queue rm stream E2E_ORDERS --allow-dangerous
q $K conn rm stream
set -e
