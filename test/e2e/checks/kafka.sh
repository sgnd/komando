# shellcheck shell=bash
# Kafka through --via bastion: conn test logs in, a topic is created
# (dry run first), a message goes in and peek reads it back without a
# consumer group, and purge and rm need --allow-dangerous.
set +e
KDC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
for _ in $(seq 1 60); do
  KDC exec -T kafka /opt/kafka/bin/kafka-broker-api-versions.sh --bootstrap-server localhost:9092 >/dev/null 2>&1 && break
  sleep 1
done
q $K conn add events kafka://kafka:9092 --via bastion
for _ in $(seq 1 30); do [ "$($K conn test events | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "kafka conn test logs in through --via" login "$($K conn test events | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "kafka info lists the advertised broker" kafka:9092 "$($K queue info events | jget 'd["data"]["brokers"][0]["address"]')"
check "kafka create --dry-run makes nothing" True "$($K --dry-run queue create events e2e-orders --partitions 2 --replicas 1 | jget 'd["data"]["dry_run"]')"
check "kafka ls is empty after the dry run" 0 "$($K queue ls events 'e2e-*' | jget 'd["data"]["count"]')"
check "kafka create" 2 "$($K queue create events e2e-orders --partitions 2 --replicas 1 | jget 'd["data"]["partitions"]')"
check "kafka send" 0 "$($K queue send events e2e-orders --value '{"id": 1}' --partition 0 | jget 'd["data"]["offset"]')"
q $K queue send events e2e-orders --value '{"id": 2}' --key 2
check "kafka peek reads both" 2 "$($K queue peek events e2e-orders | jget 'd["data"]["count"]')"
check "kafka peek joins no group" 0 "$($K queue groups events | jget 'len([g for g in d["data"]["groups"] if "e2e-orders" in g["topics"]])')"
check "kafka describe counts messages" 2 "$($K queue describe events e2e-orders | jget 'd["data"]["messages"]')"
check "kafka purge needs --allow-dangerous" POLICY_BLOCKED "$($K queue purge events e2e-orders | jget 'd["error"]["code"]')"
check "kafka rm needs --allow-dangerous" POLICY_BLOCKED "$($K queue rm events e2e-orders | jget 'd["error"]["code"]')"
check "kafka purge --dry-run counts" 2 "$($K --dry-run queue purge events e2e-orders | jget 'd["data"]["messages"]')"
q $K queue rm events e2e-orders --allow-dangerous
q $K conn rm events
set -e
