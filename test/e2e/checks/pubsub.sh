# shellcheck shell=bash
# Google Cloud Pub/Sub through --via bastion, answered by the emulator:
# conn test, a topic and a subscription are created (dry run first),
# messages go in, peek pulls them and gives every one back, and purge and
# rm need --allow-dangerous.
set +e
q $K conn add gcp 'pubsub://test-project?endpoint=http://pubsub:8085' --via bastion
for _ in $(seq 1 60); do [ "$($K conn test gcp | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
check "pubsub conn test through --via" login "$($K conn test gcp | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "pubsub http endpoint across the network is refused" INSECURE_PROTOCOL "$($K conn add gcp-plain 'pubsub://test-project?endpoint=http://pubsub.example.com:8085' | jget 'd["error"]["code"]')"
check "pubsub info names the project" test-project "$($K queue info gcp | jget 'd["data"]["project"]')"
check "pubsub create --dry-run makes nothing" TOPIC_NOT_FOUND "$($K --dry-run queue create gcp e2e-orders >/dev/null; $K queue describe gcp e2e-orders | jget 'd["error"]["code"]')"
check "pubsub create topic" projects/test-project/topics/e2e-orders "$($K queue create gcp e2e-orders | jget 'd["data"]["full_name"]')"
check "pubsub create twice" TOPIC_EXISTS "$($K queue create gcp e2e-orders | jget 'd["error"]["code"]')"
check "pubsub create subscription" e2e-orders "$($K queue create gcp subscriptions/e2e-billing --config topic=e2e-orders --config ackDeadlineSeconds=20 | jget 'd["data"]["of_topic"]')"
q $K queue send gcp e2e-orders --value '{"id": 1}' --header source=e2e
q $K queue send gcp e2e-orders --value '{"id": 2}' --key k1
check "pubsub peek of a topic points to its subscriptions" SUBSCRIPTION_NOT_FOUND "$($K queue peek gcp e2e-orders | jget 'd["error"]["code"]')"
check "pubsub peek pulls and gives back" "2 True" "$($K queue peek gcp e2e-billing | jget '"%d %s" % (d["data"]["count"], d["data"]["requeued"])')"
check "pubsub peek again sees the same messages" 2 "$($K queue peek gcp e2e-billing | jget 'd["data"]["count"]')"
check "pubsub describe lists the subscription" e2e-billing "$($K queue describe gcp e2e-orders | jget 'd["data"]["subscription_info"][0]["subscription"]')"
check "pubsub groups lists subscriptions" pull "$($K queue groups gcp | jget '[g for g in d["data"]["groups"] if g["name"] == "e2e-billing"][0]["delivery"]')"
check "pubsub lag is not supported" NOT_SUPPORTED "$($K queue lag gcp e2e-billing | jget 'd["error"]["code"]')"
check "pubsub purge needs --allow-dangerous" POLICY_BLOCKED "$($K queue purge gcp e2e-billing | jget 'd["error"]["code"]')"
check "pubsub rm needs --allow-dangerous" POLICY_BLOCKED "$($K queue rm gcp e2e-orders | jget 'd["error"]["code"]')"
check "pubsub purge empties the subscription" 0 "$($K queue purge gcp e2e-billing --allow-dangerous >/dev/null; $K queue peek gcp e2e-billing | jget 'd["data"]["count"]')"
q $K queue rm gcp subscriptions/e2e-billing e2e-orders --allow-dangerous
q $K conn rm gcp
set -e
