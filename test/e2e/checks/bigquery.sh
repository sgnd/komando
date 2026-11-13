# shellcheck shell=bash
# BigQuery through --via bastion, against komando's own fake of the REST
# API and Google's token endpoint (test/e2e/bigquery; no Google project
# here, and goccy/bigquery-emulator cannot do dry runs): a service account
# login, TLS with a private CA, the dry run before every statement, the
# byte cap, what needs --write never reaching the server. BigQuery's own
# SQL is not checked here (docs/features/databases.md).
set +e
BQC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
for _ in $(seq 1 60); do BQC exec -T bigquery test -s /e2e/sa.json 2>/dev/null && break; sleep 1; done
if ! BQC exec -T bigquery test -s /e2e/sa.json 2>/dev/null; then
  echo "  the bigquery fake is not running; its state and last log lines:"
  BQC ps -a bigquery 2>&1 | sed 's/^/    /'
  BQC logs --tail 30 bigquery 2>&1 | sed 's/^/    /'
  echo "  the BigQuery checks are skipped (the fake could not run here)"
  set -e
  return 0
fi
BQC exec -T bigquery cat /e2e/ca.crt | $K secret set bq-ca >/dev/null
BQC exec -T bigquery cat /e2e/sa.json | $K secret set bq-sa >/dev/null
q $K conn add bq 'bigquery://e2e-project/shop?location=EU&endpoint=https://bigquery.e2e.internal&ca=secret:bq-ca' --via bastion --password-ref secret:bq-sa
check "bigquery conn test logs in with a service account key through --via" login "$($K conn test bq | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "bigquery reads with a ? placeholder" "['hi', 42]" "$($K db query bq 'select ? as greeting, 42 as n' --arg hi | jget 'd["data"]["results"][0]["rows"][0]')"
check "bigquery insert needs --write" WRITE_REQUIRES_FLAG "$($K db query bq "insert into shop.orders values (1, 'pen')" | jget 'd["error"]["code"]')"
check "bigquery a dry run is BigQuery's dry run" 1024 "$($K db query bq --write --dry-run "insert into shop.orders values (1, 'pen')" | jget 'd["data"]["results"][0]["bytes_processed"]')"
check "bigquery insert" 2 "$($K db query bq --write "insert into shop.orders values (1, 'pen'), (2, 'ink')" | jget 'd["data"]["results"][0]["rows_affected"]')"
check "bigquery: only the real insert reached the server as a job" 1 "$(BQC exec -T bigquery cat /e2e/jobs.log | grep -c '^insert')"
check "bigquery: what BigQuery calls a write needs --write" WRITE_REQUIRES_FLAG "$($K db query bq 'select sneaky' | jget 'd["error"]["code"]')"
check "bigquery a query over --max-bytes does not run" DB_BYTES_LIMIT "$($K db query bq 'select * from shop.huge_events' | jget 'd["error"]["code"]')"
check "bigquery: it did not reach the server as a job" 0 "$(BQC exec -T bigquery cat /e2e/jobs.log | grep -c 'huge_events')"
check "bigquery a higher --max-bytes lets it run" 53687091200 "$($K db query bq 'select * from shop.huge_events' --max-bytes 100GB | jget 'd["data"]["results"][0]["bytes_processed"]')"
check "bigquery a write goes alone" USAGE "$($K db query bq --write "insert into shop.orders values (3, 'x'); select 1" | jget 'd["error"]["code"]')"
check "bigquery drop is destructive" POLICY_BLOCKED "$($K db query bq --write 'drop table shop.orders' | jget 'd["error"]["code"]')"
check "bigquery export is destructive" POLICY_BLOCKED "$($K db query bq --write "export data options (uri = 'gs://b/*.csv') as select 1" | jget 'd["error"]["code"]')"
check "bigquery quotes hide nothing" SQL_HIDDEN_CODE "$($K db query bq 'select 1 /* a /* b */ drop table shop.orders */' | jget 'd["error"]["code"]')"
check "bigquery explain is the dry run" DELETE "$($K db explain bq 'delete from shop.orders where id = 1' | jget 'd["data"]["results"][0]["rows"][0][1]')"
check "bigquery schema lists the dataset's tables" orders "$($K db schema bq | jget 'd["data"]["tables"][0]["name"]')"
check "bigquery schema shows a table's columns" INT64 "$($K db schema bq shop.orders | jget 'd["data"]["tables"][0]["columns"][0]["type"]')"
check "bigquery dump is not supported" NOT_SUPPORTED "$($K db dump bq --to "$TMP/bq.sql" | jget 'd["error"]["code"]')"
check "bigquery user add is not supported" NOT_SUPPORTED "$($K db user add bq bob --password-ref secret:bq-ca | jget 'd["error"]["code"]')"
q $K conn add bq-noca 'bigquery://e2e-project/shop?endpoint=https://bigquery.e2e.internal' --via bastion --password-ref secret:bq-sa
check "bigquery: a certificate from an unknown CA is refused" DB_CONNECT "$($K db query bq-noca 'select 1' | jget 'd["error"]["code"]')"
check "no bigquery key in the audit log" 0 "$(audit_text | grep -c 'PRIVATE KEY' || true)"
q $K conn rm bq
q $K conn rm bq-noca
$K secret rm bq-ca bq-sa --allow-dangerous >/dev/null 2>&1 || true
set -e
