# shellcheck shell=bash
# ClickHouse through --via bastion, over its HTTP interface: login, reads
# with readonly=1, writes with --write (each alone, a dry run only reports
# them), the table functions that reach out, schema, info, explain, sizes,
# activity, users and grants. Uses the database e2e_ch and drops it at the
# end.
set +e
CHC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
printf 'Admin-pass-1' | $K secret set ch-admin >/dev/null
printf 'Ro-pass-1x' | $K secret set ch-ro >/dev/null
q $K conn add admin-ch 'clickhouse://admin@clickhouse:8123/default' --via bastion --password-ref secret:ch-admin
for _ in $(seq 1 60); do [ "$($K conn test admin-ch | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
if [ "$($K conn test admin-ch | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" != True ]; then
  echo "  clickhouse is not answering; its state and last log lines:"
  CHC ps -a clickhouse 2>&1 | sed 's/^/    /'
  CHC logs --tail 30 clickhouse 2>&1 | sed 's/^/    /'
  echo "  the ClickHouse checks are skipped (the server could not run here)"
  q $K conn rm admin-ch
  $K secret rm ch-admin ch-ro --allow-dangerous >/dev/null 2>&1 || true
  set -e
  return 0
fi
check "clickhouse conn test logs in through --via" login "$($K conn test admin-ch | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "clickhouse create database needs --write" WRITE_REQUIRES_FLAG "$($K db query admin-ch 'create database e2e_ch' | jget 'd["error"]["code"]')"
q $K db query admin-ch --write 'create database e2e_ch'
q $K conn add shop-ch 'clickhouse://admin@clickhouse:8123/e2e_ch' --via bastion --password-ref secret:ch-admin
q $K db query shop-ch --write "create table orders (id UInt64, item String, total Decimal(10, 2), placed DateTime default now()) engine = MergeTree order by id"
check "clickhouse insert needs --write" WRITE_REQUIRES_FLAG "$($K db query shop-ch "insert into orders (id, item, total) values (1, 'pen', 1.5)" | jget 'd["error"]["code"]')"
check "clickhouse a dry run only reports a write" True "$($K db query shop-ch --write --dry-run "insert into orders (id, item, total) values (1, 'pen', 1.5)" | jget '"skipped" in d["data"]["results"][0]')"
check "clickhouse insert" 2 "$($K db query shop-ch --write "insert into orders (id, item, total) values (1, 'pen', 1.5), (2, 'ink', 12.25)" | jget 'd["data"]["results"][0]["rows_affected"]')"
check "clickhouse a write goes alone" USAGE "$($K db query shop-ch --write "insert into orders (id, item) values (3, 'x'); select 1" | jget 'd["error"]["code"]')"
check "clickhouse select with {p1:UInt64}" "['ink', '12.25']" "$($K db query shop-ch 'select item, total from orders where id = {p1:UInt64}' --arg 2 | jget 'd["data"]["results"][0]["rows"][0]')"
check "clickhouse settings are refused in a read" USAGE "$($K db query shop-ch 'select 1 settings readonly = 0' | jget 'd["error"]["code"]')"
check "clickhouse url() needs --allow-dangerous" WRITE_REQUIRES_FLAG "$($K db query shop-ch "select * from url('http://bastion:1/x', CSV, 'a String')" | jget 'd["error"]["code"]')"
check "clickhouse heredocs are refused" SQL_HIDDEN_CODE "$($K db query shop-ch 'select $$x$$' | jget 'd["error"]["code"]')"
check "clickhouse quotes hide nothing" True "$($K db query shop-ch "select 'it\\'s; drop table orders' as t" | jget 'd["ok"]')"
check "clickhouse drop is destructive" POLICY_BLOCKED "$($K db query shop-ch --write 'drop table orders' | jget 'd["error"]["code"]')"
check "clickhouse schema lists the table" True "$($K db schema shop-ch | jget 'any(t["schema"] + "." + t["name"] == "e2e_ch.orders" and t["engine"] == "MergeTree" for t in d["data"]["tables"])')"
check "clickhouse schema shows the key" "['id']" "$($K db schema shop-ch e2e_ch.orders | jget '[c["name"] for c in d["data"]["tables"][0]["columns"] if c.get("primary_key")]')"
check "clickhouse info" True "$($K db info admin-ch | jget 'd["data"]["version"] != ""')"
check "clickhouse explain" True "$($K db explain shop-ch 'select * from orders where id = 1' | jget 'any("ReadFromMergeTree" in r[0] for r in d["data"]["results"][0]["rows"])')"
check "clickhouse sizes lists the table" True "$($K db sizes admin-ch | jget 'any(t["name"] == "orders" for t in d["data"]["tables"])')"
check "clickhouse activity answers" True "$($K db activity admin-ch | jget 'd["ok"]')"
check "clickhouse locks is not supported" NOT_SUPPORTED "$($K db locks admin-ch | jget 'd["error"]["code"]')"
q $K db user add admin-ch e2e_ro --password-ref secret:ch-ro
q $K db grant admin-ch e2e_ro --privileges SELECT --on 'e2e_ch.*'
q $K conn add ro-ch 'clickhouse://e2e_ro@clickhouse:8123/e2e_ch' --via bastion --password-ref secret:ch-ro
check "clickhouse: the new user logs in with the vault password" 2 "$($K db query ro-ch 'select count() from orders' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "clickhouse: and may only read what was granted" False "$($K db query ro-ch --write "insert into orders (id) values (9)" | jget 'd["ok"]')"
check "clickhouse db grants shows SELECT" True "$($K db grants admin-ch e2e_ro | jget 'any(g["object"] == "e2e_ch.*" and "SELECT" in g["privileges"] for g in d["data"]["grants"])')"
q $K conn rm ro-ch
q $K db user rm admin-ch e2e_ro --allow-dangerous
check "clickhouse db user rm removed it" False "$($K db user ls admin-ch | jget 'any(u["name"] == "e2e_ro" for u in d["data"]["users"])')"
check "clickhouse dump is not supported" NOT_SUPPORTED "$($K db dump shop-ch --to "$TMP/c.sql" | jget 'd["error"]["code"]')"
check "no clickhouse password in the audit log" 0 "$(audit_text | grep -c -E 'Admin-pass-1|Ro-pass-1x' || true)"
q $K conn rm shop-ch
q $K db query admin-ch --write --allow-dangerous 'drop database e2e_ch'
q $K conn rm admin-ch
$K secret rm ch-admin ch-ro --allow-dangerous >/dev/null 2>&1 || true
set -e
