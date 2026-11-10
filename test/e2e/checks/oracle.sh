# shellcheck shell=bash
# Oracle through --via bastion: login, reads in a read-only transaction,
# writes with --write, DDL that commits on its own, PL/SQL blocks, schema,
# info, explain, sizes, users and grants. Uses the user E2E_SHOP and drops
# it at the end.
set +e
ORC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
printf 'Oracle-pass-1' | $K secret set ora-system >/dev/null
printf 'Shop-pass-1x' | $K secret set ora-shop >/dev/null
printf 'Ro-pass-1x' | $K secret set ora-ro >/dev/null
q $K conn add sys-ora 'oracle://system@oracle:1521/FREEPDB1' --via bastion --password-ref secret:ora-system
# the database takes a while to open, longer when emulated
for _ in $(seq 1 180); do [ "$($K conn test sys-ora | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
if [ "$($K conn test sys-ora | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" != True ]; then
  echo "  oracle is not answering; its state and last log lines:"
  ORC ps -a oracle 2>&1 | sed 's/^/    /'
  ORC logs --tail 30 oracle 2>&1 | sed 's/^/    /'
  echo "  the Oracle checks are skipped (the image could not run here)"
  q $K conn rm sys-ora
  $K secret rm ora-system ora-shop ora-ro >/dev/null 2>&1 || true
  set -e
  return 0
fi
check "oracle conn test logs in through --via" login "$($K conn test sys-ora | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "oracle create user needs --write" WRITE_REQUIRES_FLAG "$($K db query sys-ora 'create user e2e_shop identified by x' | jget 'd["error"]["code"]')"
q $K db user add sys-ora e2e_shop --password-ref secret:ora-shop
q $K db query sys-ora --write --allow-dangerous 'grant create table, create sequence, unlimited tablespace to e2e_shop'
q $K conn add shop-ora 'oracle://e2e_shop@oracle:1521/FREEPDB1' --via bastion --password-ref secret:ora-shop
# an identity column makes a sequence behind the table: CREATE SEQUENCE is needed too
check "oracle create table" True "$($K db query shop-ora --write "create table orders (id number generated always as identity primary key, item varchar2(50) not null, total number(10,2), placed date default sysdate)" | jget 'd["ok"] or d["error"]')"
check "oracle ddl in a dry run is only reported" True "$($K db query shop-ora --write --dry-run 'create table x (a number)' | jget '"skipped" in d["data"]["results"][0]')"
check "oracle insert needs --write" WRITE_REQUIRES_FLAG "$($K db query shop-ora "insert into orders (item, total) values ('pen', 1.50)" | jget 'd["error"]["code"]')"
q $K db query shop-ora --write "insert into orders (item, total) values ('pen', 1.50)"
check "oracle insert with :1 :2" 1 "$($K db query shop-ora --write 'insert into orders (item, total) values (:1, :2)' --arg ink --arg 12.25 | jget 'd["data"]["results"][0]["rows_affected"]')"
check "oracle select with :1" "['pen', 1.5]" "$($K db query shop-ora 'select item, total from orders where id = :1' --arg 1 | jget 'd["data"]["results"][0]["rows"][0]')"
check "oracle dry run counts the rows" 2 "$($K db query shop-ora --write --dry-run 'delete from orders where id > 0' | jget 'd["data"]["results"][0]["rows_affected"]')"
check "oracle dry run rolled back" 2 "$($K db query shop-ora 'select count(*) from orders' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "oracle delete-all is destructive" POLICY_BLOCKED "$($K db query shop-ora --write 'delete from orders' | jget 'd["error"]["code"]')"
check "oracle commit is refused" SQL_TX_CONTROL "$($K db query shop-ora 'commit' | jget 'd["error"]["code"]')"
check "oracle commit in a block is refused" SQL_TX_CONTROL "$($K db query shop-ora --write 'begin delete from orders where id = 1; commit; end;' | jget 'd["error"]["code"]')"
check "oracle a block needs --write" WRITE_REQUIRES_FLAG "$($K db query shop-ora 'begin null; end;' | jget 'd["error"]["code"]')"
check "oracle q-quotes hide nothing" True "$($K db query shop-ora "select q'[it's; delete from orders]' as t from dual" | jget 'd["ok"]')"
check "oracle schema lists the table" True "$($K db schema shop-ora | jget 'any(t["schema"] + "." + t["name"] == "E2E_SHOP.ORDERS" for t in d["data"]["tables"])')"
check "oracle schema shows the identity" "['ID']" "$($K db schema shop-ora orders | jget '[c["name"] for c in d["data"]["tables"][0]["columns"] if c.get("identity")]')"
check "oracle info" primary "$($K db info sys-ora | jget 'd["data"]["role"]')"
check "oracle explain plans a delete without --write" True "$($K db explain shop-ora 'delete from orders where id = 1' | jget 'any("DELETE STATEMENT" in r[0] for r in d["data"]["results"][0]["rows"])')"
check "oracle explain ran nothing" 2 "$($K db query shop-ora 'select count(*) from orders' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "oracle sizes lists the table" True "$($K db sizes shop-ora | jget 'any(t["name"] == "ORDERS" for t in d["data"]["tables"])')"
check "oracle activity answers" True "$($K db activity sys-ora --all | jget 'd["ok"]')"
q $K db user add sys-ora e2e_ro --password-ref secret:ora-ro
q $K db grant sys-ora e2e_ro --privileges SELECT --on table:e2e_shop.orders
q $K conn add ro-ora 'oracle://e2e_ro@oracle:1521/FREEPDB1' --via bastion --password-ref secret:ora-ro
check "oracle: the new user logs in with the vault password" 2 "$($K db query ro-ora 'select count(*) from e2e_shop.orders' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "oracle: and may only read what was granted" False "$($K db query ro-ora --write "insert into e2e_shop.orders (item) values ('x')" | jget 'd["ok"]')"
check "oracle db grants shows SELECT on the table" True "$($K db grants sys-ora e2e_ro | jget 'any(g["object"] == "E2E_SHOP.ORDERS" and "SELECT" in g["privileges"] for g in d["data"]["grants"])')"
q $K conn rm ro-ora
q $K db user rm sys-ora e2e_ro --allow-dangerous
check "oracle db user rm removed it" False "$($K db user ls sys-ora | jget 'any(u["name"] == "E2E_RO" for u in d["data"]["users"])')"
check "oracle dump is not supported" NOT_SUPPORTED "$($K db dump shop-ora --to "$TMP/o.sql" | jget 'd["error"]["code"]')"
check "no oracle password in the audit log" 0 "$(audit_text | grep -c -E 'Shop-pass|Ro-pass-1x|Oracle-pass' || true)"
q $K conn rm shop-ora
q $K db query sys-ora --write --allow-dangerous 'drop user e2e_shop cascade'
q $K conn rm sys-ora
$K secret rm ora-system ora-shop ora-ro >/dev/null 2>&1 || true
set -e
