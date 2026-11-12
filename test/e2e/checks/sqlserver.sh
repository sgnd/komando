# shellcheck shell=bash
# SQL Server through --via bastion: login, reads that cannot change
# anything (no read-only transaction there: komando rolls back), writes
# with --write, the T-SQL rules (a bare procedure name, a second statement
# without ;), schema, info, explain, sizes, users and grants. Uses the
# e2e_sales database and drops it at the end.
set +e
MSC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
printf 'Sales-pass-1' | $K secret set mssql-sa >/dev/null
printf 'Ro-pass-1x' | $K secret set mssql-ro >/dev/null
q $K conn add sa-mssql 'sqlserver://sa@mssql:1433/master' --via bastion --password-ref secret:mssql-sa
# SQL Server takes a while to start, longer when emulated
for _ in $(seq 1 120); do [ "$($K conn test sa-mssql | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" = True ] && break; sleep 1; done
if [ "$($K conn test sa-mssql | jget 'd["data"]["results"][0]["ok"]' 2>/dev/null)" != True ]; then
  echo "  mssql is not answering; its state and last log lines:"
  MSC ps -a mssql 2>&1 | sed 's/^/    /'
  MSC logs --tail 30 mssql 2>&1 | sed 's/^/    /'
fi
if [ "$(MSC ps -q --status running mssql 2>/dev/null)" = "" ]; then
  skipped "mssql is not running here (an arm64 machine under QEMU? see E2E_MSSQL_IMAGE in compose.yml)"
  q $K conn rm sa-mssql
  $K secret rm mssql-sa mssql-ro --allow-dangerous >/dev/null 2>&1 || true
  set -e
  return 0
fi
check "sqlserver conn test logs in through --via" login "$($K conn test sa-mssql | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "create database needs --write" WRITE_REQUIRES_FLAG "$($K db query sa-mssql 'create database e2e_sales' | jget 'd["error"]["code"]')"
q $K db query sa-mssql --write 'create database e2e_sales'
q $K conn add shop-mssql 'sqlserver://sa@mssql:1433/e2e_sales' --via bastion --password-ref secret:mssql-sa
q $K db query shop-mssql --write "create table dbo.orders (id int identity primary key, item nvarchar(50) not null, total decimal(10,2), placed datetime2 default sysdatetime())"
check "sqlserver insert needs --write" WRITE_REQUIRES_FLAG "$($K db query shop-mssql "insert into dbo.orders (item, total) values (N'pen', 1.50)" | jget 'd["error"]["code"]')"
check "sqlserver insert" 2 "$($K db query shop-mssql --write "insert into dbo.orders (item, total) values (N'pen', 1.50), (N'ink', 12.25)" | jget 'd["data"]["results"][0]["rows_affected"]')"
check "sqlserver select with @p1" "['pen', '1.50']" "$($K db query shop-mssql 'select item, total from dbo.orders where id = @p1' --arg 1 | jget 'd["data"]["results"][0]["rows"][0]')"
check "sqlserver dry run counts the rows" 2 "$($K db query shop-mssql --write --dry-run 'delete from dbo.orders where id > 0' | jget 'd["data"]["results"][0]["rows_affected"]')"
check "sqlserver dry run rolled back" 2 "$($K db query shop-mssql 'select count(*) from dbo.orders' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "a second statement without ; is caught" WRITE_REQUIRES_FLAG "$($K db query shop-mssql 'select 1 delete from dbo.orders' | jget 'd["error"]["code"]')"
check "a bare procedure name is a procedure call" WRITE_REQUIRES_FLAG "$($K db query shop-mssql 'sp_who' | jget 'd["error"]["code"]')"
check "sqlserver delete-all is destructive" POLICY_BLOCKED "$($K db query shop-mssql --write 'delete from dbo.orders' | jget 'd["error"]["code"]')"
check "sqlserver commit is refused" SQL_TX_CONTROL "$($K db query shop-mssql 'select 1 commit' | jget 'd["error"]["code"]')"
check "sqlserver schema lists the table" "['dbo.orders']" "$($K db schema shop-mssql | jget '[t["schema"] + "." + t["name"] for t in d["data"]["tables"]]')"
check "sqlserver schema shows the identity" "['id']" "$($K db schema shop-mssql dbo.orders | jget '[c["name"] for c in d["data"]["tables"][0]["columns"] if c.get("identity")]')"
check "sqlserver info" primary "$($K db info shop-mssql | jget 'd["data"]["role"]')"
check "sqlserver explain plans a delete without --write" True "$($K db explain shop-mssql 'delete from dbo.orders where id = 1' | jget 'any("Delete" in r[0] for r in d["data"]["results"][0]["rows"])')"
check "sqlserver explain ran nothing" 2 "$($K db query shop-mssql 'select count(*) from dbo.orders' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "sqlserver sizes lists the table" True "$($K db sizes shop-mssql | jget 'any(t["name"] == "orders" for t in d["data"]["tables"])')"
check "sqlserver activity answers" True "$($K db activity shop-mssql --all | jget 'd["ok"]')"
check "sqlserver kill needs --session" NOT_SUPPORTED "$($K db kill shop-mssql 99 | jget 'd["error"]["code"]')"
q $K db user add shop-mssql sales_ro --password-ref secret:mssql-ro
q $K db grant shop-mssql sales_ro --privileges SELECT --on schema:dbo
q $K conn add ro-mssql 'sqlserver://sales_ro@mssql:1433/e2e_sales' --via bastion --password-ref secret:mssql-ro
check "sqlserver: the new user logs in with the vault password" 2 "$($K db query ro-mssql 'select count(*) from dbo.orders' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "sqlserver: and may only read what was granted" False "$($K db query ro-mssql --write "insert into dbo.orders (item) values (N'x')" | jget 'd["ok"]')"
check "sqlserver db grants shows SELECT on dbo" True "$($K db grants shop-mssql sales_ro | jget 'any(g["object"] == "dbo" and "SELECT" in g["privileges"] for g in d["data"]["grants"])')"
q $K db user rm shop-mssql sales_ro --allow-dangerous
check "sqlserver db user rm removed it" False "$($K db user ls shop-mssql | jget 'any(u["name"] == "sales_ro" for u in d["data"]["users"])')"
check "sqlserver dump is not supported yet" NOT_SUPPORTED "$($K db dump shop-mssql --to "$TMP/s.sql" | jget 'd["error"]["code"]')"
check "no sqlserver password in the audit log" 0 "$(audit_text | grep -c -E 'Sales-pass|Ro-pass-1x' || true)"
q $K conn rm ro-mssql shop-mssql
q $K db query sa-mssql --write --allow-dangerous 'drop database e2e_sales'
q $K conn rm sa-mssql
$K secret rm mssql-sa mssql-ro --allow-dangerous >/dev/null 2>&1 || true
set -e
