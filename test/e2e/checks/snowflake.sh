# shellcheck shell=bash
# Snowflake through --via bastion, against komando's own fake of the SQL
# API (test/e2e/snowflake; no Snowflake account or free emulator runs
# here): key-pair and token logins, TLS with a private CA, placeholders,
# what needs --write never reaching the server, a dry run that only
# reports a write. Snowflake's own SQL is not checked here
# (docs/design/snowflake.md).
set +e
SFC() { docker compose -p "$PROJECT" -f "$E2E/compose.yml" "$@"; }
for _ in $(seq 1 60); do SFC exec -T snowflake test -s /e2e/user.key 2>/dev/null && break; sleep 1; done
if ! SFC exec -T snowflake test -s /e2e/user.key 2>/dev/null; then
  echo "  the snowflake fake is not running; its state and last log lines:"
  SFC ps -a snowflake 2>&1 | sed 's/^/    /'
  SFC logs --tail 30 snowflake 2>&1 | sed 's/^/    /'
  echo "  the Snowflake checks are skipped (the fake could not run here)"
  set -e
  return 0
fi
SFC exec -T snowflake cat /e2e/ca.crt | $K secret set sf-ca >/dev/null
SFC exec -T snowflake cat /e2e/user.key | $K secret set sf-key >/dev/null
printf 'e2e-pat-1' | $K secret set sf-pat >/dev/null
q $K conn add sf 'snowflake://e2e@e2e-acct/E2E_DB/PUBLIC?warehouse=E2E_WH&ca=secret:sf-ca' --via bastion --password-ref secret:sf-key
check "snowflake conn test logs in with a key pair through --via" login "$($K conn test sf | jget 'd["data"]["results"][0]["detail"]["check"]')"
check "snowflake reads with a ? placeholder" "['hi', 42]" "$($K db query sf 'select ? as greeting, 42 as n' --arg hi | jget 'd["data"]["results"][0]["rows"][0]')"
check "snowflake insert needs --write" WRITE_REQUIRES_FLAG "$($K db query sf "insert into orders values (1, 'pen')" | jget 'd["error"]["code"]')"
check "snowflake a dry run only reports a write" True "$($K db query sf --write --dry-run "insert into orders values (1, 'pen')" | jget '"skipped" in d["data"]["results"][0]')"
check "snowflake insert" 2 "$($K db query sf --write "insert into orders values (1, 'pen'), (2, 'ink')" | jget 'd["data"]["results"][0]["rows_affected"]')"
check "snowflake: only the real insert reached the server" 1 "$(SFC exec -T snowflake cat /e2e/statements.log | grep -c '^insert')"
check "snowflake a write goes alone" USAGE "$($K db query sf --write "insert into orders values (3, 'x'); select 1" | jget 'd["error"]["code"]')"
check "snowflake drop is destructive" POLICY_BLOCKED "$($K db query sf --write 'drop table orders' | jget 'd["error"]["code"]')"
check "snowflake cancelling a query is destructive" POLICY_BLOCKED "$($K db query sf --write "select system\$cancel_query('x')" | jget 'd["error"]["code"]')"
check "snowflake quotes hide nothing" SQL_HIDDEN_CODE "$($K db query sf 'select 1 /* a /* b */ drop table orders */' | jget 'd["error"]["code"]')"
check "snowflake dump is not supported" NOT_SUPPORTED "$($K db dump sf --to "$TMP/sf.sql" | jget 'd["error"]["code"]')"
check "snowflake user add is not supported" NOT_SUPPORTED "$($K db user add sf bob --password-ref secret:sf-pat | jget 'd["error"]["code"]')"
q $K conn add sf-pat 'snowflake://e2e@e2e-acct/E2E_DB?ca=secret:sf-ca' --via bastion --password-ref secret:sf-pat
check "snowflake logs in with a programmatic access token" login "$($K conn test sf-pat | jget 'd["data"]["results"][0]["detail"]["check"]')"
q $K conn add sf-noca 'snowflake://e2e@e2e-acct/E2E_DB' --via bastion --password-ref secret:sf-pat
check "snowflake: a certificate from an unknown CA is refused" DB_CONNECT "$($K db query sf-noca 'select 1' | jget 'd["error"]["code"]')"
check "no snowflake secret in the audit log" 0 "$(audit_text | grep -c -E 'e2e-pat-1|PRIVATE KEY' || true)"
q $K conn rm sf
q $K conn rm sf-pat
q $K conn rm sf-noca
$K secret rm sf-ca sf-key sf-pat >/dev/null 2>&1 || true
set -e
