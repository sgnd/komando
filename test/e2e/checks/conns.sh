# shellcheck shell=bash
# Conns through the bastion: PostgreSQL, MariaDB, Redis, memcached, S3
# (Garage), SFTP and FTPS, with passwords from the vault, OpenBao and
# Vaultwarden. +data has added pg, maria, cache and bucket.
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$E2E_BAO/v1/sys/health" >/dev/null && break; sleep 1; done
# a database always needs its password, so the secret manager's answer counts
curl -sf -H "X-Vault-Token: e2e-root" -d '{"data":{"pgpass":"apppass"}}' "http://127.0.0.1:$E2E_BAO/v1/secret/data/pg" >/dev/null
q $K conn add pg-bao 'postgres://app@pg:5432/app?sslmode=disable' --via bastion --password-ref 'vault:secret/pg#pgpass'
check "db password from OpenBao" 1 "$("${BAOENV[@]}" $K db query pg-bao 'select 1' | jget 'd["data"]["results"][0]["rows"][0][0]' || true)"
check "wrong OpenBao token is named" True "$(env PATH=/usr/bin:/bin VAULT_ADDR="http://127.0.0.1:$E2E_BAO" VAULT_TOKEN=bad $K db query pg-bao 'select 1' | jget '"permission denied" in json.dumps(d)' || true)"
q $K conn rm pg-bao
# Bitwarden (Vaultwarden): an account made the way a Bitwarden client makes it, read by komando
for _ in $(seq 1 30); do curl -sf "http://127.0.0.1:$E2E_VW/alive" >/dev/null && break; sleep 1; done
(cd "$ROOT" && go run ./test/e2e/bwseed "http://127.0.0.1:$E2E_VW" e2e@example.com 'e2e master pw' shop-pg apppass) >/dev/null
BWENV=(env PATH=/usr/bin:/bin KOMANDO_BW_SERVER="http://127.0.0.1:$E2E_VW" KOMANDO_BW_EMAIL=e2e@example.com KOMANDO_BW_PASSWORD='e2e master pw')
q $K conn add pg-bw 'postgres://app@pg:5432/app?sslmode=disable' --via bastion --password-ref 'bw://shop-pg/password'
check "db password from Vaultwarden (bw://)" 1 "$("${BWENV[@]}" $K db query pg-bw 'select 1' | jget 'd["data"]["results"][0]["rows"][0][0]' || true)"
check "wrong Bitwarden master password is named" True "$(env PATH=/usr/bin:/bin KOMANDO_BW_SERVER="http://127.0.0.1:$E2E_VW" KOMANDO_BW_EMAIL=e2e@example.com KOMANDO_BW_PASSWORD=nope $K db query pg-bw 'select 1' | jget '"bitwarden" in json.dumps(d)' || true)"
q $K conn rm pg-bw
# db shell is komando's own SQL shell: no psql or mysql on PATH
check "db shell on PostgreSQL" 42 "$(ptyrun 'select 41 + 1 as answer;\n\q\n' env PATH=/usr/bin:/bin "$K" db shell pg | tr -d '\r' | grep -E '^ *42 *$' | tr -d ' ' | head -1 || true)"
check "db shell is read-only" True "$(ptyrun 'create table nope(x int);\n\q\n' env PATH=/usr/bin:/bin "$K" db shell pg | grep -q 'the shell is read-only' && echo True)"
check "db shell \\write allows changes after a yes" True "$(ptyrun '\write\ny\ncreate temporary table t_e2e(x int);\ninsert into t_e2e values (1);\n\q\n' env PATH=/usr/bin:/bin "$K" db shell pg --yes | tr -d '\r' | grep -q '1 row affected' && echo True)"
check "db shell \\d lists tables" True "$(ptyrun '\d\n\q\n' env PATH=/usr/bin:/bin "$K" db shell pg | grep -q 'table\|relation' && echo True)"
check "conn test via bastion" 4 "$($K conn test all | jget 'd["data"]["summary"]["ok"]')"
check "conn test logs in" login "$($K conn test pg | jget 'd["data"]["results"][0]["detail"]["check"]')"
echo -n wrongpass | $K secret set pg-wrong >/dev/null
q $K conn add pg-wrong 'postgres://app@pg:5432/app?sslmode=disable' --via bastion --password-ref secret:pg-wrong
check "conn test catches a wrong password" False "$($K conn test pg-wrong | jget 'd["data"]["results"][0]["ok"]' || true)"
q $K conn rm pg-wrong
q $K conn edit pg --option statement_timeout=1s
check "conn statement_timeout option is used" TIMEOUT "$($K db query pg 'select pg_sleep(3)' | jget 'd["error"]["code"]' || true)"
q $K conn edit pg --option statement_timeout=

# postgres: write, read-only enforcement, dump, destroy, restore
q $K db query pg --write "create table t(id int primary key, name text); create sequence s; insert into t values (1, 'a'), (2, 'b')"
check "pg read via bastion" 2 "$($K db query pg 'select count(*) from t' | jget 'd["data"]["results"][0]["rows"][0][0]')"
set +e
$K db query pg "insert into t values (3, 'c')" >/dev/null; check "pg write needs --write" 6 $?
$K db query pg "select nextval('s')" >/dev/null; check "pg read-only enforced by server" 6 $?
$K db query pg --write "drop table t" >/dev/null; check "pg drop needs --allow-dangerous" 6 $?
set -e
check "pg dry run rolls back" 2 "$($K db query pg --write --dry-run 'delete from t where id > 0' >/dev/null; $K db query pg 'select count(*) from t' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K db dump pg --to "$TMP/pg.sql.gz"
check "pg dump is private" 600 "$(stat -c %a "$TMP/pg.sql.gz" 2>/dev/null || stat -f %Lp "$TMP/pg.sql.gz")"
q $K db query pg --write --allow-dangerous "drop table t; drop sequence s"
q $K db restore pg --from "$TMP/pg.sql.gz" --allow-dangerous
check "pg restore brings rows back" 2 "$($K db query pg 'select count(*) from t' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "db info" primary "$($K db info pg | jget 'd["data"]["role"]')"
check "db sizes lists the table" True "$($K db sizes pg | jget 'any(r["name"]=="t" for r in d["data"]["tables"])')"
check "db locks answers" 0 "$($K db locks pg | jget 'd["data"]["count"]')"
q $K db query pg --write "create table t2(id int primary key, t_id int references t(id) on delete cascade); insert into t2 values (1, 1)"
check "db schema shows foreign keys" "foreign key" "$($K db schema pg t2 | jget 'd["data"]["tables"][0]["constraints"][0]["type"]')"
($K db query pg 'select pg_sleep(30)' --timeout 60s > "$TMP/slow.json" 2>&1 &)
for _ in $(seq 1 20); do PID=$($K db activity pg | jget '[s["pid"] for s in d["data"]["sessions"] if "pg_sleep" in (s.get("query") or "")][0]' 2>/dev/null) && break; sleep 1; done
check "db activity sees the slow query" True "$([ -n "$PID" ] && echo True || echo False)"
check "db kill --dry-run names the query" True "$($K db kill pg "$PID" --dry-run | jget '"pg_sleep" in d["data"]["session"]["query"]')"
check "db kill --session needs --allow-dangerous" POLICY_BLOCKED "$($K db kill pg "$PID" --session | jget 'd["error"]["code"]' || true)"
check "db kill cancels it" "cancel query" "$($K db kill pg "$PID" | jget 'd["data"]["done"]')"
for _ in $(seq 1 10); do grep -q '"ok"' "$TMP/slow.json" 2>/dev/null && break; sleep 1; done
check "the cancelled query stopped" False "$(jget 'd["ok"]' < "$TMP/slow.json")"
q $K db dump pg --to "$TMP/t2.dump" --format custom --table public.t2
check "custom dump is a pg archive" PGDMP "$(head -c 5 "$TMP/t2.dump")"
q $K db query pg --write --allow-dangerous "drop table t2"
q $K db restore pg --from "$TMP/t2.dump" --allow-dangerous
check "pg_restore brings the table back" 1 "$($K db query pg 'select count(*) from t2' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K db dump pg --to "$TMP/schema.sql" --schema-only
check "schema-only dump has no rows" 0 "$(grep -c "COPY public.t " "$TMP/schema.sql" || true)"
# --on HOST: pg_dump/pg_restore run on a chosen server, whatever the conn's own path
q $K conn add pg-on 'postgres://app@pg:5432/app?sslmode=disable' --password-ref secret:pg-pass
check "custom dump without a server names --on" True "$($K db dump pg-on --to "$TMP/on0.dump" --format custom | jget '"--on HOST" in d["error"]["message"]' || true)"
check "dump --on dry run says where and how" "bastion True" "$($K db dump pg-on --to "$TMP/on.dump" --format custom --on bastion --dry-run | jget 'd["data"]["runs_on"] + " " + str(d["data"]["low_priority"])')"
q $K db dump pg-on --to "$TMP/on.dump" --format custom --table public.t2 --on bastion
check "dump --on writes a pg archive" PGDMP "$(head -c 5 "$TMP/on.dump")"
check "dump --on from a server that cannot reach the database" CONN_UNREACHABLE "$($K db dump pg-on --to "$TMP/on2.sql" --on direct | jget 'd["error"]["code"]' || true)"
q $K db query pg --write --allow-dangerous "drop table t2"
check "restore --on needs --allow-dangerous" POLICY_BLOCKED "$($K db restore pg-on --from "$TMP/on.dump" --on bastion | jget 'd["error"]["code"]' || true)"
q $K db restore pg-on --from "$TMP/on.dump" --on bastion --allow-dangerous
check "pg_restore --on brings the table back" 1 "$($K db query pg 'select count(*) from t2' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "audit names where the dump ran" bastion "$($K audit -n 50 | jget '" ".join(sorted({e.get("runs_on", "") for e in d["data"]["entries"] if e.get("command") == "db.dump" and str(e.get("file", "")).endswith("/on.dump")}))')"
q $K conn rm pg-on

# mariadb (protected): --yes, dump and restore through bastion
set +e; $K db query maria --write "create table p(id int primary key)" >/dev/null; check "protected conn needs --yes" 6 $?; set -e
q $K db query maria --write --yes "create table p(id int primary key, name varchar(10))"
q $K db query maria --write --yes "insert into p values (1, 'kopi'), (2, 'teh')"
check "maria typed ints" 1 "$($K db query maria 'select id from p order by id' | jget 'd["data"]["results"][0]["rows"][0][0]')"
q $K db dump maria --to "$TMP/maria.sql"
q $K db query maria --write --yes --allow-dangerous "drop table p"
q $K db restore maria --from "$TMP/maria.sql" --yes --allow-dangerous
check "maria restore brings rows back" 2 "$($K db query maria 'select count(*) from p' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "maria db info" primary "$($K db info maria | jget 'd["data"]["role"]')"
check "maria db sizes" True "$($K db sizes maria | jget 'any(r["name"]=="p" for r in d["data"]["tables"])')"
check "maria db activity answers" True "$($K db activity maria --all | jget '"sessions" in d["data"]')"
check "maria db locks names the missing privilege" DB_PRIVILEGE "$($K db locks maria | jget 'd["error"]["code"]' || true)"

# redis
q $K cache set cache greeting halo --ttl 1h
check "cache get via bastion" halo "$($K cache get cache greeting | jget 'd["data"]["value"]')"
set +e
$K cache run cache -- FLUSHALL >/dev/null; check "cache flushall blocked" 6 $?
$K cache rm cache greeting >/dev/null; check "cache rm needs --allow-dangerous" 6 $?
$K cache run cache --write -- GETDEL greeting >/dev/null; check "cache GETDEL needs --allow-dangerous" 6 $?
set -e

# memcached (with a login), through the bastion
printf mcpass | $K secret set mc-pass >/dev/null
q $K conn add mc 'memcached://e2e@memcached:11211' --password-ref secret:mc-pass --via bastion
q $K cache set mc greeting halo --ttl 1h
check "memcached get via bastion, with its time to live" "halo True" "$($K cache get mc greeting | jget 'd["data"]["value"] + " " + str(d["data"]["ttl_seconds"] > 3500)')"
check "memcached keys" "['greeting']" "$($K cache keys mc 'greet*' | jget 'd["data"]["keys"]')"
check "memcached info summary" True "$($K cache info mc | jget 'd["data"]["summary"]["version"].endswith("(memcached)")')"
check "memcached run reads" True "$($K cache run mc -- stats | jget 'any("curr_items" in l for l in d["data"]["reply"])')"
set +e
$K cache run mc -- flush_all >/dev/null; check "memcached flush_all blocked" 6 $?
$K cache rm mc greeting >/dev/null; check "memcached rm needs --allow-dangerous" 6 $?
# a newline in an argument would start a second command after the read
$K cache run mc -- get $'greeting\r\nflush_all' >/dev/null; check "memcached run refuses a newline in a word" 2 $?
$K cache run mc --write -- ' flush_all' x >/dev/null; check "memcached flush_all behind a space still needs --allow-dangerous" 6 $?
set -e
check "memcached keys survived the injection tries" "['greeting']" "$($K cache keys mc 'greet*' | jget 'd["data"]["keys"]')"
check "memcached run takes GET in capitals" halo "$($K cache run mc -- GET greeting | jget 'd["data"]["reply"][0]["value"]')"
check "memcached stats reset needs --write" WRITE_REQUIRES_FLAG "$($K cache run mc -- stats reset | jget 'd["error"]["code"]' || true)"
check "memcached rm --dry-run names the key" "['greeting']" "$($K cache rm mc greeting --dry-run | jget 'd["data"]["would_delete"]')"
q $K cache rm mc greeting --allow-dangerous
check "memcached key gone" KEY_NOT_FOUND "$($K cache get mc greeting | jget 'd["error"]["code"]' || true)"
printf wrong | $K secret set mc-pass >/dev/null
check "memcached wrong password is named" CACHE_AUTH "$($K cache info mc | jget 'd["error"]["code"]' || true)"
q $K conn rm mc

# storage
echo backup-data > "$TMP/obj.txt"
q $K storage upload bucket "$TMP/obj.txt" 2026/obj.txt
check "storage ls via bastion" 2026/obj.txt "$($K storage ls bucket --recursive | jget 'd["data"]["objects"][0]["key"]')"
q $K storage download bucket 2026/obj.txt --to "$TMP/obj-back.txt"
check "storage round trip" backup-data "$(cat "$TMP/obj-back.txt")"
# aws_profile: komando reads ~/.aws itself; no aws CLI on PATH
printf '[e2e]\naws_access_key_id = %s\naws_secret_access_key = %s\n' "$S3ID" "$(awk '/Secret key/{printf "%s", $3}' "$TMP/s3key")" > "$TMP/aws-credentials"
AWSENV=(env PATH=/usr/bin:/bin AWS_SHARED_CREDENTIALS_FILE="$TMP/aws-credentials" AWS_CONFIG_FILE=/dev/null AWS_EC2_METADATA_DISABLED=true)
q $K conn add bucket-aws "s3://backups/e2e?endpoint=http://s3:3900&region=garage" --via bastion --option aws_profile=e2e
check "s3 with aws_profile, no aws CLI" 2026/obj.txt "$("${AWSENV[@]}" $K storage ls bucket-aws --recursive | jget 'd["data"]["objects"][0]["key"]')"
q $K conn edit bucket-aws --option aws_profile=nope
check "unknown aws_profile is named" AWS_PROFILE_NOT_FOUND "$("${AWSENV[@]}" $K storage ls bucket-aws | jget 'd["error"]["code"]' || true)"
q $K conn rm bucket-aws
mkdir -p "$TMP/tree/sub" && echo one > "$TMP/tree/a.txt" && echo two > "$TMP/tree/sub/b.txt" && echo skip > "$TMP/tree/c.tmp"
check "upload -r to storage" 3 "$($K upload bucket "$TMP/tree" tree -r | jget 'd["data"]["copied"]')"
check "sync to storage sends nothing new" 0 "$($K sync "$TMP/tree" bucket:tree --exclude '*.tmp' | jget 'd["data"]["copied"] + d["data"]["updated"]')"
check "storage cat --tail" two "$($K storage cat bucket tree/sub/b.txt --tail 1 | jget 'd["data"]["content"].strip()')"
q $K download bucket tree -r --to "$TMP/tree-back"
check "download -r from storage" two "$(cat "$TMP/tree-back/sub/b.txt")"
check "download -r keeps local files" True "$(echo changed > "$TMP/tree-back/a.txt"; $K download bucket tree -r --to "$TMP/tree-back" | jget 'd["data"]["kept"] >= 1')"
check "rm --prefix --dry-run lists" True "$($K storage rm bucket --prefix tree/ --dry-run | jget 'd["data"]["count"] >= 2')"
check "rm --prefix needs --allow-dangerous" POLICY_BLOCKED "$($K storage rm bucket --prefix tree/ | jget 'd["error"]["code"]' || true)"
check "rm --older-than leaves new objects" 0 "$($K storage rm bucket --prefix tree/ --older-than 30d --allow-dangerous | jget 'd["data"]["count"]')"
check "rm --prefix removes them" True "$($K storage rm bucket --prefix tree/ --allow-dangerous | jget 'd["data"]["count"] >= 2')"

# file servers through the bastion: SFTP (shell-less account) and FTPS (TLS required)
echo -n deploypass | $K secret set files-pass >/dev/null
q $K conn add files-sftp 'sftp://deploy@sftp/uploads' --via bastion --password-ref secret:files-pass
q $K conn add files-ftps 'ftps://deploy@ftps/www?tls=skip-verify' --via bastion --password-ref secret:files-pass
for c in files-sftp files-ftps; do
  # check the upload itself, so a failed upload shows its own error instead of an empty listing below
  check "$c upload" True "$($K storage upload "$c" "$TMP/obj.txt" 2026/11/obj.txt | jget 'd["ok"] or "%s: %s" % (d["error"]["code"], d["error"]["message"])' || true)"
  check "$c upload creates folders" 2026/11/obj.txt "$($K storage ls "$c" --recursive | jget '[o["key"] for o in d["data"]["objects"] if not o.get("dir")][0]')"
  check "$c upload replaces" True "$($K storage upload "$c" "$TMP/obj.txt" 2026/11/obj.txt | jget 'd["data"]["replaced"]')"
  q $K storage download "$c" 2026/11/obj.txt --to "$TMP/$c.txt"
  check "$c round trip" backup-data "$(cat "$TMP/$c.txt")"
  set +e; $K storage rm "$c" 2026/11/obj.txt >/dev/null; check "$c rm needs --allow-dangerous" 6 $?; set -e
done

# one inventory: targets pick servers and conns together
echo "==> servers and conns together"
q $K group add stack 'bastion,pg,cache'
check "list @stack has both" "bastion,cache,pg" "$($K list @stack | jget '",".join(t["name"] for t in d["data"]["targets"])')"
check "test @stack checks both" 3 "$($K test @stack | jget 'd["data"]["summary"]["ok"]')"
check "exec @stack skips conns" "cache,pg" "$($K exec @stack --read-only -- true | jget '",".join(s["name"] for s in d["meta"]["skipped"])')"
check "db query @stack finds pg" 1 "$($K db query @stack 'select 1 as n' | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "cache on a database says use db" NO_MATCHING_TARGETS "$($K cache info pg | jget 'd["error"]["code"]' || true)"

# one verb pair for files, and tunnels to conns by name
echo hello-upload > "$TMP/up.txt"
q $K upload direct "$TMP/up.txt" /tmp/up.txt
q $K download direct /tmp/up.txt --to "$TMP/down/"
check "upload/download to a server" hello-upload "$(cat "$TMP/down/up.txt")"
check "download never replaces a local file" FILE_EXISTS "$($K download direct /tmp/up.txt --to "$TMP/down/" | jget 'd["data"]["results"][0]["error"]["code"]' || true)"
q $K download direct /tmp/up.txt --to "$TMP/down/" --overwrite
check "no temporary files left" 0 "$(find "$TMP/down" -maxdepth 1 -name '*komando-download*' | wc -l | tr -d ' ')"
dd if=/dev/urandom of="$TMP/big.bin" bs=1048576 count=40 2>/dev/null
check "large upload is streamed intact" "$(shasum -a 256 "$TMP/big.bin" | cut -c1-64)" "$($K upload direct "$TMP/big.bin" /tmp/big.bin | jget 'd["data"]["results"][0]["sha256"]')"
check "sync to a server" 2 "$($K sync "$TMP/tree" direct:/home/agent/site --exclude '*.tmp' | jget 'd["data"]["results"][0]["copied"]')"
check "sync again sends nothing" 0 "$($K sync "$TMP/tree" direct:/home/agent/site --exclude '*.tmp' | jget 'd["data"]["results"][0]["copied"] + d["data"]["results"][0]["updated"]')"
rm "$TMP/tree/sub/b.txt"
check "sync --delete needs --allow-dangerous" POLICY_BLOCKED "$($K sync "$TMP/tree" direct:/home/agent/site --delete | jget 'd["error"]["code"]' || true)"
check "sync --delete --dry-run lists it" sub/b.txt "$($K sync "$TMP/tree" direct:/home/agent/site --exclude '*.tmp' --delete --dry-run | jget '[a["path"] for a in d["data"]["results"][0]["actions"] if a["op"]=="delete"][0]')"
check "sync --delete removes it" 1 "$($K sync "$TMP/tree" direct:/home/agent/site --exclude '*.tmp' --delete --allow-dangerous | jget 'd["data"]["results"][0]["deleted"]')"
check "sync from a server" one "$($K sync direct:/home/agent/site "$TMP/site-back" >/dev/null; cat "$TMP/site-back/a.txt")"
TUN=$($K tunnel start pg | jget 'd["data"]["listen"]')
check "tunnel to a conn by name" 0 "$(nc -z "${TUN%:*}" "${TUN##*:}"; echo $?)"
q $K tunnel stop --all
