# Databases, caches and storage: value types, text output, dry runs,
# exit codes. Uses t_e2edata_* tables, t-e2edata:* keys and t-e2edata/
# objects, and removes them at the end.
set +e

# --- databases --------------------------------------------------------------
check "pg date is a date" 2024-02-29 "$($K db query pg "select '2024-02-29'::date d" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "pg timestamp has no zone" "2024-02-29 10:11:12" "$($K db query pg "select '2024-02-29 10:11:12'::timestamp t" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "pg timestamptz is an instant" "2024-02-29T08:00:00Z" "$($K db query pg "select '2024-02-29 10:00+02'::timestamptz t" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "pg money is named" money "$($K db query pg "select 1.5::money m" | jget 'd["data"]["results"][0]["columns"][0]["type"]')"
check "pg empty bytea is binary" "{'base64': ''}" "$($K db query pg "select ''::bytea b" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "maria zero date verbatim" "0000-00-00 00:00:00" "$($K db query maria "select cast('0000-00-00 00:00:00' as datetime) z" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "maria date is a date" 2024-02-29 "$($K db query maria "select cast('2024-02-29' as date) d" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "maria big unsigned is a string" 18446744073709551615 "$($K db query maria "select cast(18446744073709551615 as unsigned) u" | jget 'd["data"]["results"][0]["rows"][0][0]')"
check "maria explain --analyze" True "$($K db explain maria --analyze 'select 1' | jget 'd["ok"]')"
$K db query pg 'select $1::int, $2::int' --arg 1 >/dev/null; check "placeholder count mismatch is usage" 2 $?
check "row cap is named" rows "$($K db query pg 'select generate_series(1,5)' -n 2 | jget 'd["data"]["results"][0]["truncated"]')"
check "size cap is named" bytes "$($K db query pg "select repeat('x', 200) from generate_series(1,50)" --max-output 1000 | jget 'd["data"]["results"][0]["truncated"]')"
check "timeout says how long" "query timed out after 1s" "$($K db query pg 'select pg_sleep(3)' --timeout 1s | jget 'd["error"]["message"]')"
check "sql starting with a comment hints -f -" True "$($K db query pg $'-- note\nselect 1' | jget '"-f -" in d["error"]["hint"]')"
check "set_config is a read" read "$($K db query pg "select set_config('search_path', 'public', true)" | jget 'd["data"]["risk"]')"
check "pg_read_file hint names files" True "$($K db query pg "select pg_read_file('/etc/hostname')" | jget '"files on the database server" in d["error"]["hint"]')"
check "csv output" "a,b" "$($K db query pg 'select 1 a, 2 b' --csv | head -1)"
check "db info text shows a human size" True "$($K db info pg -o text | grep -q 'size: .*iB' && echo True || echo False)"
check "db sizes text is a table" True "$($K db sizes pg -o text | grep -q '^TABLE ' && echo True || echo False)"
$K db locks maria >/dev/null; check "missing privilege exits 4" 4 $?
q $K db query pg --write "create table t_e2edata_b(id int generated always as identity primary key, note text); create table t_e2edata_a(id int)"
check "schema keeps the asked order" "t_e2edata_b t_e2edata_a" "$($K db schema pg t_e2edata_b t_e2edata_a | jget '" ".join(t["name"] for t in d["data"]["tables"])')"
check "schema shows identity" always "$($K db schema pg t_e2edata_b | jget 'd["data"]["tables"][0]["columns"][0]["identity"]')"
q $K db query pg --write --allow-dangerous "drop table t_e2edata_a; drop table t_e2edata_b"
echo "select 1;" > "$TMP/e2edata.sql"
check "restore dry-run checks the file" True "$($K db restore pg --from "$TMP/e2edata.sql" --dry-run | jget 'd["ok"] and d["meta"]["would_be_blocked"]["code"] == "POLICY_BLOCKED"')"

# --- caches -----------------------------------------------------------------
$K cache set cache t-e2edata:a x --ttl -5s >/dev/null; check "negative ttl is usage" 2 $?
check "ttl takes days" 172800 "$($K cache set cache t-e2edata:a x --ttl 2d | jget 'd["data"]["ttl_seconds"]')"
check "no ttl is null" None "$($K cache set cache t-e2edata:a $'two\nlines' | jget 'd["data"]["ttl_seconds"]')"
check "cache get keeps a newline on one line" 'value: "two\nlines"' "$($K cache get cache t-e2edata:a -o text | grep '^value:')"
q $K cache run cache --write -- RPUSH t-e2edata:l a 'b c'
check "cache get lists items per line" '  2) "b c"' "$($K cache get cache t-e2edata:l -o text | grep '2)')"
check "cache run text like redis-cli" '2) "b c"' "$($K cache run cache -o text -- LRANGE t-e2edata:l 0 -1 | tail -1)"
check "cache info is a summary" True "$($K cache info cache | jget '"used_memory_bytes" in d["data"]["summary"]')"
$K cache info cache nosuchsection >/dev/null; check "unknown info section is usage" 2 $?
check "DEL hint points at cache rm" True "$($K cache run cache -- DEL t-e2edata:a | jget '"cache rm" in d["error"]["hint"]')"
check "cache rm dry-run lists keys" "['t-e2edata:a']" "$($K cache rm cache t-e2edata:a t-e2edata:none --dry-run | jget 'd["data"]["would_delete"]')"
q $K cache rm cache t-e2edata:a t-e2edata:l --allow-dangerous

# --- storage ----------------------------------------------------------------
echo e2edata > "$TMP/e2edata.txt"
for c in bucket files-sftp files-ftps; do
  check "$c upload into a folder keeps the name" t-e2edata/dir/e2edata.txt "$($K storage upload "$c" "$TMP/e2edata.txt" t-e2edata/dir/ | jget 'd["data"]["key"]')"
  $K storage upload "$c" "$TMP/e2edata.txt" ../escape.txt --dry-run >/dev/null; check "$c upload dry-run checks the key" 2 $?
  check "$c upload dry-run says it replaces" True "$($K storage upload "$c" "$TMP/e2edata.txt" t-e2edata/dir/ --dry-run | jget 'd["data"]["replaced"]')"
  $K storage ls "$c" t-e2edata/nope/ >/dev/null; check "$c ls of a missing folder" 3 $?
  rm -rf "$TMP/e2edata-dl"; mkdir -p "$TMP/e2edata-dl"
  q $K storage download "$c" t-e2edata/dir/e2edata.txt --to "$TMP/e2edata-dl/" --dry-run
  check "$c download dry-run writes nothing" 0 "$(ls -A "$TMP/e2edata-dl" | wc -l | tr -d ' ')"
  q $K storage download "$c" t-e2edata/dir/e2edata.txt --to "$TMP/e2edata-dl/"
  check "$c download into a folder" e2edata "$(cat "$TMP/e2edata-dl/e2edata.txt")"
  q $K storage download "$c" t-e2edata/dir/e2edata.txt --to "$TMP/e2edata-dl" --overwrite
  check "$c download to stdout" e2edata "$($K storage download "$c" t-e2edata/dir/e2edata.txt --to - -o text)"
done
printf 'ab\0cd' > "$TMP/e2edata.bin"
q $K storage upload bucket "$TMP/e2edata.bin" t-e2edata/
$K storage cat bucket t-e2edata/e2edata.bin >/dev/null; check "cat of binary is usage" 2 $?
$K storage cat bucket t-e2edata/dir/e2edata.txt --head 1 --tail 1 >/dev/null; check "cat --head with --tail is usage" 2 $?
check "cat cap is said on stderr" True "$($K storage cat bucket t-e2edata/dir/e2edata.txt --max-bytes 2 -o text 2>&1 >/dev/null | grep -q 'raise --max-bytes' && echo True || echo False)"
check "link through --via warns" True "$($K storage link bucket t-e2edata/dir/e2edata.txt | jget '"bastion" in d["data"]["warning"]')"
check "rm dry-run text has one key per line" True "$($K storage rm bucket --prefix t-e2edata/ --dry-run -o text 2>/dev/null | grep -q '  t-e2edata/dir/e2edata.txt$' && echo True || echo False)"
for c in bucket files-sftp files-ftps; do
  q $K storage rm "$c" --prefix t-e2edata/ --allow-dangerous
done
rm -rf "$TMP/e2edata-dl" "$TMP/e2edata.txt" "$TMP/e2edata.bin" "$TMP/e2edata.sql"
set -e
