# shellcheck shell=bash
# Running commands, files, transfers, sync, jobs and tunnels behave like the
# native tools (ssh, scp, rsync, sed -i, nohup).
R=/tmp/t-e2erun
L="$TMP/e2erun"
rm -rf "$L"; mkdir -p "$L/site/sub"
echo a > "$L/site/a.txt"; echo b > "$L/site/sub/b.txt"; ln -s a.txt "$L/site/link"
q $K exec direct -- "rm -rf $R ~/t-e2erun; mkdir -p $R/avail $R/enabled $R/dl/sub && printf 'x\n' > $R/avail/site && ln -s ../avail/site $R/enabled/site && echo 1 > $R/dl/ok && echo 2 > $R/dl/sub/locked && chmod 000 $R/dl/sub/locked"

# exec / runner
set +e; $K exec direct --read-only -- "rm -f $R/nothing" >/dev/null; check "--read-only refuses a change" 6 $?; set -e
check "--read-only allows a read" 0 "$($K exec direct --read-only -- 'cat /etc/hostname' >/dev/null; echo $?)"
check "single host failure names the exit code" 1 "$({ $K exec direct -o text -- 'exit 3' 2>&1 >/dev/null || true; } | grep -c 'failed (exit 3)')"
check "stderr inside each host block" True "$($K exec bastion,direct -o text -- 'echo oops >&2' 2>/dev/null | grep -q '^\[stderr\] oops' && echo True || echo False)"
check "--fail-fast reports skipped hosts" 1 "$($K exec bastion,direct --fail-fast -P 1 -- false | jget 'd["data"]["summary"]["skipped"]' || true)"
check "--stream text prints output once" 1 "$($K exec direct --stream -o text -- 'echo once' | grep -c once)"
check "exec --script --arg reaches perl" hello "$($K exec direct --script /dev/stdin --interpreter perl --arg hello <<< 'print $ARGV[0];' | jget 'd["data"]["results"][0]["stdout"]')"
set +e; $K exec direct --stdin-file "$L/nofile" -- cat >/dev/null; check "missing --stdin-file -> 3" 3 $?; set -e
check "logs --follow ends at --timeout" 0 "$($K logs direct --file $R/dl/ok --follow --timeout 2s >/dev/null; echo $?)"

# fs
q $K fs write direct $R/enabled/site --content 'new'
check "fs write through a link keeps the link" "symlink new" "$($K fs stat direct $R/enabled/site | jget 'd["data"]["info"]["type"]') $($K fs cat direct $R/avail/site | jget 'd["data"]["content"]')"
check "fs write --no-follow refuses a link" IS_A_SYMLINK "$($K fs write direct $R/enabled/site --content x --no-follow | jget 'd["error"]["code"]' || true)"
check "fs write into a missing folder" FOLDER_NOT_FOUND "$($K fs write direct $R/none/f --content x | jget 'd["error"]["code"]' || true)"
set +e; $K fs write direct $R/o --content x --owner nobody >/dev/null; check "--owner needs --sudo" 2 $?; set -e
q $K fs write direct $R/b --content b
set +e; $K fs mv direct $R/dl/ok $R/b >/dev/null; check "fs mv never replaces a file" 8 $?; set -e
set +e; $K fs mv direct $R/nope $R/c >/dev/null; check "fs mv of a missing path -> 3" 3 $?; set -e
set +e; $K fs rm direct $R/avail --allow-dangerous >/dev/null; check "fs rm of a folder needs -r -> 2" 2 $?; set -e
check "fs rm of a missing path says so" True "$($K fs rm direct $R/nope -o text --allow-dangerous | grep -q 'not found' && echo True || echo False)"
check "fs cat of a folder" IS_A_DIRECTORY "$($K fs cat direct $R/avail | jget 'd["error"]["code"]' || true)"
set +e; $K fs chmod direct $R/b 0644 >/dev/null; check "fs chmod with swapped args -> 2" 2 $?; set -e
check "fs replace dry-run says would_change" True "$($K fs replace direct $R/b --old b --new c --dry-run | jget 'd["data"]["would_change"]')"
check "diff has real hunk headers" True "$($K fs write direct $R/b --content c --dry-run | jget 'd["data"]["diff"].startswith("@@ -1 +1 @@")')"

# transfers
q $K cp -r "$L/site" direct:$R/up/site -p
q $K cp -r "$L/site" direct:$R/up/site
check "cp -r twice does not nest" "False True" "$($K fs stat direct $R/up/site/site | jget 'd["data"]["exists"]') $($K fs stat direct $R/up/site/sub/b.txt | jget 'd["data"]["exists"]')"
check "upload -r lists skipped links" link "$($K upload direct "$L/site" $R/up/site -r | jget 'd["data"]["results"][0]["skipped"][0]')"
check "upload into a missing folder" FOLDER_NOT_FOUND "$($K upload direct "$L/site/a.txt" $R/missing/a.txt | jget 'd["error"]["code"]' || true)"
check "~ is the home folder" True "$($K cp "$L/site/a.txt" 'direct:~/t-e2erun-a.txt' | jget 'd["data"]["results"][0]["dest"].startswith("/home/")')"
set +e; $K download direct $R/dl -r --to "$L/dl" >/dev/null; check "partial folder download -> 5" 5 $?; set -e
check "partial download keeps the readable files" 1 "$(cat "$L/dl/ok" 2>/dev/null)"

# sync
mkdir -p "$L/keep" && echo k > "$L/keep/k"
set +e; $K sync direct:$R/missing "$L/keep" --delete --allow-dangerous >/dev/null; check "sync from a missing folder -> 3" 3 $?; set -e
check "sync never deleted the local files" k "$(cat "$L/keep/k")"
check "sync from a file" NOT_A_FOLDER "$($K sync direct:$R/b "$L/x" | jget 'd["error"]["code"]' || true)"
check "sync dry-run grammar" True "$($K sync "$L/site" direct:$R/s --dry-run -o text 2>/dev/null | grep -q '^would copy 2, update 0, delete 0' && echo True || echo False)"

# jobs
JR=$($K job start direct -- 'sleep 60' | jget 'd["data"]["jobs"][0]["id"]')
check "job rm of a running job -> JOB_RUNNING" JOB_RUNNING "$($K job rm "$JR" | jget 'd["error"]["code"]' || true)"
set +e; $K job wait "$JR" --timeout 2s --interval 1s >/dev/null; check "job wait --timeout" 7 $?; set -e
q $K job kill "$JR"
check "a killed job says killed" killed "$($K job status "$JR" | jget 'd["data"]["state"]')"
check "kill again is a no-op" 0 "$($K job kill "$JR" >/dev/null; echo $?)"
set +e; $K job logs "$JR" --offset -5 >/dev/null; check "negative --offset -> 2" 2 $?; set -e
q $K job rm "$JR"

# recipes, tunnels
set +e; $K recipe run disk direct --var pth=/ >/dev/null; check "unknown recipe --var -> 2" 2 $?; set -e
check "an unknown recipe" RECIPE_NOT_FOUND "$($K recipe run t-e2enope direct | jget 'd["error"]["code"]' || true)"
TUN=$($K tunnel start direct -L 0:localhost:22)
TP=$(echo "$TUN" | jget 'd["data"]["listen"].split(":")[1]')
check "a port in use" PORT_IN_USE "$($K tunnel start direct -L "${TP}:localhost:22" | jget 'd["error"]["code"]' || true)"
q $K tunnel stop "$(echo "$TUN" | jget 'd["data"]["id"]')"

q $K exec direct -- "chmod -R u+rwx $R; rm -rf $R ~/t-e2erun-a.txt"
rm -rf "$L"
