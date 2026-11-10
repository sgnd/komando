# shellcheck shell=bash
# --dry-run changes nothing: every command that changes something is run
# with --dry-run, and the native tool then confirms nothing changed.
P="${PROJECT:-komando-e2e}"
nat() { docker exec -i "$P-$1-1" "${@:2}"; }
D="t-dry-$$"
# dry CMD...: ran as a dry run (--dry-run first: after -- every word is the remote command's, as with ssh)
dry() { $K --dry-run "$@" | jget 'd["meta"].get("dry_run", False)'; }

# files on a server
check "fs write --dry-run" True "$(dry fs write direct "/tmp/$D.txt" --content x)"
check "fs mkdir --dry-run" True "$(dry fs mkdir direct "/tmp/$D.dir")"
q $K fs write direct "/tmp/$D.keep" --content keep
check "fs replace --dry-run" True "$(dry fs replace direct "/tmp/$D.keep" --old keep --new gone)"
check "fs chmod --dry-run" True "$(dry fs chmod direct 600 "/tmp/$D.keep")"
check "fs mv --dry-run" True "$(dry fs mv direct "/tmp/$D.keep" "/tmp/$D.moved")"
check "fs rm --dry-run" True "$(dry fs rm direct "/tmp/$D.keep")"
echo hi >"$TMP/$D.src"
check "cp --dry-run" True "$(dry cp "$TMP/$D.src" "direct:/tmp/$D.cp")"
check "nothing written on the server" "keep 644 no no no no" \
  "$(nat direct sh -c "cat /tmp/$D.keep; echo; stat -c %a /tmp/$D.keep; for f in /tmp/$D.txt /tmp/$D.dir /tmp/$D.moved /tmp/$D.cp; do [ -e \$f ] && echo yes || echo no; done" | tr '\n' ' ' | sed 's/ *$//')"
check "download --dry-run writes nothing here" "True no" "$(dry download direct "/tmp/$D.keep" --to "$TMP/$D.down") $([ -e "$TMP/$D.down" ] && echo yes || echo no)"
check "exec --dry-run runs nothing" "True no" "$(dry exec direct -- touch "/tmp/$D.exec") $(nat direct sh -c "[ -e /tmp/$D.exec ] && echo yes || echo no")"

# databases, caches, storage
check "db query --write --dry-run rolls back" "True 0" \
  "$(dry db query pg --write "create table $D (id int)") $(nat pg psql -U app -d app -At -c "select count(*) from information_schema.tables where table_name = '$D'")"
check "cache set --dry-run" "True 0" "$(dry cache set cache "$D:k" v) $(nat redis redis-cli -a redispass --no-auth-warning EXISTS "$D:k")"
echo data >"$TMP/$D.obj"
check "storage upload --dry-run" "True no" "$(dry storage upload files-sftp "$TMP/$D.obj" "$D.obj") $(nat sftp sh -c "[ -e /home/deploy/uploads/$D.obj ] && echo yes || echo no")"

# system modules
check "user add --dry-run" "True no" "$(dry user add direct "$D") $(nat direct sh -c "id $D >/dev/null 2>&1 && echo yes || echo no")"
check "cron set --dry-run" "True 0" "$(dry cron set direct "$D" true --schedule @daily) $(nat direct sh -c "crontab -u agent -l 2>/dev/null | grep -c 'komando:$D' || true")"
check "pkg install --dry-run" "True no" "$(dry pkg install direct sl) $(nat direct sh -c "dpkg -s sl >/dev/null 2>&1 && echo yes || echo no")"

# docker and clusters
check "docker stop --dry-run" True "$(dry docker stop swarm1 nothing-runs-here)"
check "cluster scale --dry-run" "True 1" "$(dry cluster scale lab-k3s deploy/coredns 3 --namespace kube-system) $(nat k3s kubectl get deploy coredns -n kube-system -o jsonpath='{.spec.replicas}')"

# inventory and settings (komando's own files)
before=$({ cat "$KOMANDO_HOME/state.json" "$KOMANDO_HOME/vault.json" "$KOMANDO_HOME/runtime.json" "$KOMANDO_HOME/store.db" 2>/dev/null || true; } | shasum | cut -d' ' -f1)
dry host add "$D" agent@127.0.0.1 >/dev/null
dry conn add "$D" "postgres://app@127.0.0.1/app" >/dev/null
dry group add "$D" direct >/dev/null
dry config set parallel 3 >/dev/null
dry policy deny "$D" >/dev/null
dry recipe add "$D" 'echo hi' >/dev/null
printf 'v' | $K secret set "$D" --dry-run >/dev/null
check "inventory, vault, settings and runtime unchanged by dry runs" "$before" "$({ cat "$KOMANDO_HOME/state.json" "$KOMANDO_HOME/vault.json" "$KOMANDO_HOME/runtime.json" "$KOMANDO_HOME/store.db" 2>/dev/null || true; } | shasum | cut -d' ' -f1)"

q $K exec direct -- "rm -f /tmp/$D.keep"
