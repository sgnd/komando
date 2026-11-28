# shellcheck shell=bash
# Parity: the same everyday job done with the native tool (run inside the
# lab container: sh, sha256sum, psql, mariadb, redis-cli, kubectl, docker)
# and with komando must give the same answer. komando adds safety and one
# output format; it must never change the result.
P="${PROJECT:-komando-e2e}"
native() { docker exec -i "$P-$1-1" "${@:2}"; } # native SERVICE CMD...: run CMD in that lab container
nativeas() { docker exec -i -u "$1" "$P-$2-1" "${@:3}"; } # as the user komando logs in as
words() { tr '\n' ' ' | sed 's/ *$//'; }                  # lines -> one line, for comparing
V="t-par-$$"
# each part runs in the area that has its containers (run.sh)
stdout_of() { jget 'd["data"]["results"][0]["stdout"]'; }

if in_area data; then
# a command on a server (ssh host CMD)
check "exec = native shell" "$(nativeas agent direct sh -c 'uname -n; id -un' | words)" \
  "$($K host ssh exec direct --read-only -- 'uname -n; id -un' | stdout_of | words)"
check "exec keeps the remote exit code (like ssh)" 3 "$($K host ssh exec direct -- 'exit 3' | jget 'd["data"]["results"][0]["exit_code"]' || true)"

# copying a file (scp): byte for byte, both ways
head -c 300000 /dev/urandom >"$TMP/$V.bin"
q $K copy "$TMP/$V.bin" "direct:/tmp/$V.bin"
check "upload = native sha256" "$(shasum -a 256 "$TMP/$V.bin" | cut -d' ' -f1)" "$(native direct sha256sum "/tmp/$V.bin" | cut -d' ' -f1)"
q $K copy "direct:/tmp/$V.bin" "$TMP/$V.back"
check "download = the same bytes" "$(shasum -a 256 "$TMP/$V.bin" | cut -d' ' -f1)" "$(shasum -a 256 "$TMP/$V.back" | cut -d' ' -f1)"

# editing a file (sed -i): only the line asked for changes
printf 'a=1\nb=2\nc=3\n' | nativeas agent direct sh -c "cat > /tmp/$V.conf"
q $K fs replace direct "/tmp/$V.conf" --old 'b=2' --new 'b=20'
check "fs replace = sed -i result" "$(printf 'a=1\nb=20\nc=3\n')" "$(native direct cat "/tmp/$V.conf")"
check "fs cat = cat" "$(native direct cat "/tmp/$V.conf")" "$($K fs cat direct "/tmp/$V.conf" | jget 'd["data"]["content"].rstrip("\n")')"
check "fs ls = ls" "$(native direct ls -A /tmp | grep -c "^$V")" "$($K fs ls direct /tmp | jget 'str(sum(1 for e in d["data"]["entries"] if e["name"].startswith("'"$V"'")))')"

# PostgreSQL (psql -At -c)
check "database postgres query = psql" "$(native pg psql -U app -d app -At -c 'select 6*7, current_user')" \
  "$($K database postgres query pg 'select 6*7, current_user' | jget '"|".join(str(v) for v in d["data"]["results"][0]["rows"][0])')"
check "database postgres query dates = psql" "$(native pg psql -U app -d app -At -c "select date '2024-02-29', timestamp '2024-01-01 10:00:00'")" \
  "$($K database postgres query pg "select date '2024-02-29', timestamp '2024-01-01 10:00:00'" | jget '"|".join(str(v) for v in d["data"]["results"][0]["rows"][0])')"

# MariaDB (mariadb -N -e)
check "database postgres query = mariadb" "$(native maria mariadb -ushop -pshoppass shop -N -e 'select 6*7' 2>/dev/null)" \
  "$($K database mysql query maria 'select 6*7' | jget 'str(d["data"]["results"][0]["rows"][0][0])')"

# SFTP storage: what komando uploads is what the server holds
echo "parity $V" >"$TMP/$V.txt"
q $K copy "$TMP/$V.txt" "files-sftp:$V.txt"
check "storage upload = file on the sftp server" "parity $V" "$(native sftp cat "/home/deploy/uploads/$V.txt")"
check "storage sftp object list = ls" True "$($K storage sftp object list files-sftp | jget '"'"$V.txt"'" in json.dumps(d["data"])')"
fi

if in_area swarm; then
# Docker on swarm1 (docker ps / images / node ls)
check "docker images = docker image ls" "$(native swarm docker image ls --format '{{.Repository}}' | grep -v '<none>' | sort -u | words)" \
  "$($K docker images swarm1 | jget '" ".join(sorted(set(i["Repository"] for r in d["data"]["results"] for i in (r.get("data") or []) if i.get("Repository") and i["Repository"] != "<none>")))')"
fi

if in_area data; then
# packages (dpkg-query)
check "pkg installed = dpkg-query" "$(native direct dpkg-query -W -f='${Version}' curl)" "$($K pkg installed direct curl | jget 'd["data"]["results"][0]["data"][0]["version"]')"

# a read that exits non-zero fails, as with ssh: the exit code is the result
check "exec --read-only keeps ssh's exit code" "$(nativeas agent direct sh -c 'ls /nope-missing >/dev/null 2>&1; echo $?') 5" \
  "$(rc=0; $K host ssh exec direct --read-only -- 'ls /nope-missing' >"$TMP/ro.json" || rc=$?; echo "$(jget 'd["data"]["results"][0]["exit_code"]' <"$TMP/ro.json") $rc")"

# logs = tail
check "logs --file = tail" "$(native direct tail -n 5 /etc/passwd)" "$($K logs direct --file /etc/passwd -n 5 | jget 'd["data"]["results"][0]["stdout"].rstrip("\n")')"

# sync = diff -r afterwards; a session's output = the command's own output
mkdir -p "$TMP/$V.src/sub" && echo one >"$TMP/$V.src/a.txt" && echo two >"$TMP/$V.src/sub/b.txt"
q $K copy "$TMP/$V.src" "direct:/tmp/$V.sync" --sync
check "sync = same tree (diff -r)" "$(cd "$TMP/$V.src" && find . -type f | sort | xargs cat | shasum | cut -c1-12)" \
  "$(native direct sh -c "cd /tmp/$V.sync && find . -type f | sort | xargs cat | sha1sum" | cut -c1-12)"
check "a session's output = the command's output" "$(printf 'line1\nline2')" "$($K host ssh exec direct -- 'printf "line1\nline2\n"' | jget 'd["data"]["results"][0]["stdout"].rstrip("\n")')"

# redis-cli SCAN, psql's table list, the registry catalog
q $K cache redis raw cache --write -- SET "$V:a" 1
q $K cache redis raw cache --write -- SET "$V:b" 2
check "db schema = psql's tables" "$(native pg psql -U app -d app -At -c "select tablename from pg_tables where schemaname = 'public' order by 1" | words)" \
  "$($K db schema pg | jget '" ".join(sorted(t["name"] for t in d["data"]["tables"] if t["schema"] == "public" and t["type"] == "table"))')"
fi

if in_area registry; then
check "registry oci image list = the registry's catalog" "$(native bastion curl -s http://registry:5000/v2/_catalog | python3 -c 'import json,sys; print(" ".join(sorted(json.load(sys.stdin)["repositories"])))')" \
  "$($K registry oci image list reg | jget '" ".join(sorted(d["data"]["repositories"]))')"
fi

if in_area swarm; then
check "docker ps --all = docker ps -a" "$(native swarm docker ps -a --format '{{.Names}}' | sort | words)" \
  "$($K docker ps swarm1 --all | jget '" ".join(sorted(c.get("Names") or c.get("names") or c.get("name", "") for c in d["data"]["results"][0]["data"]))')"
fi

if in_area data; then
# a tunnel reaches the same service as a direct connection
T=$($K host ssh tunnel start direct -L 0:localhost:22 | jget 'd["data"]["listen"] + " " + d["data"]["id"]')
banner() { python3 -c 'import socket,sys; h,p=sys.argv[1].rsplit(":",1); s=socket.create_connection((h,int(p)),5); print(s.recv(64).decode().split()[0])' "$1"; }
check "tunnel -L = the service itself" "$(banner "127.0.0.1:$E2E_SSH_DIRECT")" "$(banner "${T% *}")"
q $K host ssh tunnel stop "${T#* }"

q $K host ssh exec direct --allow-dangerous -- "rm -rf /tmp/$V.sync"
q $K cache redis raw cache --write --allow-dangerous -- DEL "$V:a" "$V:b"
q $K host ssh exec direct --allow-dangerous -- "rm -f /tmp/$V.bin /tmp/$V.conf"
q $K cache redis raw cache --write --allow-dangerous -- DEL "$V:k"
fi
