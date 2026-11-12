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
  "$($K exec direct --read-only -- 'uname -n; id -un' | stdout_of | words)"
check "exec keeps the remote exit code (like ssh)" 3 "$($K exec direct -- 'exit 3' | jget 'd["data"]["results"][0]["exit_code"]' || true)"

# copying a file (scp): byte for byte, both ways
head -c 300000 /dev/urandom >"$TMP/$V.bin"
q $K cp "$TMP/$V.bin" "direct:/tmp/$V.bin"
check "upload = native sha256" "$(shasum -a 256 "$TMP/$V.bin" | cut -d' ' -f1)" "$(native direct sha256sum "/tmp/$V.bin" | cut -d' ' -f1)"
q $K cp "direct:/tmp/$V.bin" "$TMP/$V.back"
check "download = the same bytes" "$(shasum -a 256 "$TMP/$V.bin" | cut -d' ' -f1)" "$(shasum -a 256 "$TMP/$V.back" | cut -d' ' -f1)"

# editing a file (sed -i): only the line asked for changes
printf 'a=1\nb=2\nc=3\n' | nativeas agent direct sh -c "cat > /tmp/$V.conf"
q $K fs replace direct "/tmp/$V.conf" --old 'b=2' --new 'b=20'
check "fs replace = sed -i result" "$(printf 'a=1\nb=20\nc=3\n')" "$(native direct cat "/tmp/$V.conf")"
check "fs cat = cat" "$(native direct cat "/tmp/$V.conf")" "$($K fs cat direct "/tmp/$V.conf" | jget 'd["data"]["content"].rstrip("\n")')"
check "fs ls = ls" "$(native direct ls -A /tmp | grep -c "^$V")" "$($K fs ls direct /tmp | jget 'str(sum(1 for e in d["data"]["entries"] if e["name"].startswith("'"$V"'")))')"

# PostgreSQL (psql -At -c)
check "db query = psql" "$(native pg psql -U app -d app -At -c 'select 6*7, current_user')" \
  "$($K db query pg 'select 6*7, current_user' | jget '"|".join(str(v) for v in d["data"]["results"][0]["rows"][0])')"
check "db query dates = psql" "$(native pg psql -U app -d app -At -c "select date '2024-02-29', timestamp '2024-01-01 10:00:00'")" \
  "$($K db query pg "select date '2024-02-29', timestamp '2024-01-01 10:00:00'" | jget '"|".join(str(v) for v in d["data"]["results"][0]["rows"][0])')"

# MariaDB (mariadb -N -e)
check "db query = mariadb" "$(native maria mariadb -ushop -pshoppass shop -N -e 'select 6*7' 2>/dev/null)" \
  "$($K db query maria 'select 6*7' | jget 'str(d["data"]["results"][0]["rows"][0][0])')"

# Redis (redis-cli SET / GET / TTL)
q $K cache set cache "$V:k" "hello world" --ttl 1h
check "cache get = redis-cli GET" "$(native redis redis-cli -a redispass --no-auth-warning GET "$V:k")" "$($K cache get cache "$V:k" | jget 'd["data"]["value"]')"
check "cache TTL = redis-cli TTL" True "$(t=$(native redis redis-cli -a redispass --no-auth-warning TTL "$V:k"); $K cache get cache "$V:k" | jget "abs(d['data']['ttl_seconds'] - $t) <= 2")"

# SFTP storage: what komando uploads is what the server holds
echo "parity $V" >"$TMP/$V.txt"
q $K storage upload files-sftp "$TMP/$V.txt" "$V.txt"
check "storage upload = file on the sftp server" "parity $V" "$(native sftp cat "/home/deploy/uploads/$V.txt")"
check "storage ls = ls" True "$($K storage ls files-sftp | jget '"'"$V.txt"'" in json.dumps(d["data"])')"
fi

if in_area k8s; then
# Kubernetes (kubectl get)
check "cluster ls namespaces = kubectl" "$(native k3s kubectl get ns -o name | sed 's|namespace/||' | sort | words)" \
  "$($K cluster ls lab-k3s namespaces | jget '" ".join(sorted(i["name"] for i in d["data"]["items"]))')"
check "cluster ls kube-system deployments = kubectl" "$(native k3s kubectl get deploy -n kube-system -o name | sed 's|.*/||' | sort | words)" \
  "$($K cluster ls lab-k3s deployments --namespace kube-system | jget '" ".join(sorted(i["name"] for i in d["data"]["items"]))')"
fi

if in_area swarm; then
# Docker on swarm1 (docker ps / images / node ls)
check "docker images = docker image ls" "$(native swarm docker image ls --format '{{.Repository}}' | grep -v '<none>' | sort -u | words)" \
  "$($K docker images swarm1 | jget '" ".join(sorted(set(i["Repository"] for r in d["data"]["results"] for i in (r.get("data") or []) if i.get("Repository") and i["Repository"] != "<none>")))')"
check "Swarm nodes = docker node ls" "$(native swarm docker node ls --format '{{.Hostname}}' | sort | words)" \
  "$($K cluster ls swarm1 nodes | jget '" ".join(sorted(i["name"] for i in d["data"]["items"]))')"
fi

if in_area data; then
# packages (dpkg-query)
check "pkg installed = dpkg-query" "$(native direct dpkg-query -W -f='${Version}' curl)" "$($K pkg installed direct curl | jget 'd["data"]["results"][0]["data"][0]["version"]')"

# a read that exits non-zero fails, as with ssh: the exit code is the result
check "exec --read-only keeps ssh's exit code" "$(nativeas agent direct sh -c 'ls /nope-missing >/dev/null 2>&1; echo $?') 5" \
  "$(rc=0; $K exec direct --read-only -- 'ls /nope-missing' >"$TMP/ro.json" || rc=$?; echo "$(jget 'd["data"]["results"][0]["exit_code"]' <"$TMP/ro.json") $rc")"

# logs = tail, cron list = crontab -l, user list = getent passwd
check "logs --file = tail" "$(native direct tail -n 5 /etc/passwd)" "$($K logs direct --file /etc/passwd -n 5 | jget 'd["data"]["results"][0]["stdout"].rstrip("\n")')"
q $K cron set direct "$V" 'true' --schedule '*/5 * * * *'
check "cron list = crontab -l" "$(nativeas agent direct crontab -l | grep -c "komando:$V")" "$($K cron list direct | jget 'str(sum(1 for r in d["data"]["results"][0]["data"] if r.get("id") == "'"$V"'"))')"
check "cron schedule = what crontab holds" "*/5 * * * *" "$($K cron list direct | jget 'next(r["schedule"] for r in d["data"]["results"][0]["data"] if r.get("id") == "'"$V"'")')"
q $K cron rm direct "$V"
check "user list = getent (uid >= 1000)" "$(native direct getent passwd | awk -F: '$3 >= 1000 && $3 < 65534 {print $1}' | sort | words)" \
  "$($K user list direct | jget '" ".join(sorted(u["name"] for u in d["data"]["results"][0]["data"] if u["uid"] >= 1000))')"

# net dns = getent, net ports = ss, facts = uname / nproc
check "net dns = getent ahosts" "$(native direct getent ahosts localhost | awk '{print $1}' | sort -u | words)" "$($K net dns direct localhost | jget '" ".join(sorted(d["data"]["results"][0]["data"]["addresses"]))')"
check "net ports = ss (tcp listening)" "$(native direct ss -Htln | awk '{n=split($4,a,":"); print a[n]}' | sort -un | words)" \
  "$($K net ports direct | jget '" ".join(str(p) for p in sorted(set(r["port"] for r in d["data"]["results"][0]["data"] if r["proto"] == "tcp" and r["state"] == "LISTEN")))')"
check "facts = uname / nproc" "$(native direct sh -c 'uname -n; uname -r; nproc' | words)" \
  "$($K facts direct | jget '" ".join(str(d["data"]["results"][0]["data"][k]) for k in ("hostname", "kernel", "cpus"))')"

# sync = diff -r afterwards; job logs = the job's own output
mkdir -p "$TMP/$V.src/sub" && echo one >"$TMP/$V.src/a.txt" && echo two >"$TMP/$V.src/sub/b.txt"
q $K sync "$TMP/$V.src" "direct:/tmp/$V.sync"
check "sync = same tree (diff -r)" "$(cd "$TMP/$V.src" && find . -type f | sort | xargs cat | shasum | cut -c1-12)" \
  "$(native direct sh -c "cd /tmp/$V.sync && find . -type f | sort | xargs cat | sha1sum" | cut -c1-12)"
J=$($K job start direct -- 'printf "line1\nline2\n"' | jget 'd["data"]["jobs"][0]["id"]')
q $K job wait "$J" --timeout 1m
check "job logs = the job's output" "$(printf 'line1\nline2')" "$($K job logs "$J" | jget 'd["data"]["content"].rstrip("\n")')"

# redis-cli SCAN, psql's table list, the registry catalog
q $K cache set cache "$V:a" 1
q $K cache set cache "$V:b" 2
check "cache keys = redis-cli --scan" "$(native redis redis-cli -a redispass --no-auth-warning --scan --pattern "$V:*" | sort | words)" \
  "$($K cache keys cache "$V:*" | jget '" ".join(sorted(d["data"]["keys"]))')"
check "db schema = psql's tables" "$(native pg psql -U app -d app -At -c "select tablename from pg_tables where schemaname = 'public' order by 1" | words)" \
  "$($K db schema pg | jget '" ".join(sorted(t["name"] for t in d["data"]["tables"] if t["schema"] == "public" and t["type"] == "table"))')"
fi

if in_area registry; then
check "registry ls = the registry's catalog" "$(native bastion curl -s http://registry:5000/v2/_catalog | python3 -c 'import json,sys; print(" ".join(sorted(json.load(sys.stdin)["repositories"])))')" \
  "$($K registry ls reg | jget '" ".join(sorted(d["data"]["repositories"]))')"
fi

if in_area k8s; then
# kubectl logs, docker ps
check "cluster logs = kubectl logs" "$(native k3s kubectl logs -n kube-system deploy/coredns --tail 3)" \
  "$($K cluster logs lab-k3s deploy/coredns --namespace kube-system -n 3 | jget 'd["data"]["logs"].rstrip("\n")')"
fi

if in_area swarm; then
check "docker ps --all = docker ps -a" "$(native swarm docker ps -a --format '{{.Names}}' | sort | words)" \
  "$($K docker ps swarm1 --all | jget '" ".join(sorted(c.get("Names") or c.get("names") or c.get("name", "") for c in d["data"]["results"][0]["data"]))')"
fi

if in_area data; then
# a tunnel reaches the same service as a direct connection
T=$($K tunnel start direct -L 0:localhost:22 | jget 'd["data"]["listen"] + " " + d["data"]["id"]')
banner() { python3 -c 'import socket,sys; h,p=sys.argv[1].rsplit(":",1); s=socket.create_connection((h,int(p)),5); print(s.recv(64).decode().split()[0])' "$1"; }
check "tunnel -L = the service itself" "$(banner "127.0.0.1:$E2E_SSH_DIRECT")" "$(banner "${T% *}")"
q $K tunnel stop "${T#* }"

q $K exec direct -- "rm -rf /tmp/$V.sync"
q $K cache rm cache "$V:a" "$V:b" --allow-dangerous
q $K exec direct -- "rm -f /tmp/$V.bin /tmp/$V.conf"
q $K cache rm cache "$V:k" --allow-dangerous
fi
