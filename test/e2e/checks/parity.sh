# Parity: the same everyday job done with the native tool (run inside the
# lab container: sh, sha256sum, psql, mariadb, redis-cli, kubectl, docker)
# and with komando must give the same answer. komando adds safety and one
# output format; it must never change the result.
P="${PROJECT:-komando-e2e}"
native() { docker exec -i "$P-$1-1" "${@:2}"; } # native SERVICE CMD...: run CMD in that lab container
nativeas() { docker exec -i -u "$1" "$P-$2-1" "${@:3}"; } # as the user komando logs in as
words() { tr '\n' ' ' | sed 's/ *$//'; }                  # lines -> one line, for comparing
V="t-par-$$"
stdout_of() { jget 'd["data"]["results"][0]["stdout"]'; }

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

# Kubernetes (kubectl get)
check "cluster ls namespaces = kubectl" "$(native k3s kubectl get ns -o name | sed 's|namespace/||' | sort | words)" \
  "$($K cluster ls lab-k3s namespaces | jget '" ".join(sorted(i["name"] for i in d["data"]["items"]))')"
check "cluster ls kube-system deployments = kubectl" "$(native k3s kubectl get deploy -n kube-system -o name | sed 's|.*/||' | sort | words)" \
  "$($K cluster ls lab-k3s deployments --namespace kube-system | jget '" ".join(sorted(i["name"] for i in d["data"]["items"]))')"

# Docker on swarm1 (docker ps / images / node ls)
check "docker images = docker image ls" "$(native swarm docker image ls --format '{{.Repository}}' | grep -v '<none>' | sort -u | words)" \
  "$($K docker images swarm1 | jget '" ".join(sorted(set(i["Repository"] for r in d["data"]["results"] for i in (r.get("data") or []) if i.get("Repository") and i["Repository"] != "<none>")))')"
check "Swarm nodes = docker node ls" "$(native swarm docker node ls --format '{{.Hostname}}' | sort | words)" \
  "$($K cluster ls swarm1 nodes | jget '" ".join(sorted(i["name"] for i in d["data"]["items"]))')"

# packages (dpkg-query)
check "pkg installed = dpkg-query" "$(native direct dpkg-query -W -f='${Version}' curl)" "$($K pkg installed direct curl | jget 'd["data"]["results"][0]["data"][0]["version"]')"

q $K exec direct -- "rm -f /tmp/$V.bin /tmp/$V.conf"
q $K cache rm cache "$V:k" --allow-dangerous
