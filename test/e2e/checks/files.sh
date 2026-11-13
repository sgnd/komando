# shellcheck shell=bash
# upload, download, cp and sync with a server (direct): Ctrl-C stops a big
# copy and leaves nothing half-written, a refused download says so, a
# folder given as a symbolic link is copied, and a big file shows progress
# at a person's terminal. Uses /tmp/e2efiles* on the server and removes it.
in_area data || return 0
set +e

F="$TMP/e2efiles"
rm -rf "$F"; mkdir -p "$F"
head -c 300000000 /dev/zero > "$F/big.bin"

# sigint CMD...: start CMD, send SIGINT after 1 s; prints CMD's exit code,
# or 999 when it still ran 15 s later (then it is killed)
sigint() {
  "$@" >"$F/out" 2>&1 &
  local pid=$! n=0
  sleep 1
  kill -INT "$pid"
  while kill -0 "$pid" 2>/dev/null && [ $n -lt 30 ]; do sleep 0.5; n=$((n + 1)); done
  if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid"; wait "$pid" 2>/dev/null; echo "999"; return; fi
  wait "$pid"; echo "$?"
}
leftovers() { $K exec direct --read-only -o text -- 'ls -a /tmp /tmp/e2efiles-dir /tmp/e2efiles-sync 2>/dev/null | grep -c "^\.komando-" || true'; }

check "Ctrl-C stops an upload" 1 "$(sigint $K upload direct "$F/big.bin" /tmp/e2efiles-big.bin -o text)"
check "Ctrl-C upload says CANCELLED" True "$(grep -q CANCELLED "$F/out" && echo True || echo False)"
check "Ctrl-C upload leaves no file" 1 "$($K exec direct --read-only -o text -- 'test -e /tmp/e2efiles-big.bin; echo $?')"
mkdir -p "$F/dir"; cp "$F/big.bin" "$F/dir/"
check "Ctrl-C stops a folder upload" 1 "$(sigint $K upload direct "$F/dir" /tmp/e2efiles-dir -r -o text)"
check "Ctrl-C stops a sync" 1 "$(sigint $K sync "$F/dir" direct:/tmp/e2efiles-sync -o text)"
check "Ctrl-C leaves no temporary file on the server" 0 "$(leftovers)"

q $K exec direct -o text -- 'head -c 300000000 /dev/zero > /tmp/e2efiles-big.bin'
# sigint_when GLOB CMD...: like sigint, but the SIGINT goes as soon as a file
# matching GLOB shows (the copy has started), so a fast machine cannot finish
# the whole copy before it
sigint_when() {
  local glob=$1; shift
  "$@" >"$F/out" 2>&1 &
  local pid=$! n=0
  while ! compgen -G "$glob" >/dev/null && kill -0 "$pid" 2>/dev/null && [ $n -lt 200 ]; do sleep 0.02; n=$((n + 1)); done
  kill -INT "$pid" 2>/dev/null
  n=0
  while kill -0 "$pid" 2>/dev/null && [ $n -lt 30 ]; do sleep 0.5; n=$((n + 1)); done
  if kill -0 "$pid" 2>/dev/null; then kill -9 "$pid"; wait "$pid" 2>/dev/null; echo "999"; return; fi
  wait "$pid"; echo "$?"
}
check "Ctrl-C stops a download" 1 "$(sigint_when "$F/.komando-*" $K download direct /tmp/e2efiles-big.bin --to "$F/got.bin" -o text)"
check "Ctrl-C download leaves nothing here" 0 "$(find "$F" -maxdepth 1 \( -name got.bin -o -name '.komando-*' \) | wc -l | tr -d ' ')"

# a big file shows progress on stderr at a terminal, never in a pipe
check "download shows progress at a terminal" True "$(ptyrun '' $K download direct /tmp/e2efiles-big.bin --to "$F/pty.bin" -o text | grep -q 'e2efiles-big.bin: .* MB' && echo True || echo False)"
rm -f "$F/pty.bin"
check "no progress in a pipe" 0 "$($K download direct /tmp/e2efiles-big.bin --to "$F/pipe.bin" -o text 2>&1 | grep -c ' MB')"

# a download that meets a file already here saved nothing and says only that
echo mine > "$F/a.txt"
q $K exec direct -o text -- 'echo theirs > /tmp/e2efiles-a.txt'
out=$($K download direct /tmp/e2efiles-a.txt --to "$F/a.txt" -o text 2>&1)
check "refused download exits 8" 8 $?
check "refused download does not say downloaded" 0 "$(echo "$out" | grep -c downloaded)"
check "refused download keeps the file here" mine "$(cat "$F/a.txt")"

# a folder given as a symbolic link is copied as the folder it names
mkdir -p "$F/releases/42/css"; echo i > "$F/releases/42/index.html"; echo c > "$F/releases/42/css/a.css"
ln -s releases/42 "$F/current"
check "upload of a linked folder copies its files" 2 "$($K upload direct "$F/current" /tmp/e2efiles-site -r | jget 'd["data"]["results"][0]["files"]')"
check "sync of a linked folder copies its files" 2 "$($K sync "$F/current" direct:/tmp/e2efiles-site2 | jget 'd["data"]["results"][0]["copied"]')"

# sync --sudo: a folder only root may write, each file installed as root,
# a second run sends nothing; a folder others may change is refused
mkdir -p "$F/conf/sub"; echo a > "$F/conf/a.conf"; echo b > "$F/conf/sub/b.conf"; chmod 640 "$F/conf/a.conf"
q $K exec direct --sudo -- 'mkdir -p /etc/e2esync && chmod 755 /etc/e2esync'
check "sync --sudo without sudo is refused by the folder" True "$($K sync "$F/conf" direct:/etc/e2esync | jget 'd["ok"] == False' || true)"
check "sync --sudo copies as root" 2 "$($K sync "$F/conf" direct:/etc/e2esync --sudo | jget 'd["data"]["results"][0]["copied"]')"
check "sync --sudo keeps the mode" "640 root" "$($K exec direct --read-only -- 'stat -c "%a %U" /etc/e2esync/a.conf' | jget 'd["data"]["results"][0]["stdout"].strip()')"
check "sync --sudo a second time sends nothing" "0 0" "$($K sync "$F/conf" direct:/etc/e2esync --sudo | jget 'str(d["data"]["results"][0]["copied"])+" "+str(d["data"]["results"][0]["updated"])')"
q $K exec direct --sudo -- 'mkdir -p /tmp/e2eshared && chmod 777 /tmp/e2eshared'
check "sync --sudo into a folder others may change" SHARED_FOLDER_CONFLICT "$($K sync "$F/conf" direct:/tmp/e2eshared --sudo | jget 'd["data"]["results"][0]["error"]["code"]' || true)"
q $K exec direct --sudo -- 'rm -rf /etc/e2esync /tmp/e2eshared'

q $K exec direct -o text -- 'rm -rf /tmp/e2efiles* /tmp/.komando-*'
rm -rf "$F"
set -e
