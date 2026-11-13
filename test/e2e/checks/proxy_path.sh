# shellcheck shell=bash
# A company HTTP proxy as a --via path: a small CONNECT proxy on this
# computer, and a server reached through it (SSH inside the tunnel).
set +e
PROXY_PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')
python3 - "$PROXY_PORT" >"$TMP/proxy.log" 2>&1 <<'PY' &
import socket, sys, threading
def pipe(a, b):
    try:
        while (d := a.recv(65536)):
            b.sendall(d)
    except OSError:
        pass
    finally:
        a.close(); b.close()
def serve(c):
    head = b""
    while b"\r\n\r\n" not in head:
        head += c.recv(4096)
    line = head.split(b"\r\n")[0].decode()
    print(line, flush=True)
    method, target, _ = line.split(" ")
    host, port = target.rsplit(":", 1)
    up = socket.create_connection((host, int(port)))
    c.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
    threading.Thread(target=pipe, args=(c, up), daemon=True).start()
    pipe(up, c)
s = socket.socket(); s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("127.0.0.1", int(sys.argv[1]))); s.listen()
while True:
    threading.Thread(target=serve, args=(s.accept()[0],), daemon=True).start()
PY
PROXY_PID=$!
for _ in $(seq 1 20); do nc -z 127.0.0.1 "$PROXY_PORT" 2>/dev/null && break; sleep 0.2; done

q $K vpn add t-corp proxy --proxy-address "127.0.0.1:$PROXY_PORT"
q $K host add t-viaproxy "agent@127.0.0.1:$E2E_SSH_BASTION" --via t-corp --password-ref secret:agent-pass
check "ssh through an HTTP proxy" True "$($K exec t-viaproxy -- hostname | jget 'd["data"]["results"][0]["ok"]')"
check "the proxy carried it (CONNECT)" True "$(grep -q "CONNECT 127.0.0.1:$E2E_SSH_BASTION" "$TMP/proxy.log" && echo True || echo False)"
check "vpn status sees the proxy" True "$($K vpn status | jget 'any(r["name"] == "t-corp" and r["up"] for r in d["data"]["vpns"])')"
kill "$PROXY_PID" 2>/dev/null
check "a proxy that is gone is VPN_DOWN" VPN_DOWN "$($K exec t-viaproxy -- hostname | jget 'd["data"]["results"][0]["error"]["code"]')"
q $K host rm t-viaproxy
q $K vpn rm t-corp
set -e
