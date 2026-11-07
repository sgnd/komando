#!/bin/sh
# Start dockerd, make this node a Swarm manager, then serve SSH.
dockerd-entrypoint.sh dockerd >/var/log/dockerd.log 2>&1 &
for _ in $(seq 1 60); do docker info >/dev/null 2>&1 && break; sleep 1; done
docker swarm init --advertise-addr 127.0.0.1 >/dev/null 2>&1 || true
exec /usr/sbin/sshd -D -e
