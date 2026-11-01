# Disposable SSH server used by the end-to-end tests. Never use in production.
# The database clients let `komando db dump/restore` run here through --via.
FROM debian:13-slim
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
      openssh-server sudo procps iproute2 curl netcat-openbsd ca-certificates cron \
      postgresql-client mariadb-client \
    && rm -rf /var/lib/apt/lists/* && mkdir -p /run/sshd \
    && useradd -m -s /bin/bash agent && echo 'agent:agentpass' | chpasswd \
    && useradd -m -s /bin/bash ops && echo 'ops:opspass' | chpasswd && usermod -aG sudo ops \
    && echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent \
    && mkdir -p /etc/app && echo 'worker_connections 768;' > /etc/app/app.conf
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
