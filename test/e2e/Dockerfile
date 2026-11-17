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
# Every `--via` connection starts with a login here. sshd's default
# MaxStartups (10:30:100) drops new logins at random once ten are half-open,
# which a loaded CI runner reaches (C88, 2026-11-17). In a file Debian's
# sshd_config includes first (the first value wins), so `sshd -T` shows it.
RUN echo 'MaxStartups 200:30:400' > /etc/ssh/sshd_config.d/lab.conf
CMD ["/usr/sbin/sshd", "-D", "-e"]
