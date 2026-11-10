# A disposable server with systemd as PID 1, for the svc and logs checks
# against the real systemctl and journalctl. Never use in production.
FROM debian:13-slim
RUN apt-get update -q && apt-get install -y -q --no-install-recommends \
      systemd systemd-sysv openssh-server sudo procps dbus \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -m -s /bin/bash agent && echo 'agent:agentpass' | chpasswd \
    && echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent \
    && systemctl enable ssh \
    && printf '[Unit]\nDescription=komando test service\n[Service]\nExecStart=/bin/sh -c "echo hello from t-svc; exec sleep infinity"\nExecReload=/bin/true\n[Install]\nWantedBy=multi-user.target\n' >/etc/systemd/system/t-svc.service \
    && systemctl enable t-svc
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
