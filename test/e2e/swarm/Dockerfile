# A one-node Docker Swarm manager reachable over SSH, for the e2e test.
# Docker-in-Docker (privileged). Never use in production.
FROM docker:28-dind
RUN apk add --no-cache openssh-server sudo bash \
    && ssh-keygen -A \
    && adduser -D -s /bin/bash agent && echo 'agent:agentpass' | chpasswd \
    && addgroup agent docker \
    && echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config
COPY start.sh /start.sh
RUN chmod +x /start.sh
ENTRYPOINT ["/start.sh"]
