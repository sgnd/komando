# A disposable dnf or yum server (Rocky Linux, Amazon Linux 2), for the
# facts and pkg security checks against the real dnf/yum. Never use in
# production. BASE picks the distribution.
ARG BASE=rockylinux/rockylinux:9
FROM ${BASE}
RUN PM=$(command -v dnf || command -v yum) \
    && $PM -q -y install openssh-server sudo procps-ng iproute shadow-utils passwd \
         $( [ "${PM##*/}" = dnf ] && echo dnf-utils || echo yum-utils ) \
    && ssh-keygen -A \
    && useradd -m -s /bin/bash agent && echo 'agent:agentpass' | chpasswd \
    && echo 'agent ALL=(ALL) NOPASSWD:ALL' > /etc/sudoers.d/agent \
    && $PM -q makecache
EXPOSE 22
CMD ["/usr/sbin/sshd", "-D", "-e"]
