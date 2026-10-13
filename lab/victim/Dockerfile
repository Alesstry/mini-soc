# ⚠️  SOLO LAB. Esta imagen es DELIBERADAMENTE débil (usuario 'deploy' con contraseña
#     trivial) para que el ataque de fuerza bruta tenga éxito. Nunca la expongas a internet.
FROM debian:bookworm-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server rsyslog \
    && rm -rf /var/lib/apt/lists/* \
    && mkdir -p /run/sshd /var/log/lab \
    && useradd -m -s /bin/bash deploy  && echo 'deploy:sunshine1'      | chpasswd \
    && useradd -m -s /bin/bash analyst && echo 'analyst:Zq7!vR2#mP9x' | chpasswd \
    # Los contenedores no soportan pam_loginuid; sin esto los logins exitosos fallan.
    && sed -i 's@session\s*required\s*pam_loginuid.so@session optional pam_loginuid.so@' /etc/pam.d/sshd

COPY rsyslog.conf /etc/rsyslog.conf
COPY sshd_config  /etc/ssh/sshd_config
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
ENTRYPOINT ["/entrypoint.sh"]
