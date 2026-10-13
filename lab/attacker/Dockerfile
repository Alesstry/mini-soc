FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends hydra ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY wordlists/users.txt wordlists/passwords.txt /opt/
COPY attack_ssh_bruteforce.sh /opt/attack_ssh_bruteforce.sh
RUN chmod +x /opt/attack_ssh_bruteforce.sh
CMD ["/opt/attack_ssh_bruteforce.sh"]
