#!/usr/bin/env python3
"""Shipper mínimo: lee un log (tipo `tail -F`) y envía cada línea a la plataforma.

POR QUÉ un proceso separado de la víctima: en el mundo real es un "agente"
(Filebeat, Wazuh agent, Fluent Bit). Separarlo muestra el límite de confianza:
la víctima puede estar comprometida, la plataforma no debe depender de ella.

Solo stdlib a propósito: cero dependencias = menos superficie de ataque.

Limitaciones conocidas (ejercicio para ti, ver LEARNING.md):
  - Si se reinicia, empieza desde el final (puede perder líneas).
  - Tras 5 reintentos descarta la línea (no hay cola persistente).
"""
import json
import os
import sys
import time
import urllib.error
import urllib.request

URL = os.environ["SOC_URL"]
API_KEY = os.environ["INGEST_API_KEY"]
LOG_FILE = os.environ.get("LOG_FILE", "/var/log/lab/auth.log")
HOST = os.environ.get("SOURCE_HOST", "unknown")


def log(msg: str) -> None:
    print(f"[shipper] {msg}", file=sys.stderr, flush=True)


def send(line: str) -> bool:
    body = json.dumps({"source": "linux-auth", "host": HOST, "message": line}).encode()
    req = urllib.request.Request(
        URL, data=body, method="POST",
        headers={"Content-Type": "application/json", "X-API-Key": API_KEY},
    )
    for attempt in range(5):
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except urllib.error.HTTPError as e:      # 4xx/5xx: reintentar solo si es 5xx
            if e.code < 500:
                log(f"rechazado por la plataforma (HTTP {e.code}); descartando línea")
                return False
            err = e
        except (urllib.error.URLError, TimeoutError) as e:
            err = e
        wait = min(2 ** attempt, 30)             # backoff exponencial
        log(f"error enviando ({err}); reintento en {wait}s")
        time.sleep(wait)
    return False


def follow(path: str):
    """Genera líneas nuevas del archivo; sobrevive a rotación/truncado."""
    seek_end = os.path.exists(path)   # si ya existía al arrancar, ignoramos lo viejo
    while True:
        while not os.path.exists(path):
            time.sleep(1)
        with open(path, "r", errors="replace") as f:
            if seek_end:
                f.seek(0, os.SEEK_END)
            seek_end = False
            inode = os.fstat(f.fileno()).st_ino
            while True:
                pos = f.tell()
                line = f.readline()
                if line and line.endswith("\n"):
                    yield line.rstrip("\n")
                    continue
                if line:                          # línea a medio escribir: esperar
                    f.seek(pos)
                time.sleep(0.5)
                try:
                    st = os.stat(path)
                except FileNotFoundError:
                    break
                if st.st_ino != inode or st.st_size < f.tell():
                    break                         # rotado o truncado: reabrir


def main() -> None:
    log(f"siguiendo {LOG_FILE} -> {URL}")
    for line in follow(LOG_FILE):
        if line.strip():
            send(line)


if __name__ == "__main__":
    main()
