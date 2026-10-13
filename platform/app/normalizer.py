"""Convierte líneas crudas de syslog/sshd en Event.

Formato esperado (rsyslog con template RSYSLOG_FileFormat):
  2026-10-13T12:00:00.123456+00:00 victim sshd[123]: Failed password for root from 172.20.0.5 port 40000 ssh2

POR QUÉ regex ANCLADAS con ^ y clases \\S+ estrictas: el atacante controla parte
del log (por ejemplo el nombre de usuario que prueba). Un parser flojo puede
ser engañado con "log injection" (usuario = 'x from 1.2.3.4 port 1').
"""
import re
from datetime import datetime, timezone

from .models import Event, RawLog

SYSLOG_RE = re.compile(
    r"^(?P<ts>\S+)\s+(?P<host>\S+)\s+(?P<proc>[A-Za-z0-9_\-./]+)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)
IP = r"(?P<ip>[0-9a-fA-F:.]+)"
FAILED_RE = re.compile(rf"^Failed (?P<method>\S+) for (?:invalid user )?(?P<user>\S+) from {IP} port \d+")
ACCEPTED_RE = re.compile(rf"^Accepted (?P<method>\S+) for (?P<user>\S+) from {IP} port \d+")
INVALID_USER_RE = re.compile(rf"^Invalid user (?P<user>\S*) from {IP} port \d+")


def _parse_ts(value: str) -> datetime:
    try:
        dt = datetime.fromisoformat(value)
    except ValueError:
        return datetime.now(timezone.utc)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)  # siempre UTC internamente


def normalize(raw: RawLog) -> Event | None:
    m = SYSLOG_RE.match(raw.message.strip())
    if not m or m["proc"] != "sshd":
        return None

    msg = m["msg"]
    common = dict(
        timestamp=_parse_ts(m["ts"]),
        host=m["host"],
        category="authentication",
        process="sshd",
        raw=raw.message,
    )

    if (f := FAILED_RE.match(msg)):
        return Event(action="ssh_login", outcome="failure", source_ip=f["ip"], user=f["user"], **common)
    if (a := ACCEPTED_RE.match(msg)):
        return Event(action="ssh_login", outcome="success", source_ip=a["ip"], user=a["user"], **common)
    if (i := INVALID_USER_RE.match(msg)):
        return Event(action="ssh_invalid_user", outcome="failure", source_ip=i["ip"], user=i["user"], **common)
    return None  # línea de sshd que aún no entendemos: la ignoramos
