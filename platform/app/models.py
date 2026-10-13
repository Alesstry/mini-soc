"""Modelos de datos.

RawLog  = lo que llega del shipper (texto crudo, sin confiar en nada).
Event   = el evento normalizado, con forma parecida a ECS (Elastic Common Schema).

POR QUÉ normalizar: cada fuente (sshd, nginx, Windows...) escribe en un formato
distinto. Si las reglas de detección tuvieran que entender cada formato, serían
inmantenibles. Normalizamos UNA vez en la entrada y las reglas hablan un solo idioma.
"""
from datetime import datetime

from pydantic import BaseModel, Field


class RawLog(BaseModel):
    # POR QUÉ los max_length: la entrada es NO CONFIABLE. Limitar tamaños evita
    # que alguien nos mande 1 GB por request (DoS) o llene la base de datos.
    source: str = Field(..., max_length=64)
    host: str = Field(..., max_length=255)
    message: str = Field(..., max_length=4096)


class Event(BaseModel):
    timestamp: datetime
    host: str
    category: str              # ej. "authentication"
    action: str                # ej. "ssh_login"
    outcome: str               # "success" | "failure"
    source_ip: str | None = None
    user: str | None = None
    process: str | None = None
    raw: str

    def to_ecs(self) -> dict:
        """Representación anidada estilo ECS (así hablan Elastic/OpenSearch)."""
        return {
            "@timestamp": self.timestamp.isoformat(),
            "event": {
                "category": [self.category],
                "action": self.action,
                "outcome": self.outcome,
            },
            "host": {"name": self.host},
            "source": {"ip": self.source_ip},
            "user": {"name": self.user},
            "process": {"name": self.process},
            "message": self.raw,
        }
