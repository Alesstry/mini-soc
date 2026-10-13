"""Motor de detección.

Cada regla = una hipótesis sobre cómo se ve un ataque en los datos,
etiquetada con la técnica MITRE ATT&CK que cubre.

POR QUÉ umbral + ventana de tiempo: un solo "Failed password" es ruido
(alguien se equivocó). 5 en 60 s desde la misma IP es un patrón automatizado.
Ese equilibrio (sensibilidad vs. falsos positivos) es el trabajo diario de un
detection engineer. Lo medirás en la Fase 6.

POR QUÉ cooldown: sin él, un ataque de 1000 intentos genera 1000 alertas y el
analista deja de leerlas ("alert fatigue").

POR QUÉ usamos el tiempo del EVENTO y no el del reloj: así las pruebas son
deterministas y funciona igual si los logs llegan con retraso.
"""
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Protocol

from .models import Event
from .storage import Store


@dataclass
class Alert:
    rule_id: str
    title: str
    severity: str            # low | medium | high | critical
    mitre_tactic: str
    mitre_technique: str
    source_ip: str
    user: str | None
    ts: float
    description: str
    evidence: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["@timestamp"] = datetime.fromtimestamp(self.ts, tz=timezone.utc).isoformat()
        return d


class Rule(Protocol):
    id: str

    def evaluate(self, event: Event, store: Store) -> Alert | None: ...


class SshBruteForce:
    """MITRE T1110.001 - Brute Force: Password Guessing (TA0006 Credential Access)."""
    id = "SOC-001"

    def __init__(self, threshold: int, window_s: int, cooldown_s: int):
        self.threshold, self.window_s, self.cooldown_s = threshold, window_s, cooldown_s

    def evaluate(self, event: Event, store: Store) -> Alert | None:
        if not (event.action == "ssh_login" and event.outcome == "failure" and event.source_ip):
            return None
        ts = event.timestamp.timestamp()
        n = store.count_events("ssh_login", "failure", event.source_ip, ts - self.window_s, ts)
        if n < self.threshold:
            return None
        last = store.last_alert_ts(self.id, event.source_ip)
        if last is not None and ts - last < self.cooldown_s:
            return None
        return Alert(
            rule_id=self.id,
            title="Posible fuerza bruta SSH",
            severity="high",
            mitre_tactic="TA0006 Credential Access",
            mitre_technique="T1110.001 Password Guessing",
            source_ip=event.source_ip,
            user=event.user,
            ts=ts,
            description=f"{n} fallos de login SSH desde {event.source_ip} en {self.window_s}s",
            evidence={"failures": n, "window_s": self.window_s},
        )


class SshSuccessAfterFailures:
    """MITRE T1078 - Valid Accounts (TA0001 Initial Access).

    La alerta más importante del lab: el atacante ADIVINÓ una contraseña.
    """
    id = "SOC-002"

    def __init__(self, threshold: int, window_s: int, cooldown_s: int):
        self.threshold, self.window_s, self.cooldown_s = threshold, window_s, cooldown_s

    def evaluate(self, event: Event, store: Store) -> Alert | None:
        if not (event.action == "ssh_login" and event.outcome == "success" and event.source_ip):
            return None
        ts = event.timestamp.timestamp()
        n = store.count_events("ssh_login", "failure", event.source_ip, ts - self.window_s, ts)
        if n < self.threshold:
            return None
        last = store.last_alert_ts(self.id, event.source_ip)
        if last is not None and ts - last < self.cooldown_s:
            return None
        return Alert(
            rule_id=self.id,
            title="Login SSH exitoso tras múltiples fallos (posible cuenta comprometida)",
            severity="critical",
            mitre_tactic="TA0001 Initial Access",
            mitre_technique="T1078 Valid Accounts",
            source_ip=event.source_ip,
            user=event.user,
            ts=ts,
            description=f"Login exitoso de '{event.user}' desde {event.source_ip} tras {n} fallos en {self.window_s}s",
            evidence={"prior_failures": n, "window_s": self.window_s},
        )


class DetectionEngine:
    def __init__(self, rules: list[Rule]):
        self.rules = rules

    def process(self, event: Event, store: Store) -> list[Alert]:
        alerts = []
        for rule in self.rules:
            alert = rule.evaluate(event, store)
            if alert:
                alerts.append(alert)
        return alerts


def default_rules(settings) -> list[Rule]:
    return [
        SshBruteForce(settings.bf_threshold, settings.bf_window_s, settings.cooldown_s),
        SshSuccessAfterFailures(settings.bf_threshold, settings.saf_window_s, settings.cooldown_s),
    ]
