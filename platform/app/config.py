"""Configuración desde variables de entorno.

POR QUÉ: los secretos y umbrales NUNCA van hardcodeados en el código
(12-factor app). Así el mismo contenedor corre en lab, CI y producción.
"""
import os
from dataclasses import dataclass


@dataclass(frozen=True)
class Settings:
    api_key: str
    db_path: str = "/data/soc.db"
    bf_threshold: int = 5      # fallos para considerar fuerza bruta
    bf_window_s: int = 60      # ...dentro de esta ventana de tiempo
    cooldown_s: int = 300      # no repetir la misma alerta para la misma IP
    saf_window_s: int = 600    # ventana para "éxito tras fallos"

    @classmethod
    def from_env(cls) -> "Settings":
        key = os.environ.get("INGEST_API_KEY", "")
        # Fallar rápido y ruidoso es mejor que arrancar inseguro.
        if len(key) < 16:
            raise RuntimeError("INGEST_API_KEY ausente o demasiado corta (mín. 16 caracteres)")
        return cls(
            api_key=key,
            db_path=os.environ.get("DB_PATH", "/data/soc.db"),
            bf_threshold=int(os.environ.get("BF_THRESHOLD", "5")),
            bf_window_s=int(os.environ.get("BF_WINDOW_S", "60")),
            cooldown_s=int(os.environ.get("COOLDOWN_S", "300")),
            saf_window_s=int(os.environ.get("SAF_WINDOW_S", "600")),
        )
