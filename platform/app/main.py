"""API de la plataforma: ingesta + consulta de eventos y alertas."""
import logging
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, Query

from .config import Settings
from .detection import DetectionEngine, default_rules
from .models import RawLog
from .normalizer import normalize
from .storage import Store

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger("mini-soc")


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_env()
    store = Store(settings.db_path)
    engine = DetectionEngine(default_rules(settings))
    app = FastAPI(title="mini-soc", version="0.1.0")

    def require_key(x_api_key: str = Header(default="")) -> None:
        # compare_digest: comparación en tiempo constante (evita timing attacks).
        if not secrets.compare_digest(x_api_key.encode(), settings.api_key.encode()):
            raise HTTPException(status_code=401, detail="invalid api key")

    @app.get("/healthz")
    def healthz():
        return {"status": "ok"}

    @app.post("/ingest", dependencies=[Depends(require_key)])
    def ingest(raw: RawLog):
        event = normalize(raw)
        if event is None:
            return {"status": "ignored"}
        # Todo el ciclo guardar -> evaluar -> alertar es atómico (evita alertas duplicadas
        # cuando llegan varias requests a la vez).
        with store.lock:
            store.add_event(event)
            alerts = engine.process(event, store)
            for a in alerts:
                store.add_alert(a)
                log.warning("ALERTA [%s/%s] %s | ip=%s | %s | %s",
                            a.rule_id, a.severity, a.title, a.source_ip, a.mitre_technique, a.description)
        return {"status": "ok", "alerts": [a.rule_id for a in alerts]}

    @app.get("/events", dependencies=[Depends(require_key)])
    def events(limit: int = Query(50, ge=1, le=500)):
        return store.list_events(limit)

    @app.get("/alerts", dependencies=[Depends(require_key)])
    def alerts(limit: int = Query(50, ge=1, le=500)):
        return store.list_alerts(limit)

    return app
