import pytest
from fastapi.testclient import TestClient

from app.config import Settings
from app.main import create_app

KEY = "k" * 32


@pytest.fixture
def client(tmp_path):
    app = create_app(Settings(api_key=KEY, db_path=str(tmp_path / "t.db")))
    return TestClient(app)


def line(i, outcome="Failed", user="root"):
    return (f"2026-10-13T12:00:{i:02d}.000000+00:00 victim sshd[{100+i}]: "
            f"{outcome} password for {user} from 172.20.0.5 port {40000+i} ssh2")


def post(client, msg, key=KEY):
    return client.post("/ingest", json={"source": "linux-auth", "host": "victim", "message": msg},
                       headers={"X-API-Key": key})


def test_requires_api_key(client):
    assert post(client, line(0), key="wrong").status_code == 401
    assert client.get("/alerts").status_code == 401


def test_healthz_is_public(client):
    assert client.get("/healthz").status_code == 200


def test_end_to_end_bruteforce_then_compromise(client):
    for i in range(5):
        assert post(client, line(i)).status_code == 200
    assert post(client, line(10, "Accepted", "deploy")).json()["alerts"] == ["SOC-002"]

    alerts = client.get("/alerts", headers={"X-API-Key": KEY}).json()
    assert {a["rule_id"] for a in alerts} == {"SOC-001", "SOC-002"}


def test_rejects_oversized_message(client):
    assert post(client, "A" * 5000).status_code == 422
