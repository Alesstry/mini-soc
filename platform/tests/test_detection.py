from datetime import datetime, timezone

import pytest

from app.config import Settings
from app.detection import DetectionEngine, default_rules
from app.models import Event
from app.storage import Store

T0 = datetime(2026, 10, 13, 12, 0, 0, tzinfo=timezone.utc).timestamp()


@pytest.fixture
def env(tmp_path):
    settings = Settings(api_key="k" * 32, db_path=str(tmp_path / "t.db"))
    return Store(settings.db_path), DetectionEngine(default_rules(settings))


def ev(offset, outcome="failure", ip="172.20.0.5", user="root"):
    return Event(
        timestamp=datetime.fromtimestamp(T0 + offset, tz=timezone.utc),
        host="victim", category="authentication", action="ssh_login",
        outcome=outcome, source_ip=ip, user=user, process="sshd", raw="x",
    )


def feed(store, engine, event):
    store.add_event(event)
    alerts = engine.process(event, store)
    for a in alerts:
        store.add_alert(a)
    return alerts


def test_bruteforce_fires_on_fifth_failure_only(env):
    store, engine = env
    results = [feed(store, engine, ev(i)) for i in range(5)]
    assert [len(r) for r in results] == [0, 0, 0, 0, 1]
    assert results[4][0].rule_id == "SOC-001"
    assert results[4][0].mitre_technique.startswith("T1110.001")


def test_cooldown_prevents_alert_flood(env):
    store, engine = env
    for i in range(5):
        feed(store, engine, ev(i))
    assert feed(store, engine, ev(6)) == []


def test_slow_failures_do_not_alert(env):
    store, engine = env
    # 1 fallo cada 30 s: nunca hay 5 dentro de 60 s.
    assert all(feed(store, engine, ev(i * 30)) == [] for i in range(10))


def test_failures_from_different_ips_not_mixed(env):
    store, engine = env
    for i in range(4):
        assert feed(store, engine, ev(i, ip=f"10.0.0.{i}")) == []


def test_success_after_failures_is_critical(env):
    store, engine = env
    for i in range(5):
        feed(store, engine, ev(i))
    alerts = feed(store, engine, ev(10, outcome="success", user="deploy"))
    assert [a.rule_id for a in alerts] == ["SOC-002"]
    assert alerts[0].severity == "critical"


def test_normal_success_does_not_alert(env):
    store, engine = env
    assert feed(store, engine, ev(0, outcome="success", user="analyst")) == []
