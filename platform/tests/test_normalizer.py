from app.models import RawLog
from app.normalizer import normalize


def raw(msg):
    return RawLog(source="linux-auth", host="victim", message=msg)


def test_failed_password():
    e = normalize(raw("2026-10-13T12:00:00.123456+00:00 victim sshd[123]: Failed password for root from 172.20.0.5 port 40000 ssh2"))
    assert e.action == "ssh_login" and e.outcome == "failure"
    assert e.source_ip == "172.20.0.5" and e.user == "root"


def test_failed_password_invalid_user():
    e = normalize(raw("2026-10-13T12:00:00+00:00 victim sshd[1]: Failed password for invalid user admin from 10.0.0.9 port 22 ssh2"))
    assert e.user == "admin" and e.source_ip == "10.0.0.9"


def test_accepted_password():
    e = normalize(raw("2026-10-13T12:00:09+00:00 victim sshd[2]: Accepted password for deploy from 172.20.0.5 port 4444 ssh2"))
    assert e.outcome == "success" and e.user == "deploy"


def test_ignores_other_processes_and_garbage():
    assert normalize(raw("2026-10-13T12:00:00+00:00 victim cron[1]: hello")) is None
    assert normalize(raw("esto no es syslog")) is None


def test_log_injection_does_not_spoof_ip():
    # El atacante intenta colar una IP falsa dentro del nombre de usuario.
    e = normalize(raw("2026-10-13T12:00:00+00:00 victim sshd[1]: Failed password for invalid user x from 1.1.1.1 port 1 from 9.9.9.9 port 2 ssh2"))
    assert e.source_ip == "1.1.1.1"
