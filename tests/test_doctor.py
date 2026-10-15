import socket

from ivx_toolkit import IVXClient
from ivx_toolkit.cli import main
from ivx_toolkit.config import Settings
from ivx_toolkit.doctor import FAIL, PASS, SKIP, run


def _statuses(checks):
    return {c.name: c.status for c in checks}


def test_all_pass_against_mock(settings):
    with IVXClient(settings) as client:
        checks = run(client)
    assert _statuses(checks) == {
        "DNS": PASS,
        "TCP": PASS,
        "TLS": SKIP,  # mock is plain HTTP
        "API login": PASS,
        "API access": PASS,
    }
    login = next(c for c in checks if c.name == "API login")
    assert "/wsapis/common/v2.0.0/auth/login" in login.detail


def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def test_closed_port_stops_early():
    s = Settings(host="127.0.0.1", port=_free_port(), scheme="http", username="a", password="b")
    checks = run(IVXClient(s), timeout=1)
    assert _statuses(checks) == {
        "DNS": PASS,
        "TCP": FAIL,
        "TLS": SKIP,
        "API login": SKIP,
        "API access": SKIP,
    }
    assert "firewall" in next(c for c in checks if c.name == "TCP").hint


def test_bad_credentials_hint(settings):
    settings.password = "wrong"
    checks = run(IVXClient(settings))
    login = next(c for c in checks if c.name == "API login")
    assert login.status == FAIL and "API role" in login.hint
    assert _statuses(checks)["API access"] == SKIP


def test_unresolvable_host():
    s = Settings(host="ivx.invalid", port=443, username="a", password="b")
    checks = run(IVXClient(s), timeout=1)
    assert checks[0].name == "DNS" and checks[0].status == FAIL


def test_doctor_cli(mock_env, capsys):
    assert main(["doctor"]) == 0
    out = capsys.readouterr().out
    assert "[PASS] API access" in out and "All checks passed." in out
