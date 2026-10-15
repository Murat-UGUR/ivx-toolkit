"""HTTPS behaviour against the mock server with a throw-away self-signed certificate.

Needs the `openssl` binary to create the certificate; the tests are no-ops without it.
"""

import shutil
import subprocess
import threading

import pytest

from ivx_toolkit import IVXClient, IVXError
from ivx_toolkit.config import Settings
from ivx_toolkit.doctor import FAIL, PASS, WARN, run
from ivx_toolkit.mock_server import serve

HAVE_OPENSSL = shutil.which("openssl") is not None


@pytest.fixture()
def tls_mock(tmp_path):
    if not HAVE_OPENSSL:
        yield None
        return
    cert, key = tmp_path / "cert.pem", tmp_path / "key.pem"
    try:
        subprocess.run(
            [
                "openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
                "-keyout", str(key), "-out", str(cert), "-days", "365",
                "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost",
            ],
            check=True,
            capture_output=True,
        )  # fmt: skip
    except (OSError, subprocess.CalledProcessError):
        yield None  # old or unusual openssl build: skip these tests
        return
    server = serve("127.0.0.1", 0, str(cert), str(key))
    threading.Thread(target=server.serve_forever, daemon=True).start()
    yield server.server_address[1], str(cert)
    server.shutdown()
    server.server_close()


def _settings(port, verify):
    return Settings(
        host="localhost", port=port, username="admin", password="admin", verify_tls=verify
    )


def test_untrusted_certificate_is_rejected(tls_mock):
    if tls_mock is None:
        return
    port, _ = tls_mock
    with pytest.raises(IVXError):
        IVXClient(_settings(port, True)).login()
    checks = run(IVXClient(_settings(port, True)))
    tls = next(c for c in checks if c.name == "TLS")
    assert tls.status == FAIL and "IVX_CA_BUNDLE" in tls.hint


def test_ca_bundle_wins_over_requests_env(tls_mock, monkeypatch, tmp_path):
    """Regression: REQUESTS_CA_BUNDLE in the environment must not override IVX_CA_BUNDLE."""
    if tls_mock is None:
        return
    port, cert = tls_mock
    other = tmp_path / "unrelated-ca.pem"
    other.write_text("")
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(other))
    monkeypatch.setenv("CURL_CA_BUNDLE", str(other))
    checks = run(IVXClient(_settings(port, cert)))
    statuses = {c.name: c.status for c in checks}
    assert statuses["TLS"] == PASS
    assert statuses["API login"] == PASS and statuses["API access"] == PASS


def test_insecure_wins_over_requests_env(tls_mock, monkeypatch, tmp_path):
    if tls_mock is None:
        return
    port, _ = tls_mock
    monkeypatch.setenv("REQUESTS_CA_BUNDLE", str(tmp_path / "missing.pem"))
    client = IVXClient(_settings(port, False))
    assert client.login()
    checks = run(client)
    assert {c.name: c.status for c in checks}["TLS"] == WARN
