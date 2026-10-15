import threading

import pytest

from ivx_toolkit.config import Settings
from ivx_toolkit.mock_server import serve


@pytest.fixture()
def mock_ivx():
    server = serve("127.0.0.1", 0)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


@pytest.fixture()
def settings(mock_ivx):
    return Settings(
        host="127.0.0.1", port=mock_ivx, scheme="http", username="admin", password="admin"
    )


@pytest.fixture()
def mock_env(mock_ivx, monkeypatch, tmp_path_factory):
    # A separate directory: never the real history, and never inside a folder a test submits.
    history = tmp_path_factory.mktemp("history") / "history.db"
    monkeypatch.setenv("IVX_HISTORY", str(history))
    monkeypatch.setenv("IVX_HOST", "127.0.0.1")
    monkeypatch.setenv("IVX_PORT", str(mock_ivx))
    monkeypatch.setenv("IVX_SCHEME", "http")
    monkeypatch.setenv("IVX_USER", "admin")
    monkeypatch.setenv("IVX_PASSWORD", "admin")
