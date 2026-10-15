import json
import os
from datetime import datetime, timedelta, timezone

from ivx_toolkit.cli import main
from ivx_toolkit.history import History

SHA = "ab" * 32


def test_record_lookup_and_age(tmp_path):
    with History(tmp_path / "h.db") as h:
        old = datetime.now(timezone.utc) - timedelta(days=40)
        h.record(SHA, "/secret/path/a.exe", "IVX.lab", "1", "malicious", when=old)
        assert h.lookup(SHA, "ivx.lab", max_age_days=30) is None  # too old
        h.record(SHA.upper(), "a.exe", "ivx.lab", "2", "no-detection")
        hit = h.lookup(SHA, "IVX.LAB", max_age_days=30)
        assert hit and hit.submission_id == "2" and hit.verdict == "no-detection"
        assert h.lookup(SHA, "other-ivx", max_age_days=30) is None  # per appliance
        # only the base name is stored, never the full path
        assert {e.file_name for e in h.recent()} == {"a.exe"}


def test_errors_and_pending_are_not_cached(tmp_path):
    with History(tmp_path / "h.db") as h:
        h.record(SHA, "a.exe", "ivx", "1", "error")
        h.record(SHA, "a.exe", "ivx", "2", "pending")
        assert h.recent() == []


def test_db_is_private_on_posix(tmp_path):
    path = tmp_path / "h.db"
    History(path).close()
    if os.name == "posix":
        assert oct(path.stat().st_mode & 0o777) == "0o600"


def _submit(folder, *extra):
    return main(["submit", str(folder), "--wait", "--interval", "0", *extra])


def test_skip_known_reuses_result_with_full_detail(mock_env, tmp_path, capsys):
    sample = tmp_path / "malware_k.bin"
    sample.write_bytes(b"known payload")
    assert _submit(sample) == 0
    first = capsys.readouterr()
    assert "submitted" in first.err

    out = tmp_path / "r.json"
    assert _submit(sample, "--skip-known", "-f", "json", "-o", str(out)) == 0
    second = capsys.readouterr()
    assert "not resubmitted" in second.err and "submitted " not in second.err
    data = json.loads(out.read_text())[0]
    assert data["verdict"] == "malicious"
    assert data["cached_from"]
    assert data["malware_names"] == ["Mock.Generic.Trojan"]  # re-parsed from stored raw
    assert data["target_sha256"]


def test_without_skip_known_files_are_resubmitted(mock_env, tmp_path, capsys):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"x")
    _submit(sample)
    capsys.readouterr()
    _submit(sample)
    assert "submitted" in capsys.readouterr().err


def test_no_history_writes_nothing(mock_env, tmp_path, capsys):
    sample = tmp_path / "a.bin"
    sample.write_bytes(b"x")
    _submit(sample, "--no-history")
    capsys.readouterr()
    assert main(["history"]) == 0
    assert "No entries" in capsys.readouterr().err
    assert _submit(sample, "--no-history", "--skip-known") == 2


def test_history_command(mock_env, tmp_path, capsys):
    sample = tmp_path / "eicar.txt"
    sample.write_bytes(b"e")
    _submit(sample)
    capsys.readouterr()
    assert main(["history"]) == 0
    table = capsys.readouterr().out
    assert "eicar.txt" in table and "malicious" in table
    assert main(["history", "-f", "json"]) == 0
    entries = json.loads(capsys.readouterr().out)
    assert entries[0]["raw"] is None  # raw responses are not dumped by `history`
