import json
from pathlib import Path

from ivx_toolkit.cli import main


def test_check(mock_env, capsys):
    assert main(["check"]) == 0
    assert "OK" in capsys.readouterr().out


def test_submit_folder_wait_json(mock_env, tmp_path, capsys):
    (tmp_path / "eicar.com").write_text("sample")
    (tmp_path / "readme.txt").write_text("hello")
    report = tmp_path / "out"
    report.mkdir()
    out = report / "r.json"
    rc = main(
        [
            "submit",
            str(tmp_path),
            "--wait",
            "--interval",
            "0",
            "-f",
            "json",
            "-o",
            str(out),
            "--fail-on-malicious",
        ]
    )
    data = json.loads(out.read_text())
    verdicts = {Path(d["target"]).name: d["verdict"] for d in data}
    assert verdicts == {"eicar.com": "malicious", "readme.txt": "no-detection"}
    assert rc == 1  # --fail-on-malicious


def test_submit_no_wait_prints_ids(mock_env, tmp_path, capsys):
    f = tmp_path / "a.bin"
    f.write_bytes(b"1")
    assert main(["submit", str(f)]) == 0
    line = capsys.readouterr().out.strip()
    sid, target = line.split("\t")
    assert sid.isdigit() and target.endswith("a.bin")


def test_status_and_results(mock_env, tmp_path, capsys):
    f = tmp_path / "malware.exe"
    f.write_bytes(b"1")
    main(["submit", str(f)])
    sid = capsys.readouterr().out.split("\t")[0]
    assert main(["status", sid]) == 0
    assert main(["results", sid, "-f", "csv"]) == 0
    assert "malicious" in capsys.readouterr().out


def test_missing_host(monkeypatch, capsys):
    monkeypatch.delenv("IVX_HOST", raising=False)
    assert main(["check"]) == 2
    assert "IVX_HOST" in capsys.readouterr().err


def test_csv_output_has_clean_line_endings(mock_env, tmp_path):
    f = tmp_path / "malware.exe"
    f.write_bytes(b"1")
    out = tmp_path / "r.csv"
    main(["submit", str(f), "--wait", "--interval", "0", "-f", "csv", "-o", str(out)])
    raw = out.read_bytes()
    assert b"\r\r\n" not in raw and raw.count(b"\r\n") == 2  # header + one row
