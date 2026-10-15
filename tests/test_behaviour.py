import hashlib
import json

from ivx_toolkit.cli import main
from ivx_toolkit.report import render
from ivx_toolkit.results import parse_results

# Shaped after the documented JSON alert response (explanation > osChanges).
EXTENDED_JSON = {
    "alert": [
        {
            "id": 99,
            "name": "MALWARE_OBJECT",
            "severity": "CRIT",
            "malicious": "yes",
            "explanation": {
                "malwareDetected": {"malware": [{"name": "Trojan.X", "md5Sum": "a" * 32}]},
                "osChanges": [
                    {
                        "malicious-alert": [
                            {"classtype": "Persistence", "display-msg": "Adds Run key"},
                            {"classtype": "Persistence", "display-msg": "Adds Run key"},
                        ],
                        "process": {
                            "mode": "started",
                            "value": "C:\\\\Temp\\\\x.exe",
                            "cmdline": "x.exe -s",
                            "pid": 10,
                            "ppid": 4,
                            "parentname": "explorer.exe",
                            "md5sum": "B" * 32,
                        },
                        "process_informational": [{"cmdline": "cmd.exe /c whoami", "pid": 11}],
                        "file_informational": [
                            {"mode": "created", "value": "C:\\\\x\\\\a.dll", "md5sum": "c" * 32},
                            {"mode": "deleted", "value": "C:\\\\x\\\\b.tmp"},
                        ],
                    }
                ],
            },
        }
    ]
}

EXTENDED_XML = """<alerts><alert id="1" name="MALWARE_OBJECT" severity="MAJR" malicious="yes">
<explanation>
  <malware-detected><malware name="Trojan.Y"/></malware-detected>
  <os-changes>
    <malicious-alert classtype="Evasion">
      <display-msg>Sleeps to evade</display-msg>
    </malicious-alert>
    <process mode="started"><value>C:\\a.exe</value><cmdline>a.exe</cmdline><pid>7</pid></process>
    <file_informational mode="created"><value>C:\\b.dll</value><sha256sum>DD</sha256sum>
    </file_informational>
  </os-changes>
</explanation></alert></alerts>"""


def test_json_behaviour():
    r = parse_results("99", "application/json", json.dumps(EXTENDED_JSON))
    a = r.alerts[0]
    assert [s.message for s in a.signatures] == ["Adds Run key"]  # de-duplicated
    assert {p.cmdline for p in a.processes} == {"x.exe -s", "cmd.exe /c whoami"}
    started = next(p for p in a.processes if p.cmdline == "x.exe -s")
    assert (started.pid, started.parent, started.md5) == ("10", "explorer.exe", "b" * 32)
    assert [(f.mode, f.path) for f in a.files] == [
        ("created", "C:\\\\x\\\\a.dll"),
        ("deleted", "C:\\\\x\\\\b.tmp"),
    ]
    assert r.has_behaviour


def test_xml_behaviour():
    r = parse_results("1", "application/xml", EXTENDED_XML)
    a = r.alerts[0]
    assert a.signatures[0].classtype == "Evasion" and a.signatures[0].message == "Sleeps to evade"
    assert a.processes[0].cmdline == "a.exe" and a.processes[0].pid == "7"
    assert a.files[0].path == "C:\\b.dll" and a.files[0].sha256 == "dd"
    assert r.malware_names == ["Trojan.Y"]


def test_no_behaviour_without_os_changes():
    xml = (
        '<alerts><alert id="1" malicious="yes">'
        "<process><cmdline>x</cmdline></process></alert></alerts>"
    )
    r = parse_results("1", "application/xml", xml)
    assert not r.has_behaviour  # process outside os-changes is ignored


def test_html_and_json_include_behaviour():
    r = parse_results("99", "application/json", json.dumps(EXTENDED_JSON))
    html = render([r], "html")
    assert "Behaviour" in html and "cmd.exe /c whoami" in html and "Adds Run key" in html
    data = json.loads(render([r], "json"))[0]
    assert data["alerts"][0]["signatures"][0]["classtype"] == "Persistence"


def test_extended_results_end_to_end(mock_env, tmp_path):
    f = tmp_path / "malware_ext.bin"
    f.write_bytes(b"x")
    out = tmp_path / "r.json"
    rc = main(
        ["submit", str(f), "--wait", "--interval", "0", "--info-level", "extended"]
        + ["-f", "json", "-o", str(out)]
    )
    assert rc == 0
    alert = json.loads(out.read_text())[0]["alerts"][0]
    assert alert["signatures"][0]["message"] == "Adds a Run key for persistence"
    assert alert["processes"][0]["cmdline"] == "dropper.exe /silent"
    assert alert["files"][0]["path"].endswith("payload.dll")


def test_lookup_by_file_and_md5(mock_env, tmp_path, capsys):
    bad = tmp_path / "malware_l.bin"
    bad.write_bytes(b"lookup me")
    clean = tmp_path / "other.bin"
    clean.write_bytes(b"never submitted")
    main(["submit", str(bad), "--wait", "--interval", "0"])
    capsys.readouterr()

    assert main(["lookup", str(bad), str(clean), "-f", "json"]) == 0
    rows = json.loads(capsys.readouterr().out)
    assert [r["result"] for r in rows] == ["known-malicious", "no-alerts"]
    assert rows[0]["malware"] == ["Mock.Generic.Trojan"]

    md5 = hashlib.md5(b"lookup me").hexdigest()
    assert main(["lookup", md5, "--fail-on-malicious"]) == 1
    captured = capsys.readouterr()
    assert "known-malicious" in captured.out and "not that the file is clean" in captured.err


def test_lookup_rejects_sha256_and_garbage(mock_env, capsys):
    assert main(["lookup", "ab" * 32]) == 2
    assert "MD5 only" in capsys.readouterr().err
    assert main(["lookup", "not-a-hash"]) == 2
