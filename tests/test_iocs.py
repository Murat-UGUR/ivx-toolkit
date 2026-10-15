import csv
import io
import json
import re
from datetime import datetime, timezone

from ivx_toolkit.cli import main
from ivx_toolkit.iocs import collect, to_csv, to_stix
from ivx_toolkit.results import Alert, AnalysisResult, Malware

SHA_A = "a" * 64
SHA_B = "b" * 64
MD5_B = "c" * 32


def _malicious(**kw):
    alert = Alert(
        id="1",
        malicious="yes",
        malware=[Malware(name="Trojan.X", md5=MD5_B, sha256=SHA_B.upper())],
    )
    return AnalysisResult(submission_id="7", status="Done", alerts=[alert], **kw)


def test_collect_only_malicious_and_dedup():
    clean = AnalysisResult(submission_id="8", status="Done", target_sha256="d" * 64)
    results = [_malicious(target_sha256=SHA_A), _malicious(target_sha256=SHA_A), clean]
    iocs = collect(results)
    assert [(i.type, i.value) for i in iocs] == [
        ("sha256", SHA_A),
        ("sha256", SHA_B),  # normalised to lower case
        ("md5", MD5_B),
    ]


def test_invalid_hashes_are_dropped():
    r = _malicious()
    r.alerts[0].malware.append(Malware(name="Y", md5="not-a-hash", sha256="1234"))
    assert {i.value for i in collect([r])} == {SHA_B, MD5_B}


def test_url_iocs():
    r = _malicious(target_kind="url", target_urls=["http://evil.example/a'b"])
    assert ("url", "http://evil.example/a'b") in [(i.type, i.value) for i in collect([r])]


def test_csv_export():
    rows = list(csv.DictReader(io.StringIO(to_csv([_malicious(target_sha256=SHA_A)]))))
    assert rows[0] == {
        "type": "sha256",
        "value": SHA_A,
        "verdict": "malicious",
        "malware": "Trojan.X",
        "submission_id": "7",
    }


def test_stix_bundle_structure_and_stable_ids():
    now = datetime(2026, 10, 15, tzinfo=timezone.utc)
    r = _malicious(target_sha256=SHA_A, target_urls=["http://evil.example/a'b"])
    b1, b2 = json.loads(to_stix([r], now)), json.loads(to_stix([r], now))
    assert b1["type"] == "bundle"
    by_type = {}
    for o in b1["objects"]:
        by_type.setdefault(o["type"], []).append(o)
        assert o["type"] == "bundle" or o["spec_version"] == "2.1"
    assert len(by_type["identity"]) == 1
    assert len(by_type["malware"]) == 1 and by_type["malware"][0]["name"] == "Trojan.X"
    patterns = sorted(i["pattern"] for i in by_type["indicator"])
    assert f"[file:hashes.'SHA-256' = '{SHA_A}']" in patterns
    assert f"[file:hashes.MD5 = '{MD5_B}']" in patterns
    assert "[url:value = 'http://evil.example/a\\'b']" in patterns  # quote escaped
    # every indicator "indicates" the malware
    assert len(by_type["relationship"]) == len(by_type["indicator"])
    # object IDs are deterministic across exports (bundle ID is not)
    assert [o["id"] for o in b1["objects"]] == [o["id"] for o in b2["objects"]]
    uuid_re = re.compile(r"^[a-z-]+--[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$")
    assert all(uuid_re.match(o["id"]) for o in b1["objects"])


def test_empty_when_nothing_malicious():
    clean = AnalysisResult(submission_id="1", status="Done")
    assert collect([clean]) == []
    objs = json.loads(to_stix([clean]))["objects"]
    assert [o["type"] for o in objs] == ["identity"]


def test_cli_submit_exports_stix(mock_env, tmp_path):
    (tmp_path / "malware_x.bin").write_bytes(b"payload")
    (tmp_path / "clean.txt").write_text("hello")
    out = tmp_path / "iocs.json"
    rc = main(["submit", str(tmp_path), "--wait", "--interval", "0", "-f", "stix", "-o", str(out)])
    assert rc == 0
    indicators = [o for o in json.loads(out.read_text())["objects"] if o["type"] == "indicator"]
    patterns = " ".join(i["pattern"] for i in indicators)
    import hashlib

    assert hashlib.sha256(b"payload").hexdigest() in patterns  # submitted sample's own hash
    assert hashlib.sha256(b"hello").hexdigest() not in patterns  # clean file excluded
