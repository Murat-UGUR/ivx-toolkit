import json

from ivx_toolkit.cli import main
from ivx_toolkit.sanitize import sanitize

RAW_XML = """<?xml version="1.0"?>
<alerts appliance="ivx-ank-01.corp.example" version="9.0" msg="extended">
  <alert id="7709" name="MALWARE_OBJECT" severity="MAJR" malicious="yes"
         appliance-id="0025907A1B2C" sensor="nx-dmz-02" sensor-ip="10.20.30.40" vlan="0">
    <explanation><malware-detected>
      <malware name="Trojan.Generic"><md5sum>44d88612fea8a8f36de82e1278abb02f</md5sum></malware>
    </malware-detected>
    <os-changes>connect 8.8.8.8:53 from 192.168.1.15; dns evil.example.net</os-changes>
    </explanation>
    <src><ip>10.20.30.40</ip><port>0</port></src>
    <dst><mac>00:1A:2B:3C:4D:5E</mac><ip>203.0.113.7</ip><port>443</port></dst>
    <occurred>2026-10-15 20:00:00 +0300</occurred>
    <note>submitted by murat.ugur@corp.example from ws-murat.corp.example fe80::1</note>
  </alert>
</alerts>"""


def test_masks_internal_details_and_keeps_iocs():
    out, counts = sanitize(RAW_XML, terms=["corp.example"])
    # environment details are gone
    for secret in (
        "ivx-ank-01",
        "nx-dmz-02",
        "0025907A1B2C",
        "10.20.30.40",
        "192.168.1.15",
        "00:1A:2B:3C:4D:5E",
        "murat.ugur@",
        "ws-murat",
        "corp.example",
        "fe80::1",
    ):
        assert secret not in out, secret
    # sample details and public indicators are kept
    for kept in (
        "Trojan.Generic",
        "44d88612fea8a8f36de82e1278abb02f",
        "8.8.8.8",
        "evil.example.net",
        "2026-10-15 20:00:00 +0300",
        'vlan="0"',
        "<port>443</port>",
    ):
        assert kept in out, kept
    assert counts["mac"] == 1 and counts["email"] == 1


def test_documentation_ranges_are_not_public():
    # 203.0.113.0/24 is a documentation range (not globally routable) -> masked
    out, _ = sanitize("dst 203.0.113.7 and 8.8.4.4")
    assert "203.0.113.7" not in out and "8.8.4.4" in out


def test_consistent_placeholders():
    out, _ = sanitize("a 10.0.0.1 b 10.0.0.2 c 10.0.0.1")
    assert out == "a ip-redacted-1 b ip-redacted-2 c ip-redacted-1"


def test_all_ips_option():
    out, _ = sanitize("8.8.8.8", mask_public_ips=True)
    assert out == "ip-redacted-1"


def test_json_keys():
    raw = json.dumps({"alert": [{"appliance": "ivx-lab-1", "sensorIp": "172.16.5.5", "id": 1}]})
    out, _ = sanitize(raw)
    data = json.loads(out)  # still valid JSON
    assert "ivx-lab-1" not in out and "172.16.5.5" not in out
    assert data["alert"][0]["id"] == 1


def test_timestamps_and_hashes_untouched():
    text = "00:00:00 2026-01-01T10:11:12Z sha256=" + "ab" * 32
    assert sanitize(text)[0] == text


def test_cli_save_raw_parse_and_sanitize(mock_env, tmp_path, capsys):
    sample = tmp_path / "in" / "malware_a.bin"
    sample.parent.mkdir()
    sample.write_bytes(b"x")
    raw_dir = tmp_path / "raw"
    assert (
        main(["submit", str(sample), "--wait", "--interval", "0", "--save-raw", str(raw_dir)]) == 0
    )
    saved = list(raw_dir.iterdir())
    assert len(saved) == 1 and saved[0].suffix == ".xml"

    # offline parse of the saved file
    capsys.readouterr()
    assert main(["parse", str(saved[0]), "-f", "json"]) == 0
    parsed = json.loads(capsys.readouterr().out)
    assert parsed[0]["verdict"] == "malicious"
    assert parsed[0]["submission_id"] == saved[0].stem

    # sanitize writes a .sanitized copy next to the original
    assert main(["sanitize", str(saved[0]), "--mask", "ivx-mock"]) == 0
    clean = saved[0].with_name(f"{saved[0].stem}.sanitized.xml")
    assert clean.exists() and "ivx-mock" not in clean.read_text()


def test_parse_works_without_env(monkeypatch, tmp_path, capsys):
    for var in ("IVX_HOST", "IVX_USER", "IVX_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    f = tmp_path / "123.xml"
    f.write_text(RAW_XML)
    assert main(["parse", str(f)]) == 0
    assert "Trojan.Generic" in capsys.readouterr().out
