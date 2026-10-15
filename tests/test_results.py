import json

from ivx_toolkit.report import render
from ivx_toolkit.results import AnalysisResult, parse_results

XML = """<?xml version="1.0"?>
<alerts xmlns="http://www.fireeye.com/alert/2011/AlertSchema" appliance="x" msg="concise">
  <alert id="1" name="MALWARE_OBJECT" severity="CRIT" malicious="yes">
    <explanation><malware-detected>
      <malware name="Trojan.A"><md5sum>aa</md5sum><sha256>bb</sha256></malware>
      <malware name="Trojan.B"/>
    </malware-detected></explanation>
    <occurred>2026-01-01</occurred>
  </alert>
  <alert id="2" name="DOMAIN_MATCH" severity="MINR" malicious="no"/>
</alerts>"""

JSON = {
    "alert": [
        {
            "id": 5,
            "name": "MALWARE_OBJECT",
            "severity": "MAJR",
            "malicious": "yes",
            "explanation": {
                "malwareDetected": {"malware": [{"name": "Mal.X", "md5Sum": "cc", "sha256": "dd"}]}
            },
        }
    ]
}


def test_parse_xml():
    r = parse_results("1", "application/xml", XML, target="f.exe")
    assert r.verdict == "malicious"
    assert r.max_severity == "CRIT"
    assert r.malware_names == ["Trojan.A", "Trojan.B"]
    assert r.alerts[0].malware[0].md5 == "aa"
    assert r.alerts[0].occurred == "2026-01-01"


def test_parse_json():
    r = parse_results("5", "application/json", json.dumps(JSON))
    assert r.verdict == "malicious"
    assert r.alerts[0].malware[0].md5 == "cc"


def test_empty_and_suspicious():
    assert parse_results("1", "application/xml", "").verdict == "no-detection"
    xml = '<alerts><alert id="3" name="X" severity="MINR" malicious="no"/></alerts>'
    assert parse_results("3", "application/xml", xml).verdict == "suspicious"


def test_unparseable():
    r = parse_results("1", "application/xml", "<alerts><broken")
    assert r.verdict == "error"


def test_render_formats():
    results = [
        parse_results("1", "application/xml", XML, target="<script>.exe"),
        AnalysisResult(submission_id="2", target="b", error="timeout"),
    ]
    table = render(results, "table")
    assert "Trojan.A" in table and "error" in table
    assert json.loads(render(results, "json"))[0]["verdict"] == "malicious"
    assert render(results, "csv").splitlines()[0].startswith("submission_id")
    html = render(results, "html")
    assert "&lt;script&gt;.exe" in html and "<script>.exe" not in html
