"""Normalise IVX analysis results (XML or JSON) into a single, simple structure.

The parser is deliberately tolerant: element/key names follow the vendor
documentation (alerts > alert > explanation > malware-detected > malware),
but namespaces, casing and nesting are not assumed to be exact.
"""

from __future__ import annotations

import json
import xml.etree.ElementTree as ET
from dataclasses import asdict, dataclass, field
from typing import Any

SEVERITY_ORDER = {
    "minr": 1,
    "minor": 1,
    "low": 1,
    "majr": 2,
    "major": 2,
    "medium": 2,
    "crit": 3,
    "critical": 3,
    "high": 3,
}


@dataclass
class Malware:
    name: str = ""
    md5: str = ""
    sha256: str = ""


@dataclass
class Alert:
    id: str = ""
    name: str = ""
    severity: str = ""
    malicious: str = ""
    occurred: str = ""
    malware: list[Malware] = field(default_factory=list)


@dataclass
class AnalysisResult:
    submission_id: str
    target: str = ""
    status: str = ""
    alerts: list[Alert] = field(default_factory=list)
    error: str = ""
    target_kind: str = ""  # "file", "url" or "" (unknown, e.g. `ivx results <id>`)
    target_sha256: str = ""  # sha256 of the submitted file, computed locally
    target_urls: list[str] = field(default_factory=list)

    @property
    def verdict(self) -> str:
        if self.error:
            return "error"
        if self.status and self.status.lower() not in {"done", "completed", "complete"}:
            return "pending"
        if any(a.malicious.lower() in {"yes", "true", "1"} or a.malware for a in self.alerts):
            return "malicious"
        if self.alerts:
            return "suspicious"
        return "no-detection"

    @property
    def max_severity(self) -> str:
        best, rank = "", 0
        for a in self.alerts:
            r = SEVERITY_ORDER.get(a.severity.lower(), 0)
            if r > rank:
                best, rank = a.severity, r
        return best

    @property
    def malware_names(self) -> list[str]:
        names: list[str] = []
        for a in self.alerts:
            for m in a.malware:
                if m.name and m.name not in names:
                    names.append(m.name)
        return names

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data.update(
            verdict=self.verdict, max_severity=self.max_severity, malware_names=self.malware_names
        )
        return data


# --------------------------------------------------------------------------- XML
def _local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].lower()


def _child_text(elem: ET.Element, *names: str) -> str:
    wanted = {n.lower() for n in names}
    for child in elem.iter():
        if _local(child.tag) in wanted and child.text:
            return child.text.strip()
    return ""


def _parse_xml(body: str) -> list[Alert]:
    root = ET.fromstring(body)
    alerts: list[Alert] = []
    for elem in root.iter():
        if _local(elem.tag) != "alert":
            continue
        attrs = {k.lower(): v for k, v in elem.attrib.items()}
        alert = Alert(
            id=attrs.get("id", ""),
            name=attrs.get("name", ""),
            severity=attrs.get("severity", ""),
            malicious=attrs.get("malicious", ""),
            occurred=_child_text(elem, "occurred"),
        )
        for mw in elem.iter():
            if _local(mw.tag) == "malware":
                alert.malware.append(
                    Malware(
                        name=mw.attrib.get("name", ""),
                        md5=_child_text(mw, "md5sum", "md5"),
                        sha256=_child_text(mw, "sha256"),
                    )
                )
        alerts.append(alert)
    return alerts


# -------------------------------------------------------------------------- JSON
def _norm_keys(d: dict) -> dict:
    return {str(k).lower().replace("-", "").replace("_", ""): v for k, v in d.items()}


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _find_malware(node: Any) -> list[Malware]:
    found: list[Malware] = []
    if isinstance(node, dict):
        for key, value in node.items():
            if str(key).lower() == "malware":
                for m in _as_list(value):
                    if isinstance(m, dict):
                        n = _norm_keys(m)
                        found.append(
                            Malware(
                                name=str(n.get("name", "")),
                                md5=str(n.get("md5sum", n.get("md5", ""))),
                                sha256=str(n.get("sha256", "")),
                            )
                        )
            else:
                found.extend(_find_malware(value))
    elif isinstance(node, list):
        for item in node:
            found.extend(_find_malware(item))
    return found


def _find_alert_list(data: Any) -> list:
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        for key in ("alert", "alerts"):
            if key in data:
                inner = data[key]
                if isinstance(inner, dict) and ("alert" in inner):
                    return _as_list(inner["alert"])
                return _as_list(inner)
    return []


def _parse_json(data: Any) -> list[Alert]:
    alerts: list[Alert] = []
    for raw in _find_alert_list(data):
        if not isinstance(raw, dict):
            continue
        n = _norm_keys(raw)
        alerts.append(
            Alert(
                id=str(n.get("id", "")),
                name=str(n.get("name", "")),
                severity=str(n.get("severity", "")),
                malicious=str(n.get("malicious", "")),
                occurred=str(n.get("occurred", "")),
                malware=_find_malware(raw.get("explanation", raw)),
            )
        )
    return alerts


def parse_results(
    submission_id: str, content_type: str, body: str, target: str = "", status: str = "Done"
) -> AnalysisResult:
    """Parse a results response body (XML or JSON) into an AnalysisResult."""
    result = AnalysisResult(submission_id=submission_id, target=target, status=status)
    text = (body or "").strip()
    if not text:
        return result
    try:
        if "json" in content_type.lower() or text[:1] in "[{":
            result.alerts = _parse_json(json.loads(text))
        else:
            result.alerts = _parse_xml(text)
    except (ValueError, ET.ParseError) as exc:
        result.error = f"Could not parse results: {exc}"
    return result
