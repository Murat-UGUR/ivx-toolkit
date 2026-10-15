"""Extract indicators of compromise from analysis results and export them.

Only results with a **malicious** verdict produce IOCs, so a noisy or uncertain
alert never ends up in a block list by accident. Sources:

* hashes (MD5 / SHA-256) of malware objects reported by IVX
* the SHA-256 of the submitted file itself (computed locally before upload)
* submitted URLs

Formats: a flat CSV (type,value,verdict,malware,submission_id) and a STIX 2.1
bundle. STIX object IDs are derived deterministically from the indicator value, so
exporting the same sample twice yields the same IDs and does not create duplicates
in a TIP.
"""

from __future__ import annotations

import csv
import io
import json
import uuid
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime, timezone

from .results import AnalysisResult

# Namespace for deterministic STIX IDs (uuid5). Do not change once released.
_NS = uuid.UUID("6f1b2a0e-6a2d-4f7e-9c3e-1b7d6a9e4c21")


@dataclass(frozen=True)
class IOC:
    type: str  # "sha256" | "md5" | "url"
    value: str
    submission_id: str
    malware: str = ""
    verdict: str = "malicious"


def _hex_ok(value: str, length: int) -> bool:
    return len(value) == length and all(c in "0123456789abcdefABCDEF" for c in value)


def collect(results: Sequence[AnalysisResult]) -> list[IOC]:
    """Return de-duplicated IOCs from malicious results, in a stable order."""
    seen: set[tuple[str, str]] = set()
    iocs: list[IOC] = []

    def add(kind: str, value: str, r: AnalysisResult, malware: str = "") -> None:
        value = value.strip()
        if kind in ("sha256", "md5"):
            value = value.lower()
            if not _hex_ok(value, 64 if kind == "sha256" else 32):
                return
        key = (kind, value)
        if value and key not in seen:
            seen.add(key)
            iocs.append(IOC(kind, value, r.submission_id, malware))

    for r in results:
        if r.verdict != "malicious":
            continue
        family = ", ".join(r.malware_names)
        if r.target_sha256:
            add("sha256", r.target_sha256, r, family)
        for url in r.target_urls:
            add("url", url, r, family)
        for alert in r.alerts:
            for m in alert.malware:
                add("sha256", m.sha256, r, m.name)
                add("md5", m.md5, r, m.name)
    return iocs


def to_csv(results: Sequence[AnalysisResult]) -> str:
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["type", "value", "verdict", "malware", "submission_id"])
    for ioc in collect(results):
        writer.writerow([ioc.type, ioc.value, ioc.verdict, ioc.malware, ioc.submission_id])
    return buf.getvalue()


# ------------------------------------------------------------------------ STIX
def _sid(kind: str, key: str) -> str:
    return f"{kind}--{uuid.uuid5(_NS, f'{kind}:{key}')}"


def _escape(value: str) -> str:
    return value.replace("\\", "\\\\").replace("'", "\\'")


_PATTERN = {
    "sha256": "[file:hashes.'SHA-256' = '{v}']",
    "md5": "[file:hashes.MD5 = '{v}']",
    "url": "[url:value = '{v}']",
}


def to_stix(results: Sequence[AnalysisResult], now: datetime | None = None) -> str:
    ts = (now or datetime.now(timezone.utc)).strftime("%Y-%m-%dT%H:%M:%S.000Z")
    identity_id = _sid("identity", "ivx-toolkit")
    objects: list[dict] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": ts,
            "modified": ts,
            "name": "ivx-toolkit",
            "identity_class": "system",
        }
    ]
    malware_ids: dict[str, str] = {}

    for ioc in collect(results):
        indicator_id = _sid("indicator", f"{ioc.type}:{ioc.value}")
        objects.append(
            {
                "type": "indicator",
                "spec_version": "2.1",
                "id": indicator_id,
                "created_by_ref": identity_id,
                "created": ts,
                "modified": ts,
                "name": f"{ioc.type.upper()} {ioc.value}",
                "description": f"Trellix IVX verdict: {ioc.verdict} "
                f"(submission {ioc.submission_id})",
                "indicator_types": ["malicious-activity"],
                "pattern": _PATTERN[ioc.type].format(v=_escape(ioc.value)),
                "pattern_type": "stix",
                "valid_from": ts,
            }
        )
        for name in [n.strip() for n in ioc.malware.split(",") if n.strip()]:
            if name not in malware_ids:
                malware_ids[name] = _sid("malware", name)
                objects.append(
                    {
                        "type": "malware",
                        "spec_version": "2.1",
                        "id": malware_ids[name],
                        "created_by_ref": identity_id,
                        "created": ts,
                        "modified": ts,
                        "name": name,
                        "is_family": False,
                    }
                )
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": _sid("relationship", f"{indicator_id}>{malware_ids[name]}"),
                    "created_by_ref": identity_id,
                    "created": ts,
                    "modified": ts,
                    "relationship_type": "indicates",
                    "source_ref": indicator_id,
                    "target_ref": malware_ids[name],
                }
            )

    bundle = {"type": "bundle", "id": f"bundle--{uuid.uuid4()}", "objects": objects}
    return json.dumps(bundle, indent=2, ensure_ascii=False)
