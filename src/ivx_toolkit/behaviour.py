"""Extract sandbox behaviour (processes, files, signatures) from extended results.

Field names follow the documented alert response (``explanation > osChanges`` in JSON,
``explanation > os-changes`` in XML), where each OS-change entry may contain:

* ``process`` / ``process_informational``: ``cmdline``, ``value`` (image path), ``pid``,
  ``ppid``, ``parentname``, ``md5sum``, ``sha256sum``, ``mode``
* ``file_informational`` (and ``file``): ``value`` (path), ``mode``, ``md5sum``, ``sha256sum``
* ``malicious-alert``: ``classtype``, ``display-msg``

These sections are only present with ``--info-level extended`` (and may need OS changes
enabled on the appliance). Names are matched case- and separator-insensitively, and the
XML and JSON forms are converted to the same structure first.

NOTE: not yet validated against a live appliance; documented field names only.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Process:
    image: str = ""
    cmdline: str = ""
    pid: str = ""
    ppid: str = ""
    parent: str = ""
    mode: str = ""
    md5: str = ""
    sha256: str = ""


@dataclass(frozen=True)
class FileEvent:
    path: str = ""
    mode: str = ""
    md5: str = ""
    sha256: str = ""


@dataclass(frozen=True)
class Signature:
    classtype: str = ""
    message: str = ""


def norm(key: str) -> str:
    return str(key).rsplit("}", 1)[-1].lower().replace("-", "").replace("_", "")


def xml_to_tree(elem: ET.Element) -> Any:
    """Convert an element to plain dicts/lists/strings (attributes and children as keys)."""
    children = list(elem)
    text = (elem.text or "").strip()
    if not children and not elem.attrib:
        return text
    node: dict[str, Any] = {norm(k): v for k, v in elem.attrib.items()}
    for child in children:
        key = norm(child.tag)
        value = xml_to_tree(child)
        if key in node:
            if not isinstance(node[key], list):
                node[key] = [node[key]]
            node[key].append(value)
        else:
            node[key] = value
    if text:
        node["#text"] = text
    return node


def _as_list(value: Any) -> list:
    if value is None:
        return []
    return value if isinstance(value, list) else [value]


def _s(d: dict, *keys: str) -> str:
    for key in keys:
        value = d.get(key)
        if isinstance(value, dict):
            value = value.get("#text") or value.get("value")
        if value not in (None, "", [], {}):
            return str(value).strip()
    return ""


def _normalise(d: dict) -> dict:
    return {norm(k): v for k, v in d.items()}


@dataclass
class Behaviour:
    processes: list[Process]
    files: list[FileEvent]
    signatures: list[Signature]


def extract(alert_tree: Any) -> Behaviour:
    """Walk one alert (as dicts/lists) and collect behaviour found under osChanges."""
    processes: dict[Process, None] = {}
    files: dict[FileEvent, None] = {}
    signatures: dict[Signature, None] = {}

    def walk(node: Any, inside: bool) -> None:
        if isinstance(node, list):
            for item in node:
                walk(item, inside)
            return
        if not isinstance(node, dict):
            return
        for raw_key, value in node.items():
            key = norm(raw_key)
            if key == "oschanges":
                walk(value, True)
                continue
            if inside and key in ("process", "processinformational"):
                for p in _as_list(value):
                    if isinstance(p, dict):
                        p = _normalise(p)
                        processes[
                            Process(
                                image=_s(p, "value", "imagepath"),
                                cmdline=_s(p, "cmdline"),
                                pid=_s(p, "pid"),
                                ppid=_s(p, "ppid"),
                                parent=_s(p, "parentname"),
                                mode=_s(p, "mode"),
                                md5=_s(p, "md5sum", "md5").lower(),
                                sha256=_s(p, "sha256sum", "sha256").lower(),
                            )
                        ] = None
                continue
            if inside and key in ("file", "fileinformational"):
                for f in _as_list(value):
                    if isinstance(f, dict):
                        f = _normalise(f)
                        event = FileEvent(
                            path=_s(f, "value", "#text"),
                            mode=_s(f, "mode"),
                            md5=_s(f, "md5sum", "md5").lower(),
                            sha256=_s(f, "sha256sum", "sha256").lower(),
                        )
                        if event.path or event.md5 or event.sha256:
                            files[event] = None
                    elif isinstance(f, str) and f:
                        files[FileEvent(path=f)] = None
                continue
            if inside and key == "maliciousalert":
                for s in _as_list(value):
                    if isinstance(s, dict):
                        s = _normalise(s)
                        sig = Signature(
                            classtype=_s(s, "classtype"), message=_s(s, "displaymsg", "#text")
                        )
                    else:
                        sig = Signature(message=str(s))
                    if sig.classtype or sig.message:
                        signatures[sig] = None
                continue
            walk(value, inside)

    walk(alert_tree, False)
    return Behaviour(list(processes), list(files), list(signatures))
