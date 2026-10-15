"""`ivx` command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, doctor
from .client import IVXClient, IVXError, SubmissionOptions
from .config import Settings
from .history import Entry, History
from .report import FORMATS, render
from .results import AnalysisResult, parse_results
from .sanitize import sanitize

log = logging.getLogger("ivx_toolkit")


def _eprint(*args) -> None:
    print(*args, file=sys.stderr)


def _collect_files(paths: list[str], recursive: bool) -> list[Path]:
    files: list[Path] = []
    for p in map(Path, paths):
        if p.is_dir():
            iterator = p.rglob("*") if recursive else p.glob("*")
            files.extend(sorted(f for f in iterator if f.is_file()))
        elif p.is_file():
            files.append(p)
        else:
            raise IVXError(f"Not found: {p}")
    return files


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _options(args: argparse.Namespace) -> SubmissionOptions:
    return SubmissionOptions(
        profiles=args.profile or [],
        application=args.application,
        timeout=args.analysis_timeout,
        priority=1 if args.urgent else 0,
        analysis_type=1 if args.live else 2,
        force=args.force,
        note=args.note,
    )


def _emit(results: list[AnalysisResult], fmt: str, output: str | None) -> None:
    text = render(results, fmt)
    if output:
        # newline="" keeps CSV "\r\n" line endings intact on Windows (no "\r\r\n").
        with open(output, "w", encoding="utf-8", newline="") as fh:
            fh.write(text)
        _eprint(f"Report written to {output}")
    else:
        print(text)


@dataclass
class _Submission:
    sid: str
    target: str
    kind: str  # "file" | "url"
    sha256: str = ""
    urls: list[str] = field(default_factory=list)

    def attach(self, result: AnalysisResult) -> AnalysisResult:
        result.target_kind = self.kind
        result.target_sha256 = self.sha256
        result.target_urls = list(self.urls)
        return result


def _raw_extension(content_type: str, body: str) -> str:
    text = body.lstrip()
    return "json" if "json" in content_type.lower() or text[:1] in "[{" else "xml"


def _save_raw(directory: str | None, sid: str, content_type: str, body: str) -> None:
    if not directory:
        return
    out_dir = Path(directory)
    out_dir.mkdir(parents=True, exist_ok=True)
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in sid)
    path = out_dir / f"{safe_id}.{_raw_extension(content_type, body)}"
    path.write_text(body, encoding="utf-8")
    _eprint(f"raw response saved to {path}")


def _fetch_result(
    client: IVXClient,
    sid: str,
    target: str,
    info_level: str | None,
    status: str = "Done",
    save_raw: str | None = None,
) -> AnalysisResult:
    ctype, body = client.results_raw(sid, info_level)
    _save_raw(save_raw, sid, ctype, body)
    return parse_results(sid, ctype, body, target=target, status=status)


# ---------------------------------------------------------------- subcommands
def cmd_check(client: IVXClient, args: argparse.Namespace) -> int:
    client.login()
    print(f"OK: authenticated to {client.settings.host} (API {client.settings.api_version})")
    return 0


def cmd_doctor(client: IVXClient, args: argparse.Namespace) -> int:
    checks = doctor.run(client, timeout=args.timeout)
    print(doctor.format_checks(checks))
    failed = any(c.status == doctor.FAIL for c in checks)
    print("\nAll checks passed." if not failed else "\nSome checks failed; see hints above.")
    return 1 if failed else 0


def _open_history(args: argparse.Namespace) -> History | None:
    if args.no_history:
        return None
    return History(args.history)


def _cached_result(entry: Entry, target: str, sha256: str) -> AnalysisResult:
    result = parse_results(entry.submission_id, entry.content_type, entry.raw, target=target)
    result.cached_from = f"{entry.submission_id} @ {entry.submitted_at}"
    result.target_kind, result.target_sha256 = "file", sha256
    return result


def cmd_submit(client: IVXClient, args: argparse.Namespace) -> int:
    opts = _options(args)
    host = client.settings.host
    history = _open_history(args)
    if args.skip_known and history is None:
        _eprint("--skip-known needs the local history; drop --no-history.")
        return 2
    # Keeps input order: each item is a pending submission or a result reused from history.
    items: list[_Submission | AnalysisResult] = []
    try:
        for f in _collect_files(args.paths, args.recursive):
            digest = _sha256(f)
            entry = history.lookup(digest, host, args.max_age) if args.skip_known else None
            if entry:
                _eprint(
                    f"known   {f}  sha256={digest}  verdict={entry.verdict} "
                    f"(submission {entry.submission_id}, {entry.submitted_at}); not resubmitted"
                )
                items.append(_cached_result(entry, str(f), digest))
                continue
            sid = client.submit_file(f, opts)
            _eprint(f"submitted {f}  sha256={digest}  id={sid}")
            items.append(_Submission(sid, str(f), "file", sha256=digest))

        if args.url:
            sid = client.submit_urls(args.url, opts)
            _eprint(f"submitted {len(args.url)} URL(s)  id={sid}")
            items.append(_Submission(sid, ", ".join(args.url), "url", urls=list(args.url)))

        if not items:
            _eprint("Nothing to submit. Give file/folder paths and/or --url.")
            return 2

        if not args.wait:
            for item in items:
                if isinstance(item, AnalysisResult):
                    print(f"{item.submission_id}\t{item.target}\tcached:{item.verdict}")
                else:
                    print(f"{item.sid}\t{item.target}")
            return 0

        results: list[AnalysisResult] = []
        for item in items:
            if isinstance(item, AnalysisResult):
                results.append(item)
                continue
            s = item
            try:
                state = client.wait(
                    s.sid,
                    max_wait=args.max_wait,
                    interval=args.interval,
                    on_poll=lambda sid, st: log.info("%s: %s", sid, st),
                )
                ctype, body = client.results_raw(s.sid, args.info_level)
                _save_raw(args.save_raw, s.sid, ctype, body)
                result = s.attach(parse_results(s.sid, ctype, body, target=s.target, status=state))
                if history is not None and s.kind == "file":
                    history.record(
                        s.sha256,
                        s.target,
                        host,
                        s.sid,
                        result.verdict,
                        ", ".join(result.malware_names),
                        ctype,
                        body,
                    )
            except IVXError as exc:
                _eprint(f"[!] {s.sid}: {exc}")
                result = s.attach(
                    AnalysisResult(submission_id=s.sid, target=s.target, error=str(exc))
                )
            results.append(result)
    finally:
        if history is not None:
            history.close()

    _emit(results, args.format, args.output)
    return 1 if any(r.verdict == "malicious" for r in results) and args.fail_on_malicious else 0


def cmd_history(args: argparse.Namespace) -> int:
    with History(args.history) as history:
        entries = history.recent(limit=args.limit, sha256=args.sha256)
    if args.format == "json":
        print(json.dumps([e.__dict__ | {"raw": None} for e in entries], indent=2))
        return 0
    if not entries:
        _eprint(f"No entries in {history.path}")
        return 0
    cols = ["submitted_at", "verdict", "submission_id", "host", "file_name", "sha256", "malware"]
    rows = [{c: str(getattr(e, c) or "-") for c in cols} for e in entries]
    widths = {c: max(len(c), *(len(r[c]) for r in rows)) for c in cols}
    print("  ".join(c.upper().ljust(widths[c]) for c in cols))
    for r in rows:
        print("  ".join(r[c].ljust(widths[c]) for c in cols))
    return 0


def cmd_status(client: IVXClient, args: argparse.Namespace) -> int:
    for sid in args.ids:
        print(f"{sid}\t{client.status(sid)}")
    return 0


def cmd_results(client: IVXClient, args: argparse.Namespace) -> int:
    if args.raw:
        for sid in args.ids:
            ctype, body = client.results_raw(sid, args.info_level)
            _save_raw(args.save_raw, sid, ctype, body)
            print(body)
        return 0
    results = [
        _fetch_result(client, sid, "", args.info_level, save_raw=args.save_raw) for sid in args.ids
    ]
    _emit(results, args.format, args.output)
    return 0


# ------------------------------------------------- offline (no appliance needed)
def cmd_parse(args: argparse.Namespace) -> int:
    results: list[AnalysisResult] = []
    for name in args.files:
        path = Path(name)
        if not path.is_file():
            raise IVXError(f"Not found: {path}")
        body = path.read_text(encoding="utf-8", errors="replace")
        ctype = "application/json" if path.suffix.lower() == ".json" else ""
        results.append(parse_results(path.stem, ctype, body, target=str(path)))
    _emit(results, args.format, args.output)
    return 0


def cmd_sanitize(args: argparse.Namespace) -> int:
    terms = list(args.mask or [])
    if args.host_from_env:
        host = os.environ.get("IVX_HOST")
        if host:
            terms.append(host)
    for name in args.files:
        path = Path(name)
        if not path.is_file():
            raise IVXError(f"Not found: {path}")
        text, counts = sanitize(
            path.read_text(encoding="utf-8", errors="replace"),
            terms=terms,
            mask_public_ips=args.all_ips,
        )
        if args.in_place:
            out = path
        elif args.output_dir:
            out = Path(args.output_dir) / path.name
            out.parent.mkdir(parents=True, exist_ok=True)
        else:
            out = path.with_name(f"{path.stem}.sanitized{path.suffix}")
        out.write_text(text, encoding="utf-8")
        summary = ", ".join(f"{k}={v}" for k, v in sorted(counts.items())) or "nothing found"
        _eprint(f"{path} -> {out}  (masked: {summary})")
    _eprint("Review the output before sharing it: masking is best-effort.")
    return 0


# --------------------------------------------------------------------- parser
def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="ivx",
        description="Trellix IVX sandbox CLI. Credentials come from IVX_USER / IVX_PASSWORD "
        "environment variables (password is prompted if unset).",
    )
    parser.add_argument("--version", action="version", version=f"ivx-toolkit {__version__}")
    parser.add_argument("--host", help="IVX appliance address (default: $IVX_HOST)")
    parser.add_argument(
        "--insecure", action="store_true", help="Skip TLS certificate verification (lab use only)"
    )
    parser.add_argument("-v", "--verbose", action="count", default=0)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("check", help="Test that login works")

    p_doc = sub.add_parser(
        "doctor",
        help="Diagnose connectivity step by step (DNS, TCP, TLS, login, API access)",
    )
    p_doc.add_argument(
        "--timeout", type=float, default=5.0, help="Network timeout in seconds (default 5)"
    )

    p_sub = sub.add_parser("submit", help="Submit files, folders and/or URLs for analysis")
    p_sub.add_argument("paths", nargs="*", help="Files or folders to submit")
    p_sub.add_argument("--url", action="append", help="URL to submit (repeatable)")
    p_sub.add_argument("-r", "--recursive", action="store_true", help="Recurse into folders")
    p_sub.add_argument(
        "-p", "--profile", action="append", help="Analysis profile, e.g. win10x64 (repeatable)"
    )
    p_sub.add_argument("--application", default="0", help="Application ID (0 = auto)")
    p_sub.add_argument(
        "--analysis-timeout",
        type=int,
        default=500,
        help="Analysis timeout in seconds (default 500)",
    )
    p_sub.add_argument("--urgent", action="store_true", help="Urgent priority")
    p_sub.add_argument("--live", action="store_true", help="Live analysis instead of sandbox")
    p_sub.add_argument("--force", action="store_true", help="Re-analyse duplicates")
    p_sub.add_argument("--note", help="Submission note (v2.0.0; may be shared with DTI cloud)")
    p_sub.add_argument("-w", "--wait", action="store_true", help="Wait for results")
    p_sub.add_argument("--max-wait", type=int, default=1800, help="Max seconds to wait")
    p_sub.add_argument("--interval", type=int, default=15, help="Polling interval in seconds")
    p_sub.add_argument(
        "--skip-known",
        action="store_true",
        help="Do not resubmit files already analysed on this appliance (same SHA-256); "
        "reuse the result from the local history",
    )
    p_sub.add_argument(
        "--max-age",
        type=float,
        default=30,
        metavar="DAYS",
        help="With --skip-known: only reuse results newer than this (default 30 days)",
    )
    p_sub.add_argument(
        "--no-history", action="store_true", help="Do not read or write the local history"
    )
    p_sub.add_argument(
        "--fail-on-malicious",
        action="store_true",
        help="Exit with code 1 if any result is malicious",
    )

    sub.add_parser("status", help="Show submission status").add_argument("ids", nargs="+")

    p_res = sub.add_parser("results", help="Fetch analysis results")
    p_res.add_argument("ids", nargs="+")
    p_res.add_argument("--raw", action="store_true", help="Print the raw API response")

    for p in (p_sub, p_res):
        p.add_argument(
            "--save-raw",
            metavar="DIR",
            help="Also save each raw results response to DIR/<id>.xml|json",
        )

    p_hist = sub.add_parser("history", help="Show the local submission history")
    p_hist.add_argument("--limit", type=int, default=50, help="Number of entries (default 50)")
    p_hist.add_argument("--sha256", help="Only entries for this file hash")
    p_hist.add_argument("-f", "--format", choices=["table", "json"], default="table")

    for p in (p_sub, p_hist):
        p.add_argument(
            "--history",
            metavar="PATH",
            help="History database (default: $IVX_HISTORY or the user data directory)",
        )

    p_parse = sub.add_parser(
        "parse",
        help="Parse saved raw results files offline (no appliance needed)",
    )
    p_parse.add_argument("files", nargs="+", help="Files saved with --save-raw or --raw")

    p_san = sub.add_parser(
        "sanitize",
        help="Mask internal IPs, MACs, e-mails and host names in saved files before sharing",
    )
    p_san.add_argument("files", nargs="+")
    p_san.add_argument(
        "-m",
        "--mask",
        action="append",
        metavar="TERM",
        help="Extra host name, domain (subdomains included) or user name to mask (repeatable)",
    )
    p_san.add_argument(
        "--host-from-env", action="store_true", help="Also mask the appliance name in $IVX_HOST"
    )
    p_san.add_argument("--all-ips", action="store_true", help="Mask public IP addresses too")
    target = p_san.add_mutually_exclusive_group()
    target.add_argument("--in-place", action="store_true", help="Overwrite the input files")
    target.add_argument("--output-dir", help="Write sanitised copies to this directory")

    for p in (p_sub, p_res, p_parse):
        p.add_argument(
            "-f",
            "--format",
            choices=FORMATS,
            default="table",
            help="Output format; 'iocs' (CSV) and 'stix' (STIX 2.1) export IOCs "
            "from malicious results only",
        )
        p.add_argument("-o", "--output", help="Write the report to this file")
    for p in (p_sub, p_res):
        p.add_argument(
            "--info-level",
            choices=["concise", "normal", "extended"],
            help="Detail level of results",
        )
    return parser


COMMANDS = {
    "check": cmd_check,
    "doctor": cmd_doctor,
    "submit": cmd_submit,
    "status": cmd_status,
    "results": cmd_results,
}
OFFLINE_COMMANDS = {"parse": cmd_parse, "sanitize": cmd_sanitize, "history": cmd_history}


def _safe_console() -> None:
    """Never crash on characters the console code page cannot show (e.g. cp1254 on Windows)."""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure:
            try:
                reconfigure(errors="replace")
            except (ValueError, OSError):
                pass


def main(argv: list[str] | None = None) -> int:
    _safe_console()
    args = build_parser().parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG
        if args.verbose > 1
        else logging.INFO
        if args.verbose
        else logging.WARNING,
        format="%(levelname)s %(message)s",
    )
    if getattr(args, "info_level", None) == "concise":
        args.info_level = None  # concise is the API default; omit the parameter
    try:
        if args.command in OFFLINE_COMMANDS:
            return OFFLINE_COMMANDS[args.command](args)
        settings = Settings.from_env(host=args.host)
        if args.insecure:
            settings.verify_tls = False
            import urllib3

            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        with IVXClient(settings) as client:
            return COMMANDS[args.command](client, args)
    except (IVXError, ValueError) as exc:
        _eprint(f"error: {exc}")
        return 2
    except KeyboardInterrupt:
        _eprint("interrupted")
        return 130


if __name__ == "__main__":
    sys.exit(main())
