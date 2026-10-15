"""`ivx` command-line interface."""

from __future__ import annotations

import argparse
import hashlib
import logging
import sys
from pathlib import Path

from . import __version__
from .client import IVXClient, IVXError, SubmissionOptions
from .config import Settings
from .report import render
from .results import AnalysisResult, parse_results

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
        Path(output).write_text(text, encoding="utf-8")
        _eprint(f"Report written to {output}")
    else:
        print(text)


def _fetch_result(
    client: IVXClient, sid: str, target: str, info_level: str | None, status: str = "Done"
) -> AnalysisResult:
    ctype, body = client.results_raw(sid, info_level)
    return parse_results(sid, ctype, body, target=target, status=status)


# ---------------------------------------------------------------- subcommands
def cmd_check(client: IVXClient, args: argparse.Namespace) -> int:
    client.login()
    print(f"OK: authenticated to {client.settings.host} (API {client.settings.api_version})")
    return 0


def cmd_submit(client: IVXClient, args: argparse.Namespace) -> int:
    opts = _options(args)
    submissions: list[tuple[str, str]] = []  # (submission_id, target)

    for f in _collect_files(args.paths, args.recursive):
        digest = _sha256(f)
        sid = client.submit_file(f, opts)
        _eprint(f"submitted {f}  sha256={digest}  id={sid}")
        submissions.append((sid, str(f)))

    if args.url:
        sid = client.submit_urls(args.url, opts)
        _eprint(f"submitted {len(args.url)} URL(s)  id={sid}")
        submissions.append((sid, ", ".join(args.url)))

    if not submissions:
        _eprint("Nothing to submit. Give file/folder paths and/or --url.")
        return 2

    if not args.wait:
        for sid, target in submissions:
            print(f"{sid}\t{target}")
        return 0

    results: list[AnalysisResult] = []
    for sid, target in submissions:
        try:
            state = client.wait(
                sid,
                max_wait=args.max_wait,
                interval=args.interval,
                on_poll=lambda s, st: log.info("%s: %s", s, st),
            )
            results.append(_fetch_result(client, sid, target, args.info_level, state))
        except IVXError as exc:
            _eprint(f"[!] {sid}: {exc}")
            results.append(AnalysisResult(submission_id=sid, target=target, error=str(exc)))
    _emit(results, args.format, args.output)
    return 1 if any(r.verdict == "malicious" for r in results) and args.fail_on_malicious else 0


def cmd_status(client: IVXClient, args: argparse.Namespace) -> int:
    for sid in args.ids:
        print(f"{sid}\t{client.status(sid)}")
    return 0


def cmd_results(client: IVXClient, args: argparse.Namespace) -> int:
    if args.raw:
        for sid in args.ids:
            _, body = client.results_raw(sid, args.info_level)
            print(body)
        return 0
    results = [_fetch_result(client, sid, "", args.info_level) for sid in args.ids]
    _emit(results, args.format, args.output)
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
        "--fail-on-malicious",
        action="store_true",
        help="Exit with code 1 if any result is malicious",
    )

    sub.add_parser("status", help="Show submission status").add_argument("ids", nargs="+")

    p_res = sub.add_parser("results", help="Fetch analysis results")
    p_res.add_argument("ids", nargs="+")
    p_res.add_argument("--raw", action="store_true", help="Print the raw API response")

    for p in (p_sub, p_res):
        p.add_argument("-f", "--format", choices=["table", "json", "csv", "html"], default="table")
        p.add_argument("-o", "--output", help="Write the report to this file")
        p.add_argument(
            "--info-level",
            choices=["concise", "normal", "extended"],
            help="Detail level of results",
        )
    return parser


COMMANDS = {"check": cmd_check, "submit": cmd_submit, "status": cmd_status, "results": cmd_results}


def main(argv: list[str] | None = None) -> int:
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
