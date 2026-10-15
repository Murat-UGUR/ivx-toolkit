"""HTTP client for the Trellix IVX REST API (wsapis).

Endpoints implemented (per the public Trellix IVX API docs):

    POST /wsapis/common/<ver>/auth/login         Basic auth -> X-FeApi-Token header
    POST /wsapis/<ver>/submissions/file          multipart: options (JSON) + filename
    POST /wsapis/<ver>/submissions/url           JSON body with "urls"
    GET  /wsapis/<ver>/submissions/status/<id>   {"submissionStatus": "In Progress" | "Done"}
    GET  /wsapis/<ver>/submissions/results/<id>  alerts (XML by default, JSON if supported)
    GET  /wsapis/<ver>/alerts?md5=<hash>         existing alerts for a file hash

NOTE: This code has NOT yet been validated against a live IVX appliance.
Paths and payload shapes follow the vendor documentation; differences between
appliance versions are handled defensively where possible.
"""

from __future__ import annotations

import json
import logging
import time
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import requests

from .config import Settings

log = logging.getLogger(__name__)

DONE_STATES = {"done", "completed", "complete"}
FAILED_STATES = {"failed", "error", "cancelled", "canceled"}


class IVXError(RuntimeError):
    """Raised for API errors (HTTP failures, bad responses, timeouts)."""

    def __init__(self, message: str, status_code: int | None = None):
        super().__init__(message)
        self.status_code = status_code


@dataclass
class SubmissionOptions:
    """Analysis options sent with every submission.

    Values are sent as strings for file submissions, matching the vendor examples.
    """

    profiles: list[str] = field(default_factory=list)
    application: str = "0"  # 0 = let the appliance choose
    timeout: int = 500  # analysis timeout in seconds
    priority: int = 0  # 0 = normal, 1 = urgent
    analysis_type: int = 2  # 1 = live, 2 = sandbox
    force: bool = False  # re-analyse duplicates
    prefetch: int = 0
    note: str | None = None  # v2.0.0 only; may be shared with the DTI cloud
    enable_vnc: bool = False

    def as_file_options(self) -> dict[str, Any]:
        opts: dict[str, Any] = {
            "application": str(self.application),
            "timeout": str(self.timeout),
            "priority": str(self.priority),
            "profiles": list(self.profiles),
            "analysistype": str(self.analysis_type),
            "force": "true" if self.force else "false",
            "prefetch": str(self.prefetch),
        }
        if self.enable_vnc:
            opts["enable_vnc"] = "true"
        if self.note:
            opts["note"] = self.note
        return opts

    def as_url_options(self, urls: list[str]) -> dict[str, Any]:
        return {
            "timeout": self.timeout,
            "priority": self.priority,
            "profiles": list(self.profiles),
            "application": int(self.application),
            "force": self.force,
            "analysistype": self.analysis_type,
            "prefetch": self.prefetch,
            "urls": urls,
        }


class IVXClient:
    """Minimal session-based client. Use as a context manager to log out automatically."""

    def __init__(self, settings: Settings, session: requests.Session | None = None):
        self.settings = settings
        self.session = session or requests.Session()
        self.session.verify = settings.verify_tls
        # Passed on every request: a session-level `verify` is silently overridden by the
        # REQUESTS_CA_BUNDLE / CURL_CA_BUNDLE environment variables, which would break
        # IVX_CA_BUNDLE and --insecure on machines where those variables are set.
        self._verify = settings.verify_tls
        self.token: str | None = None
        self.login_url: str | None = None  # which login path worked (for diagnostics)
        self._base = f"{settings.scheme}://{settings.host}:{settings.port}/wsapis"

    # ------------------------------------------------------------------ helpers
    def _url(self, path: str) -> str:
        return f"{self._base}/{self.settings.api_version}/{path.lstrip('/')}"

    def _headers(self, extra: dict[str, str] | None = None) -> dict[str, str]:
        headers = {"Accept": "application/json"}
        if self.token:
            headers["X-FeApi-Token"] = self.token
        if self.settings.client_token:
            headers["X-FeClient-Token"] = self.settings.client_token
        if extra:
            headers.update(extra)
        return headers

    def _request(
        self, method: str, path: str, retry_auth: bool = True, **kwargs
    ) -> requests.Response:
        if not self.token:
            self.login()
        extra_headers = kwargs.get("headers")
        http_timeout = kwargs.get("http_timeout", 60)
        send_kwargs = {k: v for k, v in kwargs.items() if k not in {"headers", "http_timeout"}}
        try:
            resp = self.session.request(
                method,
                self._url(path),
                headers=self._headers(extra_headers),
                timeout=http_timeout,
                verify=self._verify,
                **send_kwargs,
            )
        except requests.RequestException as exc:
            raise IVXError(f"Connection to IVX failed: {exc}") from exc

        if resp.status_code == 401 and retry_auth:
            # Session tokens expire after ~15 min of inactivity; log in again once.
            log.info("Session token rejected (401); re-authenticating.")
            self.token = None
            self.login()
            return self._request(method, path, retry_auth=False, **kwargs)
        if resp.status_code >= 400:
            raise IVXError(
                f"{method} {path} failed: HTTP {resp.status_code} {resp.text[:300]}",
                resp.status_code,
            )
        return resp

    @staticmethod
    def _json(resp: requests.Response) -> Any:
        try:
            return resp.json()
        except ValueError as exc:
            raise IVXError(f"Expected JSON from IVX, got: {resp.text[:200]!r}") from exc

    @staticmethod
    def _first_id(payload: Any) -> list[str]:
        """Extract submission IDs from the different response shapes IVX/CMS return."""
        if isinstance(payload, dict) and "response" in payload:
            payload = payload["response"]
        if isinstance(payload, dict):
            payload = [payload]
        ids: list[str] = []
        for item in payload or []:
            if isinstance(item, dict):
                value = item.get("ID") or item.get("id")
                if value is not None:
                    ids.append(str(value))
        if not ids:
            raise IVXError(f"No submission ID in response: {payload!r}")
        return ids

    # --------------------------------------------------------------------- auth
    def login(self) -> str:
        ver = self.settings.api_version
        candidates = [
            f"{self._base}/common/{ver}/auth/login",  # documented for IVX
            f"{self._base}/{ver}/auth/login",  # legacy FireEye AX/NX path
        ]
        last_error = ""
        for url in candidates:
            try:
                resp = self.session.post(
                    url,
                    auth=(self.settings.username, self.settings.password),
                    headers={k: v for k, v in self._headers().items() if k != "X-FeApi-Token"},
                    timeout=30,
                    verify=self._verify,
                )
            except requests.RequestException as exc:
                raise IVXError(f"Connection to IVX failed: {exc}") from exc
            if resp.status_code == 404:
                last_error = f"404 at {url}"
                continue
            if resp.status_code >= 400:
                raise IVXError(f"Login failed: HTTP {resp.status_code}", resp.status_code)
            token = resp.headers.get("X-FeApi-Token")
            if not token:
                raise IVXError("Login succeeded but no X-FeApi-Token header was returned.")
            self.token = token
            self.login_url = url
            return token
        raise IVXError(f"Login endpoint not found ({last_error}).", 404)

    def logout(self) -> None:
        if not self.token:
            return
        for url in (
            f"{self._base}/common/{self.settings.api_version}/auth/logout",
            f"{self._base}/{self.settings.api_version}/auth/logout",
        ):
            try:
                resp = self.session.post(
                    url, headers=self._headers(), timeout=15, verify=self._verify
                )
                if resp.status_code != 404:
                    break
            except requests.RequestException:
                break
        self.token = None

    def __enter__(self) -> IVXClient:
        return self

    def __exit__(self, *exc) -> None:
        self.logout()

    # -------------------------------------------------------------- submissions
    def submit_file(self, path: str | Path, options: SubmissionOptions) -> str:
        path = Path(path)
        if not path.is_file():
            raise IVXError(f"File not found: {path}")
        content = path.read_bytes()  # bytes, so a re-authenticated retry can resend the body
        # "options" must be the first multipart part.
        files = [
            ("options", (None, json.dumps(options.as_file_options()), "application/json")),
            ("filename", (path.name, content, "application/octet-stream")),
        ]
        resp = self._request("POST", "submissions/file", files=files, http_timeout=300)
        return self._first_id(self._json(resp))[0]

    def submit_urls(self, urls: Iterable[str], options: SubmissionOptions) -> str:
        urls = [u for u in urls if u]
        if not urls:
            raise IVXError("No URLs given.")
        resp = self._request(
            "POST",
            "submissions/url",
            json=options.as_url_options(urls),
            headers={"Content-Type": "application/json"},
        )
        return self._first_id(self._json(resp))[0]

    def status(self, submission_id: str) -> str:
        resp = self._request("GET", f"submissions/status/{submission_id}")
        text = resp.text.strip()
        try:
            data = resp.json()
            value = data.get("submissionStatus") if isinstance(data, dict) else None
        except ValueError:
            value = None
            if "<submissionStatus>" in text:
                value = text.split("<submissionStatus>")[1].split("</submissionStatus>")[0]
        if not value:
            raise IVXError(f"Unexpected status response: {text[:200]!r}")
        return str(value).strip()

    def results_raw(self, submission_id: str, info_level: str | None = None) -> tuple[str, str]:
        """Return (content_type, body) for the analysis results."""
        params = {"info_level": info_level} if info_level else None
        resp = self._request("GET", f"submissions/results/{submission_id}", params=params)
        return resp.headers.get("Content-Type", ""), resp.text

    def alerts_by_md5(self, md5: str, info_level: str | None = None) -> tuple[str, str]:
        """Return (content_type, body) of existing alerts for an MD5 (not time-limited).

        No alerts does not mean the file is clean: it may simply never have been analysed.
        """
        md5 = md5.strip().lower()
        if len(md5) != 32 or any(c not in "0123456789abcdef" for c in md5):
            raise IVXError(f"Not an MD5 hash: {md5!r}")
        params = {"md5": md5}
        if info_level:
            params["info_level"] = info_level
        resp = self._request("GET", "alerts", params=params)
        return resp.headers.get("Content-Type", ""), resp.text

    def wait(
        self, submission_id: str, max_wait: int = 1800, interval: int = 15, on_poll=None
    ) -> str:
        """Poll until the submission is done. Returns the final status."""
        deadline = time.monotonic() + max_wait
        while True:
            state = self.status(submission_id)
            if on_poll:
                on_poll(submission_id, state)
            low = state.lower()
            if low in DONE_STATES:
                return state
            if low in FAILED_STATES:
                raise IVXError(f"Submission {submission_id} ended with status {state!r}")
            if time.monotonic() >= deadline:
                raise IVXError(f"Timed out after {max_wait}s waiting for {submission_id} ({state})")
            time.sleep(interval)
