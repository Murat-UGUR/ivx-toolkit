"""Step-by-step connectivity diagnostics: `ivx doctor`.

ivx-toolkit runs on a separate machine (workstation, jump host, SOC server) and talks
to the IVX appliance over HTTPS. Nothing is installed on the hardened appliance itself.
`ivx doctor` checks each layer between the two, in order, and stops at the first
failure so the problem is easy to locate:

    DNS -> TCP -> TLS -> API login -> API authorisation
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import datetime, timezone

from .client import IVXClient, IVXError

PASS, FAIL, WARN, SKIP = "PASS", "FAIL", "WARN", "SKIP"


@dataclass
class Check:
    name: str
    status: str
    detail: str = ""
    hint: str = ""


def _check_dns(host: str, port: int) -> Check:
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return Check("DNS", FAIL, str(exc), "Check the host name, or use the IP address.")
    addresses = sorted({info[4][0] for info in infos})
    return Check("DNS", PASS, f"{host} -> {', '.join(addresses)}")


def _check_tcp(host: str, port: int, timeout: float) -> Check:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            pass
    except OSError as exc:
        return Check(
            "TCP",
            FAIL,
            f"{host}:{port} not reachable ({exc})",
            "Check firewall rules / routing from this machine to the IVX management "
            "interface, and that the port is correct (IVX_PORT).",
        )
    return Check("TCP", PASS, f"{host}:{port} is reachable")


def _cert_days_left(cert: dict) -> int | None:
    not_after = cert.get("notAfter")
    if not not_after:
        return None
    expires = datetime.fromtimestamp(ssl.cert_time_to_seconds(not_after), tz=timezone.utc)
    return (expires - datetime.now(timezone.utc)).days


def _name(cert: dict, field: str) -> str:
    for rdn in cert.get(field, ()):
        for key, value in rdn:
            if key == "commonName":
                return value
    return "?"


def _check_tls(host: str, port: int, verify: bool | str, timeout: float) -> Check:
    if verify is False:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx = ssl.create_default_context(cafile=verify if isinstance(verify, str) else None)
    try:
        with socket.create_connection((host, port), timeout=timeout) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                version = tls.version()
                cert = tls.getpeercert() or {}
    except ssl.SSLCertVerificationError as exc:
        return Check(
            "TLS",
            FAIL,
            f"certificate not trusted: {exc.verify_message}",
            "Export the appliance (or issuing CA) certificate and set IVX_CA_BUNDLE to it. "
            "For a lab test only, --insecure skips verification.",
        )
    except (ssl.SSLError, OSError) as exc:
        return Check("TLS", FAIL, f"TLS handshake failed: {exc}")

    if verify is False:
        return Check(
            "TLS",
            WARN,
            f"{version}, certificate NOT verified (--insecure / IVX_VERIFY_TLS=false)",
            "Use IVX_CA_BUNDLE instead of --insecure outside the lab.",
        )
    detail = f"{version}, subject={_name(cert, 'subject')}, issuer={_name(cert, 'issuer')}"
    days = _cert_days_left(cert)
    if days is not None:
        detail += f", expires in {days} days"
        if days < 30:
            return Check("TLS", WARN, detail, "Certificate expires soon; plan a renewal.")
    return Check("TLS", PASS, detail)


def _check_login(client: IVXClient) -> Check:
    try:
        client.login()
    except IVXError as exc:
        hints = {
            401: "Wrong credentials, or the account lacks the API role. "
            "Use a dedicated account that is allowed to use the web services API.",
            403: "The account is not allowed to use the API.",
            404: "Login endpoint not found: the web services API may be disabled on the "
            "appliance, or the API version (IVX_API_VERSION) is wrong. Try v1.2.0.",
        }
        return Check("API login", FAIL, str(exc), hints.get(exc.status_code or 0, ""))
    path = (client.login_url or "").split("/wsapis", 1)[-1]
    return Check("API login", PASS, f"token received via /wsapis{path}")


def _check_api(client: IVXClient) -> Check:
    """Query a submission ID that cannot exist: 404 proves the token is accepted."""
    try:
        client.status("0")
    except IVXError as exc:
        if exc.status_code == 404:
            return Check("API access", PASS, "submissions endpoint answered (404 for a dummy ID)")
        return Check(
            "API access",
            FAIL,
            str(exc),
            "Logged in, but the submissions API refused the request. Check the account role.",
        )
    return Check("API access", PASS, "submissions endpoint answered")


def run(client: IVXClient, timeout: float = 5.0) -> list[Check]:
    s = client.settings
    checks: list[Check] = []

    def done(check: Check) -> bool:
        checks.append(check)
        return check.status != FAIL

    steps = [
        lambda: _check_dns(s.host, s.port),
        lambda: _check_tcp(s.host, s.port, timeout),
        lambda: (
            _check_tls(s.host, s.port, s.verify_tls, timeout)
            if s.scheme == "https"
            else Check("TLS", SKIP, "plain HTTP (mock server only)")
        ),
        lambda: _check_login(client),
        lambda: _check_api(client),
    ]
    names = ["DNS", "TCP", "TLS", "API login", "API access"]
    for i, step in enumerate(steps):
        if not done(step()):
            checks += [Check(n, SKIP, "skipped after previous failure") for n in names[i + 1 :]]
            break
    return checks


def format_checks(checks: list[Check]) -> str:
    width = max(len(c.name) for c in checks)
    lines = []
    for c in checks:
        lines.append(f"[{c.status}] {c.name.ljust(width)}  {c.detail}")
        if c.hint and c.status in (FAIL, WARN):
            lines.append(f"       {' ' * width}  -> {c.hint}")
    return "\n".join(lines)
