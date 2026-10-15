"""A tiny local stand-in for the IVX wsapis API, for demos and tests.

It is NOT a faithful emulation of a real appliance: it only mimics the request
paths, auth header and response shapes from the public documentation.

    ivx-mock --port 8443
    IVX_SCHEME=http IVX_HOST=127.0.0.1 IVX_PORT=8443 IVX_USER=admin IVX_PASSWORD=admin ivx check

    # HTTPS, to rehearse certificate handling (IVX_CA_BUNDLE / --insecure):
    ivx-mock --port 8443 --cert cert.pem --key key.pem

Any submitted file or URL whose name contains "malware" or "eicar" is reported
as malicious; everything else finishes with no detection. Each submission
reports "In Progress" on its first status poll and "Done" afterwards.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import itertools
import json
import re
import secrets
import ssl
import threading
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERNAME = "admin"
PASSWORD = "admin"


class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.tokens: set[str] = set()
        self.ids = itertools.count(7700)
        self.subs: dict[str, dict] = {}


_OS_CHANGES = (
    "<os-changes>"
    '<malicious-alert classtype="Mock.Persistence">'
    "<display-msg>Adds a Run key for persistence</display-msg></malicious-alert>"
    '<process mode="started"><value>C:\\Users\\admin\\AppData\\Local\\Temp\\dropper.exe</value>'
    "<cmdline>dropper.exe /silent</cmdline><pid>4242</pid><ppid>1337</ppid>"
    "<parentname>explorer.exe</parentname>"
    "<md5sum>0cc175b9c0f1b6a831c399e269772661</md5sum></process>"
    '<file_informational mode="created">'
    "<value>C:\\ProgramData\\svc\\payload.dll</value>"
    "<md5sum>92eb5ffee6ae2fec3ad71c777531578f</md5sum></file_informational>"
    "</os-changes>"
)


def _result_xml(sid: str, sub: dict, extended: bool = False) -> str:
    if not sub["malicious"]:
        return (
            '<?xml version="1.0" encoding="UTF-8"?>'
            '<alerts xmlns="http://www.fireeye.com/alert/2011/AlertSchema" '
            'appliance="ivx-mock" version="mock" msg="concise"></alerts>'
        )
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        '<alerts xmlns="http://www.fireeye.com/alert/2011/AlertSchema" '
        'appliance="ivx-mock" version="mock" msg="concise">'
        f'<alert id="{sid}" name="MALWARE_OBJECT" severity="MAJR" malicious="yes" '
        'appliance-id="mock" product="MAS">'
        "<explanation><malware-detected>"
        '<malware name="Mock.Generic.Trojan">'
        "<md5sum>44d88612fea8a8f36de82e1278abb02f</md5sum>"
        "<sha256>275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f</sha256>"
        "</malware></malware-detected>"
        f"{_OS_CHANGES if extended else ''}"
        "</explanation>"
        "<occurred>2026-01-01 00:00:00 +0000</occurred>"
        "</alert></alerts>"
    )


def _uploaded_file(content_type: str, body: bytes) -> bytes:
    """Return the bytes of the multipart part named "filename" (best effort)."""
    match = re.search(r"boundary=([^;]+)", content_type or "")
    if not match:
        return b""
    boundary = b"--" + match.group(1).strip().strip('"').encode()
    for part in body.split(boundary):
        head, _, data = part.partition(b"\r\n\r\n")
        if b'name="filename"' in head:
            return data.rsplit(b"\r\n", 1)[0]
    return b""


def make_handler(state: _State):
    class Handler(BaseHTTPRequestHandler):
        server_version = "ivx-mock/0.1"

        def log_message(self, fmt, *args):  # keep test output quiet
            pass

        def _send(
            self,
            code: int,
            body: str = "",
            ctype: str = "application/json",
            headers: dict | None = None,
        ) -> None:
            data = body.encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            for k, v in (headers or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(data)

        def _authorized(self) -> bool:
            return self.headers.get("X-FeApi-Token") in state.tokens

        def _body(self) -> bytes:
            length = int(self.headers.get("Content-Length") or 0)
            return self.rfile.read(length) if length else b""

        def do_POST(self):  # noqa: N802
            path = self.path.split("?")[0]
            body = self._body()
            if path.endswith("/auth/login") and "/common/" in path:
                auth = self.headers.get("Authorization", "")
                expected = base64.b64encode(f"{USERNAME}:{PASSWORD}".encode()).decode()
                if auth != f"Basic {expected}":
                    return self._send(401, '{"error":"invalid credentials"}')
                token = secrets.token_hex(24)
                with state.lock:
                    state.tokens.add(token)
                return self._send(200, "", headers={"X-FeApi-Token": token})
            if path.endswith("/auth/logout"):
                with state.lock:
                    state.tokens.discard(self.headers.get("X-FeApi-Token", ""))
                return self._send(204)
            if not self._authorized():
                return self._send(401, '{"error":"invalid token"}')
            if path.endswith("/submissions/file"):
                text = body.decode("latin-1").lower()
                if 'name="options"' not in text or 'name="filename"' not in text:
                    return self._send(400, '{"error":"options and filename parts required"}')
                if text.index('name="options"') > text.index('name="filename"'):
                    return self._send(400, '{"error":"options must be the first part"}')
                malicious = "malware" in text or "eicar" in text
                content = _uploaded_file(self.headers.get("Content-Type", ""), body)
                md5 = hashlib.md5(content).hexdigest()  # noqa: S324 - matching IVX's lookup key
                return self._new_submission(malicious, key="ID", md5=md5)
            if path.endswith("/submissions/url"):
                try:
                    payload = json.loads(body or b"{}")
                except ValueError:
                    return self._send(400, '{"error":"invalid json"}')
                urls = payload.get("urls") or []
                if not urls:
                    return self._send(400, '{"error":"urls required"}')
                malicious = any("malware" in u.lower() for u in urls)
                return self._new_submission(malicious, key="id")
            return self._send(404, '{"error":"not found"}')

        def _new_submission(self, malicious: bool, key: str, md5: str = ""):
            with state.lock:
                sid = str(next(state.ids))
                state.subs[sid] = {"malicious": malicious, "polls": 0, "md5": md5}
            return self._send(200, json.dumps([{key: sid}]))

        def do_GET(self):  # noqa: N802
            path, _, query = self.path.partition("?")
            params = dict(urllib.parse.parse_qsl(query))
            if not self._authorized():
                return self._send(401, '{"error":"invalid token"}')
            if path.rstrip("/").endswith("/alerts"):
                md5 = params.get("md5", "").lower()
                if md5 and not re.fullmatch(r"[0-9a-f]{32}", md5):
                    return self._send(400, '{"error":"invalid md5"}')
                with state.lock:
                    hits = [
                        (sid, sub)
                        for sid, sub in state.subs.items()
                        if sub["malicious"] and sub.get("md5") == md5
                    ]
                alerts = [
                    {
                        "id": sid,
                        "name": "MALWARE_OBJECT",
                        "severity": "MAJR",
                        "malicious": "yes",
                        "occurred": "2026-01-01 00:00:00 +0000",
                        "explanation": {
                            "malwareDetected": {
                                "malware": [{"name": "Mock.Generic.Trojan", "md5Sum": md5}]
                            }
                        },
                    }
                    for sid, sub in hits
                ]
                payload = {"alert": alerts, "appliance": "ivx-mock", "alertsCount": len(alerts)}
                return self._send(200, json.dumps(payload))
            sid = path.rstrip("/").rsplit("/", 1)[-1]
            sub = state.subs.get(sid)
            if "/submissions/" in path and sub is None:
                return self._send(404, '{"error":"unknown submission"}')
            if "/submissions/status/" in path:
                with state.lock:
                    sub["polls"] += 1
                    status = "In Progress" if sub["polls"] == 1 else "Done"
                return self._send(200, json.dumps({"submissionStatus": status}))
            if "/submissions/results/" in path:
                extended = params.get("info_level") == "extended"
                return self._send(200, _result_xml(sid, sub, extended), ctype="application/xml")
            return self._send(404, '{"error":"not found"}')

    return Handler


def serve(
    host: str = "127.0.0.1",
    port: int = 8443,
    certfile: str | None = None,
    keyfile: str | None = None,
) -> ThreadingHTTPServer:
    """Create (but do not start) a mock server. Call serve_forever() or run in a thread.

    With certfile/keyfile it serves HTTPS, otherwise plain HTTP.
    """
    server = ThreadingHTTPServer((host, port), make_handler(_State()))
    if certfile:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(certfile, keyfile)
        server.socket = ctx.wrap_socket(server.socket, server_side=True)
        # Clients that reject the certificate abort the handshake; that is expected here.
        server.handle_error = lambda request, client_address: None
    return server


def main() -> None:
    parser = argparse.ArgumentParser(description="Local mock of the IVX wsapis API")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    parser.add_argument("--cert", help="PEM certificate to serve HTTPS")
    parser.add_argument("--key", help="PEM private key for --cert")
    args = parser.parse_args()
    server = serve(args.host, args.port, args.cert, args.key)
    scheme = "https" if args.cert else "http"
    print(f"ivx-mock listening on {scheme}://{args.host}:{args.port} (user/pass: admin/admin)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
