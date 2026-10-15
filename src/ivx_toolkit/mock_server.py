"""A tiny local stand-in for the IVX wsapis API, for demos and tests.

It is NOT a faithful emulation of a real appliance: it only mimics the request
paths, auth header and response shapes from the public documentation.

    ivx-mock --port 8443
    IVX_SCHEME=http IVX_HOST=127.0.0.1 IVX_PORT=8443 IVX_USER=admin IVX_PASSWORD=admin ivx check

Any submitted file or URL whose name contains "malware" or "eicar" is reported
as malicious; everything else finishes with no detection. Each submission
reports "In Progress" on its first status poll and "Done" afterwards.
"""

from __future__ import annotations

import argparse
import base64
import itertools
import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

USERNAME = "admin"
PASSWORD = "admin"


class _State:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.tokens: set[str] = set()
        self.ids = itertools.count(7700)
        self.subs: dict[str, dict] = {}


def _result_xml(sid: str, sub: dict) -> str:
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
        "</malware></malware-detected></explanation>"
        "<occurred>2026-01-01 00:00:00 +0000</occurred>"
        "</alert></alerts>"
    )


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
                return self._new_submission(malicious, key="ID")
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

        def _new_submission(self, malicious: bool, key: str):
            with state.lock:
                sid = str(next(state.ids))
                state.subs[sid] = {"malicious": malicious, "polls": 0}
            return self._send(200, json.dumps([{key: sid}]))

        def do_GET(self):  # noqa: N802
            path = self.path.split("?")[0]
            if not self._authorized():
                return self._send(401, '{"error":"invalid token"}')
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
                return self._send(200, _result_xml(sid, sub), ctype="application/xml")
            return self._send(404, '{"error":"not found"}')

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8443) -> ThreadingHTTPServer:
    """Create (but do not start) a mock server. Call serve_forever() or run in a thread."""
    return ThreadingHTTPServer((host, port), make_handler(_State()))


def main() -> None:
    parser = argparse.ArgumentParser(description="Local mock of the IVX wsapis API (HTTP only)")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8443)
    args = parser.parse_args()
    server = serve(args.host, args.port)
    print(f"ivx-mock listening on http://{args.host}:{args.port} (user/pass: admin/admin)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
