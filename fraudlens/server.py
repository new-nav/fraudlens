"""Tiny local web server (standard library only). Nothing is stored or sent anywhere."""
from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .detector import (analyze_collect_request, analyze_message,
                       analyze_transactions, parse_csv_text, summarize)
from .samples import SAMPLE_COLLECT, SAMPLE_MESSAGES, sample_csv_text

INDEX = Path(__file__).with_name("static") / "index.html"
MAX_BODY = 512 * 1024


class Handler(BaseHTTPRequestHandler):
    server_version = "FraudLens/1.0"

    def _send(self, code: int, body: bytes, ctype: str) -> None:
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def _json(self, code: int, obj) -> None:
        self._send(code, json.dumps(obj).encode(), "application/json; charset=utf-8")

    def do_GET(self) -> None:  # noqa: N802
        if self.path in ("/", "/index.html"):
            self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/samples":
            self._json(200, {"messages": SAMPLE_MESSAGES, "collect": SAMPLE_COLLECT, "csv": sample_csv_text()})
        else:
            self._json(404, {"error": "not found"})

    def do_POST(self) -> None:  # noqa: N802
        try:
            length = int(self.headers.get("Content-Length", 0))
            if length > MAX_BODY:
                return self._json(413, {"error": "request too large"})
            data = json.loads(self.rfile.read(length) or b"{}")
            if not isinstance(data, dict):
                raise ValueError("JSON object expected")

            if self.path == "/api/message":
                return self._json(200, analyze_message(str(data.get("text", ""))).to_dict())
            if self.path == "/api/collect":
                v = analyze_collect_request(
                    str(data.get("vpa", "")), float(data.get("amount") or 0),
                    str(data.get("note", "")), str(data.get("name", "")),
                    bool(data.get("expecting_money")),
                    float(data["typical"]) if data.get("typical") else None,
                )
                return self._json(200, v.to_dict())
            if self.path == "/api/transactions":
                alerts = analyze_transactions(parse_csv_text(str(data.get("csv", ""))))
                return self._json(200, {"summary": summarize(alerts), "alerts": [a.to_dict() for a in alerts]})
            self._json(404, {"error": "not found"})
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            self._json(400, {"error": str(exc)})

    def log_message(self, fmt, *args) -> None:  # keep the console quiet; never log message contents
        pass


def serve(host: str = "127.0.0.1", port: int = 8000) -> None:
    httpd = ThreadingHTTPServer((host, port), Handler)
    print(f"FraudLens running at http://{host}:{port}  (Ctrl+C to stop)")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nBye!")
    finally:
        httpd.server_close()
