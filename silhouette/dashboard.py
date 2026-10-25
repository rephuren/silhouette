"""Локальный дашборд: JSON API поверх SQLite и одна страница. Данные приходят из внешнего мира,
поэтому страница выводит их только как текст."""
import json
import re
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

from .store import Store

INDEX = Path(__file__).with_name("dashboard.html")
NAME_RE = re.compile(r"^[a-z0-9_.\-]{1,253}$")


def latest(store, domain):
    ids = store.scan_ids(domain)
    return ids[-1] if ids else None


def route(store, path, query):
    parts = [unquote(p) for p in path.strip("/").split("/")]
    if parts[:2] == ["api", "domains"]:
        return store.domains()
    if len(parts) >= 3 and parts[0] == "api" and NAME_RE.match(parts[2]):
        domain = parts[2]
        sid = latest(store, domain)
        if sid is None:
            return None
        kind = parts[1]
        if kind == "summary":
            return store.summary(sid)
        if kind == "hosts":
            return store.hosts(sid)
        if kind == "findings":
            return store.findings(sid)
        if kind == "diff":
            return store.diff(domain) or {}
        if kind == "graph":
            return store.graph(sid)
        if kind == "host" and len(parts) == 4 and NAME_RE.match(parts[3]):
            host = next((h for h in store.hosts(sid) if h["name"] == parts[3]), None)
            return None if host is None else {**host, "findings": store.findings(sid, parts[3])}
    return None


def make_handler(db_path):
    class Handler(BaseHTTPRequestHandler):
        def _send(self, code, body, ctype):
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'")
            self.end_headers()
            self.wfile.write(body)

        def do_GET(self):
            url = urlparse(self.path)
            if url.path in ("/", "/index.html"):
                return self._send(200, INDEX.read_bytes(), "text/html; charset=utf-8")
            if url.path.startswith("/api/"):
                store = Store(db_path)
                try:
                    data = route(store, url.path, parse_qs(url.query))
                finally:
                    store.close()
                if data is None:
                    return self._send(404, b'{"error":"not found"}', "application/json")
                return self._send(200, json.dumps(data, ensure_ascii=False).encode(), "application/json")
            self._send(404, b"not found", "text/plain")

        def log_message(self, *args):
            pass

    return Handler


def serve(host, port, db_path):
    Store(db_path).close()
    httpd = ThreadingHTTPServer((host, port), make_handler(db_path))
    print(f"дашборд: http://{host}:{port}  (база {db_path})")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        httpd.server_close()
