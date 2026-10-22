"""Servidor LOCAL do DocCheck: interface web + API. Nada é gravado em disco nem registrado em log.

Proteções: escuta só em 127.0.0.1; confere o cabeçalho Host (contra DNS rebinding); exige JSON nos POSTs (impede
formulários de outros sites); limita o tamanho; não lê caminhos de arquivo enviados pelo cliente (só base64);
cabeçalhos de segurança em todas as respostas.
"""
from __future__ import annotations

import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import __version__
from .rules import run_check
from .samples import inline_fichas
from .validators import valid_cep, valid_cnh, valid_cnpj, valid_cpf

STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")
MAX_BODY = 25 * 1024 * 1024
VALIDATORS = {"cpf": valid_cpf, "cnpj": valid_cnpj, "cnh": valid_cnh, "cep": valid_cep}
CSP = ("default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; "
       "connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'")


class Handler(BaseHTTPRequestHandler):
    server_version = "DocCheck/" + __version__

    def log_message(self, *args):  # sem logs: o que passa por aqui é dado pessoal
        pass

    def _send(self, code: int, body: bytes, ctype: str = "application/json; charset=utf-8") -> None:
        self.send_response(code)
        for key, value in (("Content-Type", ctype), ("Content-Length", str(len(body))), ("Cache-Control", "no-store"),
                           ("X-Content-Type-Options", "nosniff"), ("X-Frame-Options", "DENY"),
                           ("Referrer-Policy", "no-referrer"), ("Content-Security-Policy", CSP)):
            self.send_header(key, value)
        self.end_headers()
        self.wfile.write(body)

    def _json(self, obj, code: int = 200) -> None:
        self._send(code, json.dumps(obj, ensure_ascii=False).encode())

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "").rsplit(":", 1)[0].strip("[]").lower() in ("127.0.0.1", "localhost")

    def do_GET(self):
        if not self._host_ok():
            return self._json({"error": "host não permitido"}, 403)
        if self.path in ("/", "/index.html"):
            with open(os.path.join(STATIC, "index.html"), "rb") as f:
                return self._send(200, f.read(), "text/html; charset=utf-8")
        if self.path == "/api/samples":
            return self._json(inline_fichas())
        if self.path == "/api/health":
            return self._json({"status": "ok", "version": __version__})
        self._json({"error": "rota não encontrada"}, 404)

    def do_POST(self):
        if not self._host_ok():
            return self._json({"error": "host não permitido"}, 403)
        if self.path not in ("/api/check", "/api/validate"):
            return self._json({"error": "rota não encontrada"}, 404)
        if "application/json" not in self.headers.get("Content-Type", ""):
            return self._json({"error": "envie application/json"}, 415)
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            return self._json({"error": "Content-Length inválido"}, 400)
        if length > MAX_BODY:
            return self._json({"error": "corpo grande demais (máximo 25 MB)"}, 413)
        try:
            payload = json.loads(self.rfile.read(length) or b"{}")
        except ValueError:
            return self._json({"error": "JSON inválido"}, 400)
        if not isinstance(payload, dict):
            return self._json({"error": "esperado um objeto JSON"}, 400)
        if self.path == "/api/validate":
            return self._json({k: VALIDATORS[k](v) for k, v in payload.items() if k in VALIDATORS})
        try:
            return self._json(run_check(payload, allow_paths=False))
        except Exception as exc:  # noqa: BLE001
            return self._json({"error": f"falha ao conferir: {type(exc).__name__}"}, 500)


def make_server(port: int = 8900, host: str = "127.0.0.1") -> ThreadingHTTPServer:
    server = ThreadingHTTPServer((host, port), Handler)
    server.daemon_threads = True
    return server


def serve(port: int = 8900, open_browser: bool = True) -> None:
    server = None
    for p in range(port, port + 10):
        try:
            server = make_server(p)
            port = p
            break
        except OSError:
            continue
    if not server:
        raise SystemExit("Nenhuma porta livre.")
    url = f"http://127.0.0.1:{port}"
    print(f"\n  DocCheck v{__version__} rodando em {url}\n  Roda só neste computador, não grava nada. Ctrl+C para encerrar.\n")
    if open_browser:
        import threading
        import webbrowser
        threading.Timer(0.8, webbrowser.open, [url]).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nEncerrando...")
    finally:
        server.server_close()
