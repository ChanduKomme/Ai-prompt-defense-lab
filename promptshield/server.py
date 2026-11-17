"""Minimal JSON HTTP API for the guarded agent (standard library only).

Author: Chandu Komme

Endpoints
    GET  /healthz            liveness check
    POST /v1/ask             {"question": "...", "confirmed": false}
    POST /v1/scan            {"text": "...", "channel": "user" | "context"}

Requests over 8 KB are rejected, and every response is JSON. Bind to
127.0.0.1 for local testing.
"""

from __future__ import annotations

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json

from . import __version__, detector
from .agents import GuardedAgent

__author__ = "Chandu Komme"

MAX_BODY = 8192


def make_handler(agent: GuardedAgent):
    class Handler(BaseHTTPRequestHandler):
        server_version = f"PromptShield/{__version__}"

        def log_message(self, *_args):  # keep test output quiet
            return

        def _send(self, status: int, payload: dict) -> None:
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("X-Content-Type-Options", "nosniff")
            self.end_headers()
            self.wfile.write(body)

        def _json(self) -> dict | None:
            length = int(self.headers.get("Content-Length") or 0)
            if length <= 0 or length > MAX_BODY:
                self._send(413 if length > MAX_BODY else 400, {"error": "body must be 1 to 8192 bytes of JSON"})
                return None
            try:
                data = json.loads(self.rfile.read(length))
            except (ValueError, UnicodeDecodeError):
                self._send(400, {"error": "invalid JSON"})
                return None
            if not isinstance(data, dict):
                self._send(400, {"error": "JSON object expected"})
                return None
            return data

        def do_GET(self):
            if self.path == "/healthz":
                self._send(200, {"status": "ok", "version": __version__})
            else:
                self._send(404, {"error": "not found"})

        def do_POST(self):
            if self.path not in ("/v1/ask", "/v1/scan"):
                self._send(404, {"error": "not found"})
                return
            data = self._json()
            if data is None:
                return
            if self.path == "/v1/ask":
                question = data.get("question")
                if not isinstance(question, str) or not question.strip():
                    self._send(400, {"error": "question must be a non-empty string"})
                    return
                response = agent.answer(question, confirmed=data.get("confirmed") is True)
                self._send(200, response.to_dict())
            else:
                text, channel = data.get("text"), data.get("channel", "user")
                if not isinstance(text, str) or channel not in ("user", "context"):
                    self._send(400, {"error": "text must be a string and channel user or context"})
                    return
                self._send(200, detector.scan(text, channel).to_dict())

    return Handler


def serve(host: str = "127.0.0.1", port: int = 8080, agent: GuardedAgent | None = None) -> ThreadingHTTPServer:
    return ThreadingHTTPServer((host, port), make_handler(agent or GuardedAgent()))
