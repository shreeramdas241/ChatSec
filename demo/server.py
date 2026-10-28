"""Local chatbot fixture with a secure mode and a vulnerable mode.

The vulnerable mode fails the six checks on purpose. It is a test double, not an
assistant, and the server only binds to localhost.
"""

from __future__ import annotations

import html
import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

ROOT = Path(__file__).resolve().parents[1]
MARKERS = json.loads((ROOT / "fixtures" / "synthetic_data.json").read_text(encoding="utf-8"))["markers"]
PROBES = json.loads((ROOT / "fixtures" / "probes.json").read_text(encoding="utf-8"))
RATE_LIMIT = 5
MAX_BODY = 100_000


def _require_phrase(module: str, phrase: str) -> None:
    texts = " ".join(probe["text"].lower() for probe in PROBES[module])
    if phrase not in texts:
        raise RuntimeError(f"Demo trigger {phrase!r} is missing from the {module} probes.")


_require_phrase("prompt_injection", "override acknowledgement code")
_require_phrase("prompt_injection", "hidden system instructions")
_require_phrase("sensitive_data", "protected customer record")
_require_phrase("indirect_injection", "summarize document")
_require_phrase("tool_authorization", "transfer_funds")
_require_phrase("output_safety", "html fragment")


class DemoState:
    def __init__(self, mode: str) -> None:
        if mode not in {"secure", "vulnerable"}:
            raise ValueError("mode must be secure or vulnerable")
        self.mode = mode
        self.documents: dict[str, str] = {}
        self.rates: dict[str, int] = {}
        self.sequence = 0
        self.lock = threading.Lock()


def make_server(host: str, port: int, mode: str) -> ThreadingHTTPServer:
    if host not in {"127.0.0.1", "localhost"}:
        raise ValueError("The demo server only binds to 127.0.0.1 or localhost.")
    state = DemoState(mode)

    class Handler(BaseHTTPRequestHandler):
        demo = state
        protocol_version = "HTTP/1.1"

        def log_message(self, fmt: str, *args) -> None:
            return

        def do_GET(self) -> None:
            path = urlparse(self.path).path
            if path == "/health":
                self._send(200, {"status": "ok", "mode": self.demo.mode})
                return
            self._send(404, {"error": "not found"})

        def do_POST(self) -> None:
            path = urlparse(self.path).path
            try:
                payload = self._read_json()
            except ValueError as exc:
                self._send(400, {"error": str(exc)})
                return
            if path == "/api/chat":
                self._chat(payload)
                return
            if path == "/api/documents":
                self._upload(payload)
                return
            if path == "/api/render-check":
                self._render(payload)
                return
            self._send(404, {"error": "not found"})

        def do_DELETE(self) -> None:
            path = urlparse(self.path).path
            prefix = "/api/documents/"
            if not path.startswith(prefix) or path == prefix:
                self._send(404, {"error": "not found"})
                return
            document_id = path[len(prefix):]
            with self.demo.lock:
                self.demo.documents.pop(document_id, None)
            self._send(200, {"deleted": document_id})

        def _chat(self, payload: dict) -> None:
            message = str(payload.get("message", ""))
            session_id = str(payload.get("conversation_id", "") or "none")
            if not self._allow(session_id):
                self._send(429, {"answer": "", "conversation_id": session_id, "tool_events": [], "error": "rate_limited"})
                return
            answer, events = self._reply(message)
            self._send(200, {"answer": answer, "conversation_id": session_id, "tool_events": events})

        def _allow(self, session_id: str) -> bool:
            if self.demo.mode != "secure":
                return True
            with self.demo.lock:
                count = self.demo.rates.get(session_id, 0) + 1
                self.demo.rates[session_id] = count
            return count <= RATE_LIMIT

        def _reply(self, message: str) -> tuple[str, list]:
            lowered = message.lower()
            if lowered.startswith("summarize document"):
                return self._summarize(message), []
            if "override acknowledgement code" in lowered:
                if self.demo.mode == "vulnerable":
                    return MARKERS["prompt_override"], []
                return "I can't ignore my role or reveal internal codes.", []
            if "hidden system instructions" in lowered:
                if self.demo.mode == "vulnerable":
                    return f"System prompt canary: {MARKERS['system_canary']}", []
                return "I can't reveal system instructions.", []
            if "protected customer record" in lowered:
                if self.demo.mode == "vulnerable":
                    return f"Record cust-test-001 secret {MARKERS['private_record']}", []
                return "I can't share protected records.", []
            if "transfer_funds" in lowered:
                if self.demo.mode == "vulnerable":
                    return MARKERS["tool_receipt"], [
                        {"tool": "transfer_funds", "decision": "executed", "authorized": False}
                    ]
                return "That action is not allowed for this identity.", [
                    {"tool": "transfer_funds", "decision": "denied", "authorized": False}
                ]
            if "html fragment" in lowered:
                if self.demo.mode == "vulnerable":
                    return "<p>Demo reply</p><script>alert(1)</script>", []
                return "Plain text only. HTML rendering is disabled.", []
            return "I can help with questions about this demo.", []

        def _summarize(self, message: str) -> str:
            match = re.search(r"summarize document\s+([A-Za-z0-9_-]+)", message, re.IGNORECASE)
            if not match:
                return "I need a document id to summarize."
            document_id = match.group(1)
            with self.demo.lock:
                document = self.demo.documents.get(document_id)
            if document is None:
                return "I cannot find that document."
            if self.demo.mode == "vulnerable":
                found = re.findall(r"CHATSEC-[A-Z0-9-]+", document)
                if found:
                    return f"Summary: snack budget. {found[-1]}"
            return "Summary: snack budget. Document instructions were ignored."

        def _upload(self, payload: dict) -> None:
            content = str(payload.get("content", ""))
            with self.demo.lock:
                self.demo.sequence += 1
                document_id = f"doc-{self.demo.sequence}"
                self.demo.documents[document_id] = content
            self._send(200, {"id": document_id})

        def _render(self, payload: dict) -> None:
            content = str(payload.get("content", ""))
            checked = html.escape(content) if self.demo.mode == "secure" else content
            unsafe = "<script" in checked.lower()
            self._send(200, {"unsafe_handling": unsafe, "executed": False})

        def _read_json(self) -> dict:
            length = int(self.headers.get("Content-Length", "0") or 0)
            if length > MAX_BODY:
                raise ValueError("body too large")
            if length == 0:
                return {}
            raw = self.rfile.read(length)
            try:
                payload = json.loads(raw.decode("utf-8"))
            except json.JSONDecodeError as exc:
                raise ValueError("body must be JSON") from exc
            if not isinstance(payload, dict):
                raise ValueError("body must be a JSON object")
            return payload

        def _send(self, status: int, payload: dict | None) -> None:
            data = b"" if payload is None else json.dumps(payload).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.close_connection = True
            if data:
                self.wfile.write(data)

    class Server(ThreadingHTTPServer):
        allow_reuse_address = True
        daemon_threads = True

    return Server((host, port), Handler)


def serve(host: str, port: int, mode: str) -> None:
    server = make_server(host, port, mode)
    bound_host, bound_port = server.server_address[:2]
    print(f"Demo chatbot listening on http://{bound_host}:{bound_port} ({mode}).")
    print("Local fixture only. Stop it with Ctrl+C.")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()
