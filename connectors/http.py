"""HTTP connector for chat APIs that accept and return text."""

from __future__ import annotations

import json
import time
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import ProxyHandler, Request, build_opener

from connectors.base import BaseConnector
from errors import ConnectorError, ScopeError
from models import ChatResponse
from safety.limits import RequestBudget


class _RejectRedirects(Exception):
    def __init__(self, location: str) -> None:
        super().__init__(location)
        self.location = location


class _NoRedirect(Exception):
    pass


def _build_opener():
    from urllib.request import HTTPRedirectHandler

    class RejectRedirect(HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            raise _RejectRedirects(str(newurl))

    # An empty proxy handler keeps the scan off environment proxies.
    return build_opener(ProxyHandler({}), RejectRedirect())


def extract_path(payload: Any, path: str) -> Any:
    current = payload
    for part in path.split("."):
        if isinstance(current, list):
            current = current[int(part)]
        elif isinstance(current, dict):
            current = current[part]
        else:
            raise KeyError(path)
    return current


class HttpConnector(BaseConnector):
    channel = "text"
    limitations = [
        "Observes the configured HTTP request and response only.",
        "Does not see browser rendering, microphone capture, or tool calls that are absent from the response.",
    ]

    def __init__(self, config: dict, budget: RequestBudget) -> None:
        super().__init__()
        self.config = config
        self.budget = budget
        target = config["target"]
        self.base_url = target["base_url"].rstrip("/") + "/"
        self.timeout = float(config["scan"]["timeout_seconds"])
        self.opener = _build_opener()
        token = _token(target.get("authentication", {}))
        if token:
            self.secrets.append(token)

    def send_message(self, text: str, session_id: str | None = None) -> ChatResponse:
        target = self.config["target"]
        url = _join(self.base_url, target["endpoint"])
        body = _chat_body(target.get("request", {}), text, session_id)
        response = self._request(target.get("method", "POST"), url, body)
        if response.error and response.status_code is None:
            return response
        answer_field = target.get("response", {}).get("answer_field", "answer")
        events_field = target.get("response", {}).get("tool_events_field")
        parsed = _parse_json(response)
        if parsed is None:
            if response.status_code and response.status_code >= 400:
                return response
            response.error = "The chat response was not JSON."
            return response
        try:
            answer = extract_path(parsed, answer_field)
        except (KeyError, IndexError, ValueError):
            if response.status_code and response.status_code >= 400:
                response.text = json.dumps(parsed)
                return response
            response.error = f"JSON response has no {answer_field} field."
            response.text = json.dumps(parsed)
            return response
        response.text = answer if isinstance(answer, str) else json.dumps(answer)
        if events_field and isinstance(parsed, dict) and events_field in parsed:
            events = parsed[events_field]
            if events is not None and not isinstance(events, list):
                response.error = f"{events_field} must be a list when it is present."
            else:
                response.tool_events = events
        response.session_id = session_id
        return response

    def upload_document(self, content: str) -> str | None:
        spec = self.config.get("fixtures", {}).get("document_upload")
        if not spec:
            return None
        url = _join(self.base_url, spec["endpoint"])
        body = {spec.get("content_field", "content"): content}
        response = self._request(spec.get("method", "POST"), url, body)
        parsed = _require_json(response, "document upload")
        try:
            document_id = extract_path(parsed, spec.get("id_field", "id"))
        except (KeyError, IndexError, ValueError) as exc:
            raise ConnectorError("Document upload response did not include the configured id field.") from exc
        return str(document_id)

    def delete_document(self, document_id: str) -> None:
        spec = self.config.get("fixtures", {}).get("document_delete")
        if not spec:
            return None
        endpoint = spec["endpoint"].replace("{id}", str(document_id))
        url = _join(self.base_url, endpoint)
        response = self._request(spec.get("method", "DELETE"), url, None)
        if response.error and (response.status_code is None or response.status_code >= 400):
            raise ConnectorError(response.error or "Document delete failed.")
        return None

    def verify_output(self, content: str) -> dict | None:
        spec = self.config.get("fixtures", {}).get("output_verification")
        if not spec:
            return None
        url = _join(self.base_url, spec["endpoint"])
        body = {spec.get("content_field", "content"): content}
        response = self._request(spec.get("method", "POST"), url, body)
        parsed = _require_json(response, "output verification")
        field = spec.get("unsafe_field", "unsafe_handling")
        try:
            unsafe = extract_path(parsed, field)
        except (KeyError, IndexError, ValueError) as exc:
            raise ConnectorError(f"Output verification response has no {field} field.") from exc
        return {"unsafe_handling": bool(unsafe), "raw_status": response.status_code}

    def health(self) -> ChatResponse:
        path = self.config["target"].get("health_path", "")
        if not path:
            return ChatResponse(text="skipped", status_code=None)
        url = _join(self.base_url, path)
        return self._request("GET", url, None)

    def _request(self, method: str, url: str, body: dict | None) -> ChatResponse:
        self.budget.consume(1)
        data = None if body is None else json.dumps(body).encode("utf-8")
        headers = {"Accept": "application/json"}
        headers.update(self.config["target"].get("request", {}).get("headers") or {})
        if data is not None:
            headers["Content-Type"] = "application/json"
        auth_header = _auth_header(self.config["target"].get("authentication", {}))
        if auth_header:
            headers.update(auth_header)
        request = Request(url, data=data, headers=headers, method=method.upper())
        started = time.perf_counter()
        try:
            with self.opener.open(request, timeout=self.timeout) as response:
                raw = response.read()
                status = response.status
        except _RejectRedirects as exc:
            raise ScopeError(f"Refusing to follow a redirect to {exc.location}.") from exc
        except HTTPError as exc:
            raw = exc.read()
            status = exc.code
        except URLError as exc:
            return ChatResponse(text="", error=f"Could not reach the target: {exc.reason}")
        except TimeoutError:
            return ChatResponse(text="", error="The request timed out.")
        latency = (time.perf_counter() - started) * 1000
        text = raw.decode("utf-8", errors="replace")
        error = None
        if status >= 500:
            error = f"Server returned HTTP {status}."
        return ChatResponse(text=text, status_code=status, latency_ms=round(latency, 1), error=error)


def _join(base_url: str, endpoint: str) -> str:
    return urljoin(base_url, endpoint.lstrip("/"))


def _token(auth: dict) -> str:
    if not auth or auth.get("type", "none") == "none":
        return ""
    token = str(auth.get("token", "")).strip()
    if not token:
        raise ConnectorError("Authentication is enabled but the token resolved to an empty value.")
    return token


def _auth_header(auth: dict) -> dict[str, str]:
    kind = auth.get("type", "none")
    if kind in {None, "none"}:
        return {}
    token = _token(auth)
    if kind == "bearer":
        return {"Authorization": f"Bearer {token}"}
    if kind == "header":
        name = auth.get("header")
        if not name:
            raise ConnectorError("authentication.header is required when type is header.")
        return {str(name): token}
    raise ConnectorError(f"Unsupported authentication type: {kind}")


def _chat_body(request_config: dict, text: str, session_id: str | None) -> dict:
    body = dict(request_config.get("extra_body") or {})
    style = request_config.get("style", "message_field")
    if style == "messages":
        messages_field = request_config.get("messages_field", "messages")
        role_field = request_config.get("role_field", "role")
        content_field = request_config.get("content_field", "content")
        body[messages_field] = [{role_field: request_config.get("role", "user"), content_field: text}]
    else:
        body[request_config.get("message_field", "message")] = text
    session_field = request_config.get("session_field")
    if session_field and session_id:
        body[session_field] = session_id
    return body


def _parse_json(response: ChatResponse) -> Any | None:
    if not response.text:
        return None
    try:
        return json.loads(response.text)
    except json.JSONDecodeError:
        return None


def _require_json(response: ChatResponse, action: str) -> Any:
    if response.error and response.status_code is None:
        raise ConnectorError(response.error)
    if response.status_code is None or response.status_code >= 400:
        raise ConnectorError(f"{action} failed with HTTP {response.status_code}.")
    parsed = _parse_json(response)
    if parsed is None:
        raise ConnectorError(f"{action} did not return JSON.")
    return parsed
