"""Connector contract used by every security module."""

from __future__ import annotations

from models import ChatResponse


class BaseConnector:
    channel = "text"
    limitations: list[str] = []

    def __init__(self) -> None:
        self.secrets: list[str] = []

    def send_message(self, text: str, session_id: str | None = None) -> ChatResponse:
        raise NotImplementedError

    def upload_document(self, content: str) -> str | None:
        return None

    def delete_document(self, document_id: str) -> None:
        return None

    def verify_output(self, content: str) -> dict | None:
        return None

    def health(self) -> ChatResponse:
        raise NotImplementedError
