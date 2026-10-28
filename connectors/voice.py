"""Voice as another transport. The six tests still see text in and text out."""

from __future__ import annotations

from connectors.base import BaseConnector
from connectors.http import HttpConnector
from models import ChatResponse
from safety.limits import RequestBudget


class VoiceTranscriptConnector(BaseConnector):
    """Submit text to the chatbot API and label the channel as a transcript.

    This checks the assistant behind a voice product. It does not check speech
    recognition, audio prompt injection, or spoken playback.
    """

    channel = "voice_transcript"
    limitations = [
        "Transcript mode sends text through the HTTP API.",
        "Speech recognition, spoken prompt injection, and audio playback are not tested.",
        "An audio-file adapter can be added behind this same send_message contract once recordings exist.",
    ]

    def __init__(self, inner: HttpConnector) -> None:
        super().__init__()
        self.inner = inner
        self.secrets = inner.secrets

    def send_message(self, text: str, session_id: str | None = None) -> ChatResponse:
        return self.inner.send_message(text, session_id=session_id)

    def upload_document(self, content: str) -> str | None:
        return self.inner.upload_document(content)

    def delete_document(self, document_id: str) -> None:
        return self.inner.delete_document(document_id)

    def verify_output(self, content: str) -> dict | None:
        return self.inner.verify_output(content)

    def health(self) -> ChatResponse:
        return self.inner.health()


def build_voice(config: dict, budget: RequestBudget) -> VoiceTranscriptConnector:
    mode = config.get("connector", {}).get("voice_mode", "transcript")
    if mode != "transcript":
        from errors import IntegrationUnavailable

        raise IntegrationUnavailable(
            "Audio mode is not available yet. Use connector.voice_mode transcript to test the "
            "text path of a voice bot, or add audio fixtures and an audio endpoint later. "
            "Text probes cannot measure speech recognition."
        )
    return VoiceTranscriptConnector(HttpConnector(config, budget))
