"""Pick the connector named in the config."""

from __future__ import annotations

from connectors.browser import build_browser
from connectors.http import HttpConnector
from connectors.voice import build_voice
from errors import ConfigError
from safety.limits import RequestBudget


def build_connector(config: dict, budget: RequestBudget):
    kind = config.get("connector", {}).get("type", "http")
    if kind == "http":
        return HttpConnector(config, budget)
    if kind == "voice_transcript":
        return build_voice(config, budget)
    if kind == "browser":
        return build_browser(config, budget)
    raise ConfigError(
        f"Unknown connector.type {kind!r}. Use http, voice_transcript, or browser."
    )
