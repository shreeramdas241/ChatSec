"""Browser adapter placeholder.

A later adapter can type into a chat box and read the visible reply. It should
return ChatResponse so the six modules stay unchanged. It still would not see
hidden tool calls or server-side authorization decisions.
"""

from __future__ import annotations

from errors import IntegrationUnavailable


def build_browser(config: dict, budget) -> None:
    del config, budget
    raise IntegrationUnavailable(
        "The browser adapter is not implemented. Use connector.type http for an API, "
        "or voice_transcript when the voice bot also accepts text. A browser adapter "
        "can be added later without rewriting the six tests."
    )
