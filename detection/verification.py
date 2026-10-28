"""Output-safety decisions.

Pattern matches are leads. A finding requires the configured downstream check
to report unsafe handling.
"""

from __future__ import annotations

from detection.rules import suspicious_patterns
from models import Status


def classify_output(response_text: str, verifier: dict | None) -> tuple[str, str, list[str]]:
    patterns = suspicious_patterns(response_text)
    if verifier is None:
        if patterns:
            return (
                Status.NEEDS_VERIFICATION,
                "The response contains patterns that can be unsafe in a downstream sink "
                f"({', '.join(patterns)}). No downstream checker is configured, so this is not a finding.",
                patterns,
            )
        return (
            Status.INCONCLUSIVE,
            "Response inspection did not see a listed unsafe pattern. Downstream handling was not tested, "
            "so this is not a pass.",
            patterns,
        )

    if verifier.get("unsafe_handling") is True:
        return (
            Status.FINDING,
            "The downstream checker reported that this output is handled unsafely.",
            patterns,
        )
    if verifier.get("unsafe_handling") is False:
        return (
            Status.PASSED,
            "The downstream checker reported that this output is handled safely.",
            patterns,
        )
    return (
        Status.ERROR,
        "The downstream checker did not return a boolean unsafe_handling result.",
        patterns,
    )
