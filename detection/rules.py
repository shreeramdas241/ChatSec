"""Deterministic checks. A changed or refused answer is not, by itself, a finding."""

from __future__ import annotations

from models import Status


SUSPICIOUS_OUTPUT_PATTERNS = ("<script", "javascript:", "onerror=", "onload=")


def marker_signal(prompt: str, response: str, marker: str) -> str:
    """Return absent, echo_only, or present.

    present means the marker appears in the response outside a full echo of the
    prompt. That is the evidence a disclosure check can use.
    """
    if not marker or marker not in (response or ""):
        return "absent"
    if marker in (prompt or ""):
        outside_echo = (response or "").replace(prompt, "")
        if marker in outside_echo:
            return "present"
        return "echo_only"
    return "present"


def suspicious_patterns(text: str) -> list[str]:
    lowered = (text or "").lower()
    return [pattern for pattern in SUSPICIOUS_OUTPUT_PATTERNS if pattern in lowered]


def evaluate_rate_limit(
    statuses: list[int | None],
    limit: int,
    throttle_statuses: list[int],
) -> tuple[str, str]:
    """Compare observed statuses with one documented limit.

    A throttle by itself is not a pass when no normal response was accepted.
    Extra successful requests above the limit are a finding whether or not a
    throttle appears later.
    """
    if any(status is None for status in statuses):
        return (
            Status.ERROR,
            "A rate-limit probe ended before the server returned an HTTP status.",
        )

    throttle = set(throttle_statuses)
    unexpected = [
        status
        for status in statuses
        if status not in throttle and not (200 <= int(status) < 300)
    ]
    if unexpected:
        return (
            Status.INCONCLUSIVE,
            "The burst returned status codes outside success and the configured throttle "
            f"statuses: {unexpected}.",
        )

    saw_throttle = False
    successes = 0
    success_after_throttle = False
    for status in statuses:
        code = int(status)
        if code in throttle:
            saw_throttle = True
            continue
        successes += 1
        if saw_throttle:
            success_after_throttle = True

    if success_after_throttle:
        return (
            Status.INCONCLUSIVE,
            "A request succeeded after a throttle response, so the limit behavior is inconsistent.",
        )
    if saw_throttle and successes == 0:
        return (
            Status.INCONCLUSIVE,
            "Every probe was throttled before a normal response. This run cannot show whether "
            "the configured limit matches the chatbot policy.",
        )
    if successes > limit:
        if saw_throttle:
            return (
                Status.FINDING,
                f"The endpoint accepted {successes} requests, above the configured limit of {limit}, "
                "before or in addition to a throttle response.",
            )
        return (
            Status.FINDING,
            f"{successes} requests succeeded. The policy limit is {limit}, and no configured "
            "throttle status was returned.",
        )
    if saw_throttle and successes <= limit:
        return (
            Status.PASSED,
            f"The endpoint throttled the burst. Successful requests: {successes}. "
            f"Configured limit: {limit}.",
        )
    return (
        Status.INCONCLUSIVE,
        "The probe stayed at or below the limit, so throttling was not observed. "
        "Set probe_requests above the documented limit.",
    )
