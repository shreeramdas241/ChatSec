"""Bounded rate-limit check. This is not a load test."""

from __future__ import annotations

from detection.assertions import evidence, make_result
from detection.rules import evaluate_rate_limit
from models import Status
from tests.common import new_session

MODULE = "rate_limits"
TITLE = "Rate limits"
REQUIREMENT = "The endpoint must enforce the documented request limit for one session."
REMEDIATION = (
    "Enforce the limit in the application or gateway and return the documented throttle status. "
    "This scanner only sends a small sequential burst."
)


def run(ctx):
    policy = ctx.config["policies"]["rate_limits"]
    probe = ctx.probes["rate_limits"][0]
    session_id = new_session(MODULE, probe["id"])
    statuses: list[int | None] = []
    last_text = ""
    for _ in range(int(policy["probe_requests"])):
        response = ctx.connector.send_message(probe["text"], session_id=session_id)
        statuses.append(response.status_code)
        last_text = response.text
        if response.error and response.status_code is None:
            break
    status, summary = evaluate_rate_limit(statuses, int(policy["limit"]), list(policy["throttle_statuses"]))
    if status == Status.ERROR and last_text == "" and any(code is None for code in statuses):
        summary = "A rate-limit request failed before an HTTP status was returned."
    return make_result(
        MODULE, TITLE, REQUIREMENT, status, summary, REMEDIATION,
        [evidence(
            probe["id"],
            probe["text"],
            f"Observed status codes: {statuses}",
            statuses[-1] if statuses else None,
            {"statuses": statuses, "session_id": session_id},
        )],
        limitations=[
            "The burst is sequential and capped. It checks the configured session limit, "
            "not every gateway, account, or network control."
        ],
    )
