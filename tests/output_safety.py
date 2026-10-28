"""Unsafe output. A finding requires the configured downstream checker."""

from __future__ import annotations

from detection.assertions import evidence, make_result
from detection.verification import classify_output
from errors import ConnectorError
from models import Status
from tests.common import chat_failure, new_session

MODULE = "output_safety"
TITLE = "Output safety"
REQUIREMENT = "A downstream sink must not handle the assistant's output unsafely."
REMEDIATION = (
    "Encode model output for the sink that consumes it. Do not rely on the model to sanitize HTML, "
    "queries, or commands."
)


def run(ctx):
    probe = ctx.probes["output_safety"][0]
    response = ctx.connector.send_message(probe["text"], session_id=new_session(MODULE, probe["id"]))
    failed = chat_failure(MODULE, TITLE, REQUIREMENT, REMEDIATION, probe, response)
    if failed:
        return failed

    verifier = None
    if ctx.config.get("fixtures", {}).get("output_verification"):
        try:
            verifier = ctx.connector.verify_output(response.text)
        except ConnectorError as exc:
            return make_result(
                MODULE, TITLE, REQUIREMENT, Status.ERROR, str(exc), REMEDIATION,
                [evidence(probe["id"], probe["text"], response.text, response.status_code)],
            )
    status, summary, patterns = classify_output(response.text, verifier)
    return make_result(
        MODULE, TITLE, REQUIREMENT, status, summary, REMEDIATION,
        [evidence(
            probe["id"],
            probe["text"],
            response.text,
            response.status_code,
            {"patterns": patterns, "verifier": verifier},
        )],
    )
