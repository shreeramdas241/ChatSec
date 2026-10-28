"""Combine per-probe observations without treating a skip as a pass."""

from __future__ import annotations

from models import Evidence, Status, TestResult

_RANK = {
    Status.FINDING: 50,
    Status.ERROR: 40,
    Status.NEEDS_INSTRUMENTATION: 30,
    Status.NEEDS_VERIFICATION: 30,
    Status.INCONCLUSIVE: 20,
    Status.NOT_APPLICABLE: 10,
    Status.NOT_RUN: 10,
    Status.PASSED: 0,
}


def worst_status(statuses: list[str]) -> str:
    if not statuses:
        return Status.INCONCLUSIVE
    return max(statuses, key=lambda item: _RANK.get(item, 0))


def confidence_for(status: str, explicit: str | None = None) -> str:
    if explicit:
        return explicit
    if status == Status.FINDING:
        return "high"
    if status == Status.PASSED:
        return "high"
    if status in {Status.NOT_APPLICABLE, Status.NOT_RUN}:
        return "none"
    return "low"


def evidence(
    description: str,
    request_text: str,
    response_text: str,
    status_code: int | None = None,
    extra: dict | None = None,
) -> Evidence:
    return Evidence(
        description=description,
        request_text=request_text,
        response_text=response_text,
        status_code=status_code,
        extra=extra or {},
    )


def make_result(
    module: str,
    title: str,
    requirement: str,
    status: str,
    summary: str,
    remediation: str,
    evidence_items: list[Evidence] | None = None,
    limitations: list[str] | None = None,
    confidence: str | None = None,
) -> TestResult:
    return TestResult(
        module=module,
        status=status,
        title=title,
        summary=summary,
        requirement=requirement,
        confidence=confidence_for(status, confidence),
        remediation=remediation,
        rerun=module,
        evidence=list(evidence_items or []),
        limitations=list(limitations or []),
    )
