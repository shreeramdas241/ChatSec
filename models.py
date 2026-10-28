"""Shared result and response types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class Status:
    PASSED = "passed"
    FINDING = "finding"
    INCONCLUSIVE = "inconclusive"
    NOT_APPLICABLE = "not_applicable"
    NEEDS_INSTRUMENTATION = "needs_instrumentation"
    NEEDS_VERIFICATION = "needs_verification"
    ERROR = "error"
    NOT_RUN = "not_run"


@dataclass
class ChatResponse:
    text: str
    status_code: int | None = None
    session_id: str | None = None
    latency_ms: float | None = None
    tool_events: list[dict[str, Any]] | None = None
    error: str | None = None


@dataclass
class Evidence:
    description: str
    request_text: str
    response_text: str
    status_code: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class TestResult:
    module: str
    status: str
    title: str
    summary: str
    requirement: str
    confidence: str
    remediation: str
    rerun: str
    evidence: list[Evidence] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


@dataclass
class ScanContext:
    config: dict[str, Any]
    connector: Any
    probes: dict[str, Any]
    markers: dict[str, str]
