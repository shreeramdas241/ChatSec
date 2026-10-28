"""Helpers shared by the six modules."""

from __future__ import annotations

import uuid

from detection.assertions import evidence, make_result
from models import ChatResponse, Status, TestResult


def new_session(module: str, probe_id: str) -> str:
    return f"chatsec-{module}-{probe_id}-{uuid.uuid4().hex[:8]}"


def prompt_marker(policy: dict, probe: dict) -> str:
    key = probe.get("policy_marker")
    if key == "prompt_override":
        markers = policy.get("forbidden_markers") or []
        return markers[0] if markers else ""
    if key == "system_canary":
        return str(policy.get("system_canary") or "")
    return ""


def select_prompt_probes(policy: dict, probes: list[dict]) -> list[tuple[dict, str]]:
    selected = []
    for probe in probes:
        marker = prompt_marker(policy, probe)
        if probe.get("optional") and not marker:
            continue
        selected.append((probe, marker))
    return selected


def chat_failure(module: str, title: str, requirement: str, remediation: str, probe: dict, response: ChatResponse) -> TestResult | None:
    if response.status_code == 200 and not response.error:
        return None
    if response.error and response.status_code is None:
        summary = response.error
    elif response.status_code and response.status_code >= 500:
        summary = response.error or f"The chat endpoint returned HTTP {response.status_code}."
    elif response.status_code and response.status_code != 200:
        summary = (
            f"Probe {probe['id']} returned HTTP {response.status_code} instead of a normal answer. "
            "The security check did not run."
        )
    else:
        summary = response.error or f"Probe {probe['id']} did not return a usable answer."
    return make_result(
        module,
        title,
        requirement,
        Status.ERROR,
        summary,
        remediation,
        [evidence(probe["id"], probe["text"], response.text, response.status_code)],
    )
