"""JSON and Markdown reports. Evidence is redacted before it is written."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path

from catalog import TOOL_NAME
from models import TestResult
from safety.redaction import redact_text

STATUS_LABELS = {
    "passed": "Passed",
    "finding": "Finding",
    "inconclusive": "Inconclusive",
    "not_applicable": "Not applicable",
    "needs_instrumentation": "Needs instrumentation",
    "needs_verification": "Needs verification",
    "error": "Error",
    "not_run": "Not run",
}


def build_report(config: dict, connector, results: list[TestResult], budget: dict, error: str | None = None) -> dict:
    serialized = [_serialize(result, connector.secrets) for result in results]
    counts: dict[str, int] = {}
    for result in serialized:
        counts[result["status"]] = counts.get(result["status"], 0) + 1
    return {
        "schema_version": 1,
        "tool": TOOL_NAME,
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "target": {
            "name": config["target"]["name"],
            "base_url": config["target"]["base_url"],
            "environment": config["scan"]["environment"],
            "owner": config["authorization"]["owner"],
            "purpose": config["authorization"]["purpose"],
        },
        "channel": connector.channel,
        "budget": budget,
        "summary": counts,
        "error": error,
        "limitations": list(connector.limitations) + [
            "A skipped, inconclusive, or unverified result is not a successful security test.",
            "These six modules check the requirements in the config. They do not cover every AI security risk.",
        ],
        "results": serialized,
    }


def write_report(report: dict, output_dir: str | Path) -> tuple[Path, Path]:
    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    stamp = report["generated_at"].replace("-", "").replace(":", "")
    stem = directory / f"chatsec-{stamp}-{uuid.uuid4().hex[:6]}"
    json_path = stem.with_suffix(".json")
    markdown_path = stem.with_suffix(".md")
    json_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    markdown_path.write_text(render_markdown(report), encoding="utf-8")
    return json_path, markdown_path


def render_markdown(report: dict) -> str:
    target = report["target"]
    lines = [
        f"# {report['tool']} results",
        "",
        f"Target: {target['name']}",
        f"Environment: {target['environment']}",
        f"Channel: {report['channel']}",
        f"Generated: {report['generated_at']}",
        "",
        "| Module | Status | Confidence |",
        "| --- | --- | --- |",
    ]
    for result in report["results"]:
        label = STATUS_LABELS.get(result["status"], result["status"])
        lines.append(f"| {result['title']} | {label} | {result['confidence']} |")
    if report.get("error"):
        lines.extend(["", f"Scan error: {report['error']}"])
    lines.extend(["", "## Results", ""])
    for result in report["results"]:
        label = STATUS_LABELS.get(result["status"], result["status"])
        lines.append(f"### {result['title']}: {label}")
        lines.append("")
        lines.append(result["summary"])
        lines.append("")
        lines.append(f"Requirement: {result['requirement']}")
        lines.append("")
        lines.append(f"Remediation: {result['remediation']}")
        lines.append("")
        lines.append(f"Rerun: `{result['rerun']}`")
        for note in result.get("limitations") or []:
            if note:
                lines.append("")
                lines.append(f"Limitation: {note}")
        for item in result.get("evidence") or []:
            lines.extend([
                "",
                f"Evidence ({item['description']}):",
                "",
                "Request:",
                "",
                "```",
                item["request_text"],
                "```",
                "",
                "Response:",
                "",
                "```",
                item["response_text"],
                "```",
            ])
        lines.append("")
    if report.get("limitations"):
        lines.extend(["## Scan limitations", ""])
        for note in report["limitations"]:
            lines.append(f"- {note}")
        lines.append("")
    return "\n".join(lines)


def print_summary(report: dict, json_path: Path, markdown_path: Path) -> None:
    target = report["target"]
    print("")
    print(report["tool"])
    print(f"Target: {target['name']}  Environment: {target['environment']}  Channel: {report['channel']}")
    print("")
    for result in report["results"]:
        label = STATUS_LABELS.get(result["status"], result["status"])
        print(f"{result['title']:<28} {label}")
    if report.get("error"):
        print("")
        print(f"Scan error: {report['error']}")
    findings = report["summary"].get("finding", 0)
    print("")
    print(f"Findings: {findings}")
    print(f"JSON report: {json_path}")
    print(f"Markdown report: {markdown_path}")


def _serialize(result: TestResult, secrets: list[str]) -> dict:
    return {
        "module": result.module,
        "title": result.title,
        "status": result.status,
        "summary": result.summary,
        "requirement": result.requirement,
        "confidence": result.confidence,
        "remediation": result.remediation,
        "rerun": result.rerun,
        "limitations": [note for note in result.limitations if note],
        "evidence": [
            {
                "description": item.description,
                "request_text": redact_text(item.request_text, secrets),
                "response_text": redact_text(item.response_text, secrets),
                "status_code": item.status_code,
                "extra": item.extra,
            }
            for item in result.evidence
        ],
    }
