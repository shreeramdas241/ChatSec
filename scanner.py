"""Scan orchestration."""

from __future__ import annotations

from pathlib import Path

from catalog import MODULES
from configload import estimate_requests, load_config, load_fixtures
from connectors.factory import build_connector
from detection.assertions import make_result
from errors import BudgetExceeded, ConfigError, ConnectorError, ScopeError
from models import ScanContext, Status
from reporting.report import build_report, print_summary, write_report
from safety.limits import RequestBudget
from safety.scope import enforce_scope
from tests import RUNNERS

TITLES = {item["id"]: item["title"] for item in MODULES}
PROVES = {item["id"]: item["proves"] for item in MODULES}


def run_scan(config_path: str, output_dir: str, only_tests: list[str] | None = None, strict: bool = False) -> int:
    config = load_config(config_path)
    if only_tests:
        config["scan"]["tests"] = only_tests
        from configload import _validate

        _validate(config)
    enforce_scope(config)
    probes, _markers = load_fixtures()
    estimated = estimate_requests(config, probes)
    maximum = config["scan"]["max_requests"]
    if estimated > maximum:
        raise ConfigError(
            f"This selection needs about {estimated} requests, but scan.max_requests is {maximum}. "
            f"Raise the budget up to 100 or run fewer tests."
        )

    budget = RequestBudget(maximum)
    connector = build_connector(config, budget)
    health_path = config["target"].get("health_path")
    if health_path:
        health = connector.health()
        if health.status_code != 200:
            message = health.error or f"Health check returned HTTP {health.status_code}."
            report = build_report(config, connector, [], budget.snapshot(), error=message)
            json_path, markdown_path = write_report(report, output_dir)
            print_summary(report, json_path, markdown_path)
            return 2

    context = ScanContext(config=config, connector=connector, probes=probes, markers={})
    results = []
    stopped = False
    for module_id in config["scan"]["tests"]:
        if stopped:
            results.append(_not_run(module_id, "Not run because an earlier step stopped the scan."))
            continue
        try:
            result = RUNNERS[module_id](context)
        except BudgetExceeded as exc:
            result = _error(module_id, str(exc))
            stopped = True
        except ScopeError as exc:
            result = _error(module_id, str(exc))
            stopped = True
        except ConnectorError as exc:
            result = _error(module_id, str(exc))
        except Exception as exc:
            result = _error(module_id, f"{type(exc).__name__}: {exc}")
        result.rerun = _rerun(config_path, module_id)
        results.append(result)

    report = build_report(config, connector, results, budget.snapshot())
    json_path, markdown_path = write_report(report, output_dir)
    print_summary(report, json_path, markdown_path)
    return _exit_code(results, strict)


def _rerun(config_path: str, module_id: str) -> str:
    return f"python chatsec.py scan --config {config_path} --tests {module_id}"


def _error(module_id: str, summary: str):
    return make_result(
        module_id,
        TITLES[module_id],
        PROVES[module_id],
        Status.ERROR,
        summary,
        "Fix the connector or target error, then rerun this module.",
    )


def _not_run(module_id: str, summary: str):
    return make_result(
        module_id,
        TITLES[module_id],
        PROVES[module_id],
        Status.NOT_RUN,
        summary,
        "Rerun the module after the scan can complete.",
    )


def _exit_code(results, strict: bool) -> int:
    statuses = [result.status for result in results]
    if Status.FINDING in statuses:
        return 1
    if Status.ERROR in statuses or Status.NOT_RUN in statuses:
        return 2
    if strict and any(status in {
        Status.INCONCLUSIVE,
        Status.NEEDS_INSTRUMENTATION,
        Status.NEEDS_VERIFICATION,
    } for status in statuses):
        return 1
    return 0


def default_output_dir() -> str:
    return str(Path("reports"))
