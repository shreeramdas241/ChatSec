"""Load the target file, substitute environment variables, and validate it."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from catalog import MODULE_IDS
from errors import ConfigError

_ENV = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
ROOT = Path(__file__).resolve().parent
MAX_REQUESTS = 100
MAX_RATE_PROBES = 20
MAX_TIMEOUT = 60


def load_config(path: str | Path) -> dict:
    raw_path = Path(path)
    if not raw_path.is_file():
        raise ConfigError(f"Config file not found: {raw_path}")
    try:
        import yaml
    except ImportError as exc:
        raise ConfigError("PyYAML is required. Install it with: pip install -r requirements.txt") from exc
    loaded = yaml.safe_load(raw_path.read_text(encoding="utf-8"))
    if not isinstance(loaded, dict):
        raise ConfigError("The config file must contain a YAML mapping.")
    config = _interpolate(loaded)
    _reject_inline_secrets(config)
    _validate(config)
    _resolve_auth(config)
    return config


def load_fixtures() -> tuple[dict, dict]:
    probes = json.loads((ROOT / "fixtures" / "probes.json").read_text(encoding="utf-8"))
    synthetic = json.loads((ROOT / "fixtures" / "synthetic_data.json").read_text(encoding="utf-8"))
    return probes, synthetic["markers"]


def estimate_requests(config: dict, probes: dict) -> int:
    selected = config["scan"]["tests"]
    total = 1 if config["target"].get("health_path") else 0
    if "prompt_injection" in selected:
        total += _prompt_probe_count(config, probes)
    if "sensitive_data" in selected:
        total += len(probes["sensitive_data"])
    if "indirect_injection" in selected and config["capabilities"].get("retrieves_documents"):
        total += 3
    if "tool_authorization" in selected and config["capabilities"].get("uses_tools"):
        total += len(probes["tool_authorization"])
    if "output_safety" in selected:
        total += 1
        if config.get("fixtures", {}).get("output_verification"):
            total += 1
    if "rate_limits" in selected:
        total += int(config["policies"]["rate_limits"]["probe_requests"])
    return total


def _prompt_probe_count(config: dict, probes: dict) -> int:
    from tests.common import select_prompt_probes

    policy = config["policies"]["prompt_injection"]
    return len(select_prompt_probes(policy, probes["prompt_injection"]))


def _reject_inline_secrets(config: dict) -> None:
    auth = (config.get("target") or {}).get("authentication") or {}
    if isinstance(auth, dict) and "token" in auth:
        raise ConfigError(
            "Do not store authentication.token in the config file. Use authentication.token_env."
        )


def _resolve_auth(config: dict) -> None:
    auth = config["target"].setdefault("authentication", {"type": "none"})
    kind = auth.get("type", "none")
    if kind in {None, "none"}:
        auth["type"] = "none"
        return
    env_name = auth.get("token_env")
    if not isinstance(env_name, str) or not env_name.strip():
        raise ConfigError("authentication.token_env is required when authentication is enabled.")
    token = os.environ.get(env_name, "")
    if not token.strip():
        raise ConfigError(f"Environment variable {env_name} is empty.")
    auth["token"] = token


def _require_marker_length(values: list[str], where: str) -> None:
    if any(len(value.strip()) < 8 for value in values):
        raise ConfigError(f"{where} entries must be at least 8 characters so they do not match ordinary text.")


def _interpolate(value):
    if isinstance(value, str):
        def replace(match: re.Match) -> str:
            key = match.group(1)
            if key not in os.environ:
                raise ConfigError(
                    f"Environment variable {key} is not set. "
                    "Do not paste the secret into the YAML file."
                )
            return os.environ[key]

        return _ENV.sub(replace, value)
    if isinstance(value, dict):
        return {key: _interpolate(item) for key, item in value.items()}
    if isinstance(value, list):
        return [_interpolate(item) for item in value]
    return value


def _require(mapping: dict, key: str, where: str):
    if key not in mapping:
        raise ConfigError(f"{where} is missing {key}.")
    return mapping[key]


def _validate(config: dict) -> None:
    for section in ("authorization", "target", "capabilities", "policies", "scan"):
        if section not in config or not isinstance(config[section], dict):
            raise ConfigError(f"Config is missing the {section} section.")
    target = config["target"]
    for key in ("name", "base_url", "endpoint", "method"):
        _require(target, key, "target")
    if str(target["method"]).upper() not in {"POST", "PUT"}:
        raise ConfigError("target.method must be POST or PUT for the chat endpoint.")
    auth = target.get("authentication", {"type": "none"})
    kind = auth.get("type", "none")
    if kind not in {"none", "bearer", "header"}:
        raise ConfigError("authentication.type must be none, bearer, or header.")
    request = target.get("request", {})
    style = request.get("style", "message_field")
    if style not in {"message_field", "messages"}:
        raise ConfigError("request.style must be message_field or messages.")

    capabilities = config["capabilities"]
    for key in ("retrieves_documents", "uses_tools"):
        if not isinstance(capabilities.get(key), bool):
            raise ConfigError(f"capabilities.{key} must be true or false.")

    scan = config["scan"]
    tests = scan.get("tests")
    if not isinstance(tests, list) or not tests:
        raise ConfigError("scan.tests must list at least one module.")
    unknown = [item for item in tests if item not in MODULE_IDS]
    if unknown:
        raise ConfigError(f"Unknown test modules: {', '.join(unknown)}.")
    maximum = scan.get("max_requests")
    if not isinstance(maximum, int) or not 1 <= maximum <= MAX_REQUESTS:
        raise ConfigError(f"scan.max_requests must be an integer from 1 to {MAX_REQUESTS}.")
    if scan.get("max_concurrency") != 1:
        raise ConfigError("This version only runs scans sequentially. Set scan.max_concurrency to 1.")
    timeout = scan.get("timeout_seconds")
    if not isinstance(timeout, int) or not 1 <= timeout <= MAX_TIMEOUT:
        raise ConfigError(f"scan.timeout_seconds must be an integer from 1 to {MAX_TIMEOUT}.")

    policies = config["policies"]
    if "prompt_injection" in tests:
        policy = policies.get("prompt_injection", {})
        markers = policy.get("forbidden_markers")
        if not isinstance(markers, list) or not markers or not all(isinstance(item, str) and item for item in markers):
            raise ConfigError("policies.prompt_injection.forbidden_markers needs at least one synthetic marker.")
        _require_marker_length(markers, "policies.prompt_injection.forbidden_markers")
        canary = policy.get("system_canary", "")
        if canary not in ("", None) and not isinstance(canary, str):
            raise ConfigError("policies.prompt_injection.system_canary must be a string when it is set.")
        if isinstance(canary, str) and canary:
            _require_marker_length([canary], "policies.prompt_injection.system_canary")
    if "sensitive_data" in tests:
        canaries = policies.get("sensitive_data", {}).get("canaries")
        if not isinstance(canaries, list) or not canaries:
            raise ConfigError("policies.sensitive_data.canaries needs at least one synthetic canary.")
        _require_marker_length(canaries, "policies.sensitive_data.canaries")
    if "indirect_injection" in tests and capabilities["retrieves_documents"]:
        marker = policies.get("indirect_injection", {}).get("compliance_marker")
        if not isinstance(marker, str) or not marker.strip():
            raise ConfigError("policies.indirect_injection.compliance_marker is required when document retrieval is enabled.")
        _require_marker_length([marker], "policies.indirect_injection.compliance_marker")
        upload = config.get("fixtures", {}).get("document_upload")
        delete = config.get("fixtures", {}).get("document_delete")
        if not upload or not delete:
            raise ConfigError(
                "Document retrieval is enabled, but fixtures.document_upload and "
                "fixtures.document_delete are both required. Set capabilities.retrieves_documents "
                "to false to record the test as not applicable."
            )
    if "tool_authorization" in tests and capabilities["uses_tools"]:
        instrumentation = config.get("instrumentation", {})
        tools = instrumentation.get("prohibited_tools")
        receipt = policies.get("tool_authorization", {}).get("receipt_marker")
        if not isinstance(instrumentation.get("enabled"), bool):
            raise ConfigError("instrumentation.enabled must be true or false when capabilities.uses_tools is true.")
        if instrumentation["enabled"] and not target.get("response", {}).get("tool_events_field"):
            raise ConfigError("target.response.tool_events_field is required when instrumentation.enabled is true.")
        if not isinstance(tools, list) or not tools:
            raise ConfigError("instrumentation.prohibited_tools is required when capabilities.uses_tools is true.")
        if not isinstance(receipt, str) or not receipt.strip():
            raise ConfigError("policies.tool_authorization.receipt_marker is required when tools are enabled.")
        _require_marker_length([receipt], "policies.tool_authorization.receipt_marker")
    if "rate_limits" in tests:
        policy = policies.get("rate_limits", {})
        limit = policy.get("limit")
        probes = policy.get("probe_requests")
        statuses = policy.get("throttle_statuses")
        if not isinstance(limit, int) or limit < 1:
            raise ConfigError("policies.rate_limits.limit must be a positive integer.")
        if not isinstance(probes, int) or probes <= limit or probes > MAX_RATE_PROBES:
            raise ConfigError(
                f"policies.rate_limits.probe_requests must be greater than the limit and at most {MAX_RATE_PROBES}."
            )
        if not isinstance(statuses, list) or not statuses or not all(isinstance(item, int) for item in statuses):
            raise ConfigError("policies.rate_limits.throttle_statuses must list integer HTTP status codes.")

    if "output_safety" in tests and config.get("fixtures", {}).get("output_verification"):
        spec = config["fixtures"]["output_verification"]
        for key in ("endpoint", "content_field", "unsafe_field"):
            if not spec.get(key):
                raise ConfigError(f"fixtures.output_verification.{key} is required.")
