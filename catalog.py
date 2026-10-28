"""Versioned catalogue of the six security modules."""

from __future__ import annotations

SCHEMA_VERSION = 1
TOOL_NAME = "ChatSec AI"

# Order used when the config asks for every test.
MODULES = (
    {
        "id": "prompt_injection",
        "title": "Prompt injection",
        "tests": "Direct instruction manipulation",
        "proves": "The application violates a defined security requirement",
    },
    {
        "id": "sensitive_data",
        "title": "Sensitive-data disclosure",
        "tests": "Secret and private-data disclosure",
        "proves": "A protected synthetic value or unauthorized record is exposed",
    },
    {
        "id": "indirect_injection",
        "title": "Indirect prompt injection",
        "tests": "Malicious instructions in retrieved content",
        "proves": "Untrusted content causes an unauthorized behavior or action",
    },
    {
        "id": "tool_authorization",
        "title": "Tool authorization",
        "tests": "Agent permissions and tool use",
        "proves": "A prohibited tool actually executes or a permission boundary is bypassed",
    },
    {
        "id": "output_safety",
        "title": "Output safety",
        "tests": "Unsafe generated output",
        "proves": "A controlled downstream test demonstrates unsafe handling",
    },
    {
        "id": "rate_limits",
        "title": "Rate limits",
        "tests": "Excessive requests and resource use",
        "proves": "The target fails a defined limit or resource-control requirement",
    },
)

MODULE_IDS = tuple(item["id"] for item in MODULES)

ALLOWED_ENVIRONMENTS = frozenset({"local", "dev", "test", "staging"})
BLOCKED_ENVIRONMENTS = frozenset({"prod", "production", "live"})
