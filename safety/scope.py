"""Authorization and target-scope checks.

These checks stop an accidental scan of an unlisted host. They do not prove
that the operator has permission. Only scan systems you are allowed to test.
"""

from __future__ import annotations

from urllib.parse import urlparse

from catalog import ALLOWED_ENVIRONMENTS, BLOCKED_ENVIRONMENTS
from errors import ScopeError


def _host(base_url: str) -> str:
    parsed = urlparse(base_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise ScopeError("target.base_url must be an http or https URL with a host.")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise ScopeError(
            "target.base_url must not include credentials, a query string, or a fragment. "
            "Put tokens in environment variables."
        )
    return parsed.hostname.lower()


def enforce_scope(config: dict) -> str:
    auth = config["authorization"]
    if auth.get("confirmed") is not True:
        raise ScopeError(
            "Set authorization.confirmed to true only when you are allowed to test this target."
        )
    owner = str(auth.get("owner", "")).strip()
    purpose = str(auth.get("purpose", "")).strip()
    if not owner or not purpose:
        raise ScopeError("authorization.owner and authorization.purpose are required.")

    environment = str(config["scan"].get("environment", "")).strip().lower()
    if environment in BLOCKED_ENVIRONMENTS or environment not in ALLOWED_ENVIRONMENTS:
        raise ScopeError(
            "scan.environment must be one of local, dev, test, or staging. "
            "Refusing prod, production, and live."
        )

    allowed = {str(host).lower() for host in auth.get("allowed_hosts", [])}
    if not allowed:
        raise ScopeError("authorization.allowed_hosts must list every host the scanner may contact.")

    hostname = _host(config["target"]["base_url"])
    if hostname not in allowed:
        raise ScopeError(
            f"Host {hostname} is not in authorization.allowed_hosts. "
            "The scanner will not send requests."
        )
    return hostname
