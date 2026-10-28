"""Errors the scanner raises before or during a bounded test run."""


class ConfigError(Exception):
    """The target file is missing a required setting or is internally inconsistent."""


class ScopeError(Exception):
    """The target failed the local authorization and scope checks."""


class BudgetExceeded(Exception):
    """The scan tried to send more requests than the configured budget allows."""


class ConnectorError(Exception):
    """A configured connector call failed."""


class IntegrationUnavailable(Exception):
    """The selected adapter is not implemented in this version."""
