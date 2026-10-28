"""Security modules. These call the connector and do not know the transport."""

from tests import (
    indirect_injection,
    output_safety,
    prompt_injection,
    rate_limits,
    sensitive_data,
    tool_authorization,
)

RUNNERS = {
    "prompt_injection": prompt_injection.run,
    "sensitive_data": sensitive_data.run,
    "indirect_injection": indirect_injection.run,
    "tool_authorization": tool_authorization.run,
    "output_safety": output_safety.run,
    "rate_limits": rate_limits.run,
}
