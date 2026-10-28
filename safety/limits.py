"""Request budget. Every connector call spends from the same counter."""

from __future__ import annotations

from errors import BudgetExceeded


class RequestBudget:
    def __init__(self, maximum: int) -> None:
        if maximum < 1:
            raise BudgetExceeded("The request budget must be at least 1.")
        self.maximum = maximum
        self.used = 0

    def consume(self, count: int = 1) -> None:
        if count < 1:
            return
        if self.used + count > self.maximum:
            raise BudgetExceeded(
                f"Request budget is {self.maximum}. This scan already used {self.used} "
                f"and refused to send {count} more. Raise scan.max_requests only up to the hard cap, "
                "or run fewer tests."
            )
        self.used += count

    def snapshot(self) -> dict[str, int]:
        return {"max": self.maximum, "used": self.used}
