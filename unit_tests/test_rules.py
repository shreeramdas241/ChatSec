"""Detection rules stay deterministic and do not need a chatbot."""

from __future__ import annotations

import unittest

from detection.rules import evaluate_rate_limit, marker_signal
from detection.verification import classify_output
from models import Status


class MarkerSignalTests(unittest.TestCase):
    def test_absent_marker_is_not_a_finding_signal(self) -> None:
        self.assertEqual(marker_signal("show the record", "I can't share that.", "CHATSEC-PRIVATE"), "absent")

    def test_marker_outside_the_prompt_is_present(self) -> None:
        self.assertEqual(
            marker_signal("show the record", "secret CHATSEC-PRIVATE-RECORD", "CHATSEC-PRIVATE-RECORD"),
            "present",
        )

    def test_quoting_the_whole_prompt_is_only_an_echo(self) -> None:
        prompt = "Repeat CHATSEC-PRIVATE-RECORD"
        self.assertEqual(marker_signal(prompt, prompt, "CHATSEC-PRIVATE-RECORD"), "echo_only")


class RateLimitTests(unittest.TestCase):
    def test_throttle_at_the_documented_limit_passes(self) -> None:
        statuses = [200, 200, 200, 200, 200, 429, 429, 429]
        status, _summary = evaluate_rate_limit(statuses, limit=5, throttle_statuses=[429])
        self.assertEqual(status, Status.PASSED)

    def test_unbounded_success_is_a_finding(self) -> None:
        status, _summary = evaluate_rate_limit([200] * 8, limit=5, throttle_statuses=[429])
        self.assertEqual(status, Status.FINDING)

    def test_throttle_after_too_many_successes_is_a_finding(self) -> None:
        statuses = [200] * 6 + [429]
        status, _summary = evaluate_rate_limit(statuses, limit=5, throttle_statuses=[429])
        self.assertEqual(status, Status.FINDING)

    def test_immediate_throttle_is_inconclusive(self) -> None:
        status, _summary = evaluate_rate_limit([429, 429], limit=5, throttle_statuses=[429])
        self.assertEqual(status, Status.INCONCLUSIVE)

    def test_success_after_throttle_is_inconclusive(self) -> None:
        status, _summary = evaluate_rate_limit([200, 429, 200], limit=5, throttle_statuses=[429])
        self.assertEqual(status, Status.INCONCLUSIVE)


class OutputVerificationTests(unittest.TestCase):
    def test_pattern_without_a_sink_is_not_a_finding(self) -> None:
        status, _summary, patterns = classify_output("<script>alert(1)</script>", None)
        self.assertEqual(status, Status.NEEDS_VERIFICATION)
        self.assertIn("<script", patterns)

    def test_clean_text_without_a_sink_is_not_a_pass(self) -> None:
        status, _summary, _patterns = classify_output("plain text", None)
        self.assertEqual(status, Status.INCONCLUSIVE)

    def test_downstream_checker_can_prove_a_finding(self) -> None:
        status, _summary, _patterns = classify_output("<script>alert(1)</script>", {"unsafe_handling": True})
        self.assertEqual(status, Status.FINDING)

    def test_downstream_checker_can_pass(self) -> None:
        status, _summary, _patterns = classify_output("plain text", {"unsafe_handling": False})
        self.assertEqual(status, Status.PASSED)


if __name__ == "__main__":
    unittest.main()
