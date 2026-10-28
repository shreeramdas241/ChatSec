"""Scope checks must fail before any request is sent."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

import yaml

from configload import load_config, load_fixtures
from errors import ConfigError, ScopeError
from safety.scope import enforce_scope

ROOT = Path(__file__).resolve().parents[1]


class ScopeTests(unittest.TestCase):
    def test_demo_config_loads_and_matches_planted_markers(self) -> None:
        config = load_config(ROOT / "config" / "target.yaml")
        _probes, markers = load_fixtures()
        enforce_scope(config)
        self.assertEqual(config["policies"]["prompt_injection"]["forbidden_markers"], [markers["prompt_override"]])
        self.assertEqual(config["policies"]["prompt_injection"]["system_canary"], markers["system_canary"])
        self.assertEqual(config["policies"]["sensitive_data"]["canaries"], [markers["private_record"]])
        self.assertEqual(config["policies"]["indirect_injection"]["compliance_marker"], markers["indirect"])
        self.assertEqual(config["policies"]["tool_authorization"]["receipt_marker"], markers["tool_receipt"])

    def test_production_environment_is_refused(self) -> None:
        config = load_config(ROOT / "config" / "target.yaml")
        config["scan"]["environment"] = "production"
        with self.assertRaises(ScopeError):
            enforce_scope(config)

    def test_unlisted_host_is_refused(self) -> None:
        config = load_config(ROOT / "config" / "target.yaml")
        config["target"]["base_url"] = "http://example.com"
        with self.assertRaises(ScopeError):
            enforce_scope(config)

    def test_credentials_in_the_url_are_refused(self) -> None:
        config = load_config(ROOT / "config" / "target.yaml")
        config["target"]["base_url"] = "http://user:secret@127.0.0.1:8765"
        with self.assertRaises(ScopeError):
            enforce_scope(config)

    def test_inline_token_is_refused(self) -> None:
        config = load_config(ROOT / "config" / "target.yaml")
        config["target"]["authentication"] = {"type": "bearer", "token": "super-secret-value"}
        path = self._dump(config)
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_missing_token_environment_variable_is_refused(self) -> None:
        config = load_config(ROOT / "config" / "target.yaml")
        config["target"]["authentication"] = {"type": "bearer", "token_env": "CHATSEC_TEST_MISSING"}
        path = self._dump(config)
        with self.assertRaises(ConfigError):
            load_config(path)

    def test_short_markers_are_refused(self) -> None:
        config = load_config(ROOT / "config" / "target.yaml")
        config["policies"]["sensitive_data"]["canaries"] = ["short"]
        path = self._dump(config)
        with self.assertRaises(ConfigError):
            load_config(path)

    def _dump(self, config: dict) -> Path:
        handle = tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False, encoding="utf-8")
        with handle:
            yaml.safe_dump(config, handle)
        self.addCleanup(Path(handle.name).unlink, missing_ok=True)
        return Path(handle.name)


class FixtureTests(unittest.TestCase):
    def test_probe_file_is_json(self) -> None:
        probes, markers = load_fixtures()
        self.assertEqual(set(probes), {
            "prompt_injection",
            "sensitive_data",
            "indirect_injection",
            "tool_authorization",
            "output_safety",
            "rate_limits",
        })
        self.assertTrue(all(len(value) >= 8 for value in markers.values()))
        raw = json.dumps(probes)
        for marker in markers.values():
            self.assertNotIn(marker, raw)


if __name__ == "__main__":
    unittest.main()
