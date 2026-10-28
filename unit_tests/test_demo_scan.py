"""Run the scanner against the local demo chatbot."""

from __future__ import annotations

import json
import tempfile
import threading
import time
import unittest
import urllib.request
from pathlib import Path

import yaml

from configload import load_config
from demo.server import make_server
from scanner import run_scan

ROOT = Path(__file__).resolve().parents[1]


class DemoProcess:
    def __init__(self, mode: str) -> None:
        self.server = make_server("127.0.0.1", 0, mode)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self._wait()

    def _wait(self) -> None:
        url = f"http://127.0.0.1:{self.port}/health"
        for _ in range(50):
            try:
                with urllib.request.urlopen(url, timeout=1) as response:
                    if response.status == 200:
                        return
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("demo chatbot did not start")

    def close(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class DemoScanTests(unittest.TestCase):
    def test_secure_demo_has_no_findings(self) -> None:
        self._assert_scan("secure", "http", 0, "passed")

    def test_vulnerable_demo_proves_each_finding(self) -> None:
        report = self._assert_scan("vulnerable", "http", 1, "finding")
        leaked = " ".join(item["response_text"] for result in report["results"] for item in result["evidence"])
        self.assertIn("CHATSEC-PRIVATE-RECORD-92F1", leaked)
        self.assertIn("CHATSEC-INDIRECT-COMPLIED", leaked)
        self.assertIn("CHATSEC-TOOL-EXECUTED-TRANSFER", leaked)

    def test_voice_transcript_uses_the_same_checks(self) -> None:
        self._assert_scan("secure", "voice_transcript", 0, "passed")

    def test_indirect_injection_without_retrieval_is_not_a_pass(self) -> None:
        config = load_config(ROOT / "config" / "target.yaml")
        config["target"]["health_path"] = ""
        config["capabilities"]["retrieves_documents"] = False
        config["scan"]["tests"] = ["indirect_injection"]
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.yaml"
            path.write_text(yaml.safe_dump(config), encoding="utf-8")
            code = run_scan(str(path), directory, None, False)
            reports = list(Path(directory).glob("chatsec-*.json"))
            self.assertEqual(code, 0)
            report = json.loads(reports[0].read_text(encoding="utf-8"))
        self.assertEqual(report["results"][0]["status"], "not_applicable")
        self.assertEqual(report["budget"]["used"], 0)

    def _assert_scan(self, mode: str, connector: str, expected_code: int, expected_status: str) -> dict:
        demo = DemoProcess(mode)
        self.addCleanup(demo.close)
        config = load_config(ROOT / "config" / "target.yaml")
        config["connector"]["type"] = connector
        config["target"]["base_url"] = f"http://127.0.0.1:{demo.port}"
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "target.yaml"
            path.write_text(yaml.safe_dump(config), encoding="utf-8")
            code = run_scan(str(path), directory, None, False)
            reports = list(Path(directory).glob("chatsec-*.json"))
            self.assertEqual(len(reports), 1)
            report = json.loads(reports[0].read_text(encoding="utf-8"))
        self.assertEqual(code, expected_code, report)
        self.assertEqual(report["channel"], "text" if connector == "http" else "voice_transcript")
        self.assertEqual([result["status"] for result in report["results"]], [expected_status] * 6)
        return report


if __name__ == "__main__":
    unittest.main()
