"""Fail-closed tests for the conformance orchestrator itself."""

from __future__ import annotations

import importlib.util
import json
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("run.py")
SPEC = importlib.util.spec_from_file_location("ehbp_conformance_run", MODULE_PATH)
harness = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(harness)


def fixture(fixture_id="fixture-one"):
    return {
        "id": fixture_id,
        "category": "crypto",
        "operation": "compute_nonce",
        "inputs": {"nonceBase": "00" * 12, "seqHex": "0"},
        "expect": {"outcome": "ok", "body_hex": "00" * 12},
    }


def valid_result(fixture_id="fixture-one"):
    return {
        "fixture_id": fixture_id,
        "outcome": "ok",
        "error_code": None,
        "status": None,
        "body_hex": "",
        "passthrough": False,
        "plaintext_emitted_before_error": False,
        "bytes_emitted_before_error": 0,
        "native_error": None,
        "runner": "test",
    }


class ResultValidationTests(unittest.TestCase):
    def test_accepts_schema_shaped_result(self):
        self.assertIsNone(harness.validate_result(valid_result(), "fixture-one"))

    def test_rejects_wrong_fixture_id(self):
        self.assertIn("fixture_id", harness.validate_result(valid_result("wrong"), "fixture-one"))

    def test_rejects_unknown_field(self):
        result = valid_result()
        result["concealed"] = True
        self.assertIn("unknown fields", harness.validate_result(result, "fixture-one"))

    def test_rejects_error_without_canonical_code(self):
        result = valid_result()
        result.update(outcome="error", error_code=None)
        self.assertIn("error_code", harness.validate_result(result, "fixture-one"))


class ProcessFailureTests(unittest.TestCase):
    def test_single_adapter_malformed_json_fails_closed(self):
        result = harness.run_adapter(
            [sys.executable, "-c", "print('not-json')"], fixture())
        self.assertEqual(result["error_code"], "ADAPTER_CRASH")

    def test_single_adapter_timeout_fails_closed(self):
        result = harness.run_adapter(
            [sys.executable, "-c", "import time; time.sleep(1)"],
            fixture(), timeout=0.01)
        self.assertEqual(result["error_code"], "ADAPTER_CRASH")
        self.assertIn("timed out", result["native_error"])

    def test_batch_missing_results_fail_closed(self):
        results = harness.run_batch(
            [sys.executable, "-c", "import sys; sys.stdin.read()"],
            [fixture("one"), fixture("two")])
        self.assertEqual(set(results), {"one", "two"})
        self.assertTrue(all(r["error_code"] == "ADAPTER_CRASH" for r in results.values()))

    def test_batch_duplicate_result_fails_entire_batch(self):
        encoded = json.dumps(valid_result("one"))
        program = f"print({encoded!r}); print({encoded!r})"
        results = harness.run_batch(
            [sys.executable, "-c", program], [fixture("one")])
        self.assertEqual(results["one"]["error_code"], "ADAPTER_CRASH")
        self.assertIn("duplicate", results["one"]["native_error"])


class FixturePolicyTests(unittest.TestCase):
    def test_server_fixture_requires_valid_shape(self):
        value = fixture()
        value.update(category="server", operation="decrypt_request", runners=["go"])
        harness.validate_fixture(value)

    def test_duplicate_fixture_ids_are_rejected(self):
        old_dir = harness.FIXTURE_DIR
        with tempfile.TemporaryDirectory() as temp:
            harness.FIXTURE_DIR = Path(temp)
            (Path(temp) / "fixtures.json").write_text(json.dumps([fixture(), fixture()]))
            with self.assertRaisesRegex(ValueError, "duplicate fixture id"):
                harness.load_fixtures()
        harness.FIXTURE_DIR = old_dir

    def test_skip_requires_exact_fixture_authorization(self):
        value = fixture()
        value["allowed_skips"] = {"swift": "no-public-api"}
        result = {"outcome": "skipped", "skip_reason": "no-public-api"}
        self.assertTrue(harness.is_allowed_skip(value, "swift", result))
        self.assertFalse(harness.is_allowed_skip(value, "go", result))
        result["skip_reason"] = "hard-case"
        self.assertFalse(harness.is_allowed_skip(value, "swift", result))


if __name__ == "__main__":
    unittest.main()
