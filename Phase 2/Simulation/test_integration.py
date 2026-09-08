"""
test_integration.py (Repaired & Strict Schema Verified)
========================================================
Integration checks executing real crypto/socket runs.
Verifies zero schema errors across all 40 Phase 3 columns under strict validation.
"""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parent))
from contracts import columns, validate
from validate_results import audit


class ExecutedRecovery(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.tmp.cleanup)
        cls.outputs = []
        for loss in (0, 0.2, 1):
            directory = Path(cls.tmp.name) / str(loss)
            try:
                subprocess.run(
                    [
                        sys.executable,
                        str(Path(__file__).with_name("run_simulation.py")),
                        "--output",
                        str(directory),
                        "--trials",
                        "1",
                        "--monte-carlo",
                        "2",
                        "--loss-rate",
                        str(loss),
                        "--ftti-us",
                        "50000.0",
                    ],
                    check=True,
                    capture_output=True,
                    text=True,
                )
            except subprocess.CalledProcessError as e:
                print("Subprocess stdout:\n", e.stdout)
                print("Subprocess stderr:\n", e.stderr)
                raise
            with (directory / "fault_recovery_runs.csv").open(newline="", encoding="utf-8") as stream:
                cls.outputs.append((directory, list(csv.DictReader(stream))))

    def test_complete_evidence(self):
        for directory, _ in self.outputs:
            self.assertEqual(audit(directory), [])

    def test_canonical_recovery(self):
        for _, rows in self.outputs:
            self.assertEqual(list(rows[0]), list(columns()))
            for row, count in zip(rows[:5], (0, 1, 1, 3, 8)):
                self.assertEqual(row["termination_status_code"], "SUCCESS")
                self.assertEqual(int(row["retransmitted_frames_count"]), count)
                self.assertEqual(int(row["round_1_recovered_frames"]), count)
            self.assertEqual(rows[3]["nack_bitmaps_issued_hex"], "0x000000000001c000")
            self.assertEqual(rows[4]["nack_bitmaps_issued_hex"], "0x000000000ff00000")

    def test_actual_failures(self):
        for _, rows in self.outputs:
            self.assertEqual(
                [r["termination_status_code"] for r in rows[5:8]],
                ["ERR_RETRY_EXHAUSTION", "ERR_TIMEOUT_NACK_WAIT", "ERR_CRYPTO_TAG_MISMATCH"],
            )
            self.assertEqual(rows[5]["recovery_rounds"], "3")
            self.assertEqual(rows[6]["retransmitted_frames_count"], "0")
            self.assertEqual(rows[6]["nack_turnaround_time_us"], "")
            self.assertEqual(rows[7]["injected_dropped_frame_indices"], "NONE")

    def test_probability_endpoints(self):
        for row in self.outputs[0][1][8:]:
            self.assertEqual(row["termination_status_code"], "SUCCESS")
            self.assertEqual(row["recovery_rounds"], "0")
        for row in self.outputs[2][1][8:]:
            self.assertEqual(row["termination_status_code"], "ERR_RETRY_EXHAUSTION")
            self.assertEqual(row["retransmitted_frames_count"], "123")
            self.assertEqual(row["burst_length"], "41")

    def test_strict_contract_and_physical_measurements(self):
        """Resolves Bug 22 by asserting that strict validation returns ZERO errors."""
        for directory, rows in self.outputs:
            validation_errors = validate(directory / "fault_recovery_runs.csv", strict=True)
            self.assertEqual(validation_errors, [], f"Strict validation failed: {validation_errors}")
            for row in rows:
                # Verifies all 6 physical CAN-FD columns are populated (resolves Bug 8)
                self.assertEqual(row["bitrate_regime"], "PROD_CANFD_2MBPS")
                self.assertEqual(row["nominal_baud"], "500000")
                self.assertEqual(row["data_baud"], "2000000")
                self.assertTrue(int(row["total_wire_bytes"]) >= 2436)
                self.assertTrue(0.0 <= float(row["goodput_efficiency_pct"]) <= 100.0)
                # Verifies non-negative recovery overhead (resolves Bug 6 & Bug 7)
                self.assertTrue(float(row["recovery_overhead_latency_us"]) >= 0.0)


if __name__ == "__main__":
    unittest.main()
