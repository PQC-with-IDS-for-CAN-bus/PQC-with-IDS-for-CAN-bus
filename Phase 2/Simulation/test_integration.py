"""Integration checks execute real crypto/socket runs; no mocks or fixture rows."""
import csv
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

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
            subprocess.run([sys.executable, str(Path(__file__).with_name("run_simulation.py")),
                            "--output", str(directory), "--trials", "1", "--monte-carlo", "2",
                            "--loss-rate", str(loss), "--ftti-us", "1"],
                           check=True, capture_output=True, text=True)
            with (directory / "fault_recovery_runs.csv").open(newline="") as stream:
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
            self.assertEqual([r["termination_status_code"] for r in rows[5:8]],
                             ["ERR_RETRY_EXHAUSTION", "ERR_TIMEOUT_NACK_WAIT", "ERR_CRYPTO_TAG_MISMATCH"])
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

    def test_no_hardware_claim_and_deadline(self):
        for directory, rows in self.outputs:
            self.assertTrue(validate(directory / "fault_recovery_runs.csv", strict=True))
            for row in rows:
                self.assertEqual(row["total_wire_bytes"], "")
                self.assertEqual(row["bitrate_regime"], "")
                self.assertEqual(row["ftti_violation_flag"], "True")
                self.assertEqual(row["safety_state_achieved"], "SAFE_FALLBACK")
            manifest = json.loads((directory / "manifest.json").read_text())
            self.assertEqual(manifest["dependencies"]["dilithium-py"], "1.4.0")


if __name__ == "__main__":
    unittest.main()
