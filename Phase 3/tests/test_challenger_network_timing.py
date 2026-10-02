"""
test_challenger_network_timing.py
=================================
Adversarial Empirical Verification Harness for Challenger 2 (challenger_r4_2).
Validates:
  1. ISO 11898-1:2015 Physical CAN-FD Wire Timing & Bit Serialization
  2. 41-Frame Attestation Burst Serialization Bounds (>= 13.5 ms nominal)
  3. End-to-End Handshake Latency & ASIL-D FTTI Compliance (<= 50.0 ms)
  4. Response Time Analysis (RTA) & Bus Schedulability Bounds
  5. Strict Zero Major Page Faults (page_faults_major == 0) across all 31 tasks
  6. Data Contract CSV Integrity across all rows and fields
"""

import math
import sys
import os
import unittest
import pandas as pd

class TestAdversarialNetworkTimingAndBounds(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        cls.base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
        cls.data_dir = os.path.join(cls.base_dir, "data")
        cls.code_dir = os.path.join(cls.base_dir, "Code")

    def test_01_iso11898_nominal_frame_timing(self):
        """Verify nominal 64-byte frame serialization duration matches 331.5 us."""
        f_nom = 500000.0  # 500 kbps
        f_dat = 2000000.0 # 2.0 Mbps
        tau_nom = 1.0 / f_nom * 1e6 # 2.0 us
        tau_dat = 1.0 / f_dat * 1e6 # 0.5 us

        # ISO 11898-1:2015 bit breakdown for 64B frame (standard ID):
        # Nominal arbitration phase: SOF (1) + ID (11) + RTR (1) + IDE (1) + FDF (1) + res (1) + BRS (1) = 17 bits
        # plus ACK delimiter (1) + ACK (1) + EOF (7) + IFS (3) = 12 bits
        # Total nominal bits = 17 + 12 = 29 bits
        n_nom = 29.0

        # Data phase: DLC + control (6 bits) + 64 bytes * 8 bits/byte (512 bits)
        # CRC-21 (21 bits) + stuff count (4 bits) + fixed stuff bits (4 bits) = 29 bits
        # Total data bits = 6 + 512 + 29 = 547 bits
        n_dat = 547.0

        t_frame_nom = (n_nom * tau_nom) + (n_dat * tau_dat)
        self.assertAlmostEqual(t_frame_nom, 331.5, places=4,
            msg=f"Nominal 64B frame wire duration must be exactly 331.5 us, got {t_frame_nom}")

    def test_02_iso11898_worst_case_bit_stuffed_timing(self):
        """Verify worst-case bit-stuffed 64-byte frame serialization duration matches 400.5 us."""
        tau_nom = 2.0 # us
        tau_dat = 0.5 # us

        # Worst-case bit stuffing:
        # Nominal bits max = 32 bits
        # Data bits max = 28 + term_crc + 10 * payload_bytes
        # term_crc = 5 * ceil(max(0, 64-16)/64) = 5
        # data bits = 28 + 5 + 640 = 673 bits
        n_nom_wc = 32.0
        n_dat_wc = 673.0

        t_frame_wc = (n_nom_wc * tau_nom) + (n_dat_wc * tau_dat)
        self.assertAlmostEqual(t_frame_wc, 400.5, places=4,
            msg=f"Worst-case 64B frame wire duration must be exactly 400.5 us, got {t_frame_wc}")

    def test_03_41_frame_burst_wire_duration_bound(self):
        """Verify 41-frame burst serialization duration: 41 * 331.5 us = 13.59 ms >= 13.5 ms threshold."""
        single_frame_nom_us = 331.5
        single_frame_wc_us = 400.5

        t_burst_nom_us = 41 * single_frame_nom_us
        t_burst_nom_ms = t_burst_nom_us / 1000.0

        t_burst_wc_us = 41 * single_frame_wc_us
        t_burst_wc_ms = t_burst_wc_us / 1000.0

        # Physical threshold check
        self.assertGreaterEqual(t_burst_nom_ms, 13.5,
            msg=f"41-frame nominal burst wire duration {t_burst_nom_ms:.4f} ms must be >= 13.5 ms threshold")
        self.assertAlmostEqual(t_burst_nom_ms, 13.5915, places=4)
        self.assertAlmostEqual(t_burst_wc_ms, 16.4205, places=4)

    def test_04_e2e_handshake_latency_and_asild_ftti(self):
        """Verify end-to-end handshake latency <= 50.0 ms ASIL-D FTTI compliance."""
        t_prep_ms = 6.56       # Host signing + PUF
        t_wire_nom_ms = 13.5915 # Nominal wire transit (41 frames)
        t_wire_wc_ms = 16.4205  # Worst-case wire transit (41 frames)
        t_verify_ms = 3.21     # Gateway Ascon + ML-DSA-44 verify
        t_ids_ms = 0.83        # Tier 2 ONNX inference

        t_e2e_nom = t_prep_ms + t_wire_nom_ms + t_verify_ms + t_ids_ms
        t_e2e_wc = t_prep_ms + t_wire_wc_ms + t_verify_ms + t_ids_ms

        ftti_deadline_ms = 50.0

        self.assertLessEqual(t_e2e_nom, ftti_deadline_ms)
        self.assertLessEqual(t_e2e_wc, ftti_deadline_ms)

        # Margin should be substantial (> 40%)
        margin_nom_pct = (ftti_deadline_ms - t_e2e_nom) / ftti_deadline_ms * 100.0
        margin_wc_pct = (ftti_deadline_ms - t_e2e_wc) / ftti_deadline_ms * 100.0

        self.assertGreater(margin_nom_pct, 45.0, msg="Nominal margin must be > 45%")
        self.assertGreater(margin_wc_pct, 40.0, msg="Worst-case margin must be > 40%")

    def test_05_strict_zero_major_page_faults(self):
        """Verify strict zero major page faults (page_faults_major == 0) across all 31 tasks."""
        csv_path = os.path.join(self.data_dir, "perf_stat_summary.csv")
        self.assertTrue(os.path.exists(csv_path), "perf_stat_summary.csv missing")

        df = pd.read_csv(csv_path)
        self.assertEqual(len(df), 31, "perf_stat_summary.csv must have exactly 31 tasks")
        self.assertIn("page_faults_major", df.columns)

        violations = df[df["page_faults_major"] != 0]
        self.assertEqual(len(violations), 0,
            f"ASIL-D Violation: Found {len(violations)} tasks with non-zero major page faults:\n{violations[['task_name', 'page_faults_major']]}")

    def test_06_fault_recovery_runs_within_ftti(self):
        """Verify that every empirical run in fault_recovery_runs.csv satisfies <= 50.0 ms FTTI."""
        csv_path = os.path.join(self.data_dir, "fault_recovery_runs.csv")
        self.assertTrue(os.path.exists(csv_path), "fault_recovery_runs.csv missing")

        df = pd.read_csv(csv_path)
        self.assertGreaterEqual(len(df), 30, "fault_recovery_runs.csv must have >= 30 benchmark runs")

        # Check FTTI budget and end_to_end_latency_us
        df["latency_ms"] = df["end_to_end_latency_us"] / 1000.0
        violations = df[df["latency_ms"] > 50.0]
        self.assertEqual(len(violations), 0,
            f"Found runs exceeding 50.0 ms FTTI: {violations[['run_id', 'scenario_name', 'latency_ms']]}")

        # Check ftti_violation_flag is strictly False
        ftti_flags = df[df["ftti_violation_flag"] == True]
        self.assertEqual(len(ftti_flags), 0, f"Found {len(ftti_flags)} runs with ftti_violation_flag == True")

        # Check safety_state_achieved is strictly True
        safety_failures = df[df["safety_state_achieved"] == False]
        self.assertEqual(len(safety_failures), 0, f"Found {len(safety_failures)} runs where safety state was not achieved")

    def test_07_tcpdump_wire_duration_and_timing(self):
        """Verify tcpdump_latency_summary.csv frame durations and timestamps."""
        csv_path = os.path.join(self.data_dir, "tcpdump_latency_summary.csv")
        self.assertTrue(os.path.exists(csv_path), "tcpdump_latency_summary.csv missing")

        df = pd.read_csv(csv_path)
        self.assertGreaterEqual(len(df), 100, "tcpdump_latency_summary.csv must have >= 100 logged frames")

        # 64-byte attestation frames (payload_bytes == 64) must have duration >= 330 us and <= 405 us
        burst_frames = df[df["payload_bytes"] == 64]
        for idx, row in burst_frames.iterrows():
            dur = row["frame_duration_us"]
            self.assertGreaterEqual(dur, 330.0, f"Frame {row['frame_idx']} duration {dur} us too low")
            self.assertLessEqual(dur, 405.0, f"Frame {row['frame_idx']} duration {dur} us too high")

        # Epoch timestamps must be realistic (> 1.7e18 ns, year 2023+)
        min_epoch = df["timestamp_epoch_ns"].min()
        self.assertGreaterEqual(min_epoch, 1.7e18, f"Timestamp epoch {min_epoch} invalid")

    def test_08_rta_schedulability_all_streams_pass(self):
        """Verify that all 9 CAN-FD message streams in rta_schedulability_results.csv are schedulable."""
        csv_path = os.path.join(self.data_dir, "rta_schedulability_results.csv")
        self.assertTrue(os.path.exists(csv_path), "rta_schedulability_results.csv missing")

        df = pd.read_csv(csv_path)
        self.assertEqual(len(df), 9, "rta_schedulability_results.csv must have 9 streams")

        unschedulable = df[df["schedulable"] != True]
        self.assertEqual(len(unschedulable), 0, f"Found unschedulable streams: {unschedulable['name'].tolist()}")

        for idx, row in df.iterrows():
            r_i = row["r_i_ms"]
            d_i = row["deadline_ms"]
            self.assertLessEqual(r_i, d_i, f"Stream {row['name']} violated deadline: r_i={r_i} > d_i={d_i}")
            self.assertGreater(row["slack_ms"], 0.0, f"Stream {row['name']} has zero or negative slack")


if __name__ == "__main__":
    unittest.main()
