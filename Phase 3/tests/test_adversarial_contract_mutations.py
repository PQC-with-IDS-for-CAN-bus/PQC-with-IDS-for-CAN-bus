"""
test_adversarial_contract_mutations.py
======================================
Empirical Adversarial Stress Harness for Phase 3 Data Contracts.
Authored by Challenger 2 (Milestone M2-M6 Gate Verification).

Stress-tests DataContractValidator against:
1. Column reordering, missing columns, and extra unexpected columns across all 3 contracts.
2. Negative unsigned integers (uint8, uint16, uint32, uint64).
3. Non-zero major page faults (ASIL-D / ISO 26262 violation: page_faults_major != 0).
4. Invalid regex patterns for CAN IDs (missing 0x prefix, non-hex, length violations)
   and NACK bitmaps (malformed length, invalid hex, improper delimiters).
5. Empty / null values in non-nullable physical bus fields.
6. Additional boundary and stress conditions (out-of-bounds bounds, invalid enums, invalid booleans).
"""

import os
import sys
import tempfile
import unittest
import csv

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE_DIR = os.path.join(BASE_DIR, 'Code')
CONFIG_DIR = os.path.join(BASE_DIR, 'config')
DATA_DIR = os.path.join(BASE_DIR, 'data')

if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from contract_validator import DataContractValidator

class TestAdversarialContractMutations(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema_path = os.path.join(CONFIG_DIR, 'data_contract_schemas.json')
        cls.validator = DataContractValidator(cls.schema_path)
        cls.perf_path = os.path.join(DATA_DIR, 'perf_stat_summary.csv')
        cls.tcp_path = os.path.join(DATA_DIR, 'tcpdump_latency_summary.csv')
        cls.fault_path = os.path.join(DATA_DIR, 'fault_recovery_runs.csv')

        # Verify all 3 genuine files exist before testing
        assert os.path.exists(cls.perf_path), f"Missing {cls.perf_path}"
        assert os.path.exists(cls.tcp_path), f"Missing {cls.tcp_path}"
        assert os.path.exists(cls.fault_path), f"Missing {cls.fault_path}"

    def _write_temp_csv(self, header, rows):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='', encoding='utf-8')
        writer = csv.writer(f)
        writer.writerow(header)
        for r in rows:
            writer.writerow(r)
        f.close()
        return f.name

    def _load_csv(self, path):
        with open(path, 'r', encoding='utf-8') as f:
            reader = list(csv.reader(f))
        return reader[0], reader[1:]

    # -------------------------------------------------------------------------
    # Positive Baseline Verification
    # -------------------------------------------------------------------------
    def test_00_baseline_genuine_csvs_pass_cleanly(self):
        """Verify the 3 genuine production CSVs validate with 0 errors."""
        for c_name, c_path in [
            ('perf_stat_summary', self.perf_path),
            ('tcpdump_latency_summary', self.tcp_path),
            ('fault_recovery_runs', self.fault_path)
        ]:
            valid, errors = self.validator.validate_csv(c_name, c_path)
            self.assertTrue(valid, f"Genuine CSV {c_name} unexpectedly failed: {errors}")
            self.assertEqual(len(errors), 0)

    # -------------------------------------------------------------------------
    # Dimension 1: Column Reordering & Missing / Extra Columns
    # -------------------------------------------------------------------------
    def test_01_column_reordering_rejected(self):
        """Verify that swapping column positions in header is rejected."""
        header, rows = self._load_csv(self.perf_path)
        # Swap first two columns
        swapped_header = [header[1], header[0]] + header[2:]
        swapped_rows = [[r[1], r[0]] + r[2:] for r in rows[:3]]
        temp_csv = self._write_temp_csv(swapped_header, swapped_rows)
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid, "Validator failed to reject swapped columns")
            # Should have header mismatch or row type errors due to misalignment
            self.assertTrue(len(errors) > 0)
        finally:
            os.remove(temp_csv)

    def test_02_missing_column_rejected(self):
        """Verify that omitting a mandatory column is rejected."""
        header, rows = self._load_csv(self.tcp_path)
        # Drop 'can_id_hex'
        drop_idx = header.index('can_id_hex')
        new_header = [col for i, col in enumerate(header) if i != drop_idx]
        new_rows = [[val for i, val in enumerate(r) if i != drop_idx] for r in rows[:3]]
        temp_csv = self._write_temp_csv(new_header, new_rows)
        try:
            valid, errors = self.validator.validate_csv('tcpdump_latency_summary', temp_csv)
            self.assertFalse(valid, "Validator failed to reject missing column")
            self.assertTrue(any('missing expected columns' in e.lower() for e in errors))
            self.assertTrue(any('can_id_hex' in e for e in errors))
        finally:
            os.remove(temp_csv)

    def test_03_extra_column_rejected(self):
        """Verify that injecting an unexpected extra column is rejected."""
        header, rows = self._load_csv(self.fault_path)
        new_header = header + ['unauthorized_backdoor_field']
        new_rows = [r + ['malicious_payload'] for r in rows[:3]]
        temp_csv = self._write_temp_csv(new_header, new_rows)
        try:
            valid, errors = self.validator.validate_csv('fault_recovery_runs', temp_csv)
            self.assertFalse(valid, "Validator failed to reject extra column")
            self.assertTrue(any('unexpected extra columns' in e.lower() for e in errors))
            self.assertTrue(any('unauthorized_backdoor_field' in e for e in errors))
        finally:
            os.remove(temp_csv)

    # -------------------------------------------------------------------------
    # Dimension 2: Negative Unsigned Integers
    # -------------------------------------------------------------------------
    def test_04_negative_unsigned_int_perf_stat(self):
        """Verify uint64 negative value is rejected in perf_stat_summary."""
        header, rows = self._load_csv(self.perf_path)
        col_idx = header.index('execution_wall_time_ns')
        mutated_rows = [list(rows[0])]
        mutated_rows[0][col_idx] = '-5000'
        temp_csv = self._write_temp_csv(header, mutated_rows)
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid, "Validator accepted negative execution_wall_time_ns")
            self.assertTrue(any('Unsigned integer cannot be negative' in e for e in errors))
        finally:
            os.remove(temp_csv)

    def test_05_negative_unsigned_int_tcpdump(self):
        """Verify uint16 negative value is rejected in tcpdump_latency_summary."""
        header, rows = self._load_csv(self.tcp_path)
        col_idx = header.index('frame_idx')
        mutated_rows = [list(rows[0])]
        mutated_rows[0][col_idx] = '-1'
        temp_csv = self._write_temp_csv(header, mutated_rows)
        try:
            valid, errors = self.validator.validate_csv('tcpdump_latency_summary', temp_csv)
            self.assertFalse(valid, "Validator accepted negative frame_idx")
            self.assertTrue(any('Unsigned integer cannot be negative' in e for e in errors))
        finally:
            os.remove(temp_csv)

    def test_06_negative_unsigned_int_fault_recovery(self):
        """Verify uint32 negative value is rejected in fault_recovery_runs."""
        header, rows = self._load_csv(self.fault_path)
        col_idx = header.index('total_frames_on_wire')
        mutated_rows = [list(rows[0])]
        mutated_rows[0][col_idx] = '-42'
        temp_csv = self._write_temp_csv(header, mutated_rows)
        try:
            valid, errors = self.validator.validate_csv('fault_recovery_runs', temp_csv)
            self.assertFalse(valid, "Validator accepted negative total_frames_on_wire")
            self.assertTrue(any('Unsigned integer cannot be negative' in e for e in errors))
        finally:
            os.remove(temp_csv)

    # -------------------------------------------------------------------------
    # Dimension 3: Non-zero Major Page Faults (ASIL-D Invariant)
    # -------------------------------------------------------------------------
    def test_07_non_zero_major_page_fault_rejected(self):
        """Verify ASIL-D requirement: page_faults_major must be strictly 0."""
        header, rows = self._load_csv(self.perf_path)
        col_idx = header.index('page_faults_major')
        mutated_rows = [list(rows[0])]
        mutated_rows[0][col_idx] = '1'  # 1 major page fault injected
        temp_csv = self._write_temp_csv(header, mutated_rows)
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid, "Validator accepted non-zero major page fault")
            self.assertTrue(any('ASIL-D VIOLATION' in e for e in errors), f"Missing ASIL-D violation tag in: {errors}")
        finally:
            os.remove(temp_csv)

    def test_08_large_non_zero_major_page_fault_rejected(self):
        """Verify large non-zero page_faults_major is rejected with boundary and ASIL-D errors."""
        header, rows = self._load_csv(self.perf_path)
        col_idx = header.index('page_faults_major')
        mutated_rows = [list(rows[0])]
        mutated_rows[0][col_idx] = '1024'
        temp_csv = self._write_temp_csv(header, mutated_rows)
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid, "Validator accepted 1024 major page faults")
            self.assertTrue(any('ASIL-D VIOLATION' in e for e in errors))
        finally:
            os.remove(temp_csv)

    # -------------------------------------------------------------------------
    # Dimension 4: Invalid Regex Patterns (CAN IDs & NACK Bitmaps)
    # -------------------------------------------------------------------------
    def test_09_invalid_can_id_regex_rejected(self):
        """Verify malformed CAN IDs are rejected."""
        header, rows = self._load_csv(self.tcp_path)
        col_idx = header.index('can_id_hex')

        # Test cases: missing 0x prefix, non-hex chars, empty, too long
        invalid_can_ids = [
            '200',           # Missing 0x prefix
            '0xZZZ',         # Non-hex characters
            '0x',            # Truncated
            '0x123456789A',  # Exceeds 8 hex digits (CAN 29-bit max is 0x1FFFFFFF)
            '0x12'           # Less than 3 hex digits
        ]

        for bad_id in invalid_can_ids:
            mutated_rows = [list(rows[0])]
            mutated_rows[0][col_idx] = bad_id
            temp_csv = self._write_temp_csv(header, mutated_rows)
            try:
                valid, errors = self.validator.validate_csv('tcpdump_latency_summary', temp_csv)
                self.assertFalse(valid, f"Validator accepted invalid CAN ID '{bad_id}'")
                self.assertTrue(any('regex pattern' in e.lower() for e in errors))
            finally:
                os.remove(temp_csv)

    def test_10_invalid_nack_bitmap_regex_rejected(self):
        """Verify malformed NACK bitmaps are rejected."""
        header, rows = self._load_csv(self.fault_path)
        col_idx = header.index('nack_bitmaps_issued_hex')

        invalid_bitmaps = [
            '0x1234',                            # Too short (not 16 hex digits)
            '0xGGGGGGGGGGGGGGGG',                # Non-hex characters
            'N/A',                               # Wrong format (must be N_A or 0x<16hex>)
            '0x0000000000000001,0x0000000000000002', # Comma instead of semicolon
            'INVALID_BITMAP'
        ]

        for bad_bm in invalid_bitmaps:
            mutated_rows = [list(rows[0])]
            mutated_rows[0][col_idx] = bad_bm
            temp_csv = self._write_temp_csv(header, mutated_rows)
            try:
                valid, errors = self.validator.validate_csv('fault_recovery_runs', temp_csv)
                self.assertFalse(valid, f"Validator accepted invalid NACK bitmap '{bad_bm}'")
                self.assertTrue(any('regex pattern' in e.lower() for e in errors))
            finally:
                os.remove(temp_csv)

    # -------------------------------------------------------------------------
    # Dimension 5: Empty / Null Values in Non-Nullable Physical Bus Fields
    # -------------------------------------------------------------------------
    def test_11_empty_value_in_non_nullable_fields(self):
        """Verify empty strings in non-nullable physical fields are rejected."""
        header, rows = self._load_csv(self.tcp_path)

        non_nullable_cols = [
            'can_id_hex',
            'frame_duration_us',
            'nominal_baud',
            'data_baud',
            'payload_bytes',
            'bus_channel'
        ]

        for col_name in non_nullable_cols:
            col_idx = header.index(col_name)
            mutated_rows = [list(rows[0])]
            mutated_rows[0][col_idx] = ''  # Empty string
            temp_csv = self._write_temp_csv(header, mutated_rows)
            try:
                valid, errors = self.validator.validate_csv('tcpdump_latency_summary', temp_csv)
                self.assertFalse(valid, f"Validator accepted empty value in non-nullable '{col_name}'")
                self.assertTrue(any('Non-nullable field is empty/null' in e for e in errors))
            finally:
                os.remove(temp_csv)

    def test_12_explicit_null_in_non_nullable_field(self):
        """Verify explicit 'null' in non-nullable field is rejected."""
        header, rows = self._load_csv(self.perf_path)
        col_idx = header.index('ecu_id')
        mutated_rows = [list(rows[0])]
        mutated_rows[0][col_idx] = 'null'
        temp_csv = self._write_temp_csv(header, mutated_rows)
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid, "Validator accepted explicit 'null' for non-nullable ecu_id")
            self.assertTrue(any('Non-nullable field is empty/null' in e for e in errors))
        finally:
            os.remove(temp_csv)

    # -------------------------------------------------------------------------
    # Dimension 6: Value Bounds & Enumeration Attacks
    # -------------------------------------------------------------------------
    def test_13_out_of_range_efficiency_rejected(self):
        """Verify goodput efficiency > 100% is rejected."""
        header, rows = self._load_csv(self.fault_path)
        col_idx = header.index('goodput_efficiency_pct')
        mutated_rows = [list(rows[0])]
        mutated_rows[0][col_idx] = '105.5'
        temp_csv = self._write_temp_csv(header, mutated_rows)
        try:
            valid, errors = self.validator.validate_csv('fault_recovery_runs', temp_csv)
            self.assertFalse(valid, "Validator accepted goodput > 100%")
            self.assertTrue(any('violates max bound' in e for e in errors))
        finally:
            os.remove(temp_csv)

    def test_14_unregistered_task_name_rejected(self):
        """Verify rogue task_name not in 31 audited tasks is rejected."""
        header, rows = self._load_csv(self.perf_path)
        col_idx = header.index('task_name')
        mutated_rows = [list(rows[0])]
        mutated_rows[0][col_idx] = 'crypto_backdoor_exploit'
        temp_csv = self._write_temp_csv(header, mutated_rows)
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid, "Validator accepted unregistered task_name")
            self.assertTrue(any('not in allowed enum' in e for e in errors))
        finally:
            os.remove(temp_csv)

if __name__ == '__main__':
    unittest.main(verbosity=2)
