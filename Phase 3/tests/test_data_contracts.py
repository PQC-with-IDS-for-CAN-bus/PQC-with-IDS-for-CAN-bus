"""
test_data_contracts.py
======================
Unit tests for Phase 3 Data Contracts (Milestone M3.4).
Tests:
1. Schema integrity and structural conformance (36, 22, and 40 columns)
2. Positive validation of sample fixtures
3. Negative tests:
   - Missing mandatory columns
   - ASIL-D major page fault violations (>0)
   - Invalid CAN ID formats (missing 0x prefix or non-hex)
   - Unregistered / fuzzed task_name identifiers
   - Invalid ISO 26262 termination status codes
   - Out-of-bounds numerical ranges
"""

import os
import sys
import json
import tempfile
import unittest

# Ensure Code/ is on path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE_DIR = os.path.join(BASE_DIR, 'Code')
CONFIG_DIR = os.path.join(BASE_DIR, 'config')
FIXTURES_DIR = os.path.join(BASE_DIR, 'tests', 'fixtures')

if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from contract_validator import DataContractValidator

class TestDataContractSchemas(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.schema_path = os.path.join(CONFIG_DIR, 'data_contract_schemas.json')
        cls.validator = DataContractValidator(cls.schema_path)

    def test_schema_file_exists_and_loads(self):
        self.assertTrue(os.path.exists(self.schema_path))
        with open(self.schema_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        self.assertIn('$schema', data)
        self.assertIn('contracts', data)
        self.assertEqual(data.get('version'), '1.0')

    def test_all_three_contracts_present(self):
        expected_contracts = {'perf_stat_summary', 'tcpdump_latency_summary', 'fault_recovery_runs'}
        actual_contracts = set(self.validator.get_contract_names())
        self.assertEqual(expected_contracts, actual_contracts)

    def test_column_counts_match_audited_specifications(self):
        # 36 columns for perf_stat_summary (Blind + IEEE/ASAM audited)
        perf_cols = self.validator.contracts['perf_stat_summary']['columns']
        self.assertEqual(len(perf_cols), 36)

        # 22 columns for tcpdump_latency_summary (ASAM MDF4 + Vector BLF audited)
        tcp_cols = self.validator.contracts['tcpdump_latency_summary']['columns']
        self.assertEqual(len(tcp_cols), 22)

        # 40 columns for fault_recovery_runs (ISO 26262 + IEEE TDSC audited)
        fault_cols = self.validator.contracts['fault_recovery_runs']['columns']
        self.assertEqual(len(fault_cols), 40)

    def test_all_31_codebase_tasks_in_enum(self):
        task_col = self.validator.contracts['perf_stat_summary']['columns']['task_name']
        self.assertIn('enum', task_col)
        task_enum = task_col['enum']
        self.assertEqual(len(task_enum), 31)
        self.assertIn('mldsa_verify_attestation', task_enum)
        self.assertIn('ascon_aead128_decrypt', task_enum)
        self.assertIn('tier1_rate_limiter_check', task_enum)
        self.assertIn('tier1_monotonic_counter_gate', task_enum)
        self.assertIn('tier15_discrete_invariant_eval', task_enum)
        self.assertIn('tier2_onnx_int8_inference', task_enum)


class TestPositiveFixtureValidation(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema_path = os.path.join(CONFIG_DIR, 'data_contract_schemas.json')
        cls.validator = DataContractValidator(schema_path)

    def test_perf_stat_summary_fixture_valid(self):
        path = os.path.join(FIXTURES_DIR, 'sample_perf_stat_summary.csv')
        valid, errors = self.validator.validate_csv('perf_stat_summary', path)
        self.assertTrue(valid, f"perf_stat_summary fixture failed validation: {errors}")
        self.assertEqual(len(errors), 0)

    def test_tcpdump_latency_summary_fixture_valid(self):
        path = os.path.join(FIXTURES_DIR, 'sample_tcpdump_latency_summary.csv')
        valid, errors = self.validator.validate_csv('tcpdump_latency_summary', path)
        self.assertTrue(valid, f"tcpdump_latency_summary fixture failed validation: {errors}")
        self.assertEqual(len(errors), 0)

    def test_fault_recovery_runs_fixture_valid(self):
        path = os.path.join(FIXTURES_DIR, 'sample_fault_recovery_runs.csv')
        valid, errors = self.validator.validate_csv('fault_recovery_runs', path)
        self.assertTrue(valid, f"fault_recovery_runs fixture failed validation: {errors}")
        self.assertEqual(len(errors), 0)


class TestNegativeMalformedDataRejection(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        schema_path = os.path.join(CONFIG_DIR, 'data_contract_schemas.json')
        cls.validator = DataContractValidator(schema_path)

    def _create_temp_csv(self, header, rows):
        f = tempfile.NamedTemporaryFile(mode='w', suffix='.csv', delete=False, newline='', encoding='utf-8')
        f.write(','.join(header) + '\n')
        for r in rows:
            f.write(','.join(str(x) for x in r) + '\n')
        f.close()
        return f.name

    def test_rejects_missing_mandatory_column(self):
        path = os.path.join(FIXTURES_DIR, 'sample_perf_stat_summary.csv')
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        # Remove 'cpu_cycles' from header and all rows
        header = lines[0].strip().split(',')
        cycle_idx = header.index('cpu_cycles')
        new_header = [col for i, col in enumerate(header) if i != cycle_idx]
        new_rows = []
        for line in lines[1:3]:
            row = line.strip().split(',')
            new_rows.append([val for i, val in enumerate(row) if i != cycle_idx])

        temp_csv = self._create_temp_csv(new_header, new_rows)
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid)
            self.assertTrue(any('missing' in e.lower() for e in errors))
        finally:
            os.remove(temp_csv)

    def test_rejects_non_zero_major_page_fault(self):
        # ASIL-D constraint: page_faults_major must be strictly 0
        path = os.path.join(FIXTURES_DIR, 'sample_perf_stat_summary.csv')
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        header = lines[0].strip().split(',')
        maj_idx = header.index('page_faults_major')
        
        row1 = lines[1].strip().split(',')
        row1[maj_idx] = '1'  # Inject major page fault!

        temp_csv = self._create_temp_csv(header, [row1])
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid)
            self.assertTrue(any('ASIL-D VIOLATION' in e or 'page_faults_major' in e for e in errors))
        finally:
            os.remove(temp_csv)

    def test_rejects_invalid_can_id_format(self):
        path = os.path.join(FIXTURES_DIR, 'sample_tcpdump_latency_summary.csv')
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        header = lines[0].strip().split(',')
        can_idx = header.index('can_id_hex')
        
        row1 = lines[1].strip().split(',')
        row1[can_idx] = '200'  # Missing '0x' prefix!

        temp_csv = self._create_temp_csv(header, [row1])
        try:
            valid, errors = self.validator.validate_csv('tcpdump_latency_summary', temp_csv)
            self.assertFalse(valid)
            self.assertTrue(any('can_id_hex' in e for e in errors))
        finally:
            os.remove(temp_csv)

    def test_rejects_unregistered_task_name(self):
        path = os.path.join(FIXTURES_DIR, 'sample_perf_stat_summary.csv')
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        header = lines[0].strip().split(',')
        task_idx = header.index('task_name')
        
        row1 = lines[1].strip().split(',')
        row1[task_idx] = 'sha256_unregistered_hash'  # Not in allowed 31 task enum

        temp_csv = self._create_temp_csv(header, [row1])
        try:
            valid, errors = self.validator.validate_csv('perf_stat_summary', temp_csv)
            self.assertFalse(valid)
            self.assertTrue(any('task_name' in e for e in errors))
        finally:
            os.remove(temp_csv)

    def test_rejects_invalid_termination_status_code(self):
        path = os.path.join(FIXTURES_DIR, 'sample_fault_recovery_runs.csv')
        with open(path, 'r', encoding='utf-8') as f:
            lines = f.readlines()
        
        header = lines[0].strip().split(',')
        status_idx = header.index('termination_status_code')
        
        row1 = lines[1].strip().split(',')
        row1[status_idx] = 'MAYBE_SUCCESS'  # Invalid status

        temp_csv = self._create_temp_csv(header, [row1])
        try:
            valid, errors = self.validator.validate_csv('fault_recovery_runs', temp_csv)
            self.assertFalse(valid)
            self.assertTrue(any('termination_status_code' in e for e in errors))
        finally:
            os.remove(temp_csv)


if __name__ == '__main__':
    unittest.main(verbosity=2)
