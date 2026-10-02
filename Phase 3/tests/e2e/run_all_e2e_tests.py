#!/usr/bin/env python3
"""
===============================================================================
Central E2E Test Suite Runner: Pure C++17 DockerLab Benchmarking Suite
===============================================================================
Author: Test Writer (E2E Test Suite Architect)
Standard: ISO/IEC 14882:2017 (C++17), NIST FIPS 204, NIST SP 800-232, ISO 11898-1:2015

Orchestrates and executes all 4 tiers of the requirement-driven E2E test suite:
  - Tier 1: Feature Coverage (45 tests across 9 features)
  - Tier 2: Boundary & Corner Cases (45 tests across 9 features)
  - Tier 3: Pairwise Interactions (15 multi-variable tests)
  - Tier 4: Real-World Scenarios (18 real-world & contract tests)
Total: 123 tests

Generates:
  - Console formatted execution summary
  - JSON execution report: tests/e2e/e2e_test_report.json
  - Markdown execution report: tests/e2e/e2e_test_report.md
===============================================================================
"""

import unittest
import time
import os
import sys
import json

# Ensure test package is in path
CURRENT_DIR = os.path.dirname(os.path.abspath(__file__))
if CURRENT_DIR not in sys.path:
    sys.path.insert(0, CURRENT_DIR)

import test_tier1_feature_coverage
import test_tier2_boundary_corner
import test_tier3_pairwise_interactions
import test_tier4_real_world_scenarios


class StructuredTestResult(unittest.TextTestResult):
    """Custom TestResult collecting detailed execution metrics for reporting."""

    def __init__(self, stream, descriptions, verbosity):
        super().__init__(stream, descriptions, verbosity)
        self.test_records = []
        self._start_time = None

    def startTest(self, test):
        super().startTest(test)
        self._start_time = time.perf_counter()

    def addSuccess(self, test):
        super().addSuccess(test)
        elapsed = time.perf_counter() - self._start_time
        self.test_records.append({
            "test_id": test.id(),
            "name": str(test),
            "status": "PASS",
            "elapsed_s": elapsed,
            "error": None
        })

    def addFailure(self, test, err):
        super().addFailure(test, err)
        elapsed = time.perf_counter() - self._start_time
        self.test_records.append({
            "test_id": test.id(),
            "name": str(test),
            "status": "FAIL",
            "elapsed_s": elapsed,
            "error": self._exc_info_to_string(err, test)
        })

    def addError(self, test, err):
        super().addError(test, err)
        elapsed = time.perf_counter() - self._start_time
        self.test_records.append({
            "test_id": test.id(),
            "name": str(test),
            "status": "ERROR",
            "elapsed_s": elapsed,
            "error": self._exc_info_to_string(err, test)
        })


def run_e2e_suite():
    print("=" * 80)
    print("  PURE C++17 DOCKERLAB BENCHMARKING SUITE - E2E TEST RUNNER")
    print("  4-Tier Requirement-Driven Test Execution")
    print("=" * 80)

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    tier_modules = [
        ("Tier 1: Feature Coverage (45 tests)", test_tier1_feature_coverage),
        ("Tier 2: Boundary & Corner Cases (45 tests)", test_tier2_boundary_corner),
        ("Tier 3: Pairwise Interactions (15 tests)", test_tier3_pairwise_interactions),
        ("Tier 4: Real-World Scenarios (18 tests)", test_tier4_real_world_scenarios),
    ]

    tier_reports = []
    overall_start = time.perf_counter()
    all_passed = True
    total_run = 0
    total_passed = 0
    total_failed = 0
    total_errors = 0

    for tier_name, module in tier_modules:
        print(f"\n[+] Executing {tier_name}...")
        tier_suite = loader.loadTestsFromModule(module)
        tier_start = time.perf_counter()

        runner = unittest.TextTestRunner(resultclass=StructuredTestResult, verbosity=1)
        result = runner.run(tier_suite)
        tier_elapsed = time.perf_counter() - tier_start

        passed_count = len(result.test_records) - len(result.failures) - len(result.errors)
        total_run += result.testsRun
        total_passed += passed_count
        total_failed += len(result.failures)
        total_errors += len(result.errors)

        if not result.wasSuccessful():
            all_passed = False

        tier_reports.append({
            "tier_name": tier_name,
            "tests_run": result.testsRun,
            "passed": passed_count,
            "failed": len(result.failures),
            "errors": len(result.errors),
            "elapsed_s": tier_elapsed,
            "records": result.test_records
        })

        print(f"    --> Results: {passed_count}/{result.testsRun} Passed ({tier_elapsed:.3f}s)")
        if result.failures:
            print(f"    [!] Failures: {len(result.failures)}")
        if result.errors:
            print(f"    [!] Errors: {len(result.errors)}")

    overall_elapsed = time.perf_counter() - overall_start

    # Summary Report
    print("\n" + "=" * 80)
    print("  E2E TEST EXECUTION SUMMARY")
    print("=" * 80)
    print(f"  Total Tests Executed : {total_run}")
    print(f"  Passed Tests         : {total_passed} ({total_passed/total_run*100:.1f}%)")
    print(f"  Failed Tests         : {total_failed}")
    print(f"  Errored Tests        : {total_errors}")
    print(f"  Total Duration       : {overall_elapsed:.3f}s")
    print("=" * 80)

    # Save JSON Report
    report_data = {
        "timestamp_utc": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "total_tests": total_run,
        "total_passed": total_passed,
        "total_failed": total_failed,
        "total_errors": total_errors,
        "overall_elapsed_s": overall_elapsed,
        "status": "PASS" if all_passed else "FAIL",
        "tiers": tier_reports
    }

    json_report_path = os.path.join(CURRENT_DIR, "e2e_test_report.json")
    with open(json_report_path, "w", encoding="utf-8") as f:
        json.dump(report_data, f, indent=2)
    print(f"\n[+] Saved JSON Test Report: {json_report_path}")

    # Save Markdown Report
    md_report_path = os.path.join(CURRENT_DIR, "e2e_test_report.md")
    with open(md_report_path, "w", encoding="utf-8") as f:
        f.write("# E2E Test Suite Execution Report\n\n")
        f.write(f"- **Timestamp (UTC):** {report_data['timestamp_utc']}\n")
        f.write(f"- **Status:** {'✅ PASSED (100%)' if all_passed else '❌ FAILED'}\n")
        f.write(f"- **Total Tests Executed:** {total_run}\n")
        f.write(f"- **Total Passed:** {total_passed}\n")
        f.write(f"- **Total Failed:** {total_failed}\n")
        f.write(f"- **Total Errors:** {total_errors}\n")
        f.write(f"- **Total Elapsed Time:** {overall_elapsed:.3f}s\n\n")

        f.write("## Tier Breakdown\n\n")
        f.write("| Tier | Tests Run | Passed | Failed | Errors | Duration (s) | Status |\n")
        f.write("| :--- | :---: | :---: | :---: | :---: | :---: | :---: |\n")
        for t in tier_reports:
            t_status = "✅ PASS" if (t["failed"] == 0 and t["errors"] == 0) else "❌ FAIL"
            f.write(f"| {t['tier_name']} | {t['tests_run']} | {t['passed']} | {t['failed']} | {t['errors']} | {t['elapsed_s']:.3f} | {t_status} |\n")
        f.write("\n")

        f.write("## 4-Tier Test Architecture Compliance\n\n")
        f.write("- **Tier 1 (Feature Coverage):** 45 tests across all 9 features (100% coverage).\n")
        f.write("- **Tier 2 (Boundary & Corner Cases):** 45 tests covering bit-flips, rollovers, drops, and overflows.\n")
        f.write("- **Tier 3 (Pairwise Interactions):** 15 tests covering cross-subsystem interactions.\n")
        f.write("- **Tier 4 (Real-World Scenarios):** 18 tests validating the 31 scenarios, latency budget, and contracts.\n")
    print(f"[+] Saved Markdown Test Report: {md_report_path}")

    if all_passed and total_run >= 120:
        print("\n>>> ALL TEST TIERS PASSED WITH 100% SUCCESS RATE. SYSTEM READY FOR TEST_READY.md <<<")
        return 0
    else:
        print("\n>>> TEST SUITE FAILED OR UNDERMINIMUM THRESHOLD <<<")
        return 1


if __name__ == "__main__":
    sys.exit(run_e2e_suite())
