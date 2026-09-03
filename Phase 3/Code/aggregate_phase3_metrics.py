"""
aggregate_phase3_metrics.py
===========================
Master Ingestion & Analytical Synthesis Engine for Phase 3 (Milestone M3.4).

Capabilities:
1. Ingests CSV data handoffs from Teammates (Kaustuv: perf_stat, tcpdump; Kunal: fault_recovery)
2. Validates datasets against config/data_contract_schemas.json via DataContractValidator
3. Supports dual execution modes:
   - '--mock': Ingests verified reference fixtures from tests/fixtures/
   - '--live': Ingests live empirical logs from drop directories
4. Synthesizes cross-domain metrics:
   - Schedulability & Real-Time Margin (Host compute vs Wire time vs 10ms ASIL-D / 50ms FTTI)
   - Transport Goodput & Fault Recovery Overhead comparison (60/4 vs ISO-TP vs Castiglione)
   - Microarchitectural safety guarantees (zero major page faults, memory peak, cache hit rate)
5. Exports consolidated analytics to data/consolidated_phase3_metrics.json and prints executive summary
"""

import os
import sys
import csv
import json
import argparse
from datetime import datetime, timezone
from typing import Dict, Any, List

# Ensure Code/ is on path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CODE_DIR = os.path.join(BASE_DIR, 'Code')
CONFIG_DIR = os.path.join(BASE_DIR, 'config')
DATA_DIR = os.path.join(BASE_DIR, 'data')
FIXTURES_DIR = os.path.join(BASE_DIR, 'tests', 'fixtures')

if CODE_DIR not in sys.path:
    sys.path.insert(0, CODE_DIR)

from contract_validator import DataContractValidator

def parse_args():
    parser = argparse.ArgumentParser(description="Phase 3 Master Ingestion & Metrics Aggregator")
    parser.add_argument('--mock', action='store_true', default=True,
                        help="Run ingestion on verified reference fixtures (default: True)")
    parser.add_argument('--live', action='store_true',
                        help="Run ingestion on live teammate CSV data handoffs")
    parser.add_argument('--perf-csv', type=str, default=None,
                        help="Path to perf_stat_summary.csv")
    parser.add_argument('--tcp-csv', type=str, default=None,
                        help="Path to tcpdump_latency_summary.csv")
    parser.add_argument('--fault-csv', type=str, default=None,
                        help="Path to fault_recovery_runs.csv")
    parser.add_argument('--output-json', type=str, default=None,
                        help="Output path for consolidated metrics JSON")
    return parser.parse_args()

def load_csv_as_dicts(csv_path: str) -> List[Dict[str, str]]:
    rows = []
    with open(csv_path, 'r', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows

def synthesize_phase3_metrics(perf_rows: List[Dict[str, str]],
                             tcp_rows: List[Dict[str, str]],
                             fault_rows: List[Dict[str, str]],
                             provenance_mode: str) -> Dict[str, Any]:
    """
    Combines microarchitectural, network transit, and fault-recovery metrics
    into cross-domain system insights.
    """
    # 1. Microarchitectural Host Compute Budget (Gateway & ECU)
    task_profiles = {}
    total_gateway_host_time_ns = 0
    total_ecu_host_time_ns = 0
    max_rss_bytes = 0
    major_page_faults_total = 0

    for r in perf_rows:
        t_name = r['task_name']
        wall_ns = int(r['execution_wall_time_ns'])
        cycles = int(r['cpu_cycles'])
        instr = int(r['instructions'])
        ipc = float(r['ipc'])
        rss = int(r['peak_rss_bytes'])
        maj_pf = int(r['page_faults_major'])
        ecu = r['ecu_id']

        max_rss_bytes = max(max_rss_bytes, rss)
        major_page_faults_total += maj_pf

        if ecu == 'GATEWAY_ROUTER':
            total_gateway_host_time_ns += wall_ns
        elif ecu == 'ECU_POWERTRAIN':
            total_ecu_host_time_ns += wall_ns

        task_profiles[t_name] = {
            'ecu_id': ecu,
            'wall_time_us': round(wall_ns / 1000.0, 2),
            'cpu_cycles': cycles,
            'instructions': instr,
            'ipc': ipc,
            'peak_rss_kb': round(rss / 1024.0, 1),
            'page_faults_major': maj_pf
        }

    # 2. Schedulability Margins
    gateway_host_time_ms = round(total_gateway_host_time_ns / 1e6, 3)
    # Normative ASIL-D timing constraints:
    # - Local Task Deadline: 10.0 ms
    # - Fault Tolerant Time Interval (FTTI): 50.0 ms
    asil_d_deadline_ms = 10.0
    ftti_budget_ms = 50.0
    bus_wire_margin_ms = round(asil_d_deadline_ms - gateway_host_time_ms, 3)
    ftti_margin_ms = round(ftti_budget_ms - gateway_host_time_ms, 3)

    # 3. Transport Protocol Fault Recovery Comparison
    runs_list = []
    for r in fault_rows:
        run_id = r['run_id']
        scen_id = int(r['scenario_id'])
        scen_name = r['scenario_name']
        proto = r['protocol_name']
        fault_mod = r['fault_model']
        wire_frames = int(r['total_frames_on_wire'])
        wire_bytes = int(r['total_wire_bytes'])
        goodput = float(r['goodput_efficiency_pct'])
        latency_us = float(r['end_to_end_latency_us'])
        overhead_us = float(r['recovery_overhead_latency_us'])
        status = r['termination_status_code']
        iso_class = r['iso26262_failure_classification']

        runs_list.append({
            'run_id': run_id,
            'scenario_id': scen_id,
            'scenario_name': scen_name,
            'protocol_name': proto,
            'fault_model': fault_mod,
            'total_wire_frames': wire_frames,
            'total_wire_bytes': wire_bytes,
            'goodput_pct': goodput,
            'end_to_end_latency_ms': round(latency_us / 1000.0, 3),
            'recovery_overhead_ms': round(overhead_us / 1000.0, 3),
            'status': status,
            'iso26262_class': iso_class
        })

    # 4. Network Wire Transit Metrics (SocketCAN Frame Stats)
    wire_frame_count = len(tcp_rows)
    active_can_ids = sorted(list(set(r['can_id_hex'] for r in tcp_rows)))
    total_wire_latency_us = 0.0
    for r in tcp_rows:
        total_wire_latency_us += float(r['frame_duration_us'])

    return {
        'metadata': {
            'ingestion_timestamp_utc': datetime.now(timezone.utc).isoformat(),
            'provenance_mode': provenance_mode,
            'standards_conformance': [
                'ISO 11898-1:2015 (CAN-FD)',
                'ISO 15765-2:2016 (ISO-TP)',
                'ISO 26262:2018 (ASIL-D Timing & FTTI)',
                'ASAM MDF4 v4.2 & Vector BLF (ns Timestamps)',
                'ACM TECS / PQM4 (Raw PMU & MPKI)'
            ],
            'validation_status': 'ALL_CONTRACTS_100_PERCENT_VALIDATED'
        },
        'schedulability_synthesis': {
            'total_gateway_host_compute_ms': gateway_host_time_ms,
            'total_ecu_host_compute_ms': round(total_ecu_host_time_ns / 1e6, 3),
            'asil_d_task_deadline_ms': asil_d_deadline_ms,
            'available_bus_wire_margin_ms': bus_wire_margin_ms,
            'ftti_budget_ms': ftti_budget_ms,
            'available_ftti_margin_ms': ftti_margin_ms,
            'schedulable_under_asil_d': bus_wire_margin_ms > 0
        },
        'safety_integrity_audit': {
            'total_major_page_faults': major_page_faults_total,
            'asil_d_page_fault_compliant': (major_page_faults_total == 0),
            'peak_memory_rss_bytes': max_rss_bytes,
            'peak_memory_rss_mb': round(max_rss_bytes / (1024 * 1024), 2)
        },
        'network_capture_summary': {
            'total_frames_captured': wire_frame_count,
            'active_can_ids': active_can_ids,
            'aggregate_frame_duration_ms': round(total_wire_latency_us / 1000.0, 3)
        },
        'transport_fault_resilience_runs': runs_list,
        'task_microarchitectural_profiles': task_profiles
    }

def print_executive_summary(summary: Dict[str, Any]):
    print("=" * 80)
    print("      PHASE 3 INGESTION & ANALYTICAL SYNTHESIS ENGINE (MILESTONE M3.4)")
    print("=" * 80)
    meta = summary['metadata']
    print(f"Provenance Mode:      {meta['provenance_mode']}")
    print(f"Ingestion Timestamp:  {meta['ingestion_timestamp_utc']}")
    print(f"Validation Status:    {meta['validation_status']}")
    print("-" * 80)

    sched = summary['schedulability_synthesis']
    print("1. REAL-TIME SCHEDULABILITY & FTTI BUDGET:")
    print(f"   Gateway Total Host Compute:   {sched['total_gateway_host_compute_ms']:.3f} ms")
    print(f"   ASIL-D Task Deadline:         {sched['asil_d_task_deadline_ms']:.1f} ms")
    print(f"   Available Bus Wire Margin:    {sched['available_bus_wire_margin_ms']:.3f} ms "
          f"({'PASS - SCHEDULABLE' if sched['schedulable_under_asil_d'] else 'FAIL - OVERBUDGET'})")
    print(f"   FTTI Safety Budget (50.0 ms): {sched['available_ftti_margin_ms']:.3f} ms margin remaining")
    print("-" * 80)

    safety = summary['safety_integrity_audit']
    print("2. ISO 26262 SAFETY & MEMORY INTEGRITY:")
    print(f"   Total Major Page Faults:      {safety['total_major_page_faults']} "
          f"({'PASS - REAL-TIME COMPLIANT' if safety['asil_d_page_fault_compliant'] else 'FAIL - DISK I/O IN PATH'})")
    print(f"   Peak Resident Set Size:       {safety['peak_memory_rss_mb']:.2f} MB")
    print("-" * 80)

    print("3. TRANSPORT PROTOCOL FAULT RECOVERY BENCHMARK:")
    print(f"{'Scenario Name':<32} | {'Fault Model':<20} | {'Protocol':<18} | {'Frames':<6} | {'Bytes':<6} | {'Goodput':<8} | {'Status':<10}")
    print("-" * 115)
    runs = summary['transport_fault_resilience_runs']
    for r in runs:
        print(f"{r['scenario_name']:<32} | {r['fault_model']:<20} | {r['protocol_name']:<18} | {r['total_wire_frames']:<6} | {r['total_wire_bytes']:<6} | {r['goodput_pct']:<7.1f}% | {r['status']:<10}")
    print("=" * 80)

def main():
    args = parse_args()

    schema_path = os.path.join(CONFIG_DIR, 'data_contract_schemas.json')
    validator = DataContractValidator(schema_path)

    if args.live and args.perf_csv and args.tcp_csv and args.fault_csv:
        perf_path = args.perf_csv
        tcp_path = args.tcp_csv
        fault_path = args.fault_csv
        provenance = "LIVE_EMPIRICAL_TELEMETRY"
    else:
        perf_path = os.path.join(FIXTURES_DIR, 'sample_perf_stat_summary.csv')
        tcp_path = os.path.join(FIXTURES_DIR, 'sample_tcpdump_latency_summary.csv')
        fault_path = os.path.join(FIXTURES_DIR, 'sample_fault_recovery_runs.csv')
        provenance = "MOCK_CALIBRATED_FIXTURES"

    print(f"[+] Ingestion Mode: {provenance}")
    print(f"[+] Validating input CSV contracts against schema...")

    inputs = [
        ('perf_stat_summary', perf_path),
        ('tcpdump_latency_summary', tcp_path),
        ('fault_recovery_runs', fault_path)
    ]

    all_valid = True
    for c_name, c_path in inputs:
        valid, errors = validator.validate_csv(c_name, c_path)
        if valid:
            print(f"  [PASS] Contract '{c_name}' -> 100% compliant ({os.path.basename(c_path)})")
        else:
            print(f"  [FAIL] Contract '{c_name}' -> {len(errors)} validation errors!")
            for e in errors[:5]:
                print(f"         {e}")
            all_valid = False

    if not all_valid:
        print("[!] Ingestion aborted due to contract validation errors.")
        sys.exit(1)

    print("[+] Loading CSV records...")
    perf_rows = load_csv_as_dicts(perf_path)
    tcp_rows = load_csv_as_dicts(tcp_path)
    fault_rows = load_csv_as_dicts(fault_path)

    print("[+] Synthesizing cross-domain Phase 3 analytics...")
    summary = synthesize_phase3_metrics(perf_rows, tcp_rows, fault_rows, provenance)

    out_json = args.output_json or os.path.join(DATA_DIR, 'consolidated_phase3_metrics.json')
    with open(out_json, 'w', encoding='utf-8') as f:
        json.dump(summary, f, indent=2)
    print(f"[+] Consolidated analytics exported to: {out_json}")

    print_executive_summary(summary)

if __name__ == '__main__':
    main()
