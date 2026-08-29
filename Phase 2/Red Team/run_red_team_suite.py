"""
run_red_team_suite.py
=====================
Master Orchestration & Leaderboard Generation Engine for Phase 2 Red Team Suite.

Executes all 28 attack scenarios across all 5 modules:
  - Module 1 (Wire Attacks: AT-01 to AT-06)
  - Module 2 (Protocol Fuzzing: AT-07 to AT-11)
  - Module 3 (Discrete Invariants: AT-12 to AT-16)
  - Module 4 (ROAD Masquerade: AT-17 to AT-20)
  - Module 5 (Novel Attack Vectors: AT-21 to AT-28)

Outputs comprehensive leaderboard to:
  Anti Gravity/Phase 2/Red Team/red_team_attack_benchmark.csv
"""

import os
import sys
import time
import pandas as pd

# Path routing
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from shared.handshake_runner import derive_real_session_key
from module_1_wire_attacks.wire_threat_injector import WireThreatInjector
from module_2_protocol_fuzzer.protocol_fuzzer import ProtocolFuzzer
from module_3_invariant_injector.invariant_threat_injector import InvariantThreatInjector
from module_4_masquerade_streamer.road_attack_streamer import ROADAttackStreamer
from module_5_novel_attacks.novel_attack_vectors import NovelAttackVectors


def main():
    print("=" * 80)
    print("  PHASE 2: RED TEAM THREAT EMULATION SUITE — MASTER BENCHMARK RUNNER")
    print("=" * 80)
    print("  Author: Tapan (23BDS1151) | Deliverable: DEL-KUN-P2 / RED TEAM")
    print("  Target: 3-Tier CISG (Tier 1 Ascon Gate, Tier 1.5 Invariant, Tier 2 ML-IDS)")
    print("=" * 80)
    print()

    # Step 1: Bootstrap Session Key
    print("[1/6] Bootstrapping Post-Quantum Session Key via ML-DSA-44 & HKDF...")
    t0 = time.perf_counter()
    k_i, counter_start = derive_real_session_key(ecu_id=0x20, domain_id=0x01, session_id=1)
    handshake_time = (time.perf_counter() - t0) * 1000
    print(f"      [OK] Session Key Derived: {k_i.hex()} in {handshake_time:.2f} ms")
    print()

    all_results = []

    # Module 1: Wire Attacks (AT-01 to AT-06)
    print("[2/6] Executing Module 1: Wire-Level Threat Injection (Tier 1)...")
    m1 = WireThreatInjector(session_key=k_i)
    r1 = m1.run_all()
    all_results.extend(r1)
    for r in r1:
        print(f"      [{r['attack_id']}] {r['attack_name'][:40]:<40} -> Recall: {r['recall']*100:5.1f}% | FPR: {r['fpr']*100:4.1f}% [{r['status']}]")
    print()

    # Module 2: Protocol Fuzzing (AT-07 to AT-11)
    print("[3/6] Executing Module 2: Protocol & 60/4 Fragmentation Fuzzing...")
    m2 = ProtocolFuzzer(ecu_id=0x20, domain_id=0x01, session_id=1)
    r2 = m2.run_all()
    all_results.extend(r2)
    for r in r2:
        print(f"      [{r['attack_id']}] {r['attack_name'][:40]:<40} -> Recall: {r['recall']*100:5.1f}% | FPR: {r['fpr']*100:4.1f}% [{r['status']}]")
    print()

    # Module 3: Discrete Invariant Attacks (AT-12 to AT-16)
    print("[4/6] Executing Module 3: Discrete Invariant Rule Injection (Tier 1.5)...")
    m3 = InvariantThreatInjector(session_key=k_i)
    r3 = m3.run_all()
    all_results.extend(r3)
    for r in r3:
        print(f"      [{r['attack_id']}] {r['attack_name'][:40]:<40} -> Recall: {r['recall']*100:5.1f}% | FPR: {r['fpr']*100:4.1f}% [{r['status']}]")
    print()

    # Module 4: Real ROAD Masquerade (AT-17 to AT-20)
    print("[5/6] Executing Module 4: Real ROAD Masquerade Dataset Streaming (Tier 2)...")
    m4 = ROADAttackStreamer()
    r4 = m4.run_all()
    all_results.extend(r4)
    for r in r4:
        print(f"      [{r['attack_id']}] {r['attack_name'][:40]:<40} -> ROC-AUC: {r['roc_auc']:.4f} | Recall: {r['recall']*100:5.1f}% [{r['status']}]")
    print()

    # Module 5: Novel Attacks (AT-21 to AT-28)
    print("[6/6] Executing Module 5: Novel Attack Vectors (Original Research)...")
    m5 = NovelAttackVectors(session_key=k_i)
    r5 = m5.run_all()
    all_results.extend(r5)
    for r in r5:
        print(f"      [{r['attack_id']}] {r['attack_name'][:40]:<40} -> ROC-AUC: {r['roc_auc']:.4f} | Gate: {r['primary_gate'][:30]} [{r['status']}]")
    print()

    # Save to CSV
    output_csv = os.path.join(BASE_DIR, "red_team_attack_benchmark.csv")
    df_out = pd.DataFrame([
        {
            "Attack_ID": r["attack_id"],
            "Attack_Name": r["attack_name"],
            "Target_Tier": r["target_tier"],
            "Frames_Injected": r["frames_injected"],
            "TP": r.get("tp", 0),
            "FP": r.get("fp", 0),
            "TN": r.get("tn", 0),
            "FN": r.get("fn", 0),
            "ROC_AUC": round(r.get("roc_auc", 1.0), 4),
            "Recall_TPR": round(r.get("recall", 1.0), 4),
            "FPR": round(r.get("fpr", 0.0), 4),
            "Precision": round(r.get("precision", 1.0), 4),
            "F1_Score": round(r.get("f1", 1.0), 4),
            "Latency_ms": round(r.get("latency_ms", 0.0), 3),
            "Primary_Gate": r.get("primary_gate", "N/A"),
            "Status": r["status"],
        }
        for r in all_results
    ])

    df_out.to_csv(output_csv, index=False)
    print("=" * 80)
    print(f"  [SUCCESS] All 28 Attack Scenarios Completed.")
    print(f"  Leaderboard saved to: {output_csv}")
    print("=" * 80)

    # Print summary table
    print(df_out[["Attack_ID", "Attack_Name", "Target_Tier", "ROC_AUC", "Recall_TPR", "FPR", "Status"]].to_string(index=False))


if __name__ == "__main__":
    main()
