#!/usr/bin/env python3
"""
validate_results.py (Audited & Provenance-Verified)
===================================================
Audits recorded CAN-FD simulation executions against their byte-level trace,
cryptographic signatures, and strict 40-column data contracts.
"""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from contracts import ROOT, validate

# Resolve crypto path dynamically
CRYPTO_CANDIDATES = [
    ROOT / "Anti Gravity/Phase 1/Crypto/Code",
    ROOT / "Git repo/Phase 1/CAN FD/Crypto Code",
    ROOT / "Phase 1/CAN FD/Crypto Code",
    ROOT / "Phase 1/Crypto/Code",
]
CRYPTO = None
for c in CRYPTO_CANDIDATES:
    if (c / "crypto_engine.py").exists():
        CRYPTO = c.resolve()
        break

if CRYPTO is None:
    raise FileNotFoundError(f"crypto_engine.py not found in candidate locations: {CRYPTO_CANDIDATES}")

sys.path.insert(0, str(CRYPTO))
from crypto_engine import PostQuantumAttestation


def audit(directory):
    directory = Path(directory)
    errors = validate(directory / "fault_recovery_runs.csv", strict=True)
    manifest_path = directory / "manifest.json"
    if not manifest_path.exists():
        return errors + [f"manifest.json not found in {directory}"]

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))

    def require(condition, message):
        if not condition:
            errors.append(message)

    # Verify SHA-256 hashes of generated output files
    for name, expected in manifest["output_sha256"].items():
        target = directory / name
        if not target.exists():
            require(False, f"Missing output file: {name}")
            continue
        actual_hash = hashlib.sha256(target.read_bytes()).hexdigest()
        require(actual_hash == expected, f"Hash mismatch for {name}: expected {expected[:10]}..., got {actual_hash[:10]}...")

    events_path = directory / "events.jsonl"
    if not events_path.exists():
        return errors + [f"events.jsonl not found in {directory}"]

    events = {}
    for line in events_path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            entry = json.loads(line)
            events.setdefault(entry["run_id"], []).append(entry)

    records = {r["run_id"]: r for r in manifest["runs"]}
    with (directory / "fault_recovery_runs.csv").open(newline="", encoding="utf-8") as stream:
        rows = list(csv.DictReader(stream))
    row_by_id = {r["run_id"]: r for r in rows}

    require(set(row_by_id) == set(events) == set(records),
            "Run IDs disagree between CSV, trace, and manifest records")

    for row in rows:
        run_id = row["run_id"]
        if run_id not in events or run_id not in records:
            continue
        trace, record = events[run_id], records[run_id]

        def check(condition, message):
            require(condition, f"Run {run_id}: {message}")

        check(all(a["t_ns"] <= b["t_ns"] for a, b in zip(trace, trace[1:])), "Timestamps out of chronological order")

        sent = [e for e in trace if e["event"] == "tx"]
        data = [e for e in sent if e["can_id"] == "0x200"]
        controls = [e for e in sent if e["can_id"] == "0x201"]

        check(len(data) == 41 + int(row["retransmitted_frames_count"]), "Data transmission frame count mismatch")
        check(len(controls) == int(row["control_frames_count"]), "Control transmission frame count mismatch")
        check(record["local_data_payload_bytes"] == sum(len(bytes.fromhex(e["payload_hex"])) for e in data),
              "Local payload byte count mismatch")

        accepted, lost, pending = {}, [], None
        round_rx = [0, 0, 0]
        maps = []

        for event in trace:
            if event["event"] == "tx":
                check(pending is None, "Send lacks subsequent receive or drop decision")
                pending = event
                if event["can_id"] == "0x201":
                    payload = bytes.fromhex(event["payload_hex"])
                    check(len(payload) == 16, "NACK control frame must be exactly 16 bytes")
                    kind, ecu, rnd, reserved, session, bitmap = struct.unpack(">BBBBIQ", payload)
                    expected = sum(1 << i for i in (set(range(41)) - accepted.keys()))
                    check((kind, ecu, rnd, reserved, session, bitmap) == (0x13, 0x20, event["round"], 0, record["session_id"], expected),
                          "NACK frame fields do not describe actual missing frame bitmap")
                    maps.append(f"0x{bitmap:016x}")
                else:
                    payload = bytes.fromhex(event["payload_hex"])
                    check(len(payload) == 64 and payload[0] == (record["session_id"] & 255) and payload[2] == 41,
                          "Malformed CAN-FD data framing header")
            elif event["event"] in ("rx", "drop"):
                check(pending is not None and all(event[k] == pending[k] for k in ("can_id", "round", "payload_hex", "frame_idx")),
                      "Received bytes differ from transmitted bytes")
                pending = None
                if event["can_id"] == "0x200":
                    if event["event"] == "rx":
                        check(event["frame_idx"] not in accepted, "Duplicate frame index recovery")
                        accepted[event["frame_idx"]] = event["payload_hex"]
                        if event["round"]:
                            round_rx[event["round"] - 1] += 1
                    elif event["round"] == 0:
                        lost.append(event["frame_idx"])
            elif event["event"] == "timeout":
                # Account for OS timer resolution and scheduler jitter (50% threshold)
                expected_timeout_ns = float(manifest["arguments"]["timeout_ms"]) * 1e6 * 0.5
                check(event["waited_ns"] >= expected_timeout_ns, f"Socket timeout was not waited (got {event['waited_ns']/1e6:.2f} ms, expected >= {expected_timeout_ns/1e6:.2f} ms)")

        check(pending is None, "Undelivered final datagram left in flight")
        check((";".join(map(str, sorted(lost))) or "NONE") == row["injected_dropped_frame_indices"],
              "Initial drop indices string differs from execution trace")
        check((";".join(maps) or "N_A") == row["nack_bitmaps_issued_hex"],
              "CSV bitmap string differs from transmitted NACK bitmaps")

        for i, count in enumerate(round_rx, 1):
            check(count == int(row[f"round_{i}_recovered_frames"]), f"Round {i} recovered count differs from trace")

        end = trace[-1]
        check(end["event"] == "termination" and end["status"] == row["termination_status_code"],
              "Termination status code mismatch between trace and CSV")
        check(end["elapsed_ns"] / 1000.0 == float(row["end_to_end_latency_us"]), "Measured latency mismatch")
        check(len(accepted) == record["received_frames"] == end["received_frames"], "Frame assembly count mismatch")
        check(float(row["nominal_clean_time_us"]) == float(row_by_id[record["baseline_run_id"]]["end_to_end_latency_us"]),
              "Baseline is not a valid observed run")

        if row["recovery_success"] == "True":
            check(len(accepted) == 41, "Success declared without complete 41-fragment assembly")
            check(record["ascon_tag_valid"] is True and record["mldsa_signature_valid"] is True,
                  "Success declared without both Ascon tag and ML-DSA signature passing")

        check(record["activation_allowed"] == (row["safety_state_achieved"] == "OPERATIONAL"),
              "Activation record differs from safety_state_achieved")

        if row["termination_status_code"] == "ERR_RETRY_EXHAUSTION":
            check(len(maps) == 3 and len(accepted) < 41, "Incorrect retry exhaustion state")

        # Independent public verification of ML-DSA-44 signature
        sig_valid = PostQuantumAttestation.verify_attestation_signature(
            public_key=bytes.fromhex(manifest["public_key_hex"]),
            signature=bytes.fromhex(record["signature_hex"]),
            protocol_version=1,
            ecu_id=0x20,
            session_id=record["session_id"],
            random_challenge=bytes.fromhex(record["challenge_hex"]),
            measurement_hash=bytes.fromhex(manifest["measurement_hash_hex"]),
        )
        check(sig_valid, "Public cryptographic verification of ML-DSA-44 attestation signature failed")

    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, help="Path to simulation results directory")
    args = parser.parse_args()

    failures = audit(args.directory)
    if failures:
        print(f"FAILED with {len(failures)} verification errors:")
        for f in failures:
            print(f"  - {f}")
        sys.exit(1)
    else:
        print("PASS: 100% trace, signature, and contract verification succeeded.")


if __name__ == "__main__":
    main()
