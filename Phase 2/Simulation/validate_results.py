#!/usr/bin/env python3
"""Audit recorded executions against their byte-level trace and public signatures."""
import argparse
import csv
import hashlib
import json
from pathlib import Path
import struct
import sys

from contracts import ROOT, validate


def audit(directory):
    directory = Path(directory)
    errors = validate(directory / "fault_recovery_runs.csv")
    manifest = json.loads((directory / "manifest.json").read_text())
    def require(condition, message):
        if not condition:
            errors.append(message)
    for name, expected in manifest["output_sha256"].items():
        require(hashlib.sha256((directory / name).read_bytes()).hexdigest() == expected, f"Hash mismatch: {name}")
    events = {}
    for line in (directory / "events.jsonl").read_text().splitlines():
        entry = json.loads(line)
        events.setdefault(entry["run_id"], []).append(entry)
    records = {r["run_id"]: r for r in manifest["runs"]}
    with (directory / "fault_recovery_runs.csv").open(newline="") as stream:
        rows = list(csv.DictReader(stream))
    row_by_id = {r["run_id"]: r for r in rows}
    require(set(row_by_id) == set(events) == set(records), "Run IDs disagree between CSV, trace and manifest")
    sys.path.insert(0, str(ROOT / "Phase 1/CAN FD/Crypto Code"))
    from crypto_engine import PostQuantumAttestation
    for row in rows:
        run_id = row["run_id"]
        if run_id not in events or run_id not in records:
            continue
        trace, record = events[run_id], records[run_id]
        def check(condition, message):
            require(condition, f"Run {run_id}: {message}")
        check(all(a["t_ns"] <= b["t_ns"] for a,b in zip(trace, trace[1:])), "timestamps out of order")
        sent = [e for e in trace if e["event"] == "tx"]
        data = [e for e in sent if e["can_id"] == "0x200"]
        controls = [e for e in sent if e["can_id"] == "0x201"]
        check(len(data) == 41 + int(row["retransmitted_frames_count"]), "data transmission count mismatch")
        check(len(controls) == int(row["control_frames_count"]), "control transmission count mismatch")
        check(record["local_data_payload_bytes"] == sum(len(bytes.fromhex(e["payload_hex"])) for e in data), "local byte count mismatch")
        accepted, lost, pending = {}, [], None
        round_rx = [0, 0, 0]
        maps = []
        for event in trace:
            if event["event"] == "tx":
                check(pending is None, "send lacks receive/drop decision")
                pending = event
                if event["can_id"] == "0x201":
                    payload = bytes.fromhex(event["payload_hex"])
                    check(len(payload) == 16, "NACK must be 16 bytes")
                    kind, ecu, rnd, reserved, session, bitmap = struct.unpack(">BBBBIQ", payload)
                    expected = sum(1 << i for i in set(range(41))-accepted.keys())
                    check((kind, ecu, rnd, reserved, session, bitmap) == (0x13, 0x20, event["round"], 0, record["session_id"], expected), "NACK does not describe actual missing frames")
                    maps.append(f"0x{bitmap:016x}")
                else:
                    payload = bytes.fromhex(event["payload_hex"])
                    check(len(payload) == 64 and payload[0] == record["session_id"] & 255 and payload[2] == 41, "bad data framing")
            elif event["event"] in ("rx", "drop"):
                check(pending is not None and all(event[k] == pending[k] for k in ("can_id", "round", "payload_hex", "frame_idx")), "received bytes differ from sent bytes")
                pending = None
                if event["can_id"] == "0x200":
                    if event["event"] == "rx":
                        check(event["frame_idx"] not in accepted, "duplicate recovery")
                        accepted[event["frame_idx"]] = event["payload_hex"]
                        if event["round"]:
                            round_rx[event["round"]-1] += 1
                    elif event["round"] == 0:
                        lost.append(event["frame_idx"])
            elif event["event"] == "timeout":
                check(event["waited_ns"] >= manifest["arguments"]["timeout_ms"] * 1e6, "timeout was not actually waited")
        check(pending is None, "undelivered final datagram")
        check((";".join(map(str, sorted(lost))) or "NONE") == row["injected_dropped_frame_indices"], "initial drop string differs from trace")
        check((";".join(maps) or "N_A") == row["nack_bitmaps_issued_hex"], "CSV bitmap differs from transmitted bitmap")
        for i, count in enumerate(round_rx, 1):
            check(count == int(row[f"round_{i}_recovered_frames"]), f"round {i} recovered count differs from trace")
        end = trace[-1]
        check(end["event"] == "termination" and end["status"] == row["termination_status_code"], "termination mismatch")
        check(end["elapsed_ns"]/1000 == float(row["end_to_end_latency_us"]), "measured latency mismatch")
        check(len(accepted) == record["received_frames"] == end["received_frames"], "assembly count mismatch")
        check(float(row["nominal_clean_time_us"]) == float(row_by_id[record["baseline_run_id"]]["end_to_end_latency_us"]), "baseline is not an observed run")
        if row["recovery_success"] == "True":
            check(len(accepted) == 41, "success without all fragments")
            check(record["ascon_tag_valid"] is True and record["mldsa_signature_valid"] is True, "success without both authentication checks")
        check(record["activation_allowed"] == (row["safety_state_achieved"] == "OPERATIONAL"), "activation record differs from CSV")
        if row["termination_status_code"] == "ERR_RETRY_EXHAUSTION":
            check(len(maps) == 3 and len(accepted) < 41, "incorrect exhaustion")
        check(PostQuantumAttestation.verify_attestation_signature(
            public_key=bytes.fromhex(manifest["public_key_hex"]), signature=bytes.fromhex(record["signature_hex"]),
            protocol_version=1, ecu_id=0x20, session_id=record["session_id"],
            random_challenge=bytes.fromhex(record["challenge_hex"]), measurement_hash=bytes.fromhex(manifest["measurement_hash_hex"])),
            "public verification of generated ML-DSA signature failed")
    return errors


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    parser.add_argument("--strict-phase3", action="store_true")
    args = parser.parse_args()
    errors = validate(args.directory / "fault_recovery_runs.csv", strict=True) if args.strict_phase3 else audit(args.directory)
    print("FAIL" if errors else "PASS: CSV, trace accounting, output hashes and ML-DSA signatures")
    for error in errors:
        print(error)
    raise SystemExit(bool(errors))
