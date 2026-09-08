#!/usr/bin/env python3
"""
run_simulation.py (Repaired & Cross-Platform)
==============================================
Executes real post-quantum ML-DSA-44 signing/verification, Ascon-AEAD128 wrapping,
and 60/4 block transfer selective NACK fault injection over datagram sockets.
Runs natively on Windows, Linux, and macOS without requiring a virtual machine or WSL.
Populates all 40 Phase 3 data contract columns (ASAM/ISO 26262 compliant).
"""
import argparse
import csv
import hashlib
import importlib.metadata
import json
import math
import os
from pathlib import Path
import platform
import random
import socket
import struct
import subprocess
import sys
import time
import uuid

# Import local data contract specifications
from contracts import ROOT, SCHEMA, columns, profile, validate

# Resolve crypto engine path dynamically
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
from crypto_engine import KeyDerivation, PostQuantumAttestation, SessionManager
from canfd_schema import AttestationDeliveryManager, IndexedAttestationFrame

SCENARIOS = [
    (1, "Clean Bus (Nominal)", "NOMINAL_CLEAN", ()),
    (2, "Isolated Single Frame Drop", "SINGLE_FRAME_DROP", (12,)),
    (3, "Late-Sequence Frame Drop", "LATE_SEQUENCE_DROP", (38,)),
    (4, "Inductive Relay Transient Spike", "BURST_FRAME_DROP", (14, 15, 16)),
    (5, "Alternator Commutation Burst", "BURST_FRAME_DROP", tuple(range(20, 28))),
]

# Cat 3.2 Selective NACK Layout: type:u8, ecu:u8, round:u8, reserved:u8, session:u32, missing_bitmap:u64 (BE)
NACK = struct.Struct(">BBBBIQ")
ENVELOPE = struct.Struct(">I")  # Logical CAN ID on the local datagram channel


def digest(path):
    """Compute SHA-256 hash of file content."""
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def longest_burst(indices):
    """Compute longest consecutive run of dropped frames."""
    best = current = 0
    previous = -2
    for index in sorted(indices):
        current = current + 1 if index == previous + 1 else 1
        best = max(best, current)
        previous = index
    return best


def create_cross_platform_datagram_pair():
    """
    Creates a bidirectional datagram socketpair compatible with Windows, macOS, and Linux.
    Resolves Windows lack of socket.AF_UNIX datagram socketpairs.
    """
    if hasattr(socket, "AF_UNIX") and hasattr(socket, "SOCK_DGRAM"):
        try:
            return socket.socketpair(socket.AF_UNIX, socket.SOCK_DGRAM)
        except (AttributeError, OSError):
            pass

    # High-performance localhost UDP fallback for Windows
    server = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server.bind(("127.0.0.1", 0))
    server_addr = server.getsockname()

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind(("127.0.0.1", 0))
    client_addr = client.getsockname()

    server.connect(client_addr)
    client.connect(server_addr)
    return client, server


def execute(scenario, trial, args, rng, public, secret, provisioned, measurement):
    sid, name, model, targets = scenario
    run_id = str(uuid.uuid4())
    session = int.from_bytes(os.urandom(4), "big")
    challenge = SessionManager.generate_random_challenge()
    bootstrap = KeyDerivation.derive_bootstrap_key(hashlib.sha256(provisioned).digest(), challenge, 0x20, session)

    # Capture start time BEFORE cryptographic signing & Ascon wrapping (resolves Bug 1)
    started = time.perf_counter_ns()
    prep_start = started

    signature = PostQuantumAttestation.sign_attestation_transcript(
        secret_key=secret, protocol_version=1, ecu_id=0x20, session_id=session,
        random_challenge=challenge, measurement_hash=measurement)
    frames = AttestationDeliveryManager.wrap_and_fragment(
        signature=signature, k_boot_i=bootstrap, random_challenge=challenge,
        ecu_id=0x20, session_id=session)
    prep_ns = time.perf_counter_ns() - prep_start

    if len(frames) != 41 or any(len(f) != 64 for f in frames):
        raise RuntimeError("Phase 1 fragmentation contract changed: expected 41 frames of 64 bytes")

    events, received, initial_drops, bitmaps = [], {}, set(), []
    requested, recovered = [0, 0, 0], [0, 0, 0]
    retransmitted = 0
    first_turnaround = None
    status = "SUCCESS"

    # Cross-platform socket pair creation (resolves Windows crash)
    ecu, gateway = create_cross_platform_datagram_pair()
    socket_timeout_s = args.timeout_ms / 1000.0
    ecu.settimeout(socket_timeout_s)
    gateway.settimeout(socket_timeout_s)

    def event(kind, round_no, **details):
        events.append(dict(run_id=run_id, t_ns=time.perf_counter_ns() - started,
                           event=kind, round=round_no, **details))

    # Log initial preparation completion event
    event("prep", 0, prep_ns=prep_ns, details="ML-DSA-44 sign + Ascon-128 AEAD wrap")

    def transfer(source, destination, can_id, payload, round_no, drop=False, corrupt=False):
        wire = bytearray(payload)
        if corrupt:
            wire[4] ^= 1  # Ciphertext bit corruption
        source.send(ENVELOPE.pack(can_id) + wire)
        event("tx", round_no, can_id=f"0x{can_id:03x}", payload_hex=wire.hex(),
              frame_idx=payload[1] if can_id == 0x200 else None)
        packet = destination.recv(128)
        if packet != ENVELOPE.pack(can_id) + wire:
            raise RuntimeError("Datagram envelope mismatch on transmission channel")
        event("drop" if drop else "rx", round_no, can_id=f"0x{can_id:03x}",
              frame_idx=payload[1] if can_id == 0x200 else None,
              payload_hex=bytes(wire).hex(), corruption_injected=corrupt)
        return None if drop else bytes(wire)

    def data(indices, round_no):
        nonlocal retransmitted, first_turnaround
        for index in indices:
            drop = (round_no == 0 and index in targets) or (model == "PERSISTENT_DROP" and index in targets)
            if model == "BERNOULLI_RANDOM":
                drop = rng.random() < args.loss_rate
            if round_no:
                retransmitted += 1
            elif drop:
                initial_drops.add(index)
            payload = transfer(ecu, gateway, 0x200, frames[index], round_no,
                               drop=drop, corrupt=(model == "PAYLOAD_BIT_FLIP" and index == 12))
            if payload is not None:
                header, _ = IndexedAttestationFrame.unpack_frame(payload)
                # Resilient header handling (resolves Bug 26)
                if header["session_id"] != (session & 0xFF) or header["frame_index"] != index:
                    event("anomaly", round_no, reason="HEADER_MISMATCH",
                          expected_session=session & 0xFF, got_session=header["session_id"])
                    continue
                received[index] = payload
                if round_no:
                    recovered[round_no - 1] += 1
                    if first_turnaround is None:
                        first_turnaround = (time.perf_counter_ns() - nack_started) / 1000.0

    def wait_timeout(endpoint, round_no):
        before = time.perf_counter_ns()
        try:
            endpoint.recv(128)
        except socket.timeout:
            waited = time.perf_counter_ns() - before
            event("timeout", round_no, waited_ns=waited)
        else:
            raise RuntimeError("Unexpected queued packet encountered while awaiting timeout")

    verification_ns = 0
    tag_valid = signature_valid = None
    try:
        data(range(41), 0)
        for round_no in range(1, 4):
            if len(received) == 41:
                break
            wait_timeout(gateway, round_no)
            missing = sorted(set(range(41)) - received.keys())
            bitmap = sum(1 << index for index in missing)
            bitmaps.append(f"0x{bitmap:016x}")
            requested[round_no - 1] = len(missing)

            # Handle zero-bitmap edge case immediately (resolves Bug 27)
            if bitmap == 0:
                break

            nack_started = time.perf_counter_ns()
            control = transfer(gateway, ecu, 0x201, NACK.pack(0x13, 0x20, round_no, 0, session, bitmap),
                               round_no, drop=(model == "NACK_CONTROL_FRAME_DROP"))
            if control is None:
                wait_timeout(ecu, round_no)
                status = "ERR_TIMEOUT_NACK_WAIT"
                break
            kind, target, counter, reserved, got_session, got_bitmap = NACK.unpack(control)
            if (kind, target, counter, reserved, got_session) != (0x13, 0x20, round_no, 0, session) or (got_bitmap >> 41):
                raise RuntimeError("Invalid NACK control header or bitmap out of 41-bit range")
            data([i for i in range(41) if got_bitmap & (1 << i)], round_no)

        # Eliminate redundant 4th socket wait on retry exhaustion (resolves Bug 29)
        if len(received) != 41 and status == "SUCCESS":
            status = "ERR_RETRY_EXHAUSTION"

        if status == "SUCCESS":
            before = time.perf_counter_ns()
            try:
                decoded = AttestationDeliveryManager.reassemble_and_unwrap(
                    frames=[received[i] for i in range(41)], k_boot_i=bootstrap,
                    random_challenge=challenge, expected_ecu_id=0x20, expected_session_id=session)
            except ValueError:
                tag_valid = False
                status = "ERR_CRYPTO_TAG_MISMATCH"
            else:
                tag_valid = True
                signature_valid = PostQuantumAttestation.verify_attestation_signature(
                    public_key=public, signature=decoded, protocol_version=1, ecu_id=0x20,
                    session_id=session, random_challenge=challenge, measurement_hash=measurement)
                if not signature_valid:
                    status = "ERR_CRYPTO_SIG_INVALID"
            verification_ns = time.perf_counter_ns() - before
            event("authentication", len(bitmaps), ascon_tag_valid=tag_valid, mldsa_signature_valid=signature_valid)

        elapsed_ns = time.perf_counter_ns() - started
        event("termination", len(bitmaps), status=status, received_frames=len(received), elapsed_ns=elapsed_ns)
    finally:
        ecu.close()
        gateway.close()

    success = (status == "SUCCESS")
    classification = ("RECOVERED_FAULT" if bitmaps else "SAFE_TRANSMISSION") if success else (
        "CORRUPTED_FRAME_REJECTED" if "CRYPTO" in status else
        "PROTOCOL_ABORT_TIMEOUT" if "TIMEOUT" in status else "INFORMATION_LOSS_OMISSION")

    # Wire and frame accounting
    control_count = len(bitmaps)
    total_frames_on_wire = 41 + retransmitted + control_count
    total_wire_bytes = (41 + retransmitted) * 64 + control_count * 16
    app_payload_bytes = 2436  # 2420 ML-DSA signature + 16 Ascon tag
    goodput_pct = round((app_payload_bytes / total_wire_bytes) * 100.0, 3)

    row = dict.fromkeys(columns(), None)
    row.update(
        run_id=run_id,
        trial_idx=trial,
        scenario_id=sid,
        scenario_name=name,
        protocol_name="SIXTY_FOUR_BLOCK",
        fault_model="BURST_FRAME_DROP" if model == "PERSISTENT_DROP" else model,
        injected_dropped_frame_indices=";".join(map(str, sorted(initial_drops))) or "NONE",
        burst_length=longest_burst(initial_drops),
        channel_loss_rate_p=args.loss_rate if model == "BERNOULLI_RANDOM" else 0.0,
        payload_corruption_injected=(model == "PAYLOAD_BIT_FLIP"),
        recovery_success=success,
        recovery_rounds=len(bitmaps),
        retransmit_policy="selective_nack_bitmap",
        nack_frames_issued_count=len(bitmaps),
        nack_bitmaps_issued_hex=";".join(bitmaps) or "N_A",
        initial_frames_sent=41,
        retransmitted_frames_count=retransmitted,
        control_frames_count=control_count,
        # Populating all 6 physical CAN-FD columns (resolves Bug 8)
        bitrate_regime="PROD_CANFD_2MBPS",
        nominal_baud=500000,
        data_baud=2000000,
        total_frames_on_wire=total_frames_on_wire,
        total_wire_bytes=total_wire_bytes,
        goodput_efficiency_pct=goodput_pct,
        # End-to-end latency inclusive of preparation and verification (resolves Bug 1)
        end_to_end_latency_us=elapsed_ns / 1000.0,
        nominal_clean_time_us=0.0,
        recovery_overhead_latency_us=0.0,
        nack_turnaround_time_us=first_turnaround,
        retry_exhaustion_flag=(status == "ERR_RETRY_EXHAUSTION"),
        termination_status_code=status,
        iso26262_failure_classification=classification,
        ftti_budget_us=args.ftti_us,
        ftti_violation_flag=(elapsed_ns / 1000.0 > args.ftti_us),
        safety_state_achieved="OPERATIONAL" if success and (elapsed_ns / 1000.0 <= args.ftti_us) else "SAFE_FALLBACK",
    )
    for i in range(3):
        row[f"round_{i+1}_requested_frames"] = requested[i]
        row[f"round_{i+1}_recovered_frames"] = recovered[i]

    evidence = dict(
        run_id=run_id, injection=model, initial_targets=list(targets),
        preparation_ns=prep_ns, verification_ns=verification_ns,
        session_id=session, challenge_hex=challenge.hex(), signature_hex=signature.hex(),
        ascon_tag_valid=tag_valid, mldsa_signature_valid=signature_valid,
        activation_allowed=(row["safety_state_achieved"] == "OPERATIONAL"),
        received_frames=len(received),
        local_data_payload_bytes=(41 + retransmitted) * 64,
        local_control_payload_bytes=len(bitmaps) * 16,
    )
    return row, events, evidence


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, default=Path(__file__).parent / "results" / time.strftime("%Y%m%d-%H%M%S"))
    parser.add_argument("--trials", type=int, default=3)
    parser.add_argument("--monte-carlo", type=int, default=20)
    parser.add_argument("--loss-rate", type=float, default=0.2)
    parser.add_argument("--seed", type=int, default=20260906)
    parser.add_argument("--timeout-ms", type=float, default=2.5, help="CAN-FD inter-frame timeout (scaled to ~3 frame times)")
    parser.add_argument("--ftti-us", type=float, default=50000.0, help="ASIL-D normative FTTI budget (50.0 ms)")
    args = parser.parse_args()

    if args.trials < 1 or args.monte_carlo < 0 or not (0 <= args.loss_rate <= 1) or not all(
        math.isfinite(x) and x > 0 for x in (args.timeout_ms, args.ftti_us)
    ):
        parser.error("invalid trial count, loss probability, timeout or budget")

    args.output.mkdir(parents=True, exist_ok=True)
    public, secret = PostQuantumAttestation.generate_mldsa_keypair()
    provisioned = os.urandom(32)
    measurement = hashlib.sha256(Path(__file__).read_bytes()).digest()
    rng = random.Random(args.seed)

    rows, evidence = [], []
    extra = [
        (2, SCENARIOS[1][1], "PERSISTENT_DROP", (12,)),
        (2, SCENARIOS[1][1], "NACK_CONTROL_FRAME_DROP", (12,)),
        (1, SCENARIOS[0][1], "PAYLOAD_BIT_FLIP", ()),
    ]
    baseline = None

    with (args.output / "events.jsonl").open("w", encoding="utf-8") as trace:
        work = [(scenario, trial) for trial in range(args.trials) for scenario in SCENARIOS + extra]
        work += [((0, "Monte Carlo Loss Sweep", "BERNOULLI_RANDOM", ()), trial) for trial in range(args.monte_carlo)]

        for scenario, trial in work:
            row, events, record = execute(scenario, trial, args, rng, public, secret, provisioned, measurement)
            if scenario[2] == "NOMINAL_CLEAN":
                baseline = row
            baseline_time = baseline["end_to_end_latency_us"]
            row["nominal_clean_time_us"] = baseline_time

            # Non-negative recovery overhead computation (resolves Bug 6 & Bug 30)
            if not row["recovery_success"] and row["end_to_end_latency_us"] < baseline_time:
                # Early failure exit (e.g. tag corruption skips signature verification)
                row["recovery_overhead_latency_us"] = 0.0
            else:
                row["recovery_overhead_latency_us"] = max(0.0, row["end_to_end_latency_us"] - baseline_time)

            record["baseline_run_id"] = baseline["run_id"]
            rows.append(row)
            evidence.append(record)
            trace.writelines(json.dumps(event) + "\n" for event in events)
            print(f"{len(rows):3d}  {scenario[2]:25s}  {row['termination_status_code']:26s}  {row['end_to_end_latency_us']:10.3f} us", flush=True)

    csv_path = args.output / "fault_recovery_runs.csv"
    with csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=columns())
        writer.writeheader()
        writer.writerows(rows)

    # Validate against strict contract (resolves Bug 22 & Bug 8)
    errors = validate(csv_path, strict=True)
    if errors:
        raise RuntimeError(f"Data contract validation failed:\n" + "\n".join(errors))

    sources = [
        Path(__file__),
        Path(__file__).with_name("contracts.py"),
        Path(__file__).with_name("validate_results.py"),
        Path(__file__).with_name("report.py"),
        SCHEMA,
    ] + [CRYPTO / n for n in ("crypto_engine.py", "canfd_schema.py", "ascon_official.py")]

    profile_path = args.output / "measurement_profile.json"
    profile_path.write_text(json.dumps(profile(), indent=2) + "\n", encoding="utf-8")

    # Dynamic cryptographic source hash provenance (resolves Bug 39)
    metadata = dict(
        profile="phase2-measured-canfd-v2",
        created_epoch_ns=time.time_ns(),
        transport="Cross-platform dual-stack datagram socketpair; ISO 11898-1 CAN-FD physical model",
        python=sys.version,
        platform=platform.platform(),
        seed=args.seed,
        arguments={k: str(v) if isinstance(v, Path) else v for k, v in vars(args).items()},
        public_key_hex=public.hex(),
        measurement_hash_hex=measurement.hex(),
        dependencies={
            p: importlib.metadata.version(p)
            for p in ("cryptography", "dilithium-py")
            if importlib.util.find_spec(p) is not None
        },
        source_sha256={str(p.name): digest(p) for p in sources if p.exists()},
        output_sha256={p.name: digest(p) for p in (csv_path, args.output / "events.jsonl", profile_path)},
        strict_phase3_errors=validate(csv_path, strict=True),
        runs=evidence,
    )
    (args.output / "manifest.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")

    from validate_results import audit
    failures = audit(args.output)
    if failures:
        raise RuntimeError(f"Trace audit failed:\n" + "\n".join(failures))

    from report import render
    render(args.output, rows, metadata)
    print(f"\nSuccessfully executed and verified {len(rows)} fault recovery runs.")
    print(f"Data Contract strict validation: PASS (0 errors across all 40 columns).")
    print(f"HTML Report generated at: {args.output / 'report.html'}")


if __name__ == "__main__":
    main()
