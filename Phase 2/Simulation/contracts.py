"""Phase 2 measurement profile; never substitute numbers for unobserved hardware."""
import copy
import csv
import json
import math
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = ROOT / "Phase 3/config/data_contract_schemas.json"
UNAVAILABLE = {
    "bitrate_regime", "nominal_baud", "data_baud", "total_frames_on_wire",
    "total_wire_bytes", "goodput_efficiency_pct",
}


def columns():
    return json.loads(SCHEMA.read_text())["contracts"]["fault_recovery_runs"]["columns"]


def profile():
    specs = copy.deepcopy(columns())
    for spec in specs.values():
        spec.pop("source", None)
    for name in UNAVAILABLE:
        specs[name]["nullable"] = True
        specs[name]["description"] = "Unavailable in local datagram execution; no physical CAN measurement."
    specs["end_to_end_latency_us"]["description"] = "Measured host time from immediately before first data send through authentication or failure."
    specs["nack_turnaround_time_us"]["description"] = "Measured host time from immediately before NACK send to first successfully received retry."
    specs["nack_turnaround_time_us"]["nullable_reason"] = "No retry frame successfully received, including clean bus, NACK omission and complete retry loss."
    specs["ftti_budget_us"]["description"] = "User-selected experimental deadline, not a HARA-derived budget."
    specs["termination_status_code"]["description"] = "Project-defined diagnostic outcome; not an ISO-standard literal code."
    specs["iso26262_failure_classification"]["description"] = "Project classification only; no ISO 26262 compliance claim."
    specs["safety_state_achieved"]["description"] = "Software activation decision only; no physical actuator is controlled."
    # Independent host measurements can have a negative paired difference.
    specs["recovery_overhead_latency_us"]["validation"] = {}
    specs["recovery_overhead_latency_us"]["description"] = "Signed difference between observed latency and referenced clean run; includes host variability."
    return specs


def validate(path, strict=False, enforce_delivered_requests=True):
    """Check exact ordering, finite numbers, widths, enums and accounting."""
    specs = columns() if strict else profile()
    errors, rows, identifiers = [], [], set()
    with Path(path).open(newline="") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(specs):
            return ["Header must contain exactly the 40 Phase 3 columns in order."]
        for number, raw in enumerate(reader, 2):
            row = {}
            if None in raw or None in raw.values():
                errors.append(f"Row {number}: wrong number of values")
                continue
            for name, spec in specs.items():
                value = raw[name]
                try:
                    if value == "":
                        if not spec.get("nullable", False):
                            raise ValueError("required measurement is unavailable")
                        row[name] = None
                        continue
                    kind = spec["type"]
                    if kind == "boolean":
                        if value not in ("True", "False"):
                            raise ValueError("use True or False")
                        value = value == "True"
                    elif "int" in kind:
                        value = int(value)
                        bits = int(re.search(r"\d+", kind)[0])
                        lo, hi = (0, 2**bits - 1) if kind.startswith("u") else (-2**(bits-1), 2**(bits-1)-1)
                        if not lo <= value <= hi:
                            raise ValueError("integer exceeds declared width")
                    elif kind.startswith("float"):
                        value = float(value)
                        if not math.isfinite(value):
                            raise ValueError("must be finite")
                    if "enum" in spec and value not in spec["enum"]:
                        raise ValueError("not an allowed enum")
                    rules = spec.get("validation", {})
                    if isinstance(rules, str):
                        if not re.fullmatch(rules, str(value)):
                            raise ValueError("invalid format")
                    else:
                        if "min" in rules and value < rules["min"]:
                            raise ValueError("below minimum")
                        if "max" in rules and value > rules["max"]:
                            raise ValueError("above maximum")
                        if "allowed" in rules and value not in rules["allowed"]:
                            raise ValueError("not an allowed value")
                    row[name] = value
                except (ValueError, TypeError) as exc:
                    errors.append(f"Row {number}, Column '{name}': {exc}")
            if len(row) != len(specs):
                continue
            rows.append(row)
            def require(condition, message):
                if not condition:
                    errors.append(f"Row {number}: {message}")
            require(row["run_id"] not in identifiers, "duplicate run_id")
            identifiers.add(row["run_id"])
            require(row["protocol_name"] == "SIXTY_FOUR_BLOCK", "this runner implements only SIXTY_FOUR_BLOCK")
            if not strict:
                require(all(row[x] is None for x in UNAVAILABLE), "software profile must not claim physical measurements")
            require(row["initial_frames_sent"] == 41, "initial_frames_sent must be 41")
            drops = [] if row["injected_dropped_frame_indices"] == "NONE" else [int(x) for x in row["injected_dropped_frame_indices"].split(";")]
            require(drops == sorted(set(drops)) and all(0 <= x < 41 for x in drops), "drop indices must be unique sorted indices 0..40")
            maps = [] if row["nack_bitmaps_issued_hex"] == "N_A" else [int(x, 16) for x in row["nack_bitmaps_issued_hex"].split(";")]
            require(len(maps) == row["recovery_rounds"] == row["nack_frames_issued_count"] == row["control_frames_count"], "round/control/bitmap count mismatch")
            for i in range(1, 4):
                requested, recovered = row[f"round_{i}_requested_frames"], row[f"round_{i}_recovered_frames"]
                require(0 <= recovered <= requested, f"round {i}: recovered exceeds requested")
                if i <= len(maps):
                    require(maps[i-1] < 1 << 41 and maps[i-1].bit_count() == requested, f"round {i}: bitmap disagrees with requested frames")
                else:
                    require(requested == recovered == 0, f"round {i}: unused round must be zero")
            require(row["recovery_success"] == (row["termination_status_code"] == "SUCCESS"), "success/status mismatch")
            require(row["retry_exhaustion_flag"] == (row["termination_status_code"] == "ERR_RETRY_EXHAUSTION"), "retry/status mismatch")
            require(row["ftti_violation_flag"] == (row["end_to_end_latency_us"] > row["ftti_budget_us"]), "FTTI comparison mismatch")
            require(row["safety_state_achieved"] == ("OPERATIONAL" if row["recovery_success"] and not row["ftti_violation_flag"] else "SAFE_FALLBACK"), "activation state disagrees with authentication/deadline")
            expected_retransmits = sum(row[f"round_{i}_requested_frames"] for i in range(1, 4))
            if row["termination_status_code"] == "ERR_TIMEOUT_NACK_WAIT":
                expected_retransmits -= row[f"round_{row['recovery_rounds']}_requested_frames"] if row["recovery_rounds"] else 0
            if enforce_delivered_requests:
                require(row["retransmitted_frames_count"] == expected_retransmits, "retransmit count disagrees with delivered requests")
            require(math.isclose(row["recovery_overhead_latency_us"], row["end_to_end_latency_us"] - row["nominal_clean_time_us"], abs_tol=1e-6), "baseline difference mismatch")
    if not rows and not errors:
        errors.append("CSV contains no runs")
    return errors
