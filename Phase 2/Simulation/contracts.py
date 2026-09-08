"""Phase 2 & Phase 3 Data Contract Validator for CAN-FD Fault Recovery Benchmarks."""
import copy
import csv
import json
import math
import os
from pathlib import Path
import re
import sys

# Dynamic root and schema discovery
_CURRENT_DIR = Path(__file__).resolve().parent
_CANDIDATE_SCHEMAS = [
    _CURRENT_DIR.parents[1] / "Phase 3/config/data_contract_schemas.json",
    _CURRENT_DIR.parents[2] / "Anti Gravity/Phase 3/config/data_contract_schemas.json",
    _CURRENT_DIR.parents[2] / "Git repo/Phase 3/config/data_contract_schemas.json",
    _CURRENT_DIR.parents[0] / "data_contract_schemas.json",
]

SCHEMA = None
for s in _CANDIDATE_SCHEMAS:
    if s.exists():
        SCHEMA = s.resolve()
        break

if SCHEMA is None:
    raise FileNotFoundError(f"data_contract_schemas.json not found in candidate locations: {_CANDIDATE_SCHEMAS}")

ROOT = SCHEMA.parents[2]


def columns():
    """Retrieve canonical 40-column contract specification from schema JSON."""
    raw = json.loads(SCHEMA.read_text(encoding="utf-8"))
    return raw["contracts"]["fault_recovery_runs"]["columns"]


def profile():
    """Returns validated profile specifications preserving physical validation constraints."""
    specs = copy.deepcopy(columns())
    for spec in specs.values():
        spec.pop("source", None)
    # Ensure min: 0.0 constraint is strictly preserved (resolves Bug 7)
    if "validation" not in specs["recovery_overhead_latency_us"]:
        specs["recovery_overhead_latency_us"]["validation"] = {}
    specs["recovery_overhead_latency_us"]["validation"]["min"] = 0.0
    specs["recovery_overhead_latency_us"]["description"] = (
        "Non-negative excess latency incurred by fault recovery strictly >= 0.0 us"
    )
    return specs


def validate(path, strict=False, enforce_delivered_requests=True):
    """
    Validates CSV file against canonical 40-column schema.
    Returns empty list on 100% successful validation, or list of error strings.
    """
    specs = columns() if strict else profile()
    errors, rows, identifiers = [], [], set()

    csv_path = Path(path)
    if not csv_path.exists():
        return [f"File not found: {csv_path}"]

    with csv_path.open(newline="", encoding="utf-8") as stream:
        reader = csv.DictReader(stream)
        if reader.fieldnames != list(specs):
            return [
                f"Header mismatch. Expected {len(specs)} columns in order: {list(specs.keys())}, "
                f"got {len(reader.fieldnames or [])}: {reader.fieldnames}"
            ]

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
                            raise ValueError(f"required column '{name}' cannot be empty")
                        row[name] = None
                        continue

                    kind = spec["type"]
                    if kind == "boolean":
                        if value not in ("True", "False"):
                            raise ValueError("boolean must be 'True' or 'False'")
                        value = (value == "True")
                    elif "int" in kind:
                        value = int(value)
                        bits_match = re.search(r"\d+", kind)
                        if bits_match:
                            bits = int(bits_match.group(0))
                            lo, hi = (0, 2**bits - 1) if kind.startswith("u") else (-2**(bits-1), 2**(bits-1)-1)
                            if not (lo <= value <= hi):
                                raise ValueError(f"integer {value} exceeds {kind} range [{lo}, {hi}]")
                    elif kind.startswith("float"):
                        value = float(value)
                        if not math.isfinite(value):
                            raise ValueError("float must be finite")

                    if "enum" in spec and value not in spec["enum"]:
                        raise ValueError(f"value '{value}' not in allowed enum: {spec['enum']}")

                    rules = spec.get("validation", {})
                    if isinstance(rules, str):
                        if not re.fullmatch(rules, str(value)):
                            raise ValueError(f"value '{value}' does not match regex pattern '{rules}'")
                    elif isinstance(rules, dict):
                        if "min" in rules and value < rules["min"]:
                            raise ValueError(f"value {value} is below minimum {rules['min']}")
                        if "max" in rules and value > rules["max"]:
                            raise ValueError(f"value {value} is above maximum {rules['max']}")
                        if "allowed" in rules and value not in rules["allowed"]:
                            raise ValueError(f"value {value} not in allowed list {rules['allowed']}")

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
            require(row["protocol_name"] == "SIXTY_FOUR_BLOCK", "runner implements SIXTY_FOUR_BLOCK")
            require(row["initial_frames_sent"] == 41, "initial_frames_sent must be 41")

            # Physical CAN-FD checks (resolves Bug 8)
            if strict or row.get("bitrate_regime") is not None:
                require(row["bitrate_regime"] in ("CASTIGLIONE_1MBPS", "PROD_CANFD_2MBPS", "HIGHPERF_CANFD_5MBPS"),
                        f"invalid bitrate regime {row.get('bitrate_regime')}")
                require(row["nominal_baud"] in (500000, 1000000), f"invalid nominal baud {row.get('nominal_baud')}")
                require(row["data_baud"] in (1000000, 2000000, 5000000), f"invalid data baud {row.get('data_baud')}")
                require(row["total_frames_on_wire"] is not None and row["total_frames_on_wire"] >= 41,
                        "total_frames_on_wire must be >= 41")
                require(row["total_wire_bytes"] is not None and row["total_wire_bytes"] >= 2436,
                        "total_wire_bytes must be >= 2436")
                require(0.0 <= row.get("goodput_efficiency_pct", -1) <= 100.0,
                        "goodput_efficiency_pct must be between 0.0 and 100.0")

            drops = [] if row["injected_dropped_frame_indices"] == "NONE" else [
                int(x) for x in row["injected_dropped_frame_indices"].split(";")
            ]
            require(drops == sorted(set(drops)) and all(0 <= x < 41 for x in drops),
                    "drop indices must be unique sorted indices 0..40")

            maps = [] if row["nack_bitmaps_issued_hex"] == "N_A" else [
                int(x, 16) for x in row["nack_bitmaps_issued_hex"].split(";")
            ]
            require(len(maps) == row["recovery_rounds"] == row["nack_frames_issued_count"] == row["control_frames_count"],
                    "round / control / bitmap count mismatch")

            for i in range(1, 4):
                requested = row[f"round_{i}_requested_frames"]
                recovered = row[f"round_{i}_recovered_frames"]
                require(0 <= recovered <= requested, f"round {i}: recovered exceeds requested")
                if i <= len(maps):
                    require(maps[i-1] < (1 << 41) and maps[i-1].bit_count() == requested,
                            f"round {i}: bitmap disagrees with requested frames count")
                else:
                    require(requested == recovered == 0, f"round {i}: unused round must be 0")

            require(row["recovery_success"] == (row["termination_status_code"] == "SUCCESS"),
                    "recovery_success boolean mismatch with termination_status_code")
            require(row["retry_exhaustion_flag"] == (row["termination_status_code"] == "ERR_RETRY_EXHAUSTION"),
                    "retry_exhaustion_flag mismatch with termination_status_code")
            require(row["ftti_violation_flag"] == (row["end_to_end_latency_us"] > row["ftti_budget_us"]),
                    "ftti_violation_flag calculation mismatch")
            require(row["safety_state_achieved"] == ("OPERATIONAL" if row["recovery_success"] and not row["ftti_violation_flag"] else "SAFE_FALLBACK"),
                    "safety_state_achieved mismatch with recovery_success / ftti_violation")

            expected_retransmits = sum(row[f"round_{i}_requested_frames"] for i in range(1, 4))
            if row["termination_status_code"] == "ERR_TIMEOUT_NACK_WAIT":
                expected_retransmits -= row[f"round_{row['recovery_rounds']}_requested_frames"] if row["recovery_rounds"] else 0
            if enforce_delivered_requests:
                require(row["retransmitted_frames_count"] == expected_retransmits,
                        "retransmitted_frames_count disagrees with sum of requested frames")

            # Non-negative recovery overhead validation (resolves Bug 6 & Bug 7)
            require(row["recovery_overhead_latency_us"] >= 0.0,
                    f"recovery_overhead_latency_us ({row['recovery_overhead_latency_us']}) cannot be negative")

    if not rows and not errors:
        errors.append("CSV contains no valid run records")
    return errors
