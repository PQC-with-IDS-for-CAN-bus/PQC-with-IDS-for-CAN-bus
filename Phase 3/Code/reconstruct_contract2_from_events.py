"""
reconstruct_contract2_from_events.py
====================================
Reconstructs Contract 2 (tcpdump_latency_summary.csv) directly from the 1,268
"fragment_accepted" kernel SO_TIMESTAMPNS events recorded in
Git repo/Phase 3/DockerLab/simulation_results/events.jsonl and manifest.json,
copies the companion live CSVs into Anti Gravity/Phase 3/data/, and validates
all three contracts against config/data_contract_schemas.json.

Strict Read-Only Policy:
- Never modifies or writes to Git repo/.
- Writes outputs exclusively inside Anti Gravity/Phase 3/data/.
"""

import csv
import json
import shutil
from pathlib import Path
from typing import Dict, Any, Tuple

from contract_validator import DataContractValidator

PHASE3_DIR = Path(__file__).resolve().parent.parent
WORKSPACE_ROOT = PHASE3_DIR.parent.parent
GIT_SIM_RESULTS_DIR = WORKSPACE_ROOT / "Git repo" / "Phase 3" / "DockerLab" / "simulation_results"
DATA_OUT_DIR = PHASE3_DIR / "data"
SCHEMA_PATH = PHASE3_DIR / "config" / "data_contract_schemas.json"


def reconstruct_tcpdump_latency_summary(
    events_path: Path = GIT_SIM_RESULTS_DIR / "events.jsonl",
    manifest_path: Path = GIT_SIM_RESULTS_DIR / "manifest.json",
    schema_path: Path = SCHEMA_PATH,
    out_csv_path: Path = DATA_OUT_DIR / "tcpdump_latency_summary.csv",
) -> Dict[str, Any]:
    """
    Reconstructs Contract 2 (tcpdump_latency_summary.csv) from events.jsonl.
    Returns summary metadata dictionary.
    """
    if not events_path.exists():
        raise FileNotFoundError(f"events.jsonl not found at {events_path}")
    if not manifest_path.exists():
        raise FileNotFoundError(f"manifest.json not found at {manifest_path}")

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    session_to_run: Dict[str, str] = manifest.get("arrivals", {}).get("session_to_run", {})
    run_to_session: Dict[str, str] = {run_id: sess_id for sess_id, run_id in session_to_run.items()}

    schema = json.loads(schema_path.read_text(encoding="utf-8"))
    specs = list(schema["contracts"]["tcpdump_latency_summary"]["columns"].keys())

    events = [
        json.loads(line)
        for line in events_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]

    # Index ECU TX 0x200 frames by (run_id, domain, round, frame_idx) and fallback (run_id, domain, frame_idx)
    ecu_tx_exact: Dict[Tuple[str, int, int, int], Dict[str, Any]] = {}
    ecu_tx_fallback: Dict[Tuple[str, int, int], Dict[str, Any]] = {}
    for e in events:
        if e.get("event") == "tx" and e.get("can_id") == "0x200" and str(e.get("node", "")).startswith("ecu"):
            run_id = e.get("run_id", "")
            dom = int(e.get("domain", 1))
            rnd = int(e.get("round", 0))
            f_idx = int(e.get("frame_idx", 0))
            ecu_tx_exact[(run_id, dom, rnd, f_idx)] = e
            ecu_tx_fallback[(run_id, dom, f_idx)] = e

    nominal_baud = 500000
    data_baud = 2000000
    tau_nom = 1.0 / nominal_baud
    tau_dat = 1.0 / data_baud

    clocks: Dict[Tuple[str, int], int] = {}
    previous: Dict[Tuple[str, int], int] = {}
    rows = []

    for e in events:
        if e.get("event") != "fragment_accepted" or not str(e.get("node", "")).startswith("gateway-d"):
            continue

        run_id = e.get("run_id", "")
        if run_id not in run_to_session:
            continue

        domain = int(e.get("domain", 1))
        frame_idx = int(e.get("frame_idx", 0))
        rnd = int(e.get("round", 0))
        stamp = e.get("kernel_epoch_ns")
        if stamp is None:
            raise ValueError(f"Kernel RX timestamp missing in fragment_accepted event: {e}")
        stamp = int(stamp)

        key = (run_id, domain)
        clocks.setdefault(key, stamp)
        if stamp < previous.get(key, stamp):
            raise ValueError(f"Kernel epoch clock moved backwards within session {key}")

        tx_meta = ecu_tx_exact.get((run_id, domain, rnd, frame_idx)) or ecu_tx_fallback.get(
            (run_id, domain, frame_idx), {}
        )
        payload_len = int(e.get("payload_bytes", tx_meta.get("payload_bytes", 64)))
        dlc = int(e.get("dlc", tx_meta.get("dlc", 15)))
        brs_flag = int(e.get("brs_flag", tx_meta.get("brs_flag", 1)))
        esi_flag = int(e.get("esi_flag", tx_meta.get("esi_flag", 0)))

        # Nominal ISO 11898-1:2015 physical frame duration (331.5 us for 64B @ 500k/2M)
        nom_bits = 29
        crc_bits = 29 if payload_len > 16 else 25
        data_bits = 6 + (8 * payload_len) + crc_bits
        frame_duration_us = round((nom_bits * tau_nom + data_bits * tau_dat) * 1e6, 2)

        ifat_us = round((stamp - previous[key]) / 1000.0, 2) if key in previous else None
        jitter_ns = (
            int(stamp - previous[key] - int(round(frame_duration_us * 1000)))
            if key in previous
            else None
        )

        row = dict.fromkeys(specs, None)
        row.update(
            session_id=run_to_session[run_id],
            frame_idx=frame_idx,
            total_frames_expected=41,
            bus_channel=domain,
            protocol_name="SIXTY_FOUR_BLOCK",
            frame_role="DATA",
            retransmit_attempt_idx=rnd,
            can_id_hex="0x200",
            ide_flag=0,
            dlc=dlc,
            payload_bytes=payload_len,
            payload_active_bytes=36 if frame_idx == 40 else 60,
            brs_flag=brs_flag,
            esi_flag=esi_flag,
            timestamp_epoch_ns=stamp,
            timestamp_rel_us=round((stamp - clocks[key]) / 1000.0, 2),
            ifat_us=ifat_us,
            arrival_jitter_ns=jitter_ns,
            nominal_baud=nominal_baud,
            data_baud=data_baud,
            frame_duration_us=frame_duration_us,
            interface_rx_drops=int(e.get("interface_rx_drops", 0)),
        )
        previous[key] = stamp
        rows.append(row)

    out_csv_path.parent.mkdir(parents=True, exist_ok=True)
    with out_csv_path.open("w", newline="", encoding="utf-8") as stream:
        writer = csv.DictWriter(stream, fieldnames=specs)
        writer.writeheader()
        writer.writerows(rows)

    return {
        "rows": len(rows),
        "sessions_covered": len({r["session_id"] for r in rows}),
        "output_path": str(out_csv_path),
    }


def sync_and_validate_all_contracts() -> Dict[str, Any]:
    DATA_OUT_DIR.mkdir(parents=True, exist_ok=True)
    local_sim_dir = PHASE3_DIR / "DockerLab" / "simulation_results"
    local_sim_dir.mkdir(parents=True, exist_ok=True)

    # Restore 31-task perf_stat_summary.csv and comparative fault_recovery_runs.csv in data/
    git_data_dir = WORKSPACE_ROOT / "Git repo" / "Phase 3" / "data"
    for fname in ("perf_stat_summary.csv", "fault_recovery_runs.csv"):
        src_data = git_data_dir / fname
        if src_data.exists():
            shutil.copyfile(src_data, DATA_OUT_DIR / fname)

    # Sync 31-run EndeavourOS fault_recovery_runs.csv into DockerLab/simulation_results/
    if (GIT_SIM_RESULTS_DIR / "fault_recovery_runs.csv").exists():
        shutil.copyfile(
            GIT_SIM_RESULTS_DIR / "fault_recovery_runs.csv",
            local_sim_dir / "fault_recovery_runs.csv",
        )
    # Also ensure DockerLab/simulation_results/perf_stat_summary.csv has all 31 tasks
    if (DATA_OUT_DIR / "perf_stat_summary.csv").exists():
        shutil.copyfile(
            DATA_OUT_DIR / "perf_stat_summary.csv",
            local_sim_dir / "perf_stat_summary.csv",
        )

    # Reconstruct 1,268-row Contract 2 into data/tcpdump_latency_summary.csv and copy to DockerLab/simulation_results/
    summary = reconstruct_tcpdump_latency_summary()
    shutil.copyfile(
        DATA_OUT_DIR / "tcpdump_latency_summary.csv",
        local_sim_dir / "tcpdump_latency_summary.csv",
    )

    validator = DataContractValidator(str(SCHEMA_PATH))
    validation_results = {}
    for label, target_dir in (("data", DATA_OUT_DIR), ("simulation_results", local_sim_dir)):
        validation_results[label] = {}
        for contract_name in ("perf_stat_summary", "tcpdump_latency_summary", "fault_recovery_runs"):
            csv_path = target_dir / f"{contract_name}.csv"
            valid, errors = validator.validate_csv(contract_name, str(csv_path))
            validation_results[label][contract_name] = {"valid": valid, "errors": errors}
            if not valid:
                raise RuntimeError(f"Contract validation failed for {label}/{contract_name}: {errors[:5]}")

    summary["validation"] = validation_results
    return summary


if __name__ == "__main__":
    res = sync_and_validate_all_contracts()
    print(json.dumps(res, indent=2))
