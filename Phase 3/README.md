# Phase 3 Empirical Data Contracts & Telemetry Logging Guide
**Project:** Post-Quantum In-Vehicle Network Security & Attestation over CAN-FD  
**Team Members:** Tapan (23BDS1151), Kaustuv (23BDS1060), Kunal (23BDS1097)  
**Version:** 1.0 (Synthesized & Standards-Audited)  
**Normative Compliance:** ASAM MDF4 v4.2, Vector BLF, ISO 11898-1:2015, ISO 15765-2, ISO 26262 ASIL-D, ACM TECS / PQM4

---

## Executive Summary

To ensure our empirical Docker benchmarks integrate seamlessly with the analytical models and schedulability proofs for the final capstone report, **all simulation outputs must conform to three strict data contracts**. 

Ad-hoc CSVs, missing columns, arbitrary string names, and millisecond-rounded timestamps will break the automated pipeline. Before submitting any data, you must validate your files using the provided automated validator:
```bash
python Phase 3/Code/contract_validator.py
```

---

## 1. Kaustuv's Deliverables

Kaustuv is responsible for containerized microarchitectural profiling and network packet latency logging.

### Contract 1: `perf_stat_summary.csv` (CPU & Memory Profiling)
* **Target Output Path:** `Phase 3/data/incoming/perf_stat_summary.csv`
* **Reference Template:** [`Phase 3/tests/fixtures/sample_perf_stat_summary.csv`](file:///c:/Users/tapan/Downloads/7th%20sem%20Capstone/Anti%20Gravity/Phase%203/tests/fixtures/sample_perf_stat_summary.csv)
* **Total Columns:** Exactly **36 columns** in exact sequence.

#### How to Capture Linux `perf stat` Hardware Counters in Docker:
Run your benchmark executable pinned to a dedicated CPU core (to prevent cache invalidation) with the following PMU events:
```bash
taskset -c 2 perf stat -x, \
  -e cycles,instructions,cache-references,cache-misses,L1-dcache-loads,L1-dcache-load-misses,L1-icache-load-misses,LLC-loads,LLC-load-misses,branch-instructions,branch-misses,context-switches,cpu-migrations,page-faults \
  -- python3 run_crypto_benchmark.py
```

#### Mandatory Rules & Ground-Truth Constraints:
1. **Raw Counters Must Be Preserved:** Do NOT report only IPC or miss percentages. You must provide the raw integer counts (`cpu_cycles`, `instructions`, `l1_dcache_loads`, `l1_dcache_load_misses`, `branch_instructions`, `branch_misses`).
2. **ASIL-D Major Page Fault Rule:** `page_faults_major` **MUST BE STRICTLY `0`**. Any non-zero value indicates disk paging / swap I/O in the execution path, which is an immediate safety violation under ISO 26262.
3. **Execution Units:**
   * Time must be in **integer nanoseconds** (`execution_wall_time_ns` and `task_clock_ns`). Do not use float milliseconds.
   * Memory must be in **bytes** (`peak_rss_bytes` from `ru_maxrss * 1024` or `/proc/[pid]/status` `VmHWM`).
4. **Canonical `task_name` Identifiers:** You must use the exact function names from the codebase:
   * **Crypto:** `puf_secret_reconstruction`, `hkdf_bootstrap_key_derivation`, `mldsa_sign_attestation`, `mldsa_verify_attestation`, `ascon_aead128_encrypt`, `ascon_aead128_decrypt`, `cat2_wrap_and_fragment`, `cat2_reassemble_and_unwrap`.
   * **Gateway IDS:** `tier1_rate_limiter_check`, `tier1_monotonic_counter_gate`, `tier1_ascon_tag_verification`, `tier15_discrete_invariant_eval`, `gateway_14d_feature_extraction`, `tier2_onnx_int8_inference`, `tier2_onnx_fp32_inference`.

---

### Contract 2: `tcpdump_latency_summary.csv` (Network Wire Transit)
* **Target Output Path:** `Phase 3/data/incoming/tcpdump_latency_summary.csv`
* **Reference Template:** [`Phase 3/tests/fixtures/sample_tcpdump_latency_summary.csv`](file:///c:/Users/tapan/Downloads/7th%20sem%20Capstone/Anti%20Gravity/Phase%203/tests/fixtures/sample_tcpdump_latency_summary.csv)
* **Total Columns:** Exactly **22 columns** in exact sequence.

#### Mandatory Rules & Ground-Truth Constraints:
1. **Integer Nanosecond Timestamps:**
   * `timestamp_epoch_ns` must be an unsigned 64-bit integer (`uint64_t`) from SocketCAN `SO_TIMESTAMPNS` or Wireshark `pcapng`.
   * **Why float milliseconds are rejected:** CAN-FD frame transit times are $15\,\mu\text{s}$ to $350\,\mu\text{s}$ (and loopback on `vcan0` is $12\text{--}45\,\mu\text{s}$). Float milliseconds round these to 0 ms!
2. **Strict DLC vs Payload Length Separation (ISO 11898-1:2015):**
   * `dlc` = The CAN-FD code (`15` for 64B, `10` for 16B).
   * `payload_bytes` = Physical bytes on wire (`64` or `16`).
   * `payload_active_bytes` = Non-padded payload data bytes (e.g. `60` for frames 0–39; **`36` for Frame 40** because Frame 40 has 24 bytes of zero-padding).
3. **CAN Arbitration IDs:** Must be formatted as hex with leading `0x`:
   * `0x200` = Category 2 Attestation Burst (64B frames)
   * `0x201` = Category 3.2 Selective NACK Recovery Frame (16B frame)
   * `0x0D0` = Powertrain Telemetry (Speed/RPM)
   * `0x354` = Chassis Telemetry (Steering/Brake)
   * `0x4E7` = Thermal Telemetry (Coolant Temp)
   * `0x6E0` = Wheel Speed Telemetry (4 Wheels)
4. **Inter-Frame Timing:** Calculate `ifat_us` ($\Delta t_i = t_i - t_{i-1}$ in microseconds) and `arrival_jitter_ns`. (Leave empty/null on `frame_idx = 0`).

---

## 2. Kunal's Deliverables

Kunal is responsible for empirical fault injection, frame dropping, NACK bitmap retransmission, and ISO 26262 failure classification.

### Contract 3: `fault_recovery_runs.csv` (Fault Injection & Recovery)
* **Target Output Path:** `Phase 3/data/incoming/fault_recovery_runs.csv`
* **Reference Template:** [`Phase 3/tests/fixtures/sample_fault_recovery_runs.csv`](file:///c:/Users/tapan/Downloads/7th%20sem%20Capstone/Anti%20Gravity/Phase%203/tests/fixtures/sample_fault_recovery_runs.csv)
* **Total Columns:** Exactly **40 columns** in exact sequence.

#### Mandatory Test Scenarios You Must Execute:
You must log runs across the 5 canonical fault scenarios plus random Monte Carlo loss sweeps:
1. **Scenario 1: Clean Bus (Nominal):** 0 dropped frames (`injected_dropped_frame_indices` = `NONE`, `burst_length` = 0).
2. **Scenario 2: Isolated Single Frame Drop:** Drop Frame 12 (`injected_dropped_frame_indices` = `12`, `burst_length` = 1).
3. **Scenario 3: Late-Sequence Frame Drop:** Drop Frame 38 (`injected_dropped_frame_indices` = `38`, `burst_length` = 1).
4. **Scenario 4: Inductive Relay Transient Spike:** Drop 3 consecutive frames (`injected_dropped_frame_indices` = `14;15;16`, `burst_length` = 3).
5. **Scenario 5: Alternator Commutation Burst:** Drop 8 consecutive frames (`injected_dropped_frame_indices` = `20;21;22;23;24;25;26;27`, `burst_length` = 8).

#### Mandatory Rules & Ground-Truth Constraints:
1. **Spatial Coordinates:** Injected frame drops must be recorded as a semicolon-delimited string (e.g. `"14;15;16"` or `"NONE"`).
2. **NACK Bitmaps in Hex:** Record the 64-bit NACK bitmap transmitted on CAN ID `0x201` as a hex string (e.g. `"0x000000000001c000"` for frames 14–16, or `"N_A"` for protocols that do not use bitmaps).
3. **Multi-Round Disambiguation:** Record per-round requested and recovered frame counts (`round_1_requested_frames`, `round_1_recovered_frames`, `round_2_...`, `round_3_...`).
4. **ISO 26262 Failure Codes (`termination_status_code`):** Do not just say True/False. Use standard diagnostic enums:
   * `SUCCESS` = Clean assembly and cryptographic tag verified
   * `ERR_RETRY_EXHAUSTION` = Exceeded max 3 retry rounds ($K_{\text{retry}} = 3$)
   * `ERR_TIMEOUT_NACK_WAIT` = NACK response not received before timer expiry
   * `ERR_CRYPTO_TAG_MISMATCH` = Frame delivered but Ascon AEAD tag verification failed (bit flip)
   * `ERR_SOCKET_BUFFER_OVERFLOW` = Kernel buffer drop (`ENOBUFS`)

---

## 3. How to Validate Your CSVs Before Submitting

You have two automated checks. Both must pass before handing off your data:

### Step 1: Run the Contract Validator
Run the validator directly in Python to inspect your CSV:
```bash
python Phase 3/Code/contract_validator.py
```
If there are any missing columns, out-of-bounds numbers, or wrong enums, it will print the exact row and column number:
```text
[PASS] Contract 'perf_stat_summary' -> 100% compliant
[PASS] Contract 'tcpdump_latency_summary' -> 100% compliant
[PASS] Contract 'fault_recovery_runs' -> 100% compliant
```

### Step 2: Run the Automated Unit Tests
Run the project CI test suite:
```bash
python -m unittest Phase 3/tests/test_data_contracts.py
```
Expected output:
```text
Ran 12 tests in 0.125s
OK
```

---

## 4. Summary Checklist for Handoff

- [ ] `perf_stat_summary.csv` has exactly 36 columns with raw PMU counts and `page_faults_major == 0`.
- [ ] `tcpdump_latency_summary.csv` has exactly 22 columns with `uint64_t` integer nanosecond timestamps.
- [ ] `fault_recovery_runs.csv` has exactly 40 columns covering all 5 canonical scenarios with 64-bit hex NACK bitmaps.
- [ ] Ran `python -m unittest Phase 3/tests/test_data_contracts.py` and got `OK`.
- [ ] Placed completed files in `Phase 3/data/incoming/` or committed to your feature branch.
