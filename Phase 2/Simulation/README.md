# Phase 2 fault recovery laboratory

Run real ML-DSA-44 signing, Ascon-AEAD128 encryption/decryption, HKDF derivation,
and fragment exchanges over Linux local datagram sockets. Demonstrate selective
recovery by replaying the resulting byte-level trace in `report.html`.
No Phase 3 fixture rows, fixed performance numbers, mock crypto, fabricated
hardware counters, or prerecorded success decisions are used.

## Run and present

From the repository root, using Python 3.10 or newer:

```bash
python3 -m venv 'Phase 2/Simulation/.venv'
'Phase 2/Simulation/.venv/bin/python' -m pip install -r 'Phase 2/Simulation/requirements.txt'
'Phase 2/Simulation/.venv/bin/python' 'Phase 2/Simulation/run_simulation.py'
```

On a machine with `uv`, it can create the environment and install the same pins:

```bash
uv venv 'Phase 2/Simulation/.venv'
uv pip install --python 'Phase 2/Simulation/.venv/bin/python' -r 'Phase 2/Simulation/requirements.txt'
```

Each invocation creates a new timestamped `results/` directory and refuses to
overwrite an existing directory. Open its `report.html` in a browser. Choose a run,
press Replay, or scrub through the actual recorded events. Animation is deliberately
slower than execution; the microsecond timestamps remain the measured values.
This is an offline replay, not a browser-connected live CAN controller.

```bash
'Phase 2/Simulation/.venv/bin/python' 'Phase 2/Simulation/run_simulation.py' \
  --output 'Phase 2/Simulation/results/my-demo' \
  --trials 3 --monte-carlo 20 --loss-rate 0.2 --seed 20260906 \
  --timeout-ms 5 --ftti-us 50000

'Phase 2/Simulation/.venv/bin/python' 'Phase 2/Simulation/validate_results.py' \
  'Phase 2/Simulation/results/my-demo'
```

The default suite executes 44 runs: three repetitions of five canonical scenarios
and three diagnostic scenarios, followed by 20 Bernoulli loss trials. Change the
seed and loss rate to perform further sweeps. The seed controls loss decisions
only. Cryptographic key generation, provisioning secrets and challenges use fresh
system randomness, so ciphertext and timings are not bit-for-bit reproducible.

## What is actually executed

1. Generate an ML-DSA keypair and a random software enrollment secret. This runner
   does not call the deterministic Phase 1 PUF emulator or claim physical PUF data.
2. Hash the actual runner source as the attested measurement. This demonstrates
   attestation of a real file, not a measurement of vehicle firmware.
3. For every run, choose a fresh challenge/session, derive the bootstrap key, sign
   the transcript, and wrap/fragment using the existing Phase 1 Python code.
4. Send all 41 real 64-byte encrypted frames through an `AF_UNIX/SOCK_DGRAM`
   socket pair. A four-byte local envelope carries logical CAN ID `0x200`.
5. Consume every datagram; the injection stage deliberately discards selected
   frames before application reassembly. Record both transmission and delivery/drop.
   A drop is application-level omission after socket receipt, not electrical loss.
6. If incomplete, wait on an actual socket receive timeout, derive the missing
   bitmap from receiver state, and send a 16-byte NACK with logical CAN ID `0x201`.
   Decode that NACK at the sender before selecting retransmissions. At most three
   NACK rounds are permitted. There is a final receive timeout before exhaustion.
7. Assemble by index, verify the Ascon tag, and independently verify ML-DSA.
   On failure or experimental budget overrun, report software `SAFE_FALLBACK`
   (activation denied). No physical safety actuator is controlled.

The endpoints are scheduled sequentially by one orchestrator. This intentionally
isolates protocol state transitions; it does not model competing ECUs, physical
arbitration, transceiver errors, clock drift, or gateway process scheduling.

| Scenario | Initial omitted indices | Expected protocol behavior |
|---|---|---|
| Clean Bus (Nominal) | `NONE` | Verify without retry |
| Isolated Single Frame Drop | `12` | Request bit 12; retransmit one frame |
| Late-Sequence Frame Drop | `38` | Request bit 38; retransmit one frame |
| Inductive Relay Transient Spike | `14;15;16` | Request bitmap `0x000000000001c000` |
| Alternator Commutation Burst | `20;21;22;23;24;25;26;27` | Request bitmap `0x000000000ff00000` |
| Persistent omission | `12`, including retransmissions | Exhaust three retry rounds |
| NACK omission | `12`, then discard NACK | Actual receive timeout; `ERR_TIMEOUT_NACK_WAIT` |
| Ciphertext corruption | `NONE`; flip a ciphertext bit in frame 12 | Actual Ascon rejection |
| Monte Carlo Loss Sweep | Observed initial Bernoulli drops | Draw independently for every data transmission, including retries |

The relay/alternator labels are the project's canonical names for specified drop
patterns; these experiments do not establish that real devices produce those patterns.
Control frames are loss-free during Bernoulli runs; NACK loss has its own scenario.
`burst_length` is the longest consecutive run of initial drops, not the number of
all nonadjacent drops. Retry drops remain available in `events.jsonl`.

## Data contract and honest measurement boundaries

The CSV preserves **exactly the 40 Phase 3 column names and their order**, loading
them from `Phase 3/config/data_contract_schemas.json`. Per-round counts and bitmap
strings are based on the actual trace. Missing measurements are empty CSV cells.

The strict Phase 3 schema cannot truthfully represent this software environment.
The explicitly versioned `phase2-local-datagram-v1` profile makes these changes:

| Field | Software profile treatment |
|---|---|
| `bitrate_regime`, `nominal_baud`, `data_baud` | Empty: no physical CAN device or configured bus speed |
| `total_frames_on_wire`, `total_wire_bytes`, `goodput_efficiency_pct` | Empty: no wire measurements or bit-stuffing model; local byte counts are in the manifest |
| `recovery_overhead_latency_us` | Signed measured difference; never clipped to zero |
| `end_to_end_latency_us` | Host time from immediately before the first send through authentication or failure |
| `nack_turnaround_time_us` | Host time from immediately before NACK send through first successfully received retry; empty if none arrives |

The phase-specific validator enforces the software profile. It also checks finite
numbers, integer widths, exact header order, bitmap popcounts, run-ID uniqueness,
retry accounting, status consistency, and baseline differences. The evidence audit
checks hashes, replays frame accounting, validates NACK contents against receiver
state, and independently verifies every generated public ML-DSA signature.
It cannot independently decrypt saved ciphertext: bootstrap secrets are intentionally
not saved. Ascon validation is executed during the run and its outcome recorded.

`nominal_clean_time_us` references the actual clean run of the same canonical
repetition; Monte Carlo runs reference the last clean run. This is a measured
reference, not a controlled causal estimate of recovery cost. Host scheduling and
shorter failure paths can yield negative differences. Enrollment is outside the
latency boundary; signing/encryption and verification durations are saved separately.
The timer includes Python/event-recording overhead. Do not call it hardware WCET.

```bash
# Expected to fail for software-only results; errors identify unavailable fields.
'Phase 2/Simulation/.venv/bin/python' 'Phase 2/Simulation/validate_results.py' \
  'Phase 2/Simulation/results/my-demo' --strict-phase3
```

Do not copy software-profile outputs into `Phase 3/data/incoming/` as if they passed
the unmodified physical contract. The original Phase 3 validator's direct command
only initializes its class; this Phase 2 CLI actually reads and checks the results.
Phase 3 files are unchanged.

The experiment budget defaults to 50,000 µs as a configurable demonstration input,
not a HARA-derived FTTI. Termination codes and safety labels are project enums,
not claims of ISO 26262 certification. `SUCCESS` can coexist with a budget violation:
authentication completed, but activation is denied due to the experimental deadline.
Overflow/bus-off codes are not manufactured; this environment cannot exercise them.

## Evidence and handoff

- `fault_recovery_runs.csv`: actual per-run records, with all 40 columns.
- `events.jsonl`: relative integer nanosecond timestamps, exact ciphertext/control
  bytes, logical IDs, round numbers, drops, receives, timeouts and termination.
- `manifest.json`: source/output SHA-256 hashes, Git revision, dependency versions,
  arguments, public attestation evidence, baseline links and strict-contract errors.
  Source hashes identify uncommitted work as well as the base Git revision.
- `measurement_profile.json`: explicit software schema snapshot.
- `report.html`: self-contained replay and measured results table, with no CDN or
  external runtime dependency.

For physical Phase 3 completion, use CAN-FD hardware and an agreed frame layout,
record actual controller configuration, and measure or explicitly define physical
overhead accounting. The repository's legacy C++ gateway uses a two-byte fragment
index and a variable-length index-list NACK. It is **not byte-compatible** with the
four-byte Python Category 2 header or this simulator's bitmap control frame.
This new 16-byte control layout is explicitly `>BBBBIQ`: type `0x13`, ECU `0x20`,
retry round, reserved zero, 32-bit session, 64-bit bitmap, all multibyte values
big-endian. Bit `i` requests frame `i`; upper bits 41–63 must be zero. The 8-byte
header is a Phase 2 design choice because Phase 3 specifies bitmap size but no full
control header. It needs agreement before hardware interoperability is claimed.
ISO-TP and Castiglione comparisons are not implemented or fabricated here.

## Existing Phase 2 fixes

Six Red Team imports now resolve the actual `Phase 1/CAN FD/Crypto Code` directory.
The legacy AT-11 fuzzer measures its in-process rejection loop instead of returning
a constant `0.500 ms`. That loop is still not a physical NACK timeout measurement.
Historical benchmark CSVs and reports have not been rewritten as new observations.

## Documentation consulted

- [python-can virtual interface limitations](https://github.com/hardbyte/python-can/blob/main/doc/virtual-interfaces.md), retrieved through Context7.
- [Linux SocketCAN](https://docs.kernel.org/networking/can.html), retrieved through Firecrawl.
- [dilithium-py installation and implementation scope](https://github.com/GiacomoPope/dilithium-py), retrieved through Firecrawl after Context7 returned only the unrelated C implementation.

The cryptographic package is a real educational ML-DSA implementation, not a
side-channel-hardened deployment library. These results describe this Python host.
