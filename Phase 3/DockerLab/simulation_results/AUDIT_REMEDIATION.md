# DockerLab audit remediation — 2026-09-10

Scope: `promt.md`'s six ordered patches, verified against current code and both
provided audit records. Phase 1 crypto/schema, Phase 2 simulation, model artifacts,
and Phase 3 contract schemas are imported/read only. This report does not accept
old line numbers, reconstructed snippets, or reported prior pass rates as evidence.

## Decisions on the six requested patches

1. **Image:** installs `linux-perf`, `tcpdump`, ONNX Runtime 1.20.1 and NumPy 1.26.4;
   copies existing model/scaler/threshold artifacts. Dockerfile-specific exclusions
   prevent both old Phase 2 and current Phase 3 credentials/state entering layers.
2. **Compose:** observer gets capture-specific privileges and mounts. Trusted
   application nodes retain read-only roots, default seccomp and minimal capabilities.
   `NET_ADMIN`/`SYS_PTRACE` do not by themselves grant hardware PMU access; disabling
   security for every service and changing host kernel restrictions was not needed.
3. **ECU:** preparation ends before transmission, records its own interval, uses
   250 µs application pacing and 50 ms control waits. Run preparation is reserved
   under lock; empty NACKs are rejected. Runtime uses the shared Phase 1 nonce helper.
   Optional complete recorded telemetry replaces neither actual diagnostic bytes
   nor missing sensor readings with constants.
4. **Gateway:** locked admission, 5 ms recovery gap, 50 ms diagnostic response wait,
   shared runtime nonce, real model inference with 30-sample windows. Correct nine
   raw plus five derived features, exported scaling, and standardized subsystem
   scores replace the prompt's zero padding and unsupported `0.0412` threshold.
5. **Controller:** end-to-end timing spans challenge through verification, with the
   ECU terminal timestamp used for ECU-origin timeouts. Prep is not double counted.
   Recovery overhead is nonnegative; raw timings remain unchanged. Lock file closes
   on all exits. Canonical column ordering, strict available-field checks, cross-field
   invariants, independent ML-DSA verification and artifact hashes are checked.
   Physical gaps remain visible in a separately named software profile.
6. **Observer/export:** continuous independent candump and four tcpdump captures;
   termination signals reap children. Contract 2 follows the current 22-column
   schema and uses actual gateway kernel RX timestamps. It never relabels application
   TX timestamps as kernel timestamps, invents frame duration, truncates run UUIDs,
   or stops because a previous suite's latest marker exists.

## Original master ledger disposition

| IDs | Verified disposition |
|---|---|
| 1, 38 | Docker timing and endpoint attribution corrected; prep interval and both endpoint results retained. |
| 2, 3, 5, 28 | Timeout/pacing defaults corrected as software settings; no physical timing claim. |
| 4 | 50 ms experimental admission budget enforced for normal runs. Final attack setup explicitly uses observation-only admission and records violations. No ASIL certification claimed. |
| 6, 7, 30 | Nonnegative overhead with measured baseline; strict shared constraints unchanged. No zero-baseline division. |
| 8 | Logical transmitted counts measured. Physical baud, physical wire bytes/goodput unavailable on vxcan; strict physical contract remains incomplete. |
| 9, 10 | Verified independent Docker/SocketCAN processes and per-domain gateway workers. AF_UNIX Phase 2 artifacts are not used as Docker evidence. |
| 11, 12, 17 | Hardware/model limits retained: in-path logical omission, virtual links and measured Python forwarding overhead. These cannot become physical EMI/arbitration by inserting sleeps. |
| 13, 14, 25 | Optional complete recorded-input path and real ONNX inference implemented. Existing diagnostics were source-hash/clock bytes, not 32 constant bytes. No real-vehicle detection accuracy claimed without recordings. |
| 15 | Actual kernel arrival CSV plus independent raw captures implemented. Hardware duration fields remain explicitly unavailable. |
| 16 | Tools and real PMU probe implemented. Full workload Contract 1 remains open when hardware access is denied; no fabricated counters. |
| 18 | NACK remains unauthenticated under the existing 16-byte protocol. Empty/upper-bit/old-round/wrong-session requests are rejected and rounds bounded; “indefinite retransmission” claim does not match code. A MAC-bearing protocol revision is still needed for authenticated NACKs. |
| 19 | Software bootstrap provisioning remains explicit. No physical SRAM-PUF/helper-data measurements available. |
| 20 | Legacy C++ gateway outside requested read-only boundary; incompatibility remains documented. |
| 21, 22 | Prior Phase 2 remediation left unchanged. New Docker-specific regression tests added. |
| 23 | Host UID/GID access guarded. Docker still needs a Linux kernel with SocketCAN/vxcan; Windows-native CAN is not claimed. |
| 24 | Existing fcntl operation was a Linux container file lock, not the ledger's socket fcntl snippet. Correct fix closes its lifetime with `with`; removing locking would introduce concurrent-suite races. |
| 26 | Invalid fragments are rejected without immediately aborting the legitimate transfer. Single malformed-header probe must recover; persistent malformed data terminates after bounded recovery. |
| 27 | Zero bitmap rejected without extending deadline or advancing retry state. |
| 29 | Three NACKs maximum. Each NACK, including the third, needs a response window on independent asynchronous nodes; removing the final response window would reject valid third-round arrivals. |
| 31 | Existing attacker flips the tag at byte 48; not the byte-8 snippet quoted in ledger. Replay, tag forgery, domain spoof and flood remain separate observed checks. |
| 32 | Incremental JSONL reader handles partial lines, rotation/truncation and bounded retained events; avoids rereading entire files every poll. |
| 33 | CANFD_BRS set and BRS/ESI logged. Virtual interfaces still have no physical baud clock. |
| 34, 37 | Cat 2's low session byte is fixed Phase 1 framing; full session/challenge binds AEAD and ML-DSA, and runtime keys are fresh per session. Counter reset with a different key does not replay old ciphertext. No unsupported persistent-key reuse added. |
| 35 | Enrollment and attestation hash actual bytes in the same image. Docker COPY does not normally convert CRLF to LF. Source changes require explicit reenrollment; no silent normalization hides them. |
| 36 | Relay now has independent per-domain workers and locks. Interfaces must be UP, not merely present, before receiver threads start. |
| 39 | Per-suite artifact and source hashes recorded; successful signatures independently verified. Historical source hashes are provenance, not a demand that current source equal historical source. |
| 40 | Management port is internal; attacker has no IP management network. Host-published services are read-only dashboards on localhost. Trusted management remains unauthenticated inside that boundary; external management authentication is not claimed. |

## Verification boundaries

Use `lab.py up`, `lab.py run`, and `lab.py validate` as described in README.
`test_regressions.py` executes real AEAD and real ONNX inference with explicitly
labelled numerical unit-test vectors; these are not road telemetry or benchmark
results. Saved-suite mutation checks use actual measured CSVs.

The manifest records Python/kernel/runtime/dependency versions, source hashes,
per-run outcomes, strict physical-schema gaps, attack decisions, and PMU probe
status. The requested host-specific 25–70 ms range is not forced: actual timings
may exceed it. Missing physical counters and missing recordings are reported,
not replaced by zeros, sentinel success scores, or prerecorded outcomes.
