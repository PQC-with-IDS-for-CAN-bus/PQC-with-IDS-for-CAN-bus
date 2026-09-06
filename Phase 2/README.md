# Phase 2

For the independent Docker ECU/gateway/attacker environment, use
[DockerLab/README.md](DockerLab/README.md). It includes the architecture and PQC
sequence diagrams, startup commands, live dashboard, SocketCAN evidence, and
explicit measurement limits.

For Kunal's fault recovery demonstration, start with
[Simulation/README.md](Simulation/README.md). The runner executes real cryptography
and local socket exchanges, writes a 40-column CSV plus byte-level evidence, and
generates a browser replay of the measured runs.

The simulation documents its software measurement profile and the remaining
physical Phase 3 handoff requirements. Existing IDS and Red Team benchmark files
are historical artifacts and are not substituted for newly measured results.

## Quick start: live Docker demonstration

Run these commands from the repository root on a Linux host with Docker Engine,
Docker Compose, Python 3, and CAN/CAN_RAW/VXCAN kernel support:

```bash
python3 'Phase 2/DockerLab/lab.py' up
# Open http://localhost:8088, then start the experiments:
python3 'Phase 2/DockerLab/lab.py' run
python3 'Phase 2/DockerLab/lab.py' validate
```

The default suite runs 30 handshakes and four runtime attack checks. Watch the
four domains, authentication results and recovery events in the live dashboard.
Generated CSVs and evidence are saved in `DockerLab/state/exports/`; enrollment
secrets and runtime state stay local and are excluded from Git.

```bash
# Optional searchable logs: Grafana at http://localhost:3000
python3 'Phase 2/DockerLab/lab.py' observe
# Stop the lab while retaining local evidence and enrollment:
python3 'Phase 2/DockerLab/lab.py' down
```

For later launches, repeat `up` and `run`. Before rebuilding an existing lab,
run `down`. Full prerequisites, Mermaid diagrams, image versions, troubleshooting
context and measurement limits are in [the Docker lab guide](DockerLab/README.md).
Virtual CAN cannot measure physical bitrate or arbitration; those CSV fields stay
blank, and strict Phase 3 hardware validation remains a separate requirement.
