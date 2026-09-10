FROM python:3.12-slim-bookworm@sha256:782412e85d0f0984994c290652577d4018aff08145c85b262bb63dc0c7522254
RUN apt-get update && apt-get install -y --no-install-recommends iproute2 can-utils util-linux ca-certificates linux-perf tcpdump \
    && rm -rf /var/lib/apt/lists/*
COPY ["Phase 2/Simulation/requirements.txt", "/tmp/requirements.txt"]
RUN pip install --no-cache-dir -r /tmp/requirements.txt \
    && pip install --no-cache-dir onnxruntime==1.20.1 numpy==1.26.4
COPY ["Phase 1/CAN FD/Crypto Code", "/workspace/Phase 1/CAN FD/Crypto Code"]
COPY ["Phase 2/IDS/ONNX", "/workspace/Phase 2/IDS/ONNX"]
COPY ["Phase 3/config/data_contract_schemas.json", "/workspace/Phase 3/config/data_contract_schemas.json"]
COPY ["Phase 2/Simulation/contracts.py", "/workspace/Phase 2/Simulation/contracts.py"]
COPY ["Phase 3/DockerLab", "/workspace/Phase 3/DockerLab"]
WORKDIR /workspace/Phase 3/DockerLab
ENV PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
CMD ["python", "node.py"]
