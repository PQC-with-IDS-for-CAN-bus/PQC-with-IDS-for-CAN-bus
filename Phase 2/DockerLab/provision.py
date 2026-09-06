"""Offline software enrollment; private keys are mounted only into their ECU."""
import hashlib
import json
import os
from pathlib import Path
from common import PostQuantumAttestation

base = Path('/enrollment')
base.mkdir(parents=True, exist_ok=True)
measurement = hashlib.sha256(Path('ecu.py').read_bytes()).hexdigest()
gateway = {}
for domain in range(1, 5):
    private_path = base / f'ecu{domain}.json'
    if private_path.exists():
        raise RuntimeError('Enrollment exists; refusing to replace ECU identity')
    public, secret = PostQuantumAttestation.generate_mldsa_keypair()
    provisioned = os.urandom(32)
    gateway[str(domain)] = dict(ecu_id=0x1f+domain, public_key=public.hex(),
                               ikm=hashlib.sha256(provisioned).hexdigest(), measurement=measurement)
    private_path.write_text(json.dumps(dict(secret_key=secret.hex(), provisioned=provisioned.hex())))
    private_path.chmod(0o600)
(base / 'gateway.json').write_text(json.dumps(gateway))
(base / 'gateway.json').chmod(0o600)
print('Enrolled four independent ML-DSA identities; no secret material printed.')
