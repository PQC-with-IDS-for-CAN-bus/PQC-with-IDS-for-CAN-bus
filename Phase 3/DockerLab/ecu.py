"""Independent ECU: no access to gateway keys or other ECU credentials."""
import hashlib
import json
from pathlib import Path
import socket
import threading
import time
from common import *


class ECU:
    def __init__(self, domain):
        self.domain, self.ecu_id = domain, 0x1f+domain
        self.log = Log(f'ecu{domain}')
        self.credentials = json.loads(Path('/credentials/identity.json').read_text())
        self.config, self.result, self.key, self.busy = {}, None, None, False
        self.counter = 0
        wait_interface('can0')
        self.can = CAN('can0', self.log, domain)
        self.lock = threading.Lock()
        self.log.event('ready', domain=domain, ecu_id=self.ecu_id)
        threading.Thread(target=self.loop, daemon=True).start()

    def status(self):
        return dict(ready=True, busy=self.busy, result=self.result, run_id=self.log.run_id)

    def command(self, path, config):
        with self.lock:
            if path != '/prepare' or self.busy:
                raise RuntimeError('ECU busy or unsupported command')
            self.busy = True
            self.config, self.result, self.key = config, None, None
            self.log.run_id = config['run_id']
            self.log.event('prepared', domain=self.domain)
        return self.status()

    def loop(self):
        while True:
            try:
                item = self.can.recv(.1)
            except socket.timeout:
                continue
            if not item or item[0] != CHALLENGE:
                continue
            with self.lock:
                config = self.config
                permitted = self.busy and config and self.result is None
            if not permitted:
                self.log.event('unsolicited_challenge_rejected', domain=self.domain)
                continue
            try:
                header = struct.unpack('>BBBBI', item[1][:8])
                if header[1:3] != (self.ecu_id, self.domain) or header[4] != config['session_id']:
                    self.log.event('challenge_rejected', domain=self.domain)
                    continue
                self.handshake(item[1])
            except Exception as exc:
                self.key = None
                self.result = dict(status='EXECUTION_ERROR', error=str(exc))
                self.log.event('execution_error', error=str(exc), domain=self.domain)
            finally:
                if self.result is not None:
                    with self.lock:
                        self.busy = False

    def handshake(self, challenge_frame):
        if not self.config:
            return
        _, target, domain, flags, session = struct.unpack('>BBBBI', challenge_frame[:8])
        if target != self.ecu_id or domain != self.domain:
            self.log.event('challenge_rejected', domain=self.domain)
            return
        prep_started_ns = time.monotonic_ns()
        challenge, session = ChallengeFrame.parse(challenge_frame, self.ecu_id, session)
        self.key = None
        self.counter = 0
        bootstrap = KeyDerivation.derive_bootstrap_key(
            hashlib.sha256(bytes.fromhex(self.credentials['provisioned'])).digest(), challenge, self.ecu_id, session)
        measurement = hashlib.sha256(Path(__file__).read_bytes()).digest()
        signature = PostQuantumAttestation.sign_attestation_transcript(
            secret_key=bytes.fromhex(self.credentials['secret_key']), protocol_version=1,
            ecu_id=self.ecu_id, session_id=session, random_challenge=challenge, measurement_hash=measurement)
        frames = AttestationDeliveryManager.wrap_and_fragment(signature, bootstrap, challenge, self.ecu_id, session)
        prep_ns = time.monotonic_ns() - prep_started_ns
        self.log.event('crypto_preparation', domain=self.domain, prep_started_ns=prep_started_ns, prep_ns=prep_ns)
        self.log.event('attestation_created', domain=self.domain, session_id=session,
                       measurement_sha256=measurement.hex(), signature_bytes=len(signature), frames=len(frames))
        for i, frame in enumerate(frames):
            self.can.send(ATTESTATION, frame, round=0, frame_idx=i)
            time.sleep(self.config.get('frame_gap_us', 250)/1_000_000)
        last_round = 0
        deadline = time.monotonic()+self.config.get('ecu_wait_ms', 50)/1000
        while time.monotonic() < deadline:
            try:
                item = self.can.recv(max(.001, deadline-time.monotonic()))
            except socket.timeout:
                break
            if not item:
                continue
            can_id, payload = item
            if can_id == RECOVERY:
                if len(payload) != 16:
                    continue
                kind, ecu, rnd, reserved, sid, bitmap = NACK.unpack(payload)
                if (kind, ecu, reserved, sid) != (0x13, self.ecu_id, 0, session) or bitmap == 0 or bitmap >> 41 or not last_round < rnd <= 3:
                    self.log.event('nack_rejected', domain=self.domain)
                    continue
                last_round = rnd
                self.log.event('nack_accepted', domain=self.domain, round=rnd, bitmap=f'0x{bitmap:016x}')
                for i in range(41):
                    if bitmap & (1 << i):
                        self.can.send(ATTESTATION, frames[i], round=rnd, frame_idx=i)
                        time.sleep(self.config.get('frame_gap_us', 250)/1_000_000)
                deadline = time.monotonic()+self.config.get('ecu_wait_ms', 50)/1000
            elif can_id == KEY:
                if len(payload) != 64 or payload[1] != 0xff or payload[2] != self.domain:
                    self.log.event('key_header_rejected', domain=self.domain)
                    continue
                self.key = KeyDeliveryFrame.unwrap(payload, bootstrap, session)
                self.result = dict(status='SUCCESS', session_id=session, nack_rounds=last_round, prep_ns=prep_ns, prep_started_ns=prep_started_ns)
                self.log.event('session_activated', domain=self.domain, session_id=session)
                self.counter += 1
                header = DIAG_HEADER.pack(0x1f, self.ecu_id, self.domain, 0x40, self.counter)
                # Actual file hash + actual monotonic clock; never invented vehicle signals.
                data = measurement + time.monotonic_ns().to_bytes(8, 'big')
                nonce = SessionManager.derive_runtime_nonce(self.ecu_id, self.domain, self.counter, direction=0)
                ciphertext, tag = AsconAEAD128Engine.encrypt(self.key, nonce, data, header)
                self.can.send(DIAGNOSTIC, header+ciphertext+tag, counter=self.counter)
                if self.config.get('telemetry'):
                    self.send_telemetry()
                return
        self.result = dict(status='ERR_TIMEOUT_NACK_WAIT', session_id=session, nack_rounds=last_round, prep_ns=prep_ns, prep_started_ns=prep_started_ns, terminal_ns=time.monotonic_ns())
        self.log.event('ecu_wait_timeout', domain=self.domain, session_id=session, nack_rounds=last_round)

    def send_telemetry(self):
        from telemetry import load_recording, WIRE
        samples, provenance = load_recording(Path('/input/telemetry.json'))
        self.log.event('telemetry_source', domain=self.domain, **provenance)
        for sample in samples:
            if self.counter >= 0xffffffff:
                self.key = None
                raise RuntimeError('Counter exhausted; new session required')
            self.counter += 1
            header = DIAG_HEADER.pack(0x1e, self.ecu_id, self.domain, 0x40, self.counter)
            data = WIRE.pack(*sample['values'], sample['source_can_id'])
            nonce = SessionManager.derive_runtime_nonce(self.ecu_id, self.domain, self.counter, direction=0)
            ciphertext, tag = AsconAEAD128Engine.encrypt(self.key, nonce, data, header)
            self.can.send(DIAGNOSTIC, header+ciphertext+tag, counter=self.counter)
            time.sleep(.02)  # Application replay pacing, not original capture timing.
