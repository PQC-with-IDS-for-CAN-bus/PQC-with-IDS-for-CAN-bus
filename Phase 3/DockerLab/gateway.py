"""Central gateway with four independent attestation/session state machines."""
import json
from pathlib import Path
import queue
import socket
import threading
import time
from common import *
from telemetry import IDS, WIRE


class Domain:
    def __init__(self, domain, identity, gateway=None):
        self.domain, self.identity, self.gateway = domain, identity, gateway
        self.log = Log(f'gateway-d{domain}')
        wait_interface(f'domain{domain}')
        self.can = CAN(f'domain{domain}', self.log, domain)
        self.jobs = queue.Queue(maxsize=1)
        self.result, self.busy, self.key, self.counter = None, False, None, 0
        self.runtime_seen = 0
        self.lock = threading.Lock()
        self.ids = IDS()
        self.log.event("ids_artifacts", domain=domain, sha256=self.ids.artifacts)
        self.rate_started, self.rate_count = time.monotonic(), 0
        threading.Thread(target=self.loop, daemon=True).start()
        self.log.event('ready', domain=domain)

    def loop(self):
        while True:
            try:
                config = self.jobs.get_nowait()
            except queue.Empty:
                config = None
            try:
                if config:
                    self.handshake(config)
                else:
                    item = self.can.recv(.05)
                    if item:
                        self.runtime(item)
            except socket.timeout:
                pass
            except Exception as exc:
                self.key = None
                self.result = dict(status='EXECUTION_ERROR', error=str(exc))
                self.log.event('execution_error', domain=self.domain, error=str(exc))
            finally:
                if config:
                    with self.lock:
                        self.busy = False

    def runtime(self, item):
        can_id, payload = item
        now = time.monotonic()
        if now-self.rate_started >= 1:
            self.rate_started, self.rate_count = now, 0
        self.rate_count += 1
        if self.rate_count > 100:
            self.log.event('rate_limit_rejected', domain=self.domain)
            return
        if can_id != DIAGNOSTIC and can_id not in TELEMETRY_CAN_IDS:
            self.log.event('unexpected_id_rejected', domain=self.domain, can_id=f'0x{can_id:03x}')
            return
        if not self.key:
            self.log.event('unauthenticated_rejected', domain=self.domain)
            return
        if len(payload) != 64:
            self.log.event('header_rejected', domain=self.domain)
            return
        kind, ecu, domain, flags, counter = DIAG_HEADER.unpack(payload[:8])
        if kind not in (0x11, 0x1f, 0x1e) or (ecu, domain, flags) != (self.identity['ecu_id'], self.domain, 0x40):
            self.log.event('header_rejected', domain=self.domain)
            return
        if counter <= self.counter:
            self.log.event('replay_rejected', domain=self.domain, counter=counter, last_counter=self.counter)
            return
        try:
            plaintext = AsconAEAD128Engine.decrypt(self.key, SessionManager.derive_runtime_nonce(ecu, domain, counter, direction=0),
                                                   payload[8:48], payload[:8], payload[48:])
        except ValueError:
            self.log.event('runtime_tag_rejected', domain=self.domain, counter=counter)
            return
        # Commit counter only after authentication; forged high counters cannot poison it.
        self.counter = counter
        self.runtime_seen += 1
        if kind in (0x11, 0x1e):
            values = WIRE.unpack(plaintext)
            try:
                decision = self.ids.evaluate(values[:9], values[9] if len(values) > 9 else can_id)
            except ValueError as exc:
                self.log.event('telemetry_rejected', domain=self.domain, error=str(exc))
                return
            self.log.event('telemetry_evaluated', domain=self.domain, counter=counter, **decision)

            # Step 12 & 13: Inter-Domain Default-Deny Routing & Re-encryption
            if decision.get('tier15') == 'PASS' and decision.get('tier2') != 'ANOMALY_DETECTED' and getattr(self, 'gateway', None):
                for target_domain_idx in range(1, 5):
                    if target_domain_idx != self.domain and evaluate_routing_policy(self.domain, target_domain_idx, can_id):
                        target_domain = self.gateway.domains.get(str(target_domain_idx))
                        if target_domain and target_domain.key:
                            target_domain.counter += 1
                            target_ecu = target_domain.identity['ecu_id']
                            target_header = CAT1_HEADER.pack(0x11, self.identity['ecu_id'], self.domain, 0x40, target_domain.counter)
                            target_nonce = SessionManager.derive_runtime_nonce(target_ecu, target_domain_idx, target_domain.counter, direction=1)
                            ct, atag = AsconAEAD128Engine.encrypt(target_domain.key, target_nonce, plaintext, target_header)
                            target_domain.can.send(can_id, target_header + ct + atag, routed_from=self.domain)
                            self.log.event('interdomain_routed', src_domain=self.domain, dst_domain=target_domain_idx, can_id=f'0x{can_id:03x}')
        else:
            self.log.event('diagnostic_accepted', domain=self.domain, counter=counter,
                           source_sha256=plaintext[:32].hex(), ecu_monotonic_ns=int.from_bytes(plaintext[32:], 'big'),
                           tier15='NOT_EVALUATED_NO_VEHICLE_TELEMETRY', tier2='NOT_EVALUATED_NO_VEHICLE_TELEMETRY')

    def handshake(self, config):
        self.log.run_id = config['run_id']
        self.key, self.counter, self.runtime_seen = None, 0, 0
        self.rate_count, self.rate_started = 0, time.monotonic()
        self.result = None
        ecu = self.identity['ecu_id']
        session = config['session_id']
        self.ids.reset()
        challenge_frame, challenge = ChallengeFrame.issue(ecu, self.domain, session)
        bootstrap = KeyDerivation.derive_bootstrap_key(bytes.fromhex(self.identity['ikm']), challenge, ecu, session)
        started_ns = time.monotonic_ns()
        self.can.send(CHALLENGE, challenge_frame, session_id=session)
        received, rounds = {}, []
        gap = config.get('recovery_timeout_ms', 5)/1000
        deadline = time.monotonic()+3  # Allows real Python signing, not a CAN timing claim.
        first_rx = None
        status = 'SUCCESS'
        invalid_header_seen = False
        while len(received) < 41:
            remaining = deadline-time.monotonic()
            if remaining <= 0:
                if len(rounds) == 3:
                    status = 'ERR_HEADER_OUT_OF_RANGE' if invalid_header_seen else 'ERR_RETRY_EXHAUSTION'
                    break
                missing = sum(1 << i for i in range(41) if i not in received)
                rnd = len(rounds)+1
                entry = dict(round=rnd, requested=missing.bit_count(), recovered=0, bitmap=f'0x{missing:016x}')
                entry['tx_ns'] = self.can.send(RECOVERY, NACK.pack(0x13, ecu, rnd, 0, session, missing), round=rnd)['monotonic_ns']
                rounds.append(entry)
                deadline = time.monotonic()+gap
                continue
            try:
                item = self.can.recv(remaining)
            except socket.timeout:
                continue
            if not item:
                continue
            can_id, payload = item
            if can_id != ATTESTATION:
                self.log.event('attestation_phase_id_rejected', domain=self.domain, can_id=f'0x{can_id:03x}')
                continue
            try:
                h, fragment = IndexedAttestationFrame.unpack_frame(payload)
                index = h['frame_index']
                if h['session_id'] != session & 255 or h['total_frames'] != 41 or index >= 41 or h['control_flags'] != (3 if index == 40 else 1):
                    raise ValueError('invalid Cat 2 header')
            except ValueError:
                self.log.event('header_rejected', domain=self.domain)
                invalid_header_seen = True
                continue  # A single injected header cannot abort an otherwise valid transfer.
            if index in received:
                self.log.event('duplicate_rejected', domain=self.domain, frame_idx=index)
                continue
            now_ns = time.monotonic_ns()
            if first_rx is None:
                first_rx = now_ns
            received[index] = payload
            if rounds:
                rounds[-1]['recovered'] += 1
                rounds[-1].setdefault('first_rx_ns', now_ns)
            deadline = time.monotonic()+gap
            self.log.event('fragment_accepted', domain=self.domain, frame_idx=index, round=len(rounds))
        tag_valid = sig_valid = None
        signature = None
        if status == 'SUCCESS':
            try:
                signature = AttestationDeliveryManager.reassemble_and_unwrap(
                    [received[i] for i in range(41)], bootstrap, challenge, ecu, session)
            except ValueError:
                tag_valid, status = False, 'ERR_CRYPTO_TAG_MISMATCH'
            else:
                tag_valid = True
                sig_valid = PostQuantumAttestation.verify_attestation_signature(
                    bytes.fromhex(self.identity['public_key']), signature, 1, ecu, session, challenge,
                    bytes.fromhex(self.identity['measurement']))
                if not sig_valid:
                    status = 'ERR_CRYPTO_SIG_INVALID'
        authenticated_ns = time.monotonic_ns()
        within_budget = (authenticated_ns-started_ns)/1000 <= config.get('ftti_us', 50000)
        self.log.event('authentication', domain=self.domain, ascon_tag_valid=tag_valid, mldsa_signature_valid=sig_valid, status=status)
        if status == 'SUCCESS' and (within_budget or config.get('admission_policy') == 'observe'):
            self.key = SessionManager.generate_session_key()
            self.can.send(KEY, KeyDeliveryFrame.wrap(bootstrap, self.key, 0xff, self.domain, session))
            deadline = time.monotonic()+config.get('diagnostic_timeout_ms', 50)/1000
            while time.monotonic() < deadline and not self.runtime_seen:
                try:
                    item = self.can.recv(max(.001, deadline-time.monotonic()))
                    if item:
                        self.runtime(item)
                except socket.timeout:
                    break
        self.result = dict(status=status, rounds=rounds, authenticated_ns=authenticated_ns,
                           session_id=session, started_ns=started_ns, received_frames=len(received), first_rx_ns=first_rx,
                           key_delivered=self.key is not None, diagnostic_accepted=self.runtime_seen,
                           within_admission_budget=within_budget, ascon_tag_valid=tag_valid,
                           mldsa_signature_valid=sig_valid,
                           verification_evidence=dict(signature_hex=signature.hex(), challenge_hex=challenge.hex(),
                               public_key_hex=self.identity['public_key'], measurement_hex=self.identity['measurement']) if signature else None)
        self.log.event('termination', domain=self.domain, **self.result)


class Gateway:
    def __init__(self):
        identities = json.loads(Path('/credentials/identity.json').read_text())
        self.domains = {str(d):Domain(d, identities[str(d)], gateway=self) for d in range(1,5)}
    def status(self):
        return dict(ready=True, domains={d:dict(busy=s.busy, result=s.result, run_id=s.log.run_id) for d,s in self.domains.items()})
    def command(self, path, config):
        state = self.domains[str(config['domain'])]
        with state.lock:
            if path != '/run' or state.busy:
                raise RuntimeError('domain busy or unsupported command')
            state.busy = True
            state.result = None
            try:
                state.jobs.put_nowait(config)
            except queue.Full:
                state.busy = False
                raise RuntimeError('domain queue full')
        return {'started':config['run_id']}
