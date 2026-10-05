"""Orchestrate real services and export only observed execution evidence."""
import argparse
import csv
import hashlib
import json
import importlib.metadata
import platform
import struct
from pathlib import Path
import sys
import time
import urllib.request
import uuid

from common import ROOT, atomic, PostQuantumAttestation
from evidence import validate_software, export_arrivals, export_perf_stat

sim_path = ROOT / 'Phase 2/Simulation'
if not sim_path.exists():
    sim_path = ROOT.parent / 'Git repo/Phase 2/Simulation'
sys.path.insert(0, str(sim_path))
from contracts import columns, profile, validate

TELEMETRY = False

CANONICAL = [
    ('clean',1,'Clean Bus (Nominal)','NOMINAL_CLEAN',[]),
    ('single',2,'Isolated Single Frame Drop','SINGLE_FRAME_DROP',[12]),
    ('late',3,'Late-Sequence Frame Drop','LATE_SEQUENCE_DROP',[38]),
    ('relay_spike',4,'Inductive Relay Transient Spike','BURST_FRAME_DROP',[14,15,16]),
    ('alternator',5,'Alternator Commutation Burst','BURST_FRAME_DROP',list(range(20,28))),
]


def rpc(node, path='/health', data=None):
    req = urllib.request.Request(f'http://{node}:8080{path}',
        data=json.dumps(data).encode() if data is not None else None,
        headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req, timeout=5) as response:
        return json.load(response)


def await_ready():
    deadline = time.monotonic()+90
    for node in ['relay','gateway','ecu1','ecu2','ecu3','ecu4']:
        while True:
            try:
                if rpc(node).get('ready'):
                    break
            except (OSError, ValueError):
                pass
            if time.monotonic()>deadline:
                raise RuntimeError(f'{node} never became ready')
            time.sleep(.2)


from event_reader import EventReader
EVENTS = EventReader()

def read_events():
    return EVENTS.read()


def execute(domain, scenario, trial, seed):
    mode, sid, name, fault, drops = scenario
    run_id = str(uuid.uuid4())
    config = dict(run_id=run_id, domain=domain, scenario=mode, drops=drops, seed=seed,
                  frame_gap_us=250, recovery_timeout_ms=5, ecu_wait_ms=50,
                  ftti_us=50000, loss_rate=.2, session_id=int.from_bytes(__import__('os').urandom(4),'big'),
                  admission_policy='observe' if mode=='clean' and trial==1 else 'enforce',
                  telemetry=bool(domain==1 and mode=='clean' and trial==1 and TELEMETRY))
    rpc('relay','/configure',config)
    rpc('gateway','/run',config)
    time.sleep(0.002)  # Ensure gateway thread records started_ns and enters poll() before ECU TX
    rpc(f'ecu{domain}','/prepare',config)
    deadline = time.monotonic()+35
    while True:
        gw = rpc('gateway')['domains'][str(domain)]
        ecu = rpc(f'ecu{domain}')
        if gw['run_id']==run_id and not gw['busy'] and gw['result'] and not ecu['busy'] and ecu['result']:
            break
        if time.monotonic()>deadline:
            raise RuntimeError(f'Run {run_id}: services did not finish; inspect node logs')
        time.sleep(.05)
    events = [e for e in read_events() if e.get('run_id')==run_id]
    result = gw['result']
    if result['status']=='EXECUTION_ERROR' or ecu['result']['status']=='EXECUTION_ERROR':
        raise RuntimeError(f'Execution error: gateway={result}, ecu={ecu["result"]}')
    data = [e for e in events if e['node']==f'ecu{domain}' and e['event']=='tx' and e.get('can_id')=='0x200']
    if not data:
        raise RuntimeError('No actual ECU transmissions recorded')
    initial = [e for e in data if e['round']==0]
    retransmits = len(data)-len(initial)
    omitted = sorted(set(e['frame_idx'] for e in events if e['event']=='injected_drop' and e.get('can_id')=='0x200' and e['round']==0))
    burst = current = 0
    last = -2
    for index in omitted:
        current = current+1 if index==last+1 else 1
        burst, last = max(burst,current), index
    status = result['status']
    origin = 'gateway'
    if status=='ERR_RETRY_EXHAUSTION' and ecu['result']['status']=='ERR_TIMEOUT_NACK_WAIT' and ecu['result']['nack_rounds']==0:
        status, origin = 'ERR_TIMEOUT_NACK_WAIT','ecu'
    terminal_ns = ecu['result']['terminal_ns'] if origin=='ecu' else result['authenticated_ns']
    latency = (terminal_ns-result['started_ns'])/1000
    success = status=='SUCCESS'
    rounds = result['rounds']
    classification = ('RECOVERED_FAULT' if rounds else 'SAFE_TRANSMISSION') if success else (
        'CORRUPTED_FRAME_REJECTED' if 'CRYPTO' in status or 'HEADER' in status else
        'PROTOCOL_ABORT_TIMEOUT' if 'TIMEOUT' in status else 'INFORMATION_LOSS_OMISSION')
    wire_bytes = (len(initial) + retransmits) * 64 + len(rounds) * 16
    goodput = round((2436.0 / max(1, wire_bytes)) * 100.0, 2) if success else 0.0
    row = dict.fromkeys(columns(), None)
    row.update(run_id=run_id, trial_idx=trial, scenario_id=sid, scenario_name=name, protocol_name='SIXTY_FOUR_BLOCK',
               bitrate_regime='PROD_CANFD_2MBPS', nominal_baud=500000, data_baud=2000000,
               fault_model=fault, injected_dropped_frame_indices=';'.join(map(str,omitted)) or 'NONE', burst_length=burst,
               channel_loss_rate_p=.2 if mode=='monte_carlo' else 0., payload_corruption_injected=mode in ('corrupt','malformed','header_probe'),
               recovery_success=success, recovery_rounds=len(rounds), retransmit_policy='selective_nack_bitmap',
               nack_frames_issued_count=len(rounds), nack_bitmaps_issued_hex=';'.join(r['bitmap'] for r in rounds) or 'N_A',
               initial_frames_sent=len(initial), retransmitted_frames_count=retransmits, control_frames_count=len(rounds), total_frames_on_wire=len(data)+len(rounds),
               total_wire_bytes=wire_bytes, goodput_efficiency_pct=goodput,
               end_to_end_latency_us=latency, nominal_clean_time_us=0., recovery_overhead_latency_us=0.,
               nack_turnaround_time_us=next(((r['first_rx_ns']-r['tx_ns'])/1000 for r in rounds if 'first_rx_ns' in r),None),
               retry_exhaustion_flag=status=='ERR_RETRY_EXHAUSTION', termination_status_code=status,
               iso26262_failure_classification=classification, ftti_budget_us=config['ftti_us'],
               ftti_violation_flag=latency>config['ftti_us'],
               safety_state_achieved='OPERATIONAL' if success and latency<=config['ftti_us'] else 'SAFE_FALLBACK')
    for i in range(3):
        row[f'round_{i+1}_requested_frames'] = rounds[i]['requested'] if i<len(rounds) else 0
        row[f'round_{i+1}_recovered_frames'] = rounds[i]['recovered'] if i<len(rounds) else 0
    return row, dict(domain=domain, config=config, gateway=result, ecu=ecu['result'], status_origin=origin)


def attack(run_id, name):
    identifier = str(uuid.uuid4())
    started = time.monotonic_ns()
    atomic('/mailbox/command.json', dict(id=identifier, run_id=run_id, attack=name))
    deadline = time.monotonic()+8
    expected = {'replay':'replay_rejected','forged_tag':'runtime_tag_rejected',
                'spoof_domain':'header_rejected','flood':'rate_limit_rejected'}[name]
    result = {}
    while time.monotonic()<deadline:
        path = Path('/mailbox/result.json')
        if path.exists():
            result = json.loads(path.read_text())
        observed = [e for e in read_events() if e['node']=='gateway-d1' and e['monotonic_ns']>=started and e['event']==expected]
        if result.get('id')==identifier and 'error' in result:
            break
        if result.get('id')==identifier and observed:
            crossed = [e for e in read_events() if e['node'] in ('gateway-d2','gateway-d3','gateway-d4')
                       and e['monotonic_ns']>=started and e['event']=='rx']
            return dict(attack=name, attack_id=identifier, start_ns=started, transmitted=result['transmitted'],
                        observed_event=expected, observed_count=len(observed), other_domain_rx=len(crossed), passed=not crossed)
        time.sleep(.1)
    return dict(attack=name, passed=False, error=result.get('error','Expected gateway decision not observed'))


def audit(path):
    path = Path(path)
    errors = validate_software(path/'fault_recovery_runs.csv', validate)
    metadata = json.loads((path/'manifest.json').read_text())
    with (path/'fault_recovery_runs.csv').open() as stream:
        rows = list(csv.DictReader(stream))
    events = [json.loads(line) for line in (path/'events.jsonl').read_text().splitlines()]
    for filename, expected in metadata['sha256'].items():
        if hashlib.sha256((path/filename).read_bytes()).hexdigest()!=expected:
            errors.append(f'Hash mismatch: {filename}')
    for row in rows:
        record = metadata['runs'][row['run_id']]
        terminal = record['ecu']['terminal_ns'] if record['status_origin']=='ecu' else record['gateway']['authenticated_ns']
        if float(row['end_to_end_latency_us']) != (terminal-record['gateway']['started_ns'])/1000:
            errors.append(f'{row["run_id"]}: end-to-end timing mismatch')
        log = [e for e in events if e.get('run_id')==row['run_id']]
        data = [e for e in log if e['node'].startswith('ecu') and e['event']=='tx' and e.get('can_id')=='0x200']
        if len(data)!=int(row['initial_frames_sent'])+int(row['retransmitted_frames_count']):
            errors.append(f'{row["run_id"]}: actual transmission count mismatch')
        accepts = [e for e in log if e['node'].startswith('gateway') and e['event']=='fragment_accepted']
        accepted = set()
        bitmaps = []
        for event in log:
            if event['event']=='fragment_accepted':
                if event['frame_idx'] in accepted:
                    errors.append(f'{row["run_id"]}: duplicate accepted fragment')
                accepted.add(event['frame_idx'])
            if event['node'].startswith('gateway') and event['event']=='tx' and event.get('can_id')=='0x201':
                bitmap = struct.unpack('>BBBBIQ', bytes.fromhex(event['payload_hex']))[-1]
                expected = sum(1 << i for i in set(range(41))-accepted)
                if bitmap != expected:
                    errors.append(f'{row["run_id"]}: transmitted NACK disagrees with receiver state')
                bitmaps.append(f'0x{bitmap:016x}')
        if (';'.join(bitmaps) or 'N_A') != row['nack_bitmaps_issued_hex']:
            errors.append(f'{row["run_id"]}: CSV bitmap differs from transmitted bytes')
        omitted = sorted(set(e['frame_idx'] for e in log if e['event']=='injected_drop' and e.get('can_id')=='0x200' and e['round']==0))
        if (';'.join(map(str,omitted)) or 'NONE')!=row['injected_dropped_frame_indices']:
            errors.append(f'{row["run_id"]}: CSV drop string differs from relay evidence')
        for rnd in range(1,4):
            if sum(e['round']==rnd for e in accepts)!=int(row[f'round_{rnd}_recovered_frames']):
                errors.append(f'{row["run_id"]}: round {rnd} recovery evidence mismatch')
        if row['recovery_success'] == 'True':
            proof = record['gateway'].get('verification_evidence')
            if not proof or not PostQuantumAttestation.verify_attestation_signature(
                bytes.fromhex(proof['public_key_hex']),
                bytes.fromhex(proof['signature_hex']),
                1,
                0x1F + record['domain'],
                record['gateway']['session_id'],
                bytes.fromhex(proof['challenge_hex']),
                bytes.fromhex(proof['measurement_hex'])
            ):
                errors.append(f"{row['run_id']}: independent ML-DSA verification failed")
            if len(accepted)!=41:
                errors.append(f'{row["run_id"]}: incomplete successful assembly')
            auth = [e for e in log if e['event']=='authentication']
            if not any(e.get('ascon_tag_valid') is True and e.get('mldsa_signature_valid') is True for e in auth):
                errors.append(f'{row["run_id"]}: success lacks authentication evidence')
    return errors


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--health-only', action='store_true')
    parser.add_argument('--validate-only', action='store_true')
    parser.add_argument('--telemetry', action='store_true')
    parser.add_argument('--monte-carlo', type=int, default=5)
    args = parser.parse_args()
    global TELEMETRY
    TELEMETRY = args.telemetry
    if args.validate_only:
        latest = json.loads(Path('/exports/latest.json').read_text())
        errors = audit(Path('/exports')/latest['directory'])
        print('\n'.join(errors) if errors else 'PASS: SocketCAN CSV and saved evidence')
        return bool(errors)
    await_ready()
    if args.health_only:
        print('All four ECUs, gateway and relay are ready on SocketCAN.')
        return 0

    try:
        import fcntl
        has_fcntl = True
    except ImportError:
        has_fcntl = False

    with open('/exports/.run.lock', 'a') as run_lock:
        if has_fcntl:
            try:
                fcntl.flock(run_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise SystemExit('Another experiment suite is already running.')
        suite = str(uuid.uuid4())
        out = Path('/exports')/suite
        out.mkdir(parents=True, exist_ok=True)
        rows, records, baselines, checks = [], {}, {}, []
        work = [(d,s,0) for s in CANONICAL for d in range(1,5)]
        work += [(1,('persistent',2,CANONICAL[1][2],'SINGLE_FRAME_DROP',[12]),0),
                 (1,('nack_drop',2,CANONICAL[1][2],'NACK_CONTROL_FRAME_DROP',[12]),0),
                 (1,('corrupt',1,CANONICAL[0][2],'PAYLOAD_BIT_FLIP',[]),0),
                 (1,('malformed',1,CANONICAL[0][2],'PAYLOAD_BIT_FLIP',[]),0),
                 (1,('header_probe',1,CANONICAL[0][2],'PAYLOAD_BIT_FLIP',[]),0)]
        work += [(1,('monte_carlo',0,'Monte Carlo Loss Sweep','BERNOULLI_RANDOM',[]),i) for i in range(args.monte_carlo)]
        work += [(1,CANONICAL[0],1)]  # Fresh session for runtime attacks.
        for number,(domain,scenario,trial) in enumerate(work):
            row, record = execute(domain,scenario,trial,20260907+number)
            if scenario[0]=='clean':
                baselines[domain]=row
            row['nominal_clean_time_us']=baselines[domain]['end_to_end_latency_us']
            row['recovery_overhead_latency_us']=max(0.,row['end_to_end_latency_us']-row['nominal_clean_time_us']) if row['recovery_success'] and row['recovery_rounds'] else 0.
            record['baseline_run_id']=baselines[domain]['run_id']
            records[row['run_id']]=record
            rows.append(row)
            expected = {'persistent':'ERR_RETRY_EXHAUSTION','nack_drop':'ERR_TIMEOUT_NACK_WAIT',
                        'corrupt':'ERR_CRYPTO_TAG_MISMATCH','malformed':'ERR_HEADER_OUT_OF_RANGE'}.get(scenario[0],'SUCCESS')
            passed = scenario[0]=='monte_carlo' or row['termination_status_code']==expected
            if scenario[0]=='header_probe':
                passed = passed and row['retransmitted_frames_count']==1 and row['round_1_recovered_frames']==1
            if scenario in CANONICAL:
                passed = passed and row['retransmitted_frames_count']==len(scenario[4]) and row['round_1_recovered_frames']==len(scenario[4])
            if row['recovery_success']:
                admitted = record['gateway']['within_admission_budget'] or record['config']['admission_policy']=='observe'
                passed = passed and ((record['gateway']['diagnostic_accepted']>0 and record['ecu']['status']=='SUCCESS') if admitted else (not record['gateway']['key_delivered'] and record['ecu']['status']=='ERR_TIMEOUT_NACK_WAIT'))
            checks.append(dict(run_id=row['run_id'], passed=passed, expected=expected if scenario[0]!='monte_carlo' else 'observational'))
            print(f'{number+1:02d} {domain} {scenario[0]:12s} {row["termination_status_code"]:28s} {row["end_to_end_latency_us"]:.3f} us',flush=True)
        attacks = [attack(rows[-1]['run_id'],name) for name in ['replay','forged_tag','spoof_domain','flood']]
        # Wait for queued flood packets to drain before taking the evidence snapshot.
        time.sleep(1)
        events = [e for e in read_events() if e.get('run_id') in records]
        with (out/'fault_recovery_runs.csv').open('w',newline='') as stream:
            writer=csv.DictWriter(stream,fieldnames=columns());writer.writeheader();writer.writerows(rows)
        (out/'events.jsonl').write_text(''.join(json.dumps(e)+'\n' for e in events))
        specs=profile()
        for name in ('bitrate_regime','nominal_baud','data_baud','total_wire_bytes','goodput_efficiency_pct'):
            specs[name]['description']='Unavailable: virtual SocketCAN, no physical CAN controller.'
        (out/'measurement_profile.json').write_text(json.dumps(specs,indent=2))
        capture = Path('/captures/candump.log')
        if capture.exists():
            (out/'candump_since_lab_start.log').write_bytes(capture.read_bytes())
        arrivals = export_arrivals(out, events, records)
        import subprocess
        try:
            perf = subprocess.run(
                ['perf', 'stat', '-x,', '-e', 'cycles,instructions', '--', '/usr/local/bin/cisg_gateway', '--verify'],
                capture_output=True, text=True
            )
            perf_code = perf.returncode
            perf_err = perf.stderr
        except Exception:
            perf_code = -1
            perf_err = "perf not available"
        (out/'perf_probe.txt').write_text(perf_err)

        def _avg_ns(node_role, key):
            vals = [r[node_role].get(key, 0) for r in records.values() if r[node_role].get(key, 0) > 0]
            return int(sum(vals) / len(vals)) if vals else None

        measured_timings = {
            'mldsa_verify_attestation': _avg_ns('gateway', 'mldsa_verify_ns'),
            'mldsa_sign_attestation': _avg_ns('ecu', 'mldsa_sign_ns'),
            'ascon_aead128_decrypt': _avg_ns('gateway', 'ascon_decrypt_ns'),
            'ascon_aead128_encrypt': _avg_ns('ecu', 'ascon_encrypt_ns'),
            'tier1_ascon_tag_verification': _avg_ns('gateway', 'ascon_decrypt_ns'),
            'tier2_onnx_int8_inference': _avg_ns('gateway', 'onnx_int8_ns'),
        }
        measured_timings = {k: v for k, v in measured_timings.items() if v is not None}
        export_perf_stat(out, records, measured_timings=measured_timings, perf_stderr=perf_err if perf_code == 0 else None)
        artifacts = ['fault_recovery_runs.csv', 'events.jsonl', 'measurement_profile.json',
                     'tcpdump_latency_summary.csv', 'perf_stat_summary.csv', 'perf_probe.txt']
        if (out/'candump_since_lab_start.log').exists():
            artifacts.append('candump_since_lab_start.log')

        crypto_code_dir = (ROOT/'Phase 1/CAN FD/Crypto Code') if (ROOT/'Phase 1/CAN FD/Crypto Code').exists() else (ROOT.parent/'Git repo/Phase 1/CAN FD/Crypto Code')
        schemas_file = (ROOT/'Phase 3/config/data_contract_schemas.json') if (ROOT/'Phase 3/config/data_contract_schemas.json').exists() else (ROOT.parent/'Git repo/Phase 3/config/data_contract_schemas.json')

        metadata=dict(perf_probe=dict(returncode=perf_code,
                      status='AVAILABLE_PROBE_ONLY' if perf_code==0 else 'UNAVAILABLE_PERMISSION_OR_PMU',
                      contract1_complete=True), arrivals=arrivals, profile='phase3-docker-socketcan-v2', suite=suite, created_epoch_ns=time.time_ns(),
                      transport='Linux CAN-FD vxcan, independent Docker namespaces; no datagram fallback',
                      python=sys.version, kernel=platform.release(),
                      dependencies={name:importlib.metadata.version(name) for name in ('cryptography','dilithium-py','onnxruntime','numpy')},
                      container_runtime=json.loads(Path('/runtime.json').read_text()) if Path('/runtime.json').is_file() else None,
                      runtime_nonce='Phase 1 SessionManager.derive_runtime_nonce; fresh key per session',
                      admission_note='50ms experimental budget, not ISO 26262 mandated value; final attack setup explicitly observes rather than enforces budget',
                      runs=records, scenario_checks=checks, attacks=attacks,
                      strict_phase3_errors=validate(out/'fault_recovery_runs.csv',strict=True,enforce_delivered_requests=False),
                      sha256={name:hashlib.sha256((out/name).read_bytes()).hexdigest() for name in artifacts},
                      source_sha256={str(p.relative_to(ROOT) if p.is_relative_to(ROOT) else p.name):hashlib.sha256(p.read_bytes()).hexdigest()
                                     for p in [*Path.cwd().glob('*.py'), *list(crypto_code_dir.glob('*.py')), schemas_file]})
        (out/'manifest.json').write_text(json.dumps(metadata,indent=2))
        errors=audit(out)
        passed=not errors and all(c['passed'] for c in checks+attacks)
        atomic('/exports/latest.json',dict(directory=suite, passed=passed, runs=len(rows), attacks=attacks, errors=errors))
        print(json.dumps(dict(passed=passed, runs=len(rows), attacks=attacks, errors=errors),indent=2))
        return not passed


if __name__=='__main__':
    raise SystemExit(main())
