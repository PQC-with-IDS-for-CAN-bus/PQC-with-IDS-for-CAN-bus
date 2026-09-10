"""Measured SocketCAN evidence; physical-only contract gaps stay explicit."""
import csv
import json
from pathlib import Path
from common import ROOT

PHYSICAL = {'bitrate_regime','nominal_baud','data_baud','total_wire_bytes','goodput_efficiency_pct'}


def validate_software(path, validator):
    errors = validator(path, strict=True, enforce_delivered_requests=False)
    # Never weaken the shared schema. Only explicitly unavailable hardware columns
    # are exempt in this separately named software profile.
    errors = [e for e in errors if not any(f"Column '{name}': required column '{name}' cannot be empty" in e for name in PHYSICAL)]
    seen = set()
    with Path(path).open(newline='') as stream:
        for number,row in enumerate(csv.DictReader(stream),2):
            try:
                def require(condition, message):
                    if not condition:
                        errors.append(f'Row {number}: {message}')
                require(row['run_id'] not in seen,'duplicate run_id')
                seen.add(row['run_id'])
                require(row['protocol_name']=='SIXTY_FOUR_BLOCK','wrong protocol')
                require(int(row['initial_frames_sent'])==41,'initial frame count must be 41')
                maps=[] if row['nack_bitmaps_issued_hex']=='N_A' else [int(x,16) for x in row['nack_bitmaps_issued_hex'].split(';')]
                require(len(maps)==int(row['recovery_rounds'])==int(row['control_frames_count'])==int(row['nack_frames_issued_count']),'NACK count mismatch')
                drops=[] if row['injected_dropped_frame_indices']=='NONE' else [int(x) for x in row['injected_dropped_frame_indices'].split(';')]
                require(drops==sorted(set(drops)) and all(0<=x<41 for x in drops),'invalid drop indices')
                for i in range(1,4):
                    requested=int(row[f'round_{i}_requested_frames']); recovered=int(row[f'round_{i}_recovered_frames'])
                    require(0<=recovered<=requested,'recovered exceeds requested')
                    require((0<maps[i-1]<(1<<41) and maps[i-1].bit_count()==requested) if i<=len(maps) else requested==recovered==0,'round bitmap mismatch')
                success=row['termination_status_code']=='SUCCESS'
                violation=float(row['end_to_end_latency_us'])>float(row['ftti_budget_us'])
                require((row['recovery_success']=='True')==success,'success mismatch')
                require((row['retry_exhaustion_flag']=='True')==(row['termination_status_code']=='ERR_RETRY_EXHAUSTION'),'retry flag mismatch')
                require((row['ftti_violation_flag']=='True')==violation,'FTTI flag mismatch')
                require(row['safety_state_achieved']==('OPERATIONAL' if success and not violation else 'SAFE_FALLBACK'),'safety state mismatch')
                require(float(row['recovery_overhead_latency_us'])>=0,'negative recovery overhead')
                require(int(row['total_frames_on_wire'])==41+int(row['retransmitted_frames_count'])+len(maps),'logical transmitted count mismatch')
            except (KeyError,ValueError,TypeError) as exc:
                errors.append(f'Row {number}: {exc}')
    return errors



def export_arrivals(out, events, records):
    specs = json.loads((ROOT/'Phase 3/config/data_contract_schemas.json').read_text())['contracts']['tcpdump_latency_summary']['columns']
    rows, clocks, previous, rounds = [], {}, {}, {}
    identifiers = {run:f'SESS_DOCKER_{i:06d}' for i,run in enumerate(records,1)}
    for e in events:
        run = e.get('run_id')
        if run not in records or not e['node'].startswith('gateway-d'):
            continue
        key = (run,e['domain'])
        if e['event']=='tx' and e.get('can_id')=='0x201':
            rounds[key] = bytes.fromhex(e['payload_hex'])[2]
        if e['event'] != 'rx' or e.get('can_id') != '0x200':
            continue
        stamp = e.get('kernel_epoch_ns')
        if stamp is None:
            raise ValueError('Kernel RX timestamp missing; cannot export Contract 2')
        payload = bytes.fromhex(e['payload_hex'])
        clocks.setdefault(key,stamp)
        if stamp < previous.get(key,stamp):
            raise ValueError('Kernel epoch clock moved backwards within session')
        row = dict.fromkeys(specs,None)
        row.update(session_id=identifiers[run], frame_idx=payload[1], total_frames_expected=41,
                   bus_channel=e['domain'], protocol_name='SIXTY_FOUR_BLOCK', frame_role='DATA',
                   retransmit_attempt_idx=rounds.get(key,0), can_id_hex=e['can_id'], ide_flag=0,
                   dlc=e['dlc'], payload_bytes=e['payload_bytes'],
                   payload_active_bytes=36 if payload[1]==40 else 60,
                   brs_flag=e.get('brs_flag',0), esi_flag=e.get('esi_flag',0),
                   timestamp_epoch_ns=stamp, timestamp_rel_us=(stamp-clocks[key])/1000,
                   ifat_us=(stamp-previous[key])/1000 if key in previous else None,
                   interface_rx_drops=e.get('interface_rx_drops',0))
        previous[key]=stamp
        rows.append(row)
    with (out/'tcpdump_latency_summary.csv').open('w',newline='') as stream:
        writer=csv.DictWriter(stream,fieldnames=specs);writer.writeheader();writer.writerows(rows)
    return dict(rows=len(rows), source='gateway SocketCAN recvmsg SO_TIMESTAMPNS (not tcpdump)',
                scope='actual attestation arrivals including malformed/duplicate frames; one gateway observation per frame',
                session_to_run={v:k for k,v in identifiers.items()},
                unavailable=['nominal_baud','data_baud','frame_duration_us','arrival_jitter_ns'],
                physical_contract_complete=False)
