#!/usr/bin/env python3
"""Manage only this Compose project; no dependency on host sudo or Python crypto."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
os.environ['LAB_UID'] = str(os.getuid())
os.environ['LAB_GID'] = str(os.getgid())
IMAGE = 'pqc-can-lab:local'
NODES = ['relay','gateway','ecu1','ecu2','ecu3','ecu4','attacker']
SERVICES = NODES + ['dashboard','observer']

def run(args, capture=False):
    return subprocess.run(args, cwd=HERE, check=True, text=True, stdout=subprocess.PIPE if capture else None)
def compose(*args, capture=False):
    return run(['docker','compose',*args], capture)

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('action', choices=['up','down','run','status','logs','observe','validate'])
parser.add_argument('--monte-carlo', type=int, default=5)
args = parser.parse_args()
if args.action == 'up':
    if compose('ps','-a','-q',capture=True).stdout.strip():
        sys.exit('Lab containers already exist. Use status, run, or down before rebuilding.')
    state = HERE/'state'
    for folder in ['credentials','exports','mailbox','captures'] + [f'logs/{n}' for n in ['attacker',*[f'ecu{i}' for i in range(1,5)], *[f'gateway-d{i}' for i in range(1,5)], *[f'bus-d{i}' for i in range(1,5)]]]:
        (state/folder).mkdir(parents=True, exist_ok=True)
    compose('build','relay')
    if not (state/'credentials/gateway.json').exists():
        run(['docker','run','--rm','--network','none','--user',f'{os.getuid()}:{os.getgid()}',
             '-v',f'{state}/credentials:/enrollment',IMAGE,'python','provision.py'])
    runtime = dict(image_id=run(['docker','image','inspect',IMAGE,'--format','{{.Id}}'],True).stdout.strip(),
                   docker=run(['docker','version','--format','{{.Server.Version}}'],True).stdout.strip())
    (state/'runtime.json').write_text(json.dumps(runtime,indent=2))
    compose('up','-d',*SERVICES)
    pids = {}
    for service in NODES:
        cid = compose('ps','-q',service,capture=True).stdout.strip()
        pids[service] = int(run(['docker','inspect','-f','{{.State.Pid}}',cid], True).stdout)
    try:
        run(['docker','run','--rm','--network','host','--pid','host','--cap-drop','ALL',
             '--cap-add','NET_ADMIN','--cap-add','SYS_ADMIN','--cap-add','SYS_PTRACE',
             '--security-opt','apparmor=unconfined',IMAGE,'python','topology.py',json.dumps(pids)])
        compose('run','--rm','controller','python','controller.py','--health-only')
    except subprocess.CalledProcessError:
        print('Topology/startup failed. No transport fallback used. Inspect logs, then run lab.py down.', file=sys.stderr)
        raise
    print('Live dashboard: http://localhost:8088\nRun experiments: python3 lab.py run')
elif args.action == 'down':
    compose('--profile','observability','down')
elif args.action == 'run':
    if args.monte_carlo < 0:
        parser.error('--monte-carlo must be nonnegative')
    compose('run','--rm','controller','python','controller.py','--monte-carlo',str(args.monte_carlo))
elif args.action == 'observe':
    compose('--profile','observability','up','-d','loki','alloy','grafana')
elif args.action == 'validate':
    compose('run','--rm','controller','python','controller.py','--validate-only')
elif args.action == 'logs':
    compose('logs','--tail','100','-f')
else:
    compose('--profile','observability','ps')
