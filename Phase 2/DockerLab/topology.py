"""One-shot helper joins only the explicitly supplied lab network namespaces."""
import json
import subprocess
import sys

pids = json.loads(sys.argv[1])
if set(pids) != {'relay','gateway','attacker','ecu1','ecu2','ecu3','ecu4'}:
    raise ValueError('Expected exactly the seven lab container PIDs')
if any(not isinstance(pid,int) or pid <= 1 for pid in pids.values()):
    raise ValueError('Unsafe namespace PID')

def run(pid, *args):
    subprocess.run(['nsenter', '-t', str(pid), '-n', '--', *args], check=True)

for domain in range(1,5):
    for port, target, peer in [(f'e{domain}',f'ecu{domain}','can0'), (f'g{domain}','gateway',f'domain{domain}')]:
        run(pids['relay'], 'ip','link','add',port,'type','vxcan','peer','name',peer,'netns',str(pids[target]))
        run(pids['relay'], 'ip','link','set',port,'up')
        run(pids[target], 'ip','link','set',peer,'up')
run(pids['relay'], 'ip','link','add','a1','type','vxcan','peer','name','can0','netns',str(pids['attacker']))
run(pids['relay'], 'ip','link','set','a1','up')
run(pids['attacker'], 'ip','link','set','can0','up')
print('Created nine vxcan pairs across four isolated logical CAN domains.')
