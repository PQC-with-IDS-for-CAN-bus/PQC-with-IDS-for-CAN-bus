"""Independent can-utils capture in the gateway network namespace."""
from pathlib import Path
import subprocess
from common import wait_interface

for domain in range(1,5):
    wait_interface(f'domain{domain}')
Path('/captures').mkdir(exist_ok=True)
with Path('/captures/candump.log').open('a') as stream:
    subprocess.run(['candump','-L','any'],stdout=stream,check=True)
