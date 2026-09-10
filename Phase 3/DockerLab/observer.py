"""Independent, continuous candump and per-domain tcpdump captures.

Contract CSV export uses measured kernel RX events in controller.py. Capture
processes remain alive across repeated suites and are reaped on shutdown.
"""
from pathlib import Path
import signal
import subprocess
import threading
import time
from common import wait_interface

for domain in range(1,5):
    wait_interface(f'domain{domain}')
base = Path('/captures')
base.mkdir(exist_ok=True)
stop = threading.Event()
for sig in (signal.SIGTERM,signal.SIGINT):
    signal.signal(sig, lambda *_:stop.set())
children, streams = [], []
try:
    stream = (base/'candump.log').open('a')
    streams.append(stream)
    children.append(subprocess.Popen(['candump','-L','any'],stdout=stream))
    stamp = time.time_ns()
    for domain in range(1,5):
        # -Z prevents tcpdump attempting a setuid transition after cap_drop ALL.
        children.append(subprocess.Popen(['tcpdump','-Z','root','-p','-U','-i',f'domain{domain}',
                         '-w',str(base/f'domain{domain}-{stamp}.pcap')]))
    while not stop.wait(.5):
        if any(p.poll() is not None for p in children):
            raise RuntimeError('Independent capture process exited; inspect container logs')
finally:
    for child in children:
        if child.poll() is None:
            child.terminate()
    for child in children:
        try:
            child.wait(timeout=3)
        except subprocess.TimeoutExpired:
            child.kill();child.wait()
    for stream in streams:
        stream.close()
