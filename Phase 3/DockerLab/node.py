import os
from common import api

role = os.environ['ROLE']
engine = os.environ.get('GATEWAY_ENGINE', 'py').lower()

if role == 'ecu':
    if engine == 'cpp':
        import subprocess
        print(f"[ECU] Spawning native C++17 ECU Engine on Domain {os.environ.get('DOMAIN', '1')}...")
        subprocess.run(['/usr/local/bin/ecu_node', '--domain', str(os.environ.get('DOMAIN', '1'))])
    else:
        from ecu import ECU
        app = ECU(int(os.environ['DOMAIN']))
        api(app)
elif role == 'gateway':
    if engine == 'cpp':
        import subprocess
        print('[GATEWAY] Spawning native C++17 CISG Gateway Engine...')
        subprocess.run(['/usr/local/bin/cisg_gateway'])
    else:
        from gateway import Gateway
        app = Gateway()
        api(app)
elif role == 'relay':
    if engine == 'cpp':
        import subprocess
        print('[RELAY] Spawning native C++17 Fault Injection Relay Engine...')
        subprocess.run(['/usr/local/bin/relay_node'])
    else:
        from relay import Relay
        app = Relay()
        api(app)
else:
    raise RuntimeError('Unknown role')
