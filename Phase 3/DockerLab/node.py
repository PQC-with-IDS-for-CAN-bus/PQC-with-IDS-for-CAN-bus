import os
from common import api

role = os.environ['ROLE']
engine = os.environ.get('GATEWAY_ENGINE', 'py').lower()

if role == 'ecu':
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
    from relay import Relay
    app = Relay()
    api(app)
else:
    raise RuntimeError('Unknown role')
