import os
from common import api

role = os.environ['ROLE']
if role == 'ecu':
    from ecu import ECU
    app = ECU(int(os.environ['DOMAIN']))
elif role == 'gateway':
    from gateway import Gateway
    app = Gateway()
elif role == 'relay':
    from relay import Relay
    app = Relay()
else:
    raise RuntimeError('Unknown role')
api(app)
