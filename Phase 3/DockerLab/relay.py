"""Four logical CAN segments; deliberate fault stage has no cryptographic keys."""
import random
import select
import socket
import threading
from common import *


class Relay:
    def __init__(self):
        self.channels, self.configs, self.logs, self.rounds, self.rng = {}, {}, {}, {}, {}
        self.locks = {d:threading.Lock() for d in range(1,5)}
        for domain in range(1,5):
            self.logs[domain] = Log(f'bus-d{domain}')
            self.configs[domain] = {}
            self.rounds[domain] = 0
            for port in (f'e{domain}', f'g{domain}') + (('a1',) if domain == 1 else ()):
                wait_interface(port)
                self.channels[port] = CAN(port, self.logs[domain], domain)
        self.workers = [threading.Thread(target=self.loop,args=(d,),daemon=True) for d in range(1,5)]
        for worker in self.workers:
            worker.start()

    def status(self):
        return dict(ready=all(w.is_alive() for w in self.workers), domains=self.configs)
    def command(self, path, config):
        if path != '/configure' or config['domain'] not in range(1,5):
            raise ValueError('invalid relay configuration')
        p = config.get('loss_rate', 0)
        if not 0 <= p <= 1:
            raise ValueError('loss rate out of range')
        domain = config['domain']
        with self.locks[domain]:
            self.configs[domain] = config
            self.rounds[domain] = 0
            self.rng[domain] = random.Random(config.get('seed',0))
            self.logs[domain].run_id = config['run_id']
            self.logs[domain].event('fault_configured', domain=domain, scenario=config['scenario'], targets=config.get('drops', []))
        return {'configured': config['run_id']}

    def loop(self, domain):
        by_socket = {c.socket:(p,c) for p,c in self.channels.items() if c.domain==domain}
        while True:
            ready, _, _ = select.select(list(by_socket), [], [], 1)
            for sock in ready:
                port, channel = by_socket[sock]
                item = channel.recv(.1)
                if not item:
                    continue
                can_id, payload = item
                domain = channel.domain
                with self.locks[domain]:
                    config = self.configs[domain]
                    mode = config.get('scenario', 'clean')
                    if port.startswith('g') and can_id == RECOVERY and len(payload) == 16:
                        self.rounds[domain] = NACK.unpack(payload)[2]
                    rnd = self.rounds[domain]
                    drop, mutate = False, False
                    index = payload[1] if can_id == ATTESTATION and len(payload)==64 else None
                    if port.startswith('e') and index is not None:
                        drop = index in config.get('drops', []) and (rnd == 0 or mode == 'persistent')
                        if mode == 'monte_carlo':
                            drop = self.rng[domain].random() < config.get('loss_rate',.2)
                        mutate = mode == 'corrupt' and index == 12
                        if (mode == 'malformed' or mode == 'header_probe' and rnd == 0) and index == 12:
                            payload = payload[:1]+b'\xff'+payload[2:]
                            self.logs[domain].event('injected_header_corruption', domain=domain, frame_idx=index, round=rnd)
                    if port.startswith('g') and can_id == RECOVERY and mode == 'nack_drop':
                        drop = True
                    if drop:
                        self.logs[domain].event('injected_drop', domain=domain, source=port,
                                                can_id=f'0x{can_id:03x}', frame_idx=index, round=rnd)
                        continue
                    if mutate:
                        altered = bytearray(payload)
                        altered[4] ^= 1
                        payload = bytes(altered)
                        self.logs[domain].event('injected_corruption', domain=domain, frame_idx=index, round=rnd)
                    # Broadcast only within this domain, excluding ingress. The
                    # gateway has four separate interfaces, never a flat shared bus.
                    targets = [f'e{domain}', f'g{domain}'] + (['a1'] if domain == 1 else [])
                    for target in targets:
                        if target != port:
                            self.channels[target].send(can_id, payload, source=port, round=rnd, frame_idx=index)
