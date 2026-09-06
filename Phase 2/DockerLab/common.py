"""Wire formats and evidence utilities shared by independent container processes."""
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / 'Phase 1/CAN FD/Crypto Code'))
from crypto_engine import AsconAEAD128Engine, KeyDerivation, PostQuantumAttestation, SessionManager
from canfd_schema import ChallengeFrame, AttestationDeliveryManager, IndexedAttestationFrame, KeyDeliveryFrame

CANFD = struct.Struct('=IBB2x64s')
NACK = struct.Struct('>BBBBIQ')
CHALLENGE, ATTESTATION, RECOVERY, KEY, DIAGNOSTIC = 0x202, 0x200, 0x201, 0x203, 0x300
# Lab diagnostic schema (not vehicle telemetry): 40 actual SHA256/clock bytes,
# authenticated 8B header. Protocol version 1, private diagnostic type 0xF.
DIAG_HEADER = struct.Struct('>BBBBI')
DOMAIN_NAMES = ['powertrain', 'chassis', 'body', 'infotainment']


def atomic(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix('.tmp')
    temp.write_text(json.dumps(value))
    temp.replace(path)


class Log:
    def __init__(self, node):
        self.node, self.run_id = node, None
        path = Path('/logs') / node
        path.mkdir(parents=True, exist_ok=True)
        self.stream = (path / 'events.jsonl').open('a', buffering=1)
        self.lock = threading.Lock()

    def event(self, event, **details):
        row = dict(node=self.node, run_id=self.run_id, event=event,
                   monotonic_ns=time.monotonic_ns(), epoch_ns=time.time_ns(), **details)
        line = json.dumps(row)
        with self.lock:
            self.stream.write(line+'\n')
            print(line, flush=True)
        return row


class CAN:
    def __init__(self, interface, log, domain):
        self.interface, self.log, self.domain = interface, log, domain
        self.socket = socket.socket(socket.PF_CAN, socket.SOCK_RAW, socket.CAN_RAW)
        self.socket.setsockopt(socket.SOL_CAN_RAW, socket.CAN_RAW_FD_FRAMES, 1)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024*1024)
        self.socket.setsockopt(socket.SOL_SOCKET, getattr(socket, 'SO_TIMESTAMPNS', 35), 1)
        self.socket.bind((interface,))

    def send(self, can_id, payload, **details):
        if len(payload) not in (16, 64):
            raise ValueError('Lab CAN-FD payload must be 16 or 64 bytes')
        self.socket.send(CANFD.pack(can_id, len(payload), 0, payload.ljust(64, b'\0')))
        return self.log.event('tx', domain=self.domain, interface=self.interface,
                              can_id=f'0x{can_id:03x}', payload_hex=payload.hex(),
                              payload_bytes=len(payload), dlc=10 if len(payload)==16 else 15, **details)

    def recv(self, timeout):
        self.socket.settimeout(timeout)
        packet, ancillary, _, _ = self.socket.recvmsg(CANFD.size, 128)
        if len(packet) != CANFD.size:
            self.log.event('reject_non_fd', domain=self.domain, packet_bytes=len(packet))
            return None
        can_id, length, flags, data = CANFD.unpack(packet)
        if length not in (16, 64) or can_id > 0x7ff:
            self.log.event('reject_frame_format', domain=self.domain, raw_can_id=can_id, length=length)
            return None
        kernel_epoch_ns = None
        for level, kind, value in ancillary:
            if level == socket.SOL_SOCKET and kind == getattr(socket, 'SO_TIMESTAMPNS', 35):
                seconds, ns = struct.unpack('@ll', value[:struct.calcsize('@ll')])
                kernel_epoch_ns = seconds*1_000_000_000+ns
        payload = data[:length]
        self.log.event('rx', domain=self.domain, interface=self.interface,
                       can_id=f'0x{can_id:03x}', payload_hex=payload.hex(),
                       payload_bytes=length, dlc=10 if length==16 else 15,
                       kernel_epoch_ns=kernel_epoch_ns)
        return can_id, payload

    def close(self):
        self.socket.close()


def api(app):
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass
        def do_GET(self):
            self.reply(200, app.status())
        def do_POST(self):
            try:
                length = int(self.headers.get('Content-Length', '0'))
                if not 0 < length <= 65536:
                    raise ValueError('invalid request length')
                result = app.command(self.path, json.loads(self.rfile.read(length)))
                self.reply(200, result)
            except (ValueError, KeyError, RuntimeError) as exc:
                self.reply(409, {'error': str(exc)})
        def reply(self, status, data):
            encoded = json.dumps(data).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json')
            self.send_header('Content-Length', str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()


def wait_interface(name):
    deadline = time.monotonic()+120
    while not Path('/sys/class/net', name).exists():
        if time.monotonic() > deadline:
            raise RuntimeError(f'{name} unavailable; topology setup did not finish')
        time.sleep(.1)
