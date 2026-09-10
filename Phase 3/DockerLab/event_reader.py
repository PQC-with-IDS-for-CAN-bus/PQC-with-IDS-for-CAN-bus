"""Incremental JSONL reader with bounded memory and partial-write handling."""
from collections import deque
import json
from pathlib import Path
import threading


class EventReader:
    def __init__(self, root='/logs', limit=200000):
        self.root = Path(root)
        self.rows = deque(maxlen=limit)
        self.positions = {}
        self.lock = threading.Lock()

    def read(self):
        with self.lock:
            for path in self.root.glob('*/events.jsonl'):
                stat = path.stat()
                inode, offset = self.positions.get(path,(stat.st_ino,0))
                if inode != stat.st_ino or stat.st_size < offset:
                    offset = 0
                with path.open('rb') as stream:
                    stream.seek(offset)
                    while True:
                        start = stream.tell()
                        line = stream.readline()
                        if not line or not line.endswith(b'\n'):
                            offset = start
                            break
                        try:
                            self.rows.append(json.loads(line))
                        except (ValueError,UnicodeError):
                            pass
                self.positions[path] = (stat.st_ino,offset)
            return sorted(self.rows,key=lambda e:e['monotonic_ns'])
