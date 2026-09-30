#!/usr/bin/env python3
"""
run_dashboard.py
================
Lightweight local HTTP launcher for the Phase 3 In-Vehicle CAN-FD Security Dashboard.
Runs locally without third-party web framework dependencies.
"""

import http.server
import socketserver
import os
import sys
import webbrowser

PORT = 8085
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class Handler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)

def main():
    os.chdir(DIRECTORY)
    # Attempt to bind to PORT or increment if busy
    port = PORT
    max_tries = 10
    httpd = None

    for p in range(port, port + max_tries):
        try:
            socketserver.TCPServer.allow_reuse_address = True
            httpd = socketserver.TCPServer(("", p), Handler)
            port = p
            break
        except OSError:
            continue

    if httpd is None:
        print(f"[ERROR] Could not bind to any port in range {PORT}-{PORT+max_tries}.")
        sys.exit(1)

    url = f"http://localhost:{port}/index.html"
    print("=" * 80)
    print("   PQC & 3-TIER IDS IN-VEHICLE CAN-FD DIGITAL TWIN DASHBOARD")
    print("=" * 80)
    print(f"[*] Serving from: {DIRECTORY}")
    print(f"[+] Dashboard Live URL: {url}")
    print("[*] Press Ctrl+C to terminate.")
    print("=" * 80)

    # Automatically open in user's default browser if desktop session is detected
    if os.environ.get("DISPLAY") or os.environ.get("WAYLAND_DISPLAY"):
        try:
            webbrowser.open(url)
        except Exception:
            pass

    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[+] Dashboard server stopped cleanly.")
        httpd.server_close()

if __name__ == "__main__":
    main()
