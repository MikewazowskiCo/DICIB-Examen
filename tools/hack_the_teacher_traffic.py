#!/usr/bin/env python3
"""HACK THE TEACHER - isolated training traffic generator.

Generates only synthetic HTTP/DNS-like lab traffic to 192.168.0.136:8610.
No real credentials, external services, scanning, or attack traffic are used.
Run only on the instructor's lab server/network.
"""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
import threading, time, random, socket

HOST = "0.0.0.0"
PORT = 8610
DURATION = 120 * 60
START = time.time()

# Synthetic identities deliberately used only for the exercise.
EVENTS = [
    ("09:01:12", "/noise", "Routine lab heartbeat: node=ALFA-02"),
    ("09:04:18", "/identity", "CASE=HTT-001 USER=mike.w ROLE=teacher SQUAD=INSTRUCTOR"),
    ("09:08:42", "/network", "CASE=HTT-002 USER=mike.w HOST=TEACHER-LAPTOP IP=192.168.0.114 SQUAD=INSTRUCTOR"),
    ("09:13:07", "/auth", "LAB LOGIN user=mike.w password=BlueShield-Lab-7421 status=SUCCESS"),
    ("09:17:55", "/noise", "Routine lab heartbeat: node=BRAVO-01"),
    ("09:22:31", "/mail", "MAIL FROM=mike.w@blue-shield.test TO=security@blue-shield.test SUBJECT=VERIFY code=739214"),
    ("09:29:14", "/web", "WEB user=mike.w host=portal.blue-shield.test method=GET path=/verify token=WZK-4821"),
    ("09:36:28", "/dns", "DNS QUESTION=portal.blue-shield.test ANSWER=192.168.0.136"),
    ("09:44:09", "/correlation", "TIMELINE user=mike.w login=09:13 mail=09:22 web=09:29"),
    ("09:53:46", "/squad", "DIRECTORY user=mike.w squad=INSTRUCTOR role=TEACHER"),
    ("10:03:22", "/noise", "Routine lab heartbeat: node=CHARLIE-03"),
    ("10:12:40", "/evidence", "EVIDENCE ip=192.168.0.114 user=mike.w service=HTTP port=8610"),
    ("10:21:18", "/hint", "HINT: Find the Teacher. Do not trust a single packet; correlate timestamps."),
    ("10:33:51", "/noise", "Routine lab heartbeat: node=DELTA-02"),
    ("10:46:06", "/finalhint", "PUBLIC-LEAD username=@mikevargax source=PUBLIC_PROFILE"),
]

class Handler(BaseHTTPRequestHandler):
    def send_text(self, body):
        data = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Lab", "HACK-THE-TEACHER")
        self.end_headers()
        self.wfile.write(data)
    def do_GET(self):
        path = urlparse(self.path).path
        if path == "/":
            self.send_text("HACK THE TEACHER // LAB ACTIVE // Use Wireshark. Traffic is synthetic.")
            return
        for _, p, msg in EVENTS:
            if path == p:
                self.send_text(msg)
                return
        self.send_text("NOISE // Nothing useful here. Correlate other packets.")
    def log_message(self, *args):
        pass

def periodic():
    while time.time() - START < DURATION:
        time.sleep(random.randint(18, 45))
        try:
            with socket.create_connection(("127.0.0.1", PORT), timeout=2) as s:
                path = random.choice(["/noise", "/identity", "/network", "/mail", "/web", "/dns", "/correlation"])
                req = f"GET {path} HTTP/1.1\r\nHost: 192.168.0.136:8610\r\nConnection: close\r\n\r\n"
                s.sendall(req.encode())
                s.recv(4096)
        except OSError:
            pass

if __name__ == "__main__":
    print(f"[+] HACK THE TEACHER lab listening on :{PORT}")
    print("[+] Synthetic traffic only. Duration: 120 minutes.")
    threading.Thread(target=periodic, daemon=True).start()
    ThreadingHTTPServer((HOST, PORT), Handler).serve_forever()
