"""
Lightweight, secure maintenance server for Render deployment migration.
Binds to 0.0.0.0:$PORT to pass Render health checks while preventing the SIEM
application or SQLite database from being loaded or accessed during file transfer.
"""
import http.server
import json
import os
import sys

PORT = int(os.environ.get("PORT", 10000))
HEALTH_PATHS = ("/healthz", "/health", "/_health")


class MaintenanceHTTPHandler(http.server.BaseHTTPRequestHandler):
    server_version = "SOC-Maintenance/1.0"
    sys_version = ""

    def do_GET(self):
        # Dedicated health check endpoint for Render routing proxy
        if self.path in HEALTH_PATHS:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(b'{"status":"HEALTHY","mode":"maintenance","ready_for_migration":true}\n')
            return

        # All other paths return 503 Maintenance. Zero files or listings are served.
        self.send_response(503)
        self.send_header("Content-Type", "application/json")
        self.send_header("Retry-After", "300")
        self.send_header("Cache-Control", "no-cache")
        self.end_headers()
        payload = json.dumps({
            "status": "MAINTENANCE",
            "service": "AI-SIEM Cyber Threat Detection",
            "message": "Persistent database migration in progress. Service temporarily offline."
        }).encode("utf-8")
        self.wfile.write(payload)

    def do_HEAD(self):
        # HEAD requests mirror status codes of GET: 200 for health checks, 503 otherwise
        if self.path in HEALTH_PATHS:
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
        else:
            self.send_response(503)
            self.send_header("Content-Type", "application/json")
            self.send_header("Retry-After", "300")
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()

    def do_POST(self):
        self.send_response(503)
        self.end_headers()

    def log_message(self, format, *args):
        sys.stdout.write(f"[MAINTENANCE] {args[0]} - {args[1]} {args[2]}\n")
        sys.stdout.flush()


def run():
    server = http.server.HTTPServer(("0.0.0.0", PORT), MaintenanceHTTPHandler)
    print(f"[MAINTENANCE] Secure maintenance server listening on 0.0.0.0:{PORT}...")
    server.serve_forever()


if __name__ == "__main__":
    run()
