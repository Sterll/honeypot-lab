#!/usr/bin/env python3
"""
FTP Honeypot
Simulates an FTP server with fake files to capture brute-force and file access attempts.
Logs JSON events to /var/log/honeypot/ftp.json
Uses pyftpdlib.
"""

import json
import uuid
import os
import sys
import signal
from datetime import datetime, timezone

from pyftpdlib.authorizers import DummyAuthorizer, AuthenticationFailed
from pyftpdlib.handlers import FTPHandler
from pyftpdlib.servers import FTPServer

LOG_PATH = "/var/log/honeypot/ftp.json"
LISTEN_PORT = 21
FAKE_FS_ROOT = "/opt/honeypot-ftp/fakefs"

# ── Logging ──────────────────────────────────────────────────────────────────

def log_event(event: dict):
    event.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    event.setdefault("session", str(uuid.uuid4())[:12])
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")

# ── Custom Authorizer (accepts any creds) ────────────────────────────────────

class HoneypotAuthorizer(DummyAuthorizer):
    """Authorizer that logs and accepts any username/password combination."""

    def __init__(self):
        super().__init__()
        # Add anonymous user
        if os.path.isdir(FAKE_FS_ROOT):
            self.add_anonymous(FAKE_FS_ROOT, perm="elr")

    def validate_authentication(self, username, password, handler):
        src_ip = handler.remote_ip
        src_port = handler.remote_port

        # Always log the attempt
        log_event({
            "eventid": "ftp.login.attempt",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": username,
            "password": password,
        })

        # Accept a few common credentials to lure attackers deeper
        accepted_users = {"admin", "root", "ftp", "user", "test", "backup", "anonymous", "www-data"}
        if username.lower() in accepted_users:
            log_event({
                "eventid": "ftp.login.success",
                "src_ip": src_ip,
                "src_port": src_port,
                "username": username,
            })
            # Dynamically add the user so pyftpdlib allows the session
            if not self.has_user(username):
                self.add_user(username, password, FAKE_FS_ROOT, perm="elr")
            return

        # Reject others
        log_event({
            "eventid": "ftp.login.failed",
            "src_ip": src_ip,
            "src_port": src_port,
            "username": username,
        })
        raise AuthenticationFailed("Authentication failed.")

# ── Custom FTP Handler ───────────────────────────────────────────────────────

class HoneypotFTPHandler(FTPHandler):
    banner = "220 ProFTPD 1.3.5e Server (Production FTP) [::ffff:10.30.30.10]"

    def on_connect(self):
        log_event({
            "eventid": "ftp.session.connect",
            "src_ip": self.remote_ip,
            "src_port": self.remote_port,
        })

    def on_disconnect(self):
        log_event({
            "eventid": "ftp.session.closed",
            "src_ip": self.remote_ip,
            "src_port": self.remote_port,
        })

    def on_file_sent(self, file):
        log_event({
            "eventid": "ftp.file.download",
            "src_ip": self.remote_ip,
            "src_port": self.remote_port,
            "filename": file,
            "username": self.username or "anonymous",
        })

    def on_file_received(self, file):
        log_event({
            "eventid": "ftp.file.upload",
            "src_ip": self.remote_ip,
            "src_port": self.remote_port,
            "filename": file,
            "username": self.username or "anonymous",
        })

    def ftp_PASS(self, line):
        # Override to capture password before parent handles it
        super().ftp_PASS(line)

    def ftp_unknown(self, line):
        """Log any unrecognized FTP command."""
        log_event({
            "eventid": "ftp.command.input",
            "src_ip": self.remote_ip,
            "src_port": self.remote_port,
            "input": line,
            "username": self.username or "",
        })

# ── Setup fake filesystem ────────────────────────────────────────────────────

def setup_fake_fs():
    os.makedirs(FAKE_FS_ROOT, exist_ok=True)

    fake_files = {
        "backup.sql": "-- MySQL dump 10.13  Distrib 8.0.36\n-- Database: production_db\nDROP TABLE IF EXISTS `users`;\nCREATE TABLE `users` (\n  `id` int NOT NULL AUTO_INCREMENT,\n  `email` varchar(255),\n  `password_hash` varchar(255),\n  PRIMARY KEY (`id`)\n);\n",
        "employees.csv": "id,name,email,department,salary\n1,John Smith,john.smith@company.local,Engineering,85000\n2,Jane Doe,jane.doe@company.local,HR,72000\n3,Bob Wilson,bob.wilson@company.local,Finance,78000\n",
        ".env.bak": "DB_HOST=10.30.30.5\nDB_USER=prod_admin\nDB_PASS=Pr0d_S3cur3!2024\nDB_NAME=production_db\nSECRET_KEY=a8f5f167f44f4964e6c998dee827110c\n",
        "README.txt": "FTP Backup Server\nLast sync: 2026-03-28\nContact: admin@company.local\n",
        "config/db.conf": "[database]\nhost = 10.30.30.5\nport = 3306\nuser = backup_user\npassword = Bckp2024!\n",
        "www/index.html": "<html><head><title>Under Maintenance</title></head><body><h1>Site Under Maintenance</h1></body></html>\n",
    }

    for path, content in fake_files.items():
        full_path = os.path.join(FAKE_FS_ROOT, path)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        if not os.path.exists(full_path):
            with open(full_path, "w") as f:
                f.write(content)

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    setup_fake_fs()

    authorizer = HoneypotAuthorizer()
    handler = HoneypotFTPHandler
    handler.authorizer = authorizer
    handler.passive_ports = range(60000, 60100)
    handler.masquerade_address = "10.30.30.10"

    server = FTPServer(("0.0.0.0", LISTEN_PORT), handler)
    server.max_cons = 50
    server.max_cons_per_ip = 10

    print(f"[ftp-honeypot] Listening on port {LISTEN_PORT}")

    def shutdown(sig, frame):
        print("[ftp-honeypot] Shutting down...")
        server.close_all()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.close_all()

if __name__ == "__main__":
    main()
