#!/usr/bin/env python3
"""
HTTP WordPress Honeypot
Simulates a vulnerable WordPress installation to capture web scanning and brute-force attempts.
Logs JSON events to /var/log/honeypot/http.json
"""

import json
import uuid
import html
import os
import sys
import signal
from datetime import datetime, timezone
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs

LOG_PATH = "/var/log/honeypot/http.json"
LISTEN_PORT = 8080

# ── Logging ──────────────────────────────────────────────────────────────────

def log_event(event: dict):
    event.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    event.setdefault("session", str(uuid.uuid4())[:12])
    with open(LOG_PATH, "a") as f:
        f.write(json.dumps(event) + "\n")

# ── Fake WordPress pages ─────────────────────────────────────────────────────

WP_LOGIN_PAGE = """<!DOCTYPE html>
<html lang="en-US">
<head><title>Log In &lsaquo; Production Blog &#8212; WordPress</title>
<meta name="robots" content="max-image-preview:large, noindex, noarchive" />
<style>body{{background:#f1f1f1;font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Oxygen,Ubuntu,Cantarell,sans-serif}}
.login{{width:320px;margin:0 auto;padding:8% 0 0}}h1 a{{background-image:url(data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmciIHdpZHRoPSI0MCIgaGVpZ2h0PSI0MCI+PHJlY3Qgd2lkdGg9IjQwIiBoZWlnaHQ9IjQwIiBmaWxsPSIjMDA3M2FhIi8+PC9zdmc+);width:84px;height:84px;display:block;margin:0 auto 25px;background-size:84px}}
.login form{{background:#fff;border:1px solid #c3c4c7;box-shadow:0 1px 3px rgba(0,0,0,.04);padding:26px 24px;margin-top:20px}}
.login label{{font-size:14px;color:#1e1e1e}}
.login input[type=text],.login input[type=password]{{width:100%;padding:3px 5px;margin:2px 6px 16px 0;font-size:24px;border:1px solid #8c8f94;box-sizing:border-box}}
.login .submit input{{background:#2271b1;border-color:#2271b1;color:#fff;padding:0 12px;font-size:13px;height:36px;cursor:pointer;border-radius:3px}}
.login .submit input:hover{{background:#135e96}}
p.message{{background:#d63638;color:#fff;padding:12px;margin:0 0 16px;border-left:4px solid #d63638}}</style></head>
<body class="login">
<div class="login">
<h1><a href="https://wordpress.org/">Production Blog</a></h1>
{message}
<form method="post" action="/wp-login.php">
<p><label for="user_login">Username or Email Address</label>
<input type="text" name="log" id="user_login" value="{username}" size="20" autocapitalize="off" autocomplete="username" /></p>
<p><label for="user_pass">Password</label>
<input type="password" name="pwd" id="user_pass" size="20" autocomplete="current-password" /></p>
<p class="submit"><input type="submit" value="Log In" /></p>
</form>
<p><a href="/wp-login.php?action=lostpassword">Lost your password?</a></p>
</div></body></html>"""

WP_XMLRPC_RESPONSE = """<?xml version="1.0" encoding="UTF-8"?>
<methodResponse><params><param><value><array><data>
<value><struct>
<member><name>isAdmin</name><value><boolean>1</boolean></value></member>
<member><name>url</name><value><string>http://production-blog.local/</string></value></member>
<member><name>blogid</name><value><string>1</string></value></member>
<member><name>blogName</name><value><string>Production Blog</string></value></member>
</struct></value>
</data></array></value></param></params></methodResponse>"""

WP_HOMEPAGE = """<!DOCTYPE html>
<html lang="en-US"><head><title>Production Blog – Internal Company Blog</title>
<meta name="generator" content="WordPress 6.4.3" />
<meta charset="UTF-8" /></head>
<body><div id="page"><header><h1>Production Blog</h1><p>Internal updates and documentation</p></header>
<main><article><h2>Q1 2026 Infrastructure Update</h2>
<p>We have completed the migration to the new data center. All services are now running on updated hardware.</p>
<p class="meta">Posted on March 15, 2026 by admin</p></article>
<article><h2>New Employee Onboarding Guide</h2>
<p>Please refer to the updated onboarding documentation for new team members joining this quarter.</p>
<p class="meta">Posted on February 28, 2026 by hr-team</p></article></main>
<footer><p>Powered by WordPress</p></footer></div></body></html>"""

ROBOTS_TXT = """User-agent: *
Disallow: /wp-admin/
Allow: /wp-admin/admin-ajax.php
Sitemap: http://production-blog.local/sitemap.xml
"""

# Probe paths that attackers commonly scan for
PROBE_PATHS = {
    "/.env", "/wp-config.php", "/wp-config.php.bak", "/wp-config.php.old",
    "/wp-config.php.save", "/wp-config.txt", "/.git/config", "/.git/HEAD",
    "/backup.sql", "/dump.sql", "/db.sql", "/database.sql",
    "/phpmyadmin/", "/pma/", "/myadmin/", "/mysql/",
    "/debug.log", "/wp-content/debug.log", "/error_log",
    "/.htaccess", "/.htpasswd", "/server-status", "/server-info",
    "/wp-includes/wlwmanifest.xml", "/wp-json/wp/v2/users",
    "/readme.html", "/license.txt",
}

# ── Request Handler ──────────────────────────────────────────────────────────

class HoneypotHTTPHandler(BaseHTTPRequestHandler):
    server_version = "Apache/2.4.56"
    sys_version = ""

    def log_message(self, format, *args):
        pass  # Suppress default stderr logging

    def _get_client_ip(self):
        return self.client_address[0]

    def _base_event(self):
        return {
            "src_ip": self._get_client_ip(),
            "src_port": self.client_address[1],
            "method": self.command,
            "path": self.path,
            "user_agent": self.headers.get("User-Agent", ""),
            "host": self.headers.get("Host", ""),
        }

    def _send(self, code, body, content_type="text/html"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("X-Powered-By", "PHP/8.1.27")
        self.send_header("Server", "Apache/2.4.56 (Debian)")
        self.end_headers()
        self.wfile.write(body if isinstance(body, bytes) else body.encode())

    def do_GET(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        ev = self._base_event()

        if path == "/wp-login.php":
            ev["eventid"] = "http.request"
            ev["response_code"] = 200
            log_event(ev)
            page = WP_LOGIN_PAGE.format(message="", username="")
            self._send(200, page)

        elif path == "/wp-admin" or path.startswith("/wp-admin/"):
            ev["eventid"] = "http.request"
            ev["response_code"] = 302
            log_event(ev)
            self.send_response(302)
            self.send_header("Location", "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1")
            self.end_headers()

        elif path == "/xmlrpc.php":
            ev["eventid"] = "http.xmlrpc"
            ev["response_code"] = 200
            log_event(ev)
            self._send(200, "XML-RPC server accepts POST requests only.", "text/plain")

        elif path in PROBE_PATHS or any(path.startswith(p.rstrip("/")) for p in PROBE_PATHS if p.endswith("/")):
            ev["eventid"] = "http.probe"
            ev["response_code"] = 403
            log_event(ev)
            self._send(403, "<html><body><h1>403 Forbidden</h1></body></html>")

        elif path == "/robots.txt":
            ev["eventid"] = "http.request"
            ev["response_code"] = 200
            log_event(ev)
            self._send(200, ROBOTS_TXT, "text/plain")

        elif path == "/wp-json/wp/v2/users":
            ev["eventid"] = "http.probe"
            ev["response_code"] = 200
            users = [{"id": 1, "name": "admin", "slug": "admin", "link": "http://production-blog.local/author/admin/"}]
            log_event(ev)
            self._send(200, json.dumps(users), "application/json")

        elif path == "/" or path == "/index.php":
            ev["eventid"] = "http.request"
            ev["response_code"] = 200
            log_event(ev)
            self._send(200, WP_HOMEPAGE)

        else:
            ev["eventid"] = "http.request"
            ev["response_code"] = 404
            log_event(ev)
            self._send(404, "<html><body><h1>404 Not Found</h1></body></html>")

    def do_POST(self):
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/") or "/"
        ev = self._base_event()

        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8", errors="replace") if content_length > 0 else ""

        if path == "/wp-login.php":
            params = parse_qs(body)
            username = params.get("log", [""])[0]
            password = params.get("pwd", [""])[0]

            ev["eventid"] = "http.login.attempt"
            ev["username"] = username
            ev["password"] = password
            ev["response_code"] = 200
            log_event(ev)

            msg = '<p class="message">The password you entered for the username <strong>{}</strong> is incorrect.</p>'.format(
                html.escape(username)
            )
            page = WP_LOGIN_PAGE.format(message=msg, username=html.escape(username))
            self._send(200, page)

        elif path == "/xmlrpc.php":
            ev["eventid"] = "http.xmlrpc"
            ev["post_body"] = body[:2000]
            ev["response_code"] = 200
            log_event(ev)

            if "wp.getUsersBlogs" in body:
                self._send(200, WP_XMLRPC_RESPONSE, "text/xml")
            else:
                self._send(200, '<?xml version="1.0"?><methodResponse><fault><value><struct>'
                           '<member><name>faultCode</name><value><int>-32601</int></value></member>'
                           '<member><name>faultString</name><value><string>Requested method not found</string></value></member>'
                           '</struct></value></fault></methodResponse>', "text/xml")
        else:
            ev["eventid"] = "http.request"
            ev["response_code"] = 405
            log_event(ev)
            self._send(405, "<html><body><h1>405 Method Not Allowed</h1></body></html>")

    def do_HEAD(self):
        self.do_GET()

# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)

    server = HTTPServer(("0.0.0.0", LISTEN_PORT), HoneypotHTTPHandler)
    print(f"[http-honeypot] Listening on port {LISTEN_PORT}")

    def shutdown(sig, frame):
        print("[http-honeypot] Shutting down...")
        server.shutdown()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

if __name__ == "__main__":
    main()
