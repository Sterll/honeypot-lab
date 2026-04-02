#!/bin/bash
set -e

# HTTP honeypot service
cat > /etc/systemd/system/honeypot-http.service << 'UNIT'
[Unit]
Description=HTTP WordPress Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/honeypot-http/server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

# FTP honeypot service
cat > /etc/systemd/system/honeypot-ftp.service << 'UNIT'
[Unit]
Description=FTP Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/honeypot-ftp/server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

# SMB honeypot service
cat > /etc/systemd/system/honeypot-smb.service << 'UNIT'
[Unit]
Description=SMB Honeypot
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/python3 /opt/honeypot-smb/server.py
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable honeypot-http honeypot-ftp honeypot-smb
systemctl start honeypot-http honeypot-ftp honeypot-smb
sleep 2
echo "=== STATUS ==="
systemctl is-active honeypot-http honeypot-ftp honeypot-smb
echo "=== PORTS ==="
ss -tlnp | grep -E '(8080|:21 |:445)'
