#!/usr/bin/env python3
"""
SMB Honeypot - Captures auth attempts, share enumeration, and file access.
Logs JSON events to /var/log/honeypot/smb.json
"""

import json
import uuid
import os
import sys
import signal
import socket
import struct
import threading
from datetime import datetime, timezone

LOG_PATH = "/var/log/honeypot/smb.json"
LISTEN_PORT = 445

_log_lock = threading.Lock()

def log_event(event: dict):
    event.setdefault("timestamp", datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ"))
    with _log_lock:
        with open(LOG_PATH, "a") as f:
            f.write(json.dumps(event) + "\n")
            f.flush()


# ── NTLM helpers ─────────────────────────────────────────────────────────────

def build_ntlm_challenge():
    """Build NTLMSSP CHALLENGE (type 2) message."""
    target = "HONEYPOT".encode("utf-16-le")
    challenge = os.urandom(8)

    # Target info: NetBIOS domain name
    ti_domain = struct.pack("<HH", 2, len(target)) + target
    ti_end = struct.pack("<HH", 0, 0)
    target_info = ti_domain + ti_end

    # Offsets: target name at 56, target info after it
    tn_offset = 56
    ti_offset = tn_offset + len(target)

    msg = bytearray()
    msg += b"NTLMSSP\x00"
    msg += struct.pack("<I", 2)  # type CHALLENGE
    msg += struct.pack("<HHI", len(target), len(target), tn_offset)  # target name fields
    msg += struct.pack("<I", 0x00A28233)  # negotiate flags (NTLM, unicode, target info, etc)
    msg += challenge
    msg += b"\x00" * 8  # reserved
    msg += struct.pack("<HHI", len(target_info), len(target_info), ti_offset)  # target info fields
    # Pad to target name offset
    while len(msg) < tn_offset:
        msg += b"\x00"
    msg += target
    msg += target_info
    return bytes(msg)


def extract_ntlm_auth(blob):
    """Extract username and domain from NTLMSSP AUTH (type 3) message."""
    idx = blob.find(b"NTLMSSP\x00")
    if idx < 0:
        return None, None
    ntlm = blob[idx:]
    if len(ntlm) < 44:
        return None, None
    msg_type = struct.unpack("<I", ntlm[8:12])[0]
    if msg_type != 3:
        return None, None
    try:
        domain_len = struct.unpack("<H", ntlm[28:30])[0]
        domain_off = struct.unpack("<I", ntlm[32:36])[0]
        user_len = struct.unpack("<H", ntlm[36:38])[0]
        user_off = struct.unpack("<I", ntlm[40:44])[0]
        domain = ntlm[domain_off:domain_off+domain_len].decode("utf-16-le", errors="replace")
        username = ntlm[user_off:user_off+user_len].decode("utf-16-le", errors="replace")
        return username, domain
    except Exception:
        return None, None


def wrap_spnego_challenge(ntlm_challenge):
    """Wrap NTLM challenge in SPNEGO NegTokenResp."""
    # NegTokenResp { responseToken: ntlm_challenge }
    # responseToken [2] OCTET STRING
    resp_token = b"\xa2" + _asn1_len(2 + len(ntlm_challenge)) + b"\x04" + _asn1_len(len(ntlm_challenge)) + ntlm_challenge
    # NegTokenResp SEQUENCE
    inner = b"\x30" + _asn1_len(len(resp_token)) + resp_token
    # Context [1] for NegTokenResp
    return b"\xa1" + _asn1_len(len(inner)) + inner


def build_spnego_init():
    """Build SPNEGO NegTokenInit advertising NTLMSSP."""
    ntlmssp_oid = b"\x06\x0a\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a"
    mech_types = b"\x30" + _asn1_len(len(ntlmssp_oid)) + ntlmssp_oid
    mech_types_ctx = b"\xa0" + _asn1_len(len(mech_types)) + mech_types
    neg_init = b"\x30" + _asn1_len(len(mech_types_ctx)) + mech_types_ctx
    neg_init_ctx = b"\xa0" + _asn1_len(len(neg_init)) + neg_init
    spnego_oid = b"\x06\x06\x2b\x06\x01\x05\x05\x02"
    inner = spnego_oid + neg_init_ctx
    return b"\x60" + _asn1_len(len(inner)) + inner


def _asn1_len(n):
    if n < 0x80:
        return bytes([n])
    elif n < 0x100:
        return bytes([0x81, n])
    else:
        return bytes([0x82]) + struct.pack(">H", n)


# ── SMB2 response builders ──────────────────────────────────────────────────

SMB2_MAGIC = b"\xfeSMB"
SMB1_MAGIC = b"\xffSMB"

def smb2_header(command, status=0, credit=1, session_id=0, message_id=0, flags=0x01):
    """Build a 64-byte SMB2 header."""
    hdr = bytearray(64)
    hdr[0:4] = SMB2_MAGIC
    hdr[4:6] = struct.pack("<H", 64)       # structure size
    hdr[6:8] = struct.pack("<H", 0)        # credit charge
    hdr[8:12] = struct.pack("<I", status)
    hdr[12:14] = struct.pack("<H", command)
    hdr[14:16] = struct.pack("<H", credit)
    hdr[16:20] = struct.pack("<I", flags)   # flags (response)
    hdr[24:28] = struct.pack("<I", 0)       # next command
    hdr[28:36] = struct.pack("<Q", message_id)
    hdr[40:48] = struct.pack("<Q", session_id)
    return hdr


# ── SMB Honeypot ─────────────────────────────────────────────────────────────

class SMBHoneypot:
    def __init__(self, host="0.0.0.0", port=LISTEN_PORT):
        self.host = host
        self.port = port
        self.running = False
        self.server_guid = os.urandom(16)

    def start(self):
        self.running = True
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.settimeout(1.0)
        srv.bind((self.host, self.port))
        srv.listen(20)
        self._sock = srv
        print(f"[smb-honeypot] Listening on port {self.port}")

        while self.running:
            try:
                client, addr = srv.accept()
                t = threading.Thread(target=self._handle, args=(client, addr), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except OSError:
                break

    def stop(self):
        self.running = False
        try:
            self._sock.close()
        except Exception:
            pass

    def _handle(self, client, addr):
        src_ip, src_port = addr
        sid = str(uuid.uuid4())[:11]
        session_id = 0x1000 + (hash(sid) & 0xFFFF)

        log_event({
            "eventid": "smb.session.connect",
            "src_ip": src_ip,
            "src_port": src_port,
            "session": sid,
        })

        client.settimeout(30)
        authed = False
        username_captured = None

        try:
            while True:
                # NetBIOS session header (4 bytes)
                hdr = self._recv(client, 4)
                if not hdr:
                    break
                msg_len = struct.unpack(">I", hdr)[0] & 0x00FFFFFF
                if msg_len == 0 or msg_len > 1048576:
                    break
                data = self._recv(client, msg_len)
                if not data:
                    break

                resp = None

                if data[:4] == SMB1_MAGIC:
                    resp = self._on_smb1(data, src_ip, sid, session_id)
                elif data[:4] == SMB2_MAGIC:
                    resp, authed_now, uname = self._on_smb2(data, src_ip, sid, session_id, authed)
                    if authed_now:
                        authed = True
                    if uname:
                        username_captured = uname
                else:
                    break

                if resp:
                    nb = struct.pack(">I", len(resp))
                    client.sendall(nb + resp)
                else:
                    break

        except (ConnectionResetError, BrokenPipeError, socket.timeout, OSError):
            pass
        finally:
            log_event({
                "eventid": "smb.session.closed",
                "src_ip": src_ip,
                "src_port": src_port,
                "session": sid,
                "username": username_captured,
            })
            client.close()

    def _recv(self, sock, n):
        buf = b""
        while len(buf) < n:
            chunk = sock.recv(n - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # ── SMB1 ──

    def _on_smb1(self, data, src_ip, sid, session_id):
        if len(data) < 33:
            return None
        cmd = data[4]

        if cmd == 0x72:  # NEGOTIATE
            log_event({
                "eventid": "smb.negotiate",
                "src_ip": src_ip,
                "session": sid,
                "protocol": "SMB1",
            })
            # Return negotiate response that steers client to SMB2
            # Select dialect "SMB 2.002" if present, else first dialect
            dialects = self._parse_smb1_dialects(data)
            smb2_idx = None
            for i, d in enumerate(dialects):
                if "SMB 2" in d:
                    smb2_idx = i
                    break
            idx = smb2_idx if smb2_idx is not None else 0
            return self._smb1_negotiate_resp(idx)

        elif cmd == 0x73:  # SESSION_SETUP
            username, domain = self._extract_smb1_creds(data)
            log_event({
                "eventid": "smb.login.attempt",
                "src_ip": src_ip,
                "session": sid,
                "username": username or "",
                "domain": domain or "",
                "message": f"SMB1 login: {domain}\\{username}" if domain else f"SMB1 login: {username}",
            })
            return self._smb1_session_resp()

        return None

    def _parse_smb1_dialects(self, data):
        """Parse dialect strings from SMB1 negotiate request."""
        dialects = []
        try:
            offset = 32  # SMB header
            wc = data[offset]
            offset += 1 + wc * 2
            bc = struct.unpack("<H", data[offset:offset+2])[0]
            offset += 2
            end = offset + bc
            while offset < end and offset < len(data):
                if data[offset] == 0x02:  # dialect buffer format
                    offset += 1
                    null = data.index(0, offset)
                    dialects.append(data[offset:null].decode("ascii", errors="replace"))
                    offset = null + 1
                else:
                    break
        except Exception:
            pass
        return dialects

    def _smb1_negotiate_resp(self, dialect_idx):
        """SMB1 negotiate response - NT LM 0.12 compatible."""
        resp = bytearray(73)
        resp[0:4] = SMB1_MAGIC
        resp[4] = 0x72  # NEGOTIATE
        resp[5:9] = struct.pack("<I", 0)  # STATUS_SUCCESS
        resp[9] = 0x98  # flags
        resp[10:12] = struct.pack("<H", 0xC853)  # flags2 (unicode, ntlm, extended security)
        # Word count = 17 for extended security negotiate response
        resp[32] = 17
        resp[33:35] = struct.pack("<H", dialect_idx)  # selected dialect
        resp[35] = 0x03  # security mode (user, encrypt)
        resp[36:38] = struct.pack("<H", 50)  # max mpx
        resp[38:40] = struct.pack("<H", 1)   # max VCs
        resp[40:44] = struct.pack("<I", 65536)  # max buffer
        resp[44:48] = struct.pack("<I", 65536)  # max raw
        resp[48:52] = struct.pack("<I", 0x1234)  # session key
        resp[52:56] = struct.pack("<I", 0xF3F9)  # capabilities (extended security, unicode, NT smbs, large files)
        # system time (8 bytes) and timezone (2 bytes) at 56-66
        resp[66:68] = struct.pack("<H", 0)  # byte count (security blob follows but keep simple)
        return bytes(resp[:68])

    def _extract_smb1_creds(self, data):
        try:
            offset = 32
            wc = data[offset]
            offset += 1 + wc * 2
            bc = struct.unpack("<H", data[offset:offset+2])[0]
            offset += 2
            blob = data[offset:offset+bc]
            return extract_ntlm_auth(blob) if b"NTLMSSP" in blob else (None, None)
        except Exception:
            return None, None

    def _smb1_session_resp(self):
        resp = bytearray(39)
        resp[0:4] = SMB1_MAGIC
        resp[4] = 0x73
        resp[5:9] = struct.pack("<I", 0xC000006D)  # LOGON_FAILURE
        resp[9] = 0x98
        resp[10:12] = struct.pack("<H", 0xC853)
        resp[32] = 0
        resp[33:35] = struct.pack("<H", 0)
        return bytes(resp)

    # ── SMB2 ──

    def _on_smb2(self, data, src_ip, sid, session_id, authed):
        if len(data) < 64:
            return None, False, None
        cmd = struct.unpack("<H", data[12:14])[0]
        msg_id = struct.unpack("<Q", data[28:36])[0] if len(data) >= 36 else 0

        if cmd == 0:  # NEGOTIATE
            log_event({
                "eventid": "smb.negotiate",
                "src_ip": src_ip,
                "session": sid,
                "protocol": "SMB2",
            })
            return self._smb2_negotiate_resp(msg_id), False, None

        elif cmd == 1:  # SESSION_SETUP
            return self._smb2_session_setup(data, src_ip, sid, session_id, msg_id)

        elif cmd == 3:  # TREE_CONNECT
            return self._smb2_tree_connect(data, src_ip, sid, session_id, msg_id, authed)

        elif cmd == 4:  # TREE_DISCONNECT
            resp = smb2_header(4, session_id=session_id, message_id=msg_id)
            resp += struct.pack("<H", 4)  # struct size
            resp += b"\x00\x00"  # reserved
            return bytes(resp), False, None

        elif cmd == 2:  # LOGOFF
            resp = smb2_header(2, session_id=session_id, message_id=msg_id)
            resp += struct.pack("<H", 4)
            resp += b"\x00\x00"
            return bytes(resp), False, None

        return None, False, None

    def _smb2_negotiate_resp(self, msg_id):
        """SMB2 negotiate with SPNEGO security buffer."""
        sec_blob = build_spnego_init()
        sec_offset = 128  # header(64) + negotiate_resp(64)
        body_size = 64 + len(sec_blob)

        hdr = smb2_header(0, message_id=msg_id)
        body = bytearray(64 + len(sec_blob))
        body[0:2] = struct.pack("<H", 65)   # structure size
        body[2:4] = struct.pack("<H", 0x03) # security mode
        body[4:6] = struct.pack("<H", 0x0202)  # dialect SMB 2.0.2
        body[8:24] = self.server_guid        # server GUID
        body[24:28] = struct.pack("<I", 0x07)  # capabilities
        body[28:32] = struct.pack("<I", 1048576)  # max transact
        body[32:36] = struct.pack("<I", 1048576)  # max read
        body[36:40] = struct.pack("<I", 1048576)  # max write
        body[48:50] = struct.pack("<H", sec_offset)  # security buffer offset
        body[50:52] = struct.pack("<H", len(sec_blob))  # security buffer length
        body[64:64+len(sec_blob)] = sec_blob
        return bytes(hdr) + bytes(body)

    def _smb2_session_setup(self, data, src_ip, sid, session_id, msg_id):
        """Handle SMB2 session setup - NTLM negotiate/auth."""
        ntlm_idx = data.find(b"NTLMSSP\x00")
        if ntlm_idx >= 0 and len(data) > ntlm_idx + 12:
            msg_type = struct.unpack("<I", data[ntlm_idx+8:ntlm_idx+12])[0]

            if msg_type == 1:  # NTLM NEGOTIATE -> send CHALLENGE
                log_event({
                    "eventid": "smb.login.attempt",
                    "src_ip": src_ip,
                    "session": sid,
                    "message": "NTLM negotiation started",
                })
                challenge = build_ntlm_challenge()
                spnego_resp = wrap_spnego_challenge(challenge)
                sec_offset = 72
                hdr = smb2_header(1, status=0xC0000016, session_id=session_id, message_id=msg_id)
                body = bytearray(8 + len(spnego_resp))
                body[0:2] = struct.pack("<H", 9)  # struct size
                body[2:4] = struct.pack("<H", 0)   # session flags
                body[4:6] = struct.pack("<H", sec_offset)
                body[6:8] = struct.pack("<H", len(spnego_resp))
                body[8:8+len(spnego_resp)] = spnego_resp
                return bytes(hdr) + bytes(body), False, None

            elif msg_type == 3:  # NTLM AUTH -> extract creds, reject
                username, domain = extract_ntlm_auth(data)
                log_event({
                    "eventid": "smb.login.attempt",
                    "src_ip": src_ip,
                    "session": sid,
                    "username": username or "",
                    "domain": domain or "",
                    "message": f"SMB login: {domain}\\{username}" if domain else f"SMB login: {username or 'unknown'}",
                })
                # Accept the login (let them try to access shares)
                hdr = smb2_header(1, status=0, session_id=session_id, message_id=msg_id)
                body = bytearray(8)
                body[0:2] = struct.pack("<H", 9)
                body[2:4] = struct.pack("<H", 0)  # session flags
                body[4:6] = struct.pack("<H", 0)  # no security buffer
                body[6:8] = struct.pack("<H", 0)
                return bytes(hdr) + bytes(body), True, username

        # Fallback - reject
        hdr = smb2_header(1, status=0xC000006D, session_id=session_id, message_id=msg_id)
        body = struct.pack("<H", 9) + b"\x00" * 6
        return bytes(hdr) + bytes(body), False, None

    def _smb2_tree_connect(self, data, src_ip, sid, session_id, msg_id, authed):
        """Handle tree connect - log share access attempts."""
        share_name = ""
        try:
            # Tree connect request: struct size (9), reserved, path offset, path length
            body_start = 64
            if len(data) > body_start + 8:
                path_offset = struct.unpack("<H", data[body_start+4:body_start+6])[0]
                path_len = struct.unpack("<H", data[body_start+6:body_start+8])[0]
                if path_offset and path_len and path_offset + path_len <= len(data):
                    share_name = data[path_offset:path_offset+path_len].decode("utf-16-le", errors="replace").rstrip("\x00")
        except Exception:
            pass

        # Extract just the share part from \\server\SHARE
        short_share = share_name.split("\\")[-1] if share_name else "unknown"

        log_event({
            "eventid": "smb.share.access",
            "src_ip": src_ip,
            "session": sid,
            "share": short_share,
            "full_path": share_name,
            "message": f"Accessing share: {short_share}",
        })

        if short_share.upper() == "IPC$":
            # Allow IPC$ for share enumeration
            tree_id = 0x01
        elif short_share.upper() in ("DOCUMENTS", "BACKUP"):
            tree_id = 0x02
            log_event({
                "eventid": "smb.share.enum",
                "src_ip": src_ip,
                "session": sid,
                "share": short_share,
                "message": f"Enumerated share: {short_share}",
            })
        else:
            # Unknown share - reject
            hdr = smb2_header(3, status=0xC0000022, session_id=session_id, message_id=msg_id)
            body = bytearray(16)
            body[0:2] = struct.pack("<H", 16)
            return bytes(hdr) + bytes(body), False, None

        hdr = smb2_header(3, status=0, session_id=session_id, message_id=msg_id)
        # Set tree ID in header
        hdr_mut = bytearray(hdr)
        hdr_mut[36:40] = struct.pack("<I", tree_id)
        body = bytearray(16)
        body[0:2] = struct.pack("<H", 16)  # struct size
        body[2] = 0x01  # share type: disk
        body[4:8] = struct.pack("<I", 0x30)  # share flags
        body[8:12] = struct.pack("<I", 0x001F01FF)  # max access rights
        return bytes(hdr_mut) + bytes(body), False, None


# ── Main ─────────────────────────────────────────────────────────────────────

def main():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    hp = SMBHoneypot()

    def shutdown(sig, frame):
        hp.stop()
        sys.exit(0)

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    try:
        hp.start()
    except KeyboardInterrupt:
        hp.stop()

if __name__ == "__main__":
    main()
