"""Minimal SIP caller: rings a SIP address (e.g. your Linphone app) and hangs up.

No external dependencies. Uses TLS (or TCP) to the SIP proxy, handles digest
auth, rings for a while, and ends the call (CANCEL if unanswered, BYE if answered).
"""
import hashlib
import os
import random
import socket
import ssl
import time
import uuid


def _h(algo, s):
    fn = hashlib.sha256 if algo.upper().startswith("SHA-256") else hashlib.md5
    return fn(s.encode()).hexdigest()


def _parse_challenge(value):
    scheme, _, rest = value.strip().partition(" ")
    params, key, buf, inq = {}, "", "", False
    for ch in rest + ",":
        if ch == '"':
            inq = not inq
        elif ch == "=" and not inq and not key:
            key, buf = buf.strip(), ""
        elif ch == "," and not inq:
            if key:
                params[key.lower()] = buf.strip()
            key, buf = "", ""
        else:
            buf += ch
    return scheme, params


class SipCall:
    def __init__(self, user, password, domain="sip.linphone.org",
                 proxy=None, port=None, transport="tls"):
        self.user, self.password, self.domain = user, password, domain
        self.transport = transport.lower()
        self.proxy = proxy or domain
        self.port = port or (5061 if self.transport == "tls" else 5060)
        self.call_id = uuid.uuid4().hex
        self.from_tag = uuid.uuid4().hex[:10]
        self.cseq = random.randint(1, 1000)
        self.buf = b""

    # ---- transport ----
    def _connect(self):
        raw = socket.create_connection((self.proxy, self.port), timeout=10)
        if self.transport == "tls":
            ctx = ssl.create_default_context()
            raw = ctx.wrap_socket(raw, server_hostname=self.proxy)
        self.sock = raw
        self.local_ip, self.local_port = raw.getsockname()[:2]

    def _send(self, msg):
        self.sock.sendall(msg.encode())

    def _recv(self, timeout):
        self.sock.settimeout(timeout)
        while b"\r\n\r\n" not in self.buf:
            chunk = self.sock.recv(65535)
            if not chunk:
                raise ConnectionError("SIP server closed the connection")
            self.buf += chunk
        head, _, rest = self.buf.partition(b"\r\n\r\n")
        lines = head.decode(errors="replace").split("\r\n")
        headers = []
        for ln in lines[1:]:
            k, _, v = ln.partition(":")
            headers.append((k.strip().lower(), v.strip()))
        clen = int(next((v for k, v in headers if k in ("content-length", "l")), "0"))
        while len(rest) < clen:
            rest += self.sock.recv(65535)
        self.buf = rest[clen:]
        return lines[0], headers

    @staticmethod
    def _get(headers, name, all_=False):
        vals = [v for k, v in headers if k == name]
        return vals if all_ else (vals[0] if vals else None)

    # ---- message building ----
    def _via(self, branch):
        t = "TLS" if self.transport == "tls" else "TCP"
        return f"SIP/2.0/{t} {self.local_ip}:{self.local_port};branch={branch};rport;alias"

    def _contact(self):
        t = "tls" if self.transport == "tls" else "tcp"
        return f"<sip:{self.user}@{self.local_ip}:{self.local_port};transport={t}>"

    def _request(self, method, uri, branch, cseq, to, extra=(), body=""):
        from_ = f'"{self.display}" <sip:{self.user}@{self.domain}>;tag={self.from_tag}'
        hdr = [
            f"{method} {uri} SIP/2.0",
            f"Via: {self._via(branch)}",
            "Max-Forwards: 70",
            f"From: {from_}",
            f"To: {to}",
            f"Call-ID: {self.call_id}",
            f"CSeq: {cseq} {method}",
            *extra,
            "User-Agent: claude-caller/1.0",
            f"Content-Length: {len(body.encode())}",
        ]
        return "\r\n".join(hdr) + "\r\n\r\n" + body

    def _auth_header(self, headers, method, uri):
        for name, out in (("proxy-authenticate", "Proxy-Authorization"),
                          ("www-authenticate", "Authorization")):
            chals = [_parse_challenge(v)[1] for v in self._get(headers, name, True)]
            if not chals:
                continue
            # prefer MD5 (widest support), else first offered
            c = next((c for c in chals if c.get("algorithm", "MD5").upper() == "MD5"), chals[0])
            algo = c.get("algorithm", "MD5")
            realm, nonce = c.get("realm", ""), c.get("nonce", "")
            ha1 = _h(algo, f"{self.user}:{realm}:{self.password}")
            ha2 = _h(algo, f"{method}:{uri}")
            parts = [f'username="{self.user}"', f'realm="{realm}"', f'nonce="{nonce}"',
                     f'uri="{uri}"', f"algorithm={algo}"]
            if "auth" in c.get("qop", "").split(","):
                cnonce, nc = uuid.uuid4().hex[:16], "00000001"
                resp = _h(algo, f"{ha1}:{nonce}:{nc}:{cnonce}:auth:{ha2}")
                parts += [f"qop=auth", f"nc={nc}", f'cnonce="{cnonce}"']
            else:
                resp = _h(algo, f"{ha1}:{nonce}:{ha2}")
            parts.append(f'response="{resp}"')
            if "opaque" in c:
                parts.append(f'opaque="{c["opaque"]}"')
            return f"{out}: Digest " + ", ".join(parts)
        return None

    # ---- the call ----
    def ring(self, target, display="Claude", ring_seconds=30, talk_seconds=3):
        """Ring `target` (sip:user@domain or just a username). Returns a status string."""
        self.display = display.replace('"', "'")[:60]
        if not target.startswith("sip:"):
            target = f"sip:{target}" if "@" in target else f"sip:{target}@{self.domain}"
        self._connect()
        to = f"<{target}>"
        sdp = (f"v=0\r\no=- 1 1 IN IP4 {self.local_ip}\r\ns=-\r\nc=IN IP4 {self.local_ip}\r\n"
               f"t=0 0\r\nm=audio 40000 RTP/AVP 0 8 101\r\na=rtpmap:0 PCMU/8000\r\n"
               f"a=rtpmap:8 PCMA/8000\r\na=rtpmap:101 telephone-event/8000\r\na=sendrecv\r\n")
        base = [f"Contact: {self._contact()}", "Content-Type: application/sdp",
                "Allow: INVITE, ACK, CANCEL, BYE, OPTIONS"]
        if self.display != "Claude":
            base.append(f"Subject: {self.display}")
        auth = None
        try:
            for _attempt in range(3):
                self.cseq += 1
                branch = "z9hG4bK" + uuid.uuid4().hex
                extra = base + ([auth] if auth else [])
                self._send(self._request("INVITE", target, branch, self.cseq, to, extra, sdp))
                deadline = time.time() + ring_seconds
                ringing = False
                while True:
                    left = deadline - time.time()
                    if left <= 0:
                        return self._cancel(target, branch, to, ringing)
                    try:
                        status, hdrs = self._recv(left)
                    except socket.timeout:
                        return self._cancel(target, branch, to, ringing)
                    if status.startswith("SIP/2.0"):
                        if self._get(hdrs, "cseq", False) and "INVITE" not in self._get(hdrs, "cseq"):
                            continue
                        code = int(status.split()[1])
                    else:  # a request from the server (e.g. OPTIONS keepalive); ignore
                        continue
                    if code < 200:
                        ringing = ringing or code in (180, 183)
                        continue
                    to_resp = self._get(hdrs, "to")
                    if code in (401, 407):
                        self._ack_error(target, branch, to_resp)
                        auth = self._auth_header(hdrs, "INVITE", target)
                        if not auth or _attempt:
                            return f"auth failed ({code}) - check username/password"
                        break  # retry with credentials
                    if 200 <= code < 300:
                        return self._answered(hdrs, to_resp, talk_seconds)
                    self._ack_error(target, branch, to_resp)
                    reason = status.split(" ", 2)[2] if status.count(" ") >= 2 else ""
                    if code in (486, 600, 603):
                        return f"declined/busy ({code} {reason})"
                    if code == 480:
                        return "unavailable (480) - is Linphone open and logged in on your phone?"
                    return f"failed ({code} {reason})"
            return "failed"
        finally:
            try:
                self.sock.close()
            except Exception:
                pass

    def _ack_error(self, target, branch, to_resp):
        self._send(self._request("ACK", target, branch, self.cseq, to_resp))

    def _cancel(self, target, branch, to, ringing):
        self._send(self._request("CANCEL", target, branch, self.cseq, to))
        end = time.time() + 5
        try:
            while time.time() < end:
                status, hdrs = self._recv(end - time.time())
                if status.startswith("SIP/2.0") and "INVITE" in (self._get(hdrs, "cseq") or ""):
                    if int(status.split()[1]) >= 300:
                        self._ack_error(target, branch, self._get(hdrs, "to"))
                        break
        except Exception:
            pass
        return "rang, no answer (cancelled)" if ringing else "no ringing reported (cancelled)"

    def _answered(self, hdrs, to_resp, talk_seconds):
        contact = self._get(hdrs, "contact") or ""
        uri = contact[contact.find("<") + 1:contact.find(">")] if "<" in contact else contact.split(";")[0]
        rr = []
        for v in self._get(hdrs, "record-route", True):
            rr += [x.strip() for x in v.split(",")]
        routes = [f"Route: {r}" for r in reversed(rr)]
        n = self.cseq
        self._send(self._request("ACK", uri, "z9hG4bK" + uuid.uuid4().hex, n, to_resp, routes))
        time.sleep(talk_seconds)
        self.cseq += 1
        self._send(self._request("BYE", uri, "z9hG4bK" + uuid.uuid4().hex, self.cseq, to_resp, routes))
        try:
            self._recv(3)
        except Exception:
            pass
        return "answered"


def call_from_env(message="Claude", ring_seconds=30):
    c = SipCall(
        user=os.environ["SIP_USER"],
        password=os.environ["SIP_PASSWORD"],
        domain=os.environ.get("SIP_DOMAIN", "sip.linphone.org"),
        transport=os.environ.get("SIP_TRANSPORT", "tls"),
    )
    return c.ring(os.environ["SIP_TARGET"], display=message, ring_seconds=ring_seconds)


if __name__ == "__main__":
    import sys
    print(call_from_env(" ".join(sys.argv[1:]) or "Claude"))
