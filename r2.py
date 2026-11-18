#!/usr/bin/env python3
"""One-time setup receiver for the Spike desk droplet (stdlib only).
HTTPS on :443, self-signed cert. Every call except /hello needs header X-T=<token>.
GET /hello?n=<nonce> -> HMAC(token, nonce+cert_sha256) so the caller can pin the real cert.
PUT /put?p=<path>&m=<octal mode> writes a file. POST /exec?t=<secs> runs the body with bash.
POST /done stops it. Stops by itself after 2 hours or 20 bad tokens."""
import hashlib, hmac, json, os, ssl, subprocess, sys, threading, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
TOK = sys.argv[1].encode(); D = "/root/.r"; os.makedirs(D, mode=0o700, exist_ok=True)
subprocess.run(["openssl", "req", "-x509", "-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256",
    "-nodes", "-days", "2", "-subj", "/CN=spike-setup", "-keyout", D + "/k.pem", "-out", D + "/c.pem"],
    check=True, capture_output=True)
FP = hashlib.sha256(ssl.PEM_cert_to_DER_cert(open(D + "/c.pem").read())).hexdigest()
bad = [0]
def bye(): os._exit(0)
threading.Timer(7200, bye).start()
class H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def out(self, code, obj):
        b = json.dumps(obj).encode(); self.send_response(code)
        self.send_header("Content-Type", "application/json"); self.send_header("Content-Length", str(len(b)))
        self.end_headers(); self.wfile.write(b)
    def ok(self):
        if hmac.compare_digest(self.headers.get("X-T", "").encode(), TOK): return True
        bad[0] += 1; self.out(403, {"err": "no"})
        if bad[0] >= 20: threading.Timer(1, bye).start()
        return False
    def q(self):
        u = urllib.parse.urlparse(self.path); return u.path, dict(urllib.parse.parse_qsl(u.query))
    def body(self): return self.rfile.read(int(self.headers.get("Content-Length", 0)))
    def do_GET(self):
        p, a = self.q()
        if p == "/hello":
            n = a.get("n", "")[:100]
            return self.out(200, {"mac": hmac.new(TOK, (n + FP).encode(), hashlib.sha256).hexdigest()})
        self.out(404, {})
    def do_PUT(self):
        p, a = self.q()
        if not self.ok(): return
        if p != "/put": return self.out(404, {})
        f = a["p"]; os.makedirs(os.path.dirname(f) or "/", exist_ok=True); data = self.body()
        fd = os.open(f, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, int(a.get("m", "600"), 8))
        with os.fdopen(fd, "wb") as w: w.write(data)
        os.chmod(f, int(a.get("m", "600"), 8)); self.out(200, {"bytes": len(data)})
    def do_POST(self):
        p, a = self.q()
        if not self.ok(): return
        if p == "/done":
            self.out(200, {"bye": 1}); threading.Timer(1, bye).start(); return
        if p != "/exec": return self.out(404, {})
        cmd = self.body().decode()
        try:
            r = subprocess.run(["bash", "-c", cmd], stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               stdin=subprocess.DEVNULL, timeout=min(int(a.get("t", "120")), 900), cwd="/root")
            self.out(200, {"rc": r.returncode, "out": r.stdout.decode(errors="replace")[-60000:]})
        except subprocess.TimeoutExpired as e:
            self.out(200, {"rc": -9, "out": "timeout " + (e.stdout or b"").decode(errors="replace")[-20000:]})
C = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); C.load_cert_chain(D + "/c.pem", D + "/k.pem")
class S(ThreadingHTTPServer):
    daemon_threads = True
    def finish_request(self, req, addr):  # TLS handshake per connection, in its own thread, with a timeout
        req.settimeout(20); req = C.wrap_socket(req, server_side=True); req.settimeout(300)
        H(req, addr, self)
    def handle_error(self, *a): pass
s = S(("0.0.0.0", int(os.environ.get("RX_PORT", "443"))), H)
print("up", FP, flush=True); s.serve_forever()
