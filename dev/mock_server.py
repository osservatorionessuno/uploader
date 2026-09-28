#!/usr/bin/env python3
"""Local stand-in for the Lua backend: same endpoints, same semantics, stdlib only.

  POST   /up             -> 201 {"id": <32 hex>}          (Upload-Length checked against MAX)
  HEAD   /up/<id>        -> 200, Upload-Offset: <bytes received so far>
  PATCH  /up/<id>        -> 204, Upload-Offset: <new size>; 409 on offset mismatch
  POST   /up/<id>/done   -> 200 {"id","size"}; 400 unless the file starts with the age magic
  DELETE /up/<id>        -> 204
  POST   /up/form        -> no-JS path: multipart with the pre-encrypted file, HTML result page
Everything else is served from dist/ (run `npm run build` first). Telegram is printed to stdout.

  python3 dev/mock_server.py [port]
  FLAKY=0.3 drops 30% of PATCHes mid-request; STALL=0.2 hangs 20% silently; RATE=300000 caps read speed (B/s)
  MAX=5368709120 total size cap in bytes (default 5 GiB)
"""
import json, os, random, re, secrets, sys, threading, time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
WEB = os.path.join(HERE, "..", "dist")
DATA = os.path.join(HERE, "data")
TMP, DONE = os.path.join(DATA, "tmp"), os.path.join(DATA, "done")
MAX = int(os.environ.get("MAX", 5 * 1024 ** 3))   # total size cap in bytes; keep equal to config.json maxGiB
FLAKY = float(os.environ.get("FLAKY", "0"))    # fraction of PATCHes dropped mid-request (connection reset)
STALL = float(os.environ.get("STALL", "0"))    # fraction of PATCHes that hang silently after half the body
RATE = int(os.environ.get("RATE", "0"))        # bytes/s read cap per PATCH (0 = unlimited), e.g. 300000 ~ a Tor circuit
ID = re.compile(r"^/up/([a-f0-9]{32})(/done)?$")
AGE_MAGIC = (b"age-encryption.org/v1", b"-----BEGIN AGE ENCRYPTED FILE-----")
os.makedirs(TMP, exist_ok=True); os.makedirs(DONE, exist_ok=True)
# Offset check + append (and size check + rename) must be atomic per upload: after a stall
# abort the old request body may still be arriving while the client resumes. One global lock
# is enough for the mock; the Lua port needs resty.lock keyed by id around the same sections.
LOCK = threading.Lock()


class H(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=WEB, **kw)

    def end_headers(self):
        self.send_header("Cache-Control", "no-store")  # dev only: rebuilds show up on refresh
        # Same CSP the nginx vhost will send, so inline-script/style slips fail here first.
        self.send_header("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; "
                         "img-src 'self'; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'")
        super().end_headers()

    def reply(self, code, body=None, **headers):
        self.send_response(code)
        for k, v in headers.items():
            self.send_header(k.replace("_", "-"), str(v))
        data = json.dumps(body).encode() if body is not None else b""
        self.send_header("Content-Length", len(data))
        self.end_headers()
        self.wfile.write(data)

    def part(self):
        m = ID.match(self.path)
        if not m:
            return None, None
        return os.path.join(TMP, m.group(1)), m.group(1)

    def do_POST(self):
        if self.path == "/up/form":  # no-JS path: one multipart POST, file is the last part
            return self.form()
        if self.path == "/up":
            length = int(self.headers.get("Upload-Length", 0))  # mandatory: /done checks the size against it
            if length <= 0:
                return self.reply(400, {"error": "Upload-Length required"})
            if length > MAX:
                return self.reply(413)
            uid = secrets.token_hex(16)
            open(os.path.join(TMP, uid), "wb").close()
            with open(os.path.join(TMP, uid + ".len"), "w") as f:
                f.write(str(length))
            return self.reply(201, {"id": uid})
        path, uid = self.part()
        if not (path and self.path.endswith("/done") and os.path.exists(path)):
            return self.reply(404)
        with LOCK:
            if not os.path.exists(path + ".len"):
                return self.reply(404)
            size = os.path.getsize(path)
            if size != int(open(path + ".len").read()):
                return self.reply(409, {"error": "incomplete"}, Upload_Offset=size)
            with open(path, "rb") as f:
                if not f.read(40).startswith(AGE_MAGIC):
                    self.remove(path)
                    return self.reply(400, {"error": "not an age file"})
            os.rename(path, os.path.join(DONE, uid + ".age"))
            os.remove(path + ".len")
        print(f"TELEGRAM: nuovo upload {uid} ({size} bytes)", flush=True)
        self.reply(200, {"id": uid, "size": size})

    def form(self):
        import email.parser
        raw = self.rfile.read(int(self.headers["Content-Length"]))
        msg = email.parser.BytesParser().parsebytes(b"Content-Type: " + self.headers["Content-Type"].encode() + b"\r\n\r\n" + raw)
        data = next((p.get_payload(decode=True) for p in msg.walk() if p.get_filename()), None)
        page = open(os.path.join(WEB, "result.html"), "rb").read()
        if data is None or not data.startswith(AGE_MAGIC):
            body = page.replace(b"__CLASS__", b"err").replace(b"__ID__", b"")
            return self.reply_html(400, body)
        if len(data) > MAX:
            return self.reply_html(413, page.replace(b"__CLASS__", b"big").replace(b"__ID__", b""))
        uid = secrets.token_hex(16)
        with open(os.path.join(DONE, uid + ".age"), "wb") as f:
            f.write(data)
        print(f"TELEGRAM: nuovo upload {uid} ({len(data)} bytes)", flush=True)
        self.reply_html(200, page.replace(b"__CLASS__", b"ok").replace(b"__ID__", uid.encode()))

    def reply_html(self, code, body):
        self.send_response(code)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", len(body))
        self.end_headers()
        self.wfile.write(body)

    @staticmethod
    def remove(path):
        for p in (path, path + ".len"):
            if os.path.exists(p):
                os.remove(p)

    def do_HEAD(self):
        path, _ = self.part()
        if path is None:
            return super().do_HEAD()
        if not os.path.exists(path):
            return self.reply(404)
        self.reply(200, Upload_Offset=os.path.getsize(path))

    def do_PATCH(self):
        path, _ = self.part()
        if not (path and os.path.exists(path)):
            return self.reply(404)
        offset = int(self.headers.get("Upload-Offset", -1))
        n = int(self.headers["Content-Length"])
        if offset != os.path.getsize(path):
            return self.reply(409, Upload_Offset=os.path.getsize(path))
        if offset + n > MAX:
            return self.reply(413)
        r = random.random()
        if r < FLAKY + STALL:  # take half the body, then die (reset) or hang (stall)
            body = self.read(n // 2)
            if r >= FLAKY:
                time.sleep(3600)
            with LOCK:
                if os.path.exists(path) and os.path.getsize(path) == offset:
                    with open(path, "ab") as f:
                        f.write(body)
            self.close_connection = True
            return
        body = self.read(n)  # whole body first (nginx does the same), then check+append atomically
        with LOCK:
            if not os.path.exists(path):  # DELETEd meanwhile: do not resurrect it as an orphan
                return self.reply(404)
            size = os.path.getsize(path)
            if size != offset:
                return self.reply(409, Upload_Offset=size)
            with open(path, "ab") as f:
                f.write(body)
        self.reply(204, Upload_Offset=offset + n)

    def read(self, n):
        if not RATE:
            return self.rfile.read(n)
        out, step = b"", RATE // 10
        while len(out) < n:
            out += self.rfile.read(min(step, n - len(out)))
            time.sleep(0.1)
        return out

    def do_DELETE(self):
        path, _ = self.part()
        if path:
            with LOCK:
                self.remove(path)
        self.reply(204)

    def send_error(self, code, *a, **kw):
        if code == 404 and self.command == "GET":  # nginx: error_page 404 /index.html
            body = open(os.path.join(WEB, "index.html"), "rb").read()
            self.send_response(404); self.send_header("Content-Type", "text/html")
            self.send_header("Content-Length", len(body)); self.end_headers(); self.wfile.write(body)
            return
        super().send_error(code, *a, **kw)


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8089
    print(f"http://127.0.0.1:{port}  (data in {DATA}, FLAKY={FLAKY})")
    ThreadingHTTPServer(("127.0.0.1", port), H).serve_forever()
