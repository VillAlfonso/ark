#!/usr/bin/env python3
"""ark web UI -- a local control room for salvaging codebases.

    python web.py            # http://127.0.0.1:8777
    python web.py --port N

Zero dependencies (stdlib http.server). One background job at a time
(scan / build / verify), live log via polling. Everything the CLI does,
with eyes.
"""
import argparse, json, sys, threading, webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import ark

HERE = Path(__file__).parent
LAST = {"scan": None, "plan": None, "build": None, "verify": None, "status": None}


def _scan_public(d):
    """scan dict minus the huge save_list (UI gets a top slice)."""
    if not d:
        return None
    pub = {k: v for k, v in d.items() if k != "save_list"}
    pub["save_top"] = sorted(d["save_list"], key=lambda e: -e["s"])[:200]
    return pub


class H(BaseHTTPRequestHandler):
    def log_message(self, *a):                        # quiet server log
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        if self.path in ("/", "/index.html"):
            body = (HERE / "web.html").read_bytes()
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        elif self.path.startswith("/api/state"):
            job = ark._CURRENT["job"]
            self._json({"job": job.snapshot(tail=200) if job else None,
                        "scan": _scan_public(LAST["scan"]),
                        "build": LAST["build"], "verify": LAST["verify"],
                        "status": LAST["status"]})
        else:
            self._json({"err": "not found"}, 404)

    def do_POST(self):
        try:
            req = self._body()
            path = req.get("path", "").strip()
            if self.path == "/api/scan":
                def work(log):
                    LAST["scan"] = ark.scan(path, log=log)
                    return {"save": LAST["scan"]["save"]}
                job = ark.run_job("scan", work)
            elif self.path == "/api/build":
                out = (req.get("out") or "").strip() or str(
                    Path(path).resolve().parent / (Path(path).resolve().name + "-ark"))
                hash_source = bool(req.get("hash_source"))
                def work(log):
                    p = ark.plan(path, LAST["scan"] if LAST["scan"]
                                 and LAST["scan"]["root"] == str(Path(path).resolve()) else None,
                                 exclude=req.get("exclude") or (), log=log)
                    LAST["build"] = ark.build(path, out, p, hash_source=hash_source, log=log)
                    return LAST["build"]
                job = ark.run_job("build", work)
            elif self.path == "/api/verify":
                def work(log):
                    LAST["verify"] = ark.verify(req.get("ark", "").strip(), log=log)
                    return LAST["verify"]
                job = ark.run_job("verify", work)
            elif self.path == "/api/status":
                def work(log):
                    LAST["status"] = ark.status(path, req.get("ark") or None, log=log)
                    return LAST["status"]
                job = ark.run_job("status", work)
            else:
                return self._json({"err": "not found"}, 404)
            self._json({"job": job.id})
        except RuntimeError as ex:                     # job already running
            self._json({"err": str(ex)}, 409)
        except Exception as ex:                        # noqa: BLE001
            self._json({"err": str(ex)}, 500)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8777)
    ap.add_argument("--no-open", action="store_true")
    a = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", a.port), H)
    url = f"http://127.0.0.1:{a.port}"
    print(f"ark web ui -> {url}")
    if not a.no_open:
        threading.Timer(0.4, lambda: webbrowser.open(url)).start()
    srv.serve_forever()


if __name__ == "__main__":
    main()
