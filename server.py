#!/usr/bin/env python3
"""
Zoth OSINT Workstation Daemon v2.0 (server.py)
Serves the Zoth OSINT Web Workstation on http://127.0.0.1:8148 and exposes:
  GET  /health
  GET  /api/scan?target=<target>
  POST /api/scan
  GET  /api/arsenal?target=<target>
  POST /api/arsenal/run
  POST /api/forensics
  GET  /api/wayback?domain=<domain>
  GET  /api/dorks?target=<target>
  GET  /api/cases
  GET  /api/cases/<id>
"""

import argparse
import base64
import json
import mimetypes
import os
import sys
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
PUBLIC_DIR = os.path.join(ROOT_DIR, "public")
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from engine.arsenal_runner import execute_arsenal_tool, get_arsenal_status  # noqa: E402
from engine.case_store import correlate_cases, get_case, list_cases  # noqa: E402
from engine.osint_core import (  # noqa: E402
    analyze_bytes_forensics,
    classify_target,
    recon_asn_bgp,
    recon_favicon_mmh3,
    recon_http_stack,
    recon_new_age_identity,
    recon_rdap,
    recon_wayback,
    run_unified_scan,
    synthesize_dorks,
)


class ZothOsintHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt: str, *args) -> None:
        pass

    def _send_json(self, payload: dict, status: int = 200) -> None:
        raw = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(raw)

    def do_OPTIONS(self) -> None:
        self._send_json({"ok": True})

    def do_GET(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        qs = urllib.parse.parse_qs(parsed.query)

        if path == "/health":
            arsenal = get_arsenal_status("nullai.tech")
            self._send_json(
                {
                    "status": "ok",
                    "service": "zoth-osint",
                    "version": "2.0.0",
                    "port": self.server.server_port,
                    "arsenal_total": arsenal["total_tools"],
                    "arsenal_installed": arsenal["installed_or_builtin"],
                    "saved_cases": len(list_cases(limit=50)),
                }
            )
            return

        if path == "/api/scan":
            target = (qs.get("target") or ["1nc0gn30"])[0]
            self._send_json(run_unified_scan(target))
            return

        if path == "/api/arsenal":
            target = (qs.get("target") or ["nullai.tech"])[0]
            self._send_json(get_arsenal_status(target))
            return

        if path == "/api/wayback":
            domain = (qs.get("domain") or ["nullai.tech"])[0]
            self._send_json(recon_wayback(domain))
            return

        if path == "/api/favicon":
            domain = (qs.get("domain") or ["nullai.tech"])[0]
            self._send_json(recon_favicon_mmh3(domain))
            return

        if path == "/api/web3":
            target = (qs.get("target") or ["1nc0gn30"])[0]
            self._send_json(recon_new_age_identity(target))
            return

        if path == "/api/rdap":
            target = (qs.get("target") or ["nullai.tech"])[0]
            self._send_json(recon_rdap(target))
            return

        if path == "/api/tech":
            domain = (qs.get("domain") or ["nullai.tech"])[0]
            self._send_json(recon_http_stack(domain))
            return

        if path == "/api/asn":
            asn = (qs.get("asn") or ["13335"])[0]
            self._send_json(recon_asn_bgp(asn))
            return

        if path == "/api/correlate":
            raw_ids = (qs.get("ids") or [""])[0]
            ids = [int(x) for x in raw_ids.split(",") if x.strip().isdigit()]
            self._send_json(correlate_cases(ids))
            return

        if path == "/api/dorks":
            target = (qs.get("target") or ["nullai.tech"])[0]
            t_type = classify_target(target)
            self._send_json({"target": target, "type": t_type, "dorks": synthesize_dorks(target, t_type)})
            return

        if path == "/api/cases":
            self._send_json({"cases": list_cases(limit=25)})
            return

        if path.startswith("/api/cases/"):
            try:
                cid = int(path.split("/api/cases/")[1].strip("/"))
                case_data = get_case(cid)
                if case_data:
                    self._send_json(case_data)
                else:
                    self._send_json({"error": "Case not found"}, status=404)
            except Exception as e:
                self._send_json({"error": str(e)}, status=400)
            return

        # Serve static files from public/
        rel_path = path.lstrip("/") or "index.html"
        full_path = os.path.normpath(os.path.join(PUBLIC_DIR, rel_path))
        if not full_path.startswith(PUBLIC_DIR) or not os.path.isfile(full_path):
            full_path = os.path.join(PUBLIC_DIR, "index.html")

        try:
            with open(full_path, "rb") as f:
                data = f.read()
            ctype, _ = mimetypes.guess_type(full_path)
            self.send_response(200)
            self.send_header("Content-Type", ctype or "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(data)
        except Exception as e:
            self._send_json({"error": str(e)}, status=500)

    def do_POST(self) -> None:
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8", errors="replace"))
        except Exception:
            payload = {}

        if path == "/api/scan":
            target = str(payload.get("target") or "1nc0gn30")
            self._send_json(run_unified_scan(target))
            return

        if path == "/api/arsenal/run":
            tool_id = str(payload.get("tool_id") or "sherlock")
            target = str(payload.get("target") or "1nc0gn30")
            self._send_json(execute_arsenal_tool(tool_id, target))
            return

        if path == "/api/forensics":
            filename = str(payload.get("filename") or "upload.bin")
            b64 = str(payload.get("data_base64") or "")
            try:
                raw_bytes = base64.b64decode(b64)
            except Exception:
                raw_bytes = b""
            self._send_json(analyze_bytes_forensics(raw_bytes, filename=filename))
            return

        self._send_json({"error": "Not found"}, status=404)


def main() -> None:
    parser = argparse.ArgumentParser(description="Zoth OSINT Workstation Daemon v2.0")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8148, help="Bind port (default: 8148)")
    args = parser.parse_args()

    srv = ThreadingHTTPServer((args.host, args.port), ZothOsintHandler)
    print(f"[zoth-osint v2.0] Sovereign OSINT Workstation listening on http://{args.host}:{args.port}")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
