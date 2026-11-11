"""Deterministic offline unit and HTTP integration tests for zoth-osint."""
import json
import sys
import threading
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from engine.mitre_attack import map_mitre_attack  # noqa: E402
from engine.osint_core import (  # noqa: E402
    _mmh3_hash32,
    analyze_bytes_forensics,
    classify_target,
    normalize_domain,
    synthesize_dorks,
)
from engine.takeover import TAKEOVER_SIGNATURES  # noqa: E402
from mcp_server import MCP_TOOLS, handle_rpc  # noqa: E402
from server import ZothOsintHandler  # noqa: E402


def test_target_classifier_six_domains():
    assert classify_target("1.1.1.1") == "ip"
    assert classify_target("sec@nullai.tech") == "email"
    assert classify_target("0x742d35Cc6634C0532925a3b844Bc454e4438f44e") == "wallet"
    assert classify_target("TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA") == "wallet"
    assert classify_target("bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq") == "wallet"
    assert classify_target("+1-757-555-0199") == "phone"
    assert classify_target("https://zoth.nullai.tech/arsenal") == "domain"
    assert classify_target("@1nc0gn30") == "username"
    assert classify_target("1nc0gn30") == "username"
    assert normalize_domain("https://Zoth.NullAI.tech:443/docs") == "zoth.nullai.tech"


def test_mmh3_hash32_ground_truth():
    assert _mmh3_hash32(b"", 0) == 0
    assert _mmh3_hash32(b"hello", 0) == 613153351
    assert isinstance(_mmh3_hash32(b"\x00\x01\x02\x03\x04", 0), int)


def test_dork_synthesizer_and_forensics():
    dorks = synthesize_dorks("nullai.tech", "domain")
    assert len(dorks) >= 9
    assert all("query" in d and "url" in d for d in dorks)

    sample = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR"
    forensics = analyze_bytes_forensics(sample, "sample.png")
    assert forensics["size_bytes"] == len(sample)
    assert len(forensics["hashes"]["sha256"]) == 64


def test_mitre_attack_and_takeover_catalog():
    assert len(TAKEOVER_SIGNATURES) >= 20
    scan_stub = {
        "target": "example.com",
        "type": "domain",
        "ports": [22, 80, 3389],
        "findings": ["Exposed .env configuration file", "Missing DMARC record"],
    }
    report = map_mitre_attack(scan_stub["findings"], scan_stub)
    assert "techniques" in report or "matched_techniques" in report or isinstance(report, dict)
    serialized = json.dumps(report)
    assert "T1" in serialized


def test_mcp_rpc_initialize_and_tools():
    init = handle_rpc({"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}})
    assert init["result"]["serverInfo"]["name"] == "zoth-osint-mcp"
    listed = handle_rpc({"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}})
    names = {t["name"] for t in listed["result"]["tools"]}
    assert {"osint_scan", "osint_favicon_mmh3", "osint_mitre", "osint_breach"} <= names
    assert len(MCP_TOOLS) >= 8


def test_http_server_health_and_loopback_cors():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), ZothOsintHandler)
    port = httpd.server_port
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        req = urllib.request.Request(
            f"http://127.0.0.1:{port}/health",
            headers={"Origin": f"http://127.0.0.1:{port}"},
        )
        with urllib.request.urlopen(req, timeout=5) as resp:
            assert resp.status == 200
            assert resp.headers.get("Access-Control-Allow-Origin") == f"http://127.0.0.1:{port}"
            data = json.loads(resp.read().decode("utf-8"))
            assert data["status"] == "ok"
            assert data["service"] == "zoth-osint"
            assert data["arsenal_total"] >= 30

        bad_req = urllib.request.Request(
            f"http://127.0.0.1:{port}/health",
            headers={"Origin": "https://evil.example"},
        )
        try:
            urllib.request.urlopen(bad_req, timeout=5)
            assert False, "Expected 403 on cross-origin browser request"
        except urllib.error.HTTPError as e:
            assert e.code == 403
    finally:
        httpd.shutdown()
        httpd.server_close()
