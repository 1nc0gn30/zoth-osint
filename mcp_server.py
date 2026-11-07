#!/usr/bin/env python3
"""
Zoth OSINT Model Context Protocol (MCP) STDIO Server (mcp_server.py)
Exposes Zoth OSINT v3.0 capabilities as native JSON-RPC 2.0 MCP tools for AI agents:
  - osint_scan
  - osint_favicon_mmh3
  - osint_web3_identity
  - osint_rdap
  - osint_wallet
  - osint_wayback
"""

import json
import os
import sys
from typing import Any, Dict

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
if ROOT_DIR not in sys.path:
    sys.path.insert(0, ROOT_DIR)

from engine.osint_core import (  # noqa: E402
    recon_favicon_mmh3,
    recon_new_age_identity,
    recon_rdap,
    recon_wallet,
    recon_wayback,
    run_unified_scan,
)

MCP_TOOLS = [
    {
        "name": "osint_scan",
        "description": "Auto-classify a target (username, domain, IPv4, email, crypto wallet, or phone) and run a full Zoth OSINT multi-pivot scan with Entity Graph and STIX 2.1 bundle.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Target handle, domain, IP, email, wallet, or phone"}},
            "required": ["target"],
        },
    },
    {
        "name": "osint_favicon_mmh3",
        "description": "Download a domain's /favicon.ico and compute its 32-bit signed MurmurHash3 (mmh3), SHA-256, and Shodan/Censys/FOFA infrastructure pivot queries.",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Target domain (e.g. nullai.tech)"}},
            "required": ["domain"],
        },
    },
    {
        "name": "osint_web3_identity",
        "description": "Resolve decentralized identities across Bluesky ATProto (did:plc), Ethereum Name Service (.eth ENS), and HuggingFace AI Hub.",
        "inputSchema": {
            "type": "object",
            "properties": {"target": {"type": "string", "description": "Handle, domain, or .eth name"}},
            "required": ["target"],
        },
    },
    {
        "name": "osint_rdap",
        "description": "Query IETF RDAP structured registry data (registrar, registration/expiration dates, DNSSEC status) for a domain or IP.",
        "inputSchema": {
            "type": "object",
            "properties": {
                "target": {"type": "string", "description": "Domain or IPv4 address"},
                "is_ip": {"type": "boolean", "description": "True if target is an IP address"},
            },
            "required": ["target"],
        },
    },
    {
        "name": "osint_wallet",
        "description": "Zero-key blockchain RPC inspection for Solana Mainnet, Ethereum/EVM, and Bitcoin wallet addresses.",
        "inputSchema": {
            "type": "object",
            "properties": {"address": {"type": "string", "description": "Wallet address"}},
            "required": ["address"],
        },
    },
    {
        "name": "osint_wayback",
        "description": "Query the Internet Archive Wayback Machine CDX API for historical archived URLs and sensitive paths.",
        "inputSchema": {
            "type": "object",
            "properties": {"domain": {"type": "string", "description": "Target domain"}},
            "required": ["domain"],
        },
    },
]


def handle_rpc(req: Dict[str, Any]) -> Dict[str, Any]:
    method = req.get("method", "")
    req_id = req.get("id")
    params = req.get("params") or {}

    if method == "initialize":
        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {
                "protocolVersion": "2024-11-05",
                "serverInfo": {"name": "zoth-osint-mcp", "version": "3.0.0"},
                "capabilities": {"tools": {}},
            },
        }

    if method == "tools/list":
        return {"jsonrpc": "2.0", "id": req_id, "result": {"tools": MCP_TOOLS}}

    if method == "tools/call":
        name = params.get("name")
        args = params.get("arguments") or {}
        if name == "osint_scan":
            res = run_unified_scan(str(args.get("target", "1nc0gn30")))
        elif name == "osint_favicon_mmh3":
            res = recon_favicon_mmh3(str(args.get("domain", "nullai.tech")))
        elif name == "osint_web3_identity":
            res = recon_new_age_identity(str(args.get("target", "1nc0gn30")))
        elif name == "osint_rdap":
            res = recon_rdap(str(args.get("target", "nullai.tech")), bool(args.get("is_ip", False)))
        elif name == "osint_wallet":
            res = recon_wallet(str(args.get("address", "")))
        elif name == "osint_wayback":
            res = recon_wayback(str(args.get("domain", "nullai.tech")))
        else:
            return {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32601, "message": f"Unknown tool: {name}"}}

        return {
            "jsonrpc": "2.0",
            "id": req_id,
            "result": {"content": [{"type": "text", "text": json.dumps(res, indent=2)}]},
        }

    return {"jsonrpc": "2.0", "id": req_id, "result": {}}


def run_mcp_stdio() -> None:
    for line in sys.stdin:
        line = line.strip()
        if not line:
            continue
        try:
            req = json.loads(line)
            if "id" in req:
                resp = handle_rpc(req)
                sys.stdout.write(json.dumps(resp) + "\n")
                sys.stdout.flush()
        except Exception as e:
            err = {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": str(e)}}
            sys.stdout.write(json.dumps(err) + "\n")
            sys.stdout.flush()


if __name__ == "__main__":
    run_mcp_stdio()
