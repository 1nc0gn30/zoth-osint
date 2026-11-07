#!/usr/bin/env python3
"""
Zoth OSINT Persistent SQLite Case Store & STIX 2.1 Exporter (engine/case_store.py)
Stores investigation snapshots locally in ~/.zoth-osint/cases.db with zero cloud telemetry,
and synthesizes OASIS STIX 2.1 Cyber Threat Intelligence bundles.
"""

import datetime
import hashlib
import json
import os
import sqlite3
import uuid
from typing import Any, Dict, List, Optional

DEFAULT_DB_DIR = os.path.expanduser("~/.zoth-osint")
DEFAULT_DB_PATH = os.path.join(DEFAULT_DB_DIR, "cases.db")


def _get_conn(db_path: str = DEFAULT_DB_PATH) -> sqlite3.Connection:
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS osint_cases (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            target_type TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            node_count INTEGER DEFAULT 0,
            edge_count INTEGER DEFAULT 0,
            summary TEXT DEFAULT '',
            payload_json TEXT NOT NULL
        )
        """
    )
    conn.commit()
    return conn


def save_case(scan_data: Dict[str, Any], db_path: str = DEFAULT_DB_PATH) -> int:
    target = str(scan_data.get("target") or "unknown")
    ttype = str(scan_data.get("type") or "unknown")
    ts = str(scan_data.get("timestamp") or datetime.datetime.now(datetime.timezone.utc).isoformat())
    graph = scan_data.get("graph") or {}
    nodes = graph.get("nodes") or []
    edges = graph.get("edges") or []
    findings = scan_data.get("findings") or []
    summary = findings[0] if findings else f"Scanned {target} ({ttype})"

    conn = _get_conn(db_path)
    try:
        cur = conn.execute(
            """
            INSERT INTO osint_cases (target, target_type, timestamp, node_count, edge_count, summary, payload_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (target, ttype, ts, len(nodes), len(edges), summary, json.dumps(scan_data)),
        )
        conn.commit()
        return int(cur.lastrowid or 0)
    finally:
        conn.close()


def list_cases(limit: int = 25, db_path: str = DEFAULT_DB_PATH) -> List[Dict[str, Any]]:
    conn = _get_conn(db_path)
    try:
        rows = conn.execute(
            """
            SELECT id, target, target_type, timestamp, node_count, edge_count, summary
            FROM osint_cases
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]
    finally:
        conn.close()


def get_case(case_id: int, db_path: str = DEFAULT_DB_PATH) -> Optional[Dict[str, Any]]:
    conn = _get_conn(db_path)
    try:
        row = conn.execute("SELECT payload_json FROM osint_cases WHERE id = ?", (case_id,)).fetchone()
        if not row:
            return None
        return json.loads(row["payload_json"])
    finally:
        conn.close()


def export_stix_bundle(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """Synthesize an OASIS STIX 2.1 Threat Intelligence Bundle from a Zoth OSINT scan."""
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    target = str(scan_data.get("target") or "unknown")
    ttype = str(scan_data.get("type") or "unknown")

    identity_id = "identity--zoth-osint-nullai-0000-0000-000000000001"
    objects: List[Dict[str, Any]] = [
        {
            "type": "identity",
            "spec_version": "2.1",
            "id": identity_id,
            "created": now,
            "modified": now,
            "name": "Zoth OSINT Sovereign Engine (NullAI)",
            "identity_class": "system",
        }
    ]

    graph = scan_data.get("graph") or {}
    node_stix_ids: Dict[str, str] = {}

    for node in graph.get("nodes", []):
        nid = str(node.get("id", ""))
        label = str(node.get("label", ""))
        ntype = str(node.get("type", "ENTITY")).upper()
        det_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"zoth-osint:{target}:{nid}:{label}"))

        if ntype == "IPV4":
            stix_type = "ipv4-addr"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id, "value": label}
        elif ntype in ("DOMAIN", "SUBDOMAIN", "HOSTNAME", "MX"):
            stix_type = "domain-name"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id, "value": label}
        elif ntype == "CVE":
            stix_type = "vulnerability"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id, "created": now, "modified": now, "name": label}
        else:
            stix_type = "grouping"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {
                "type": stix_type,
                "spec_version": "2.1",
                "id": stix_id,
                "created": now,
                "modified": now,
                "name": f"[{ntype}] {label}",
                "context": "suspicious-activity",
                "object_refs": [identity_id],
            }

        node_stix_ids[nid] = stix_id
        objects.append(obj)

    for idx, edge in enumerate(graph.get("edges", [])):
        src = node_stix_ids.get(edge.get("from", ""))
        dst = node_stix_ids.get(edge.get("to", ""))
        if src and dst:
            rel_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"zoth-rel:{src}:{dst}:{idx}"))
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{rel_uuid}",
                    "created": now,
                    "modified": now,
                    "relationship_type": (edge.get("label") or "related-to").lower().replace(" ", "-"),
                    "source_ref": src,
                    "target_ref": dst,
                }
            )

    bundle_uuid = hashlib.md5(f"{target}:{now}".encode("utf-8")).hexdigest()
    return {
        "type": "bundle",
        "id": f"bundle--{bundle_uuid[:8]}-{bundle_uuid[8:12]}-{bundle_uuid[12:16]}-{bundle_uuid[16:20]}-{bundle_uuid[20:32]}",
        "objects": objects,
    }
