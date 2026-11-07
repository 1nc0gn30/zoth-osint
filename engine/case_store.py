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

from engine.mitre_attack import build_mitre_stix_objects, map_mitre_attack

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
        elif ntype in ("CVE", "VULN", "TAKEOVER"):
            stix_type = "vulnerability"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id, "created": now, "modified": now, "name": label}
        elif ntype in ("BREACH", "LEAK"):
            stix_type = "incident"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {
                "type": stix_type,
                "spec_version": "2.1",
                "id": stix_id,
                "created": now,
                "modified": now,
                "name": f"Breach Exposure: {label}",
                "description": f"Compromised credential / leak archive entry: {label}",
            }
        elif ntype in ("PASTE", "DUMP", "GIST"):
            stix_type = "indicator"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {
                "type": stix_type,
                "spec_version": "2.1",
                "id": stix_id,
                "created": now,
                "modified": now,
                "name": f"Paste Record: {label}",
                "indicator_types": ["compromised-credentials"],
                "pattern": f"[{'email-addr' if '@' in label else 'user-account'}:value = '{label}']",
                "pattern_type": "stix",
                "valid_from": now,
            }
        elif ntype == "EMAIL":
            stix_type = "email-addr"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id, "value": label}
        elif ntype == "PROFILE":
            stix_type = "user-account"
            stix_id = f"{stix_type}--{det_uuid}"
            obj = {"type": stix_type, "spec_version": "2.1", "id": stix_id, "account_login": label}
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

    # Embed MITRE ATT&CK Enterprise Matrix Objects (SDO type 'attack-pattern', 'course-of-action', and SRO 'relationship')
    mitre_data = scan_data.get("mitre_attack")
    if not mitre_data:
        try:
            mitre_data = map_mitre_attack(scan_data)
        except Exception:
            mitre_data = None

    if mitre_data:
        try:
            mitre_stix_objs = build_mitre_stix_objects(mitre_data, identity_id, now_iso=now)
            objects.extend(mitre_stix_objs)
        except Exception:
            pass

    bundle_uuid = hashlib.md5(f"{target}:{now}".encode("utf-8")).hexdigest()
    return {
        "type": "bundle",
        "id": f"bundle--{bundle_uuid[:8]}-{bundle_uuid[8:12]}-{bundle_uuid[12:16]}-{bundle_uuid[16:20]}-{bundle_uuid[20:32]}",
        "objects": objects,
    }


def export_gexf_xml(graph: Dict[str, Any], title: str = "Zoth OSINT Entity Graph") -> str:
    """Export an entity graph to Gephi / Cytoscape GEXF 1.3 XML format."""
    import xml.sax.saxutils as saxutils

    esc = saxutils.escape
    lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<gexf xmlns="http://www.gexf.net/1.3" version="1.3">',
        f'  <meta lastmodifieddate="{datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d")}">',
        '    <creator>Zoth OSINT v4.0 (NullAI Platform)</creator>',
        f'    <description>{esc(title)}</description>',
        '  </meta>',
        '  <graph mode="static" defaultedgetype="directed">',
        '    <attributes class="node">',
        '      <attribute id="0" title="entity_type" type="string"/>',
        '      <attribute id="1" title="pivot" type="string"/>',
        '    </attributes>',
        '    <nodes>',
    ]
    for n in graph.get("nodes", []):
        nid = esc(str(n.get("id", "")))
        lbl = esc(str(n.get("label", "")))
        ntype = esc(str(n.get("type", "ENTITY")))
        piv = esc(str(n.get("pivot", "")))
        lines.append(f'      <node id="{nid}" label="{lbl}">')
        lines.append('        <attvalues>')
        lines.append(f'          <attvalue for="0" value="{ntype}"/>')
        lines.append(f'          <attvalue for="1" value="{piv}"/>')
        lines.append('        </attvalues>')
        lines.append('      </node>')
    lines.append('    </nodes>')
    lines.append('    <edges>')
    for i, e in enumerate(graph.get("edges", [])):
        src = esc(str(e.get("from", "")))
        dst = esc(str(e.get("to", "")))
        elbl = esc(str(e.get("label", "")))
        lines.append(f'      <edge id="{i}" source="{src}" target="{dst}" label="{elbl}"/>')
    lines.append('    </edges>')
    lines.append('  </graph>')
    lines.append('</gexf>')
    return "\n".join(lines)


def correlate_payloads(payloads: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Merge multiple OSINT scan payloads into a Unified Cross-Pivot Supergraph and detect shared entities."""
    merged_nodes: Dict[str, Dict[str, Any]] = {}
    merged_edges: List[Dict[str, str]] = []
    occurrence_map: Dict[str, List[str]] = {}
    targets = []

    for idx, p in enumerate(payloads):
        t_name = str(p.get("target") or f"target_{idx}")
        targets.append(t_name)
        g = p.get("graph") or {}
        id_remap: Dict[str, str] = {}

        for n in g.get("nodes", []):
            orig_id = str(n.get("id", ""))
            lbl = str(n.get("label", "")).strip()
            ntype = str(n.get("type", "ENTITY")).upper()
            canon_key = f"{ntype}:{lbl.lower()}"
            id_remap[orig_id] = canon_key

            if canon_key not in occurrence_map:
                occurrence_map[canon_key] = []
            if t_name not in occurrence_map[canon_key]:
                occurrence_map[canon_key].append(t_name)

            if canon_key not in merged_nodes:
                merged_nodes[canon_key] = {
                    "id": canon_key,
                    "label": lbl,
                    "type": ntype,
                    "color": "#00d5ff" if orig_id == "root" else n.get("color", "#32ff85"),
                    "pivot": n.get("pivot", lbl),
                }

        for e in g.get("edges", []):
            u = id_remap.get(str(e.get("from", "")))
            v = id_remap.get(str(e.get("to", "")))
            if u and v:
                merged_edges.append({"from": u, "to": v, "label": str(e.get("label", ""))})

    overlaps = []
    breach_overlaps = []
    for canon_key, seen_targets in occurrence_map.items():
        if len(seen_targets) > 1:
            node_obj = merged_nodes[canon_key]
            if node_obj["type"] in ("BREACH", "LEAK", "PASTE", "INCIDENT"):
                node_obj["color"] = "#f43f5e"  # Highlight shared breach leaks in crimson
                breach_overlaps.append(node_obj["label"])
            else:
                node_obj["color"] = "#ffb800"  # Highlight shared overlap nodes in gold
            overlaps.append(
                {
                    "entity": node_obj["label"],
                    "type": node_obj["type"],
                    "shared_across": seen_targets,
                }
            )

    findings = [
        f"Merged {len(payloads)} investigations ({', '.join(targets)}) into a Unified Supergraph ({len(merged_nodes)} unique entities, {len(merged_edges)} links).",
    ]
    if breach_overlaps:
        findings.append(f"BREACH CORRELATION ALERT: Detected {len(breach_overlaps)} shared compromised breach dumps across investigated targets ({', '.join(breach_overlaps[:6])}).")
    if overlaps:
        findings.append(f"SHARED PIVOT ALERT: Detected {len(overlaps)} overlapping entities shared across multiple targets ({', '.join(o['entity'] for o in overlaps[:6])}).")
    else:
        findings.append("Zero direct entity overlaps detected between the selected targets; graphs combined for side-by-side link analysis.")

    super_graph = {"nodes": list(merged_nodes.values()), "edges": merged_edges}
    result = {
        "target": " ⊕ ".join(targets),
        "type": "correlation",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "targets_merged": targets,
        "shared_overlaps": overlaps,
        "findings": findings,
        "graph": super_graph,
    }
    result["stix_bundle"] = export_stix_bundle(result)
    result["gexf_xml"] = export_gexf_xml(super_graph, title=f"Correlation: {' + '.join(targets)}")
    return result


def correlate_cases(case_ids: List[int], db_path: str = DEFAULT_DB_PATH) -> Dict[str, Any]:
    payloads = []
    for cid in case_ids:
        c = get_case(cid, db_path=db_path)
        if c:
            payloads.append(c)
    if not payloads:
        for row in list_cases(limit=3, db_path=db_path):
            c = get_case(row["id"], db_path=db_path)
            if c:
                payloads.append(c)
    return correlate_payloads(payloads)
