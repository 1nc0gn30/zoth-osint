#!/usr/bin/env python3
"""
Zoth OSINT Breach & Leak Intelligence Engine (engine/breach_intel.py)
Zero-key native reconnaissance across:
  1. Have I Been Pwned (HIBP) SHA-1 prefix k-anonymity (Pwned Passwords zero-knowledge model)
  2. XposedOrNot public breach analytics and paste dumps (zero-key API)
  3. LeakCheck public breach database & exposed field index
  4. Public Pastebin, Dpaste, and Rentry.co direct endpoint probes
  5. GitHub public commit leaks and user Gists
  6. 6-Vector tactical breach & leak dork synthesizer
  7. Deterministic Breach Risk Scoring (0-100) & STIX-ready entity graph synthesis
"""

import concurrent.futures
import datetime
import hashlib
import json
import re
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) ZothOSINT/4.0 (+https://nullai.tech)"


def _safe_get_json(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 4.5) -> Optional[Any]:
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            return json.loads(raw)
    except Exception:
        return None


def _safe_get_text(url: str, headers: Optional[Dict[str, str]] = None, timeout: float = 4.0) -> Tuple[int, str]:
    req_headers = {"User-Agent": USER_AGENT}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            code = resp.status
            body = resp.read().decode("utf-8", errors="replace")
            return code, body
    except urllib.error.HTTPError as he:
        return he.code, ""
    except Exception:
        return 0, ""


def probe_hibp_k_anonymity(value: str) -> Dict[str, Any]:
    """
    Computes SHA-1 hash and queries HIBP Pwned Passwords using mathematical k-anonymity.
    Only the 5-character prefix is transmitted over the wire; matching occurs strictly client-side.
    """
    clean_val = value.strip()
    if not clean_val:
        return {"checked": False, "pwned": False, "occurrences": 0}

    sha1_hex = hashlib.sha1(clean_val.encode("utf-8")).hexdigest().upper()
    prefix = sha1_hex[:5]
    suffix = sha1_hex[5:]
    url = f"https://api.pwnedpasswords.com/range/{prefix}"

    code, body = _safe_get_text(url, timeout=4.5)
    if code != 200 or not body:
        return {
            "checked": False,
            "pwned": False,
            "occurrences": 0,
            "hash_prefix": prefix,
            "sha1": sha1_hex,
            "model": "HIBP SHA-1 k-Anonymity (Service Offline/Unreachable)",
        }

    for line in body.splitlines():
        line = line.strip()
        if line.startswith(suffix):
            parts = line.split(":")
            cnt = int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else 1
            return {
                "checked": True,
                "pwned": True,
                "occurrences": cnt,
                "hash_prefix": prefix,
                "suffix_masked": suffix[:4] + "***",
                "sha1": sha1_hex,
                "model": "HIBP SHA-1 k-Anonymity (Verified Match)",
            }

    return {
        "checked": True,
        "pwned": False,
        "occurrences": 0,
        "hash_prefix": prefix,
        "suffix_masked": suffix[:4] + "***",
        "sha1": sha1_hex,
        "model": "HIBP SHA-1 k-Anonymity (Clean / Zero Occurrences)",
    }


def probe_xposedornot(email: str) -> Dict[str, Any]:
    """
    Queries XposedOrNot zero-key API for verified breach events, details, and paste dumps.
    """
    clean_email = email.strip().lower()
    if "@" not in clean_email:
        return {"breaches": [], "pastes": [], "metrics": {}}

    url = f"https://api.xposedornot.com/v1/breach-analytics?email={urllib.parse.quote(clean_email)}"
    data = _safe_get_json(url, timeout=5.0)

    breaches: List[Dict[str, Any]] = []
    pastes: List[Dict[str, Any]] = []
    metrics: Dict[str, Any] = {}

    if isinstance(data, dict):
        metrics = data.get("BreachMetrics") or {}
        details = (data.get("ExposedBreaches") or {}).get("breaches_details") or []
        for b in details:
            breaches.append(
                {
                    "name": str(b.get("breach") or "Unnamed Breach"),
                    "domain": str(b.get("domain") or ""),
                    "industry": str(b.get("industry") or "General"),
                    "data_classes": [x.strip() for x in (b.get("xposed_data") or "").split(";") if x.strip()],
                    "date": str(b.get("xposed_date") or ""),
                    "records": b.get("xposed_records"),
                    "password_risk": str(b.get("password_risk") or "unknown"),
                    "description": str(b.get("details") or ""),
                }
            )

        exposed_pastes = (data.get("ExposedPastes") or {}).get("pastes_details") or []
        for p in exposed_pastes:
            pid = str(p.get("paste_id") or "")
            pastes.append(
                {
                    "source": "XposedOrNot Paste Archive",
                    "title": str(p.get("paste_title") or f"Paste Record {pid}"),
                    "url": f"https://pastebin.com/{pid}" if pid and not pid.startswith("http") else pid,
                    "date": str(p.get("paste_date") or ""),
                    "preview": f"Leaked record identifier: {pid}",
                }
            )

    # Fallback to simple endpoint if analytics empty
    if not breaches:
        simple_url = f"https://api.xposedornot.com/v1/check-email/{urllib.parse.quote(clean_email)}"
        simple_data = _safe_get_json(simple_url, timeout=4.0)
        if isinstance(simple_data, dict) and "breaches" in simple_data:
            raw_b = simple_data.get("breaches")
            if isinstance(raw_b, list):
                flattened = []
                for item in raw_b:
                    if isinstance(item, list):
                        flattened.extend(item)
                    elif isinstance(item, str):
                        flattened.append(item)
                for b_name in flattened:
                    if b_name:
                        breaches.append(
                            {
                                "name": str(b_name),
                                "domain": "",
                                "industry": "Public Breach",
                                "data_classes": ["Account Credentials"],
                                "date": "",
                                "records": None,
                                "password_risk": "moderate",
                                "description": f"Target was compromised in the {b_name} database leak.",
                            }
                        )

    return {"breaches": breaches, "pastes": pastes, "metrics": metrics}


def probe_leakcheck(query: str) -> Dict[str, Any]:
    """
    Queries LeakCheck public endpoint for leak occurrences and exposed field categories.
    """
    clean_q = query.strip()
    if not clean_q:
        return {"found": 0, "fields": [], "sources": []}

    for domain in ("leakcheck.io", "leakcheck.net"):
        url = f"https://{domain}/api/public?check={urllib.parse.quote(clean_q)}"
        data = _safe_get_json(url, timeout=4.0)
        if isinstance(data, dict) and data.get("success"):
            return {
                "found": int(data.get("found") or 0),
                "fields": [str(f) for f in (data.get("fields") or [])],
                "sources": data.get("sources") or [],
            }
    return {"found": 0, "fields": [], "sources": []}


def probe_pastes_and_gists(query: str, query_type: str = "username") -> List[Dict[str, Any]]:
    """
    Probes public paste repositories (Rentry.co, Dpaste.org) and GitHub user Gists.
    """
    clean_q = query.strip()
    pastes: List[Dict[str, Any]] = []

    # 1. Rentry.co direct slug lookup
    try:
        rentry_url = f"https://rentry.co/api/raw/{urllib.parse.quote(clean_q)}"
        code, body = _safe_get_text(rentry_url, timeout=3.5)
        if code == 200 and body and not body.strip().startswith('{"status": "404"'):
            preview = body[:220].strip()
            pastes.append(
                {
                    "source": "Rentry.co",
                    "title": f"Rentry Paste: {clean_q}",
                    "url": f"https://rentry.co/{clean_q}",
                    "date": "Active Paste",
                    "preview": preview or "Active paste record hosted on rentry.co",
                }
            )
    except Exception:
        pass

    # 2. Dpaste.org direct slug lookup
    try:
        dpaste_url = f"https://dpaste.org/{urllib.parse.quote(clean_q)}.txt"
        code, body = _safe_get_text(dpaste_url, timeout=3.5)
        if code == 200 and body and "Page Not Found" not in body:
            preview = body[:220].strip()
            pastes.append(
                {
                    "source": "Dpaste.org",
                    "title": f"Dpaste Raw Entry: {clean_q}",
                    "url": f"https://dpaste.org/{clean_q}",
                    "date": "Active Paste",
                    "preview": preview or "Active plain text snippet on dpaste.org",
                }
            )
    except Exception:
        pass

    # 3. GitHub Gists (if username target)
    if query_type == "username":
        try:
            gists_url = f"https://api.github.com/users/{urllib.parse.quote(clean_q)}/gists?per_page=8"
            gists = _safe_get_json(gists_url, timeout=4.5)
            if isinstance(gists, list):
                for g in gists:
                    files = list((g.get("files") or {}).keys())
                    desc = g.get("description") or f"Gist ({', '.join(files[:2])})"
                    pastes.append(
                        {
                            "source": "GitHub Gists",
                            "title": desc[:90],
                            "url": g.get("html_url") or f"https://gist.github.com/{clean_q}/{g.get('id')}",
                            "date": (g.get("created_at") or "")[:10],
                            "preview": f"Files: {', '.join(files)} | Updated: {(g.get('updated_at') or '')[:10]}",
                        }
                    )
        except Exception:
            pass

    return pastes


def probe_github_commits(query: str) -> List[Dict[str, Any]]:
    """
    Searches public GitHub commit messages and patches for target leaks or mentions.
    """
    clean_q = query.strip()
    commits: List[Dict[str, Any]] = []
    url = f"https://api.github.com/search/commits?q={urllib.parse.quote(clean_q)}&per_page=6"
    headers = {"Accept": "application/vnd.github.cloak-preview"}

    data = _safe_get_json(url, headers=headers, timeout=4.5)
    if isinstance(data, dict):
        for item in data.get("items", [])[:6]:
            repo = (item.get("repository") or {}).get("full_name") or "Unknown Repo"
            commit = item.get("commit") or {}
            msg = (commit.get("message") or "").splitlines()[0] if commit.get("message") else "No commit message"
            author = commit.get("author") or {}
            commits.append(
                {
                    "repo": repo,
                    "message": msg[:100],
                    "author": f"{author.get('name', '')} <{author.get('email', '')}>",
                    "date": (author.get("date") or "")[:10],
                    "url": item.get("html_url") or "",
                }
            )
    return commits


def synthesize_breach_dorks(query: str) -> List[Dict[str, str]]:
    """
    Generates 6 targeted OSINT dork links for manual deep-dive verification across leak indexes.
    """
    q_enc = urllib.parse.quote(query)
    return [
        {
            "category": "Paste Archives",
            "name": "Pastebin Deep Search",
            "query": f'site:pastebin.com "{query}"',
            "url": f'https://www.google.com/search?q={urllib.parse.quote(f"site:pastebin.com \"{query}\"")}',
        },
        {
            "category": "Paste Dumps",
            "name": "Multi-Paste Aggregator Dork",
            "query": f'(site:rentry.co OR site:dpaste.org OR site:justpaste.it OR site:ghostbin.com) "{query}"',
            "url": f'https://www.google.com/search?q={urllib.parse.quote(f"(site:rentry.co OR site:dpaste.org OR site:justpaste.it OR site:ghostbin.com) \"{query}\"")}',
        },
        {
            "category": "Code Leaks",
            "name": "GitHub Sensitive File Commits",
            "query": f'"{query}" (filename:.env OR filename:credentials OR filename:config)',
            "url": f'https://github.com/search?q={urllib.parse.quote(f"\"{query}\" filename:.env")}&type=code',
        },
        {
            "category": "IntelX",
            "name": "Intelligence X Public Archive",
            "query": f"intelx.io?s={q_enc}",
            "url": f"https://intelx.io/?s={q_enc}",
        },
        {
            "category": "Public Dumps",
            "name": "Breach Directory Index Dork",
            "query": f'"{query}" (password OR hash OR email OR leak OR dump)',
            "url": f'https://www.google.com/search?q={urllib.parse.quote(f"\"{query}\" (password OR hash OR leak)")}',
        },
        {
            "category": "Wayback CDX",
            "name": "Wayback Machine Pastebin Snapshots",
            "query": f"web.archive.org/web/*/pastebin.com/*{q_enc}*",
            "url": f"https://web.archive.org/web/*/pastebin.com/*{q_enc}*",
        },
    ]


def calculate_breach_risk(
    breaches: List[Dict[str, Any]],
    pastes: List[Dict[str, Any]],
    k_anon: Dict[str, Any],
    leakcheck: Dict[str, Any],
    commit_leaks: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """
    Computes a deterministic 0-100 risk score and qualitative threat level.
    """
    score = 0
    factors: List[str] = []

    # 1. Breach count scoring (up to 40 pts)
    b_count = len(breaches)
    if b_count > 0:
        pts = min(40, b_count * 8)
        score += pts
        factors.append(f"Identified in {b_count} public breach archive(s) (+{pts} pts)")

    # 2. HIBP SHA-1 k-anonymity proof (up to 30 pts)
    if k_anon.get("pwned"):
        occ = k_anon.get("occurrences", 0)
        if occ >= 1000:
            score += 30
            factors.append(f"HIBP k-Anonymity confirmed pervasive credential leak ({occ:,} hits, +30 pts)")
        elif occ >= 10:
            score += 20
            factors.append(f"HIBP k-Anonymity confirmed exposure ({occ:,} hits, +20 pts)")
        else:
            score += 12
            factors.append(f"HIBP k-Anonymity flagged exposure (+12 pts)")

    # 3. Leaked field sensitivity from LeakCheck (up to 20 pts)
    fields = [f.lower() for f in leakcheck.get("fields", [])]
    if any(k in fields for k in ("password", "hash", "salt")):
        score += 15
        factors.append("Confirmed leaked password/credential fields in breach records (+15 pts)")
    if any(k in fields for k in ("phone", "ssn", "dob", "address")):
        score += 10
        factors.append("Personally Identifiable Information (PII) exposed (+10 pts)")

    # 4. Pastes and commits (up to 15 pts)
    if pastes:
        pts = min(10, len(pastes) * 4)
        score += pts
        factors.append(f"Discovered in {len(pastes)} public paste snippet(s) (+{pts} pts)")
    if commit_leaks:
        score += 10
        factors.append(f"Public GitHub commit mentions detected ({len(commit_leaks)} hits, +10 pts)")

    final_score = min(100, max(0, score))

    if final_score >= 80:
        level, color = "CRITICAL", "#ef4444"
    elif final_score >= 55:
        level, color = "HIGH", "#f97316"
    elif final_score >= 30:
        level, color = "MODERATE", "#ffb800"
    elif final_score > 0:
        level, color = "LOW", "#38bdf8"
    else:
        level, color = "CLEAN", "#32ff85"
        factors.append("Zero public breach or paste disclosures identified across queried indices.")

    return {
        "score": final_score,
        "level": level,
        "color": color,
        "factors": factors,
    }


def recon_breaches_and_pastes(query: str, query_type: str = "") -> Dict[str, Any]:
    """
    Main zero-key Breach & Paste OSINT reconnaissance entrypoint.
    Executes multi-threaded concurrent probes across HIBP, XposedOrNot, LeakCheck,
    Rentry/Dpaste paste platforms, and GitHub commit intelligence.
    """
    clean_q = query.strip()
    if not query_type or query_type == "auto":
        query_type = "email" if ("@" in clean_q and "." in clean_q) else "username"

    now_iso = datetime.datetime.now(datetime.timezone.utc).isoformat()
    result: Dict[str, Any] = {
        "target": clean_q,
        "type": "breach",
        "query_type": query_type,
        "timestamp": now_iso,
        "breaches": [],
        "pastes": [],
        "pwned_passwords_k_anonymity": {},
        "leakcheck": {},
        "commit_mentions": [],
        "dorks": synthesize_breach_dorks(clean_q),
        "risk": {},
        "findings": [],
        "graph": {"nodes": [], "edges": []},
    }

    # Run probes concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        f_hibp = ex.submit(probe_hibp_k_anonymity, clean_q)
        f_xposed = ex.submit(probe_xposedornot, clean_q) if query_type == "email" else None
        f_leak = ex.submit(probe_leakcheck, clean_q)
        f_pastes = ex.submit(probe_pastes_and_gists, clean_q, query_type)
        f_commits = ex.submit(probe_github_commits, clean_q)

        k_anon = f_hibp.result()
        xposed_res = f_xposed.result() if f_xposed else {"breaches": [], "pastes": []}
        leak_res = f_leak.result()
        pastes_res = f_pastes.result()
        commits_res = f_commits.result()

    # Consolidate breaches
    breaches_map: Dict[str, Dict[str, Any]] = {}
    for b in xposed_res.get("breaches", []):
        bname = b.get("name", "").strip()
        if bname:
            breaches_map[bname.lower()] = b

    # Combine LeakCheck sources if present
    for src in leak_res.get("sources", []):
        sname = src.get("name") if isinstance(src, dict) else str(src)
        if sname and sname.lower() not in breaches_map:
            breaches_map[sname.lower()] = {
                "name": sname,
                "domain": "",
                "industry": "Leak Archive",
                "data_classes": leak_res.get("fields", []),
                "date": src.get("date", "") if isinstance(src, dict) else "",
                "records": None,
                "password_risk": "high" if "password" in leak_res.get("fields", []) else "moderate",
                "description": f"Source recorded in LeakCheck database index.",
            }

    all_breaches = list(breaches_map.values())

    # Consolidate pastes
    all_pastes = list(pastes_res)
    for p in xposed_res.get("pastes", []):
        if not any(x["url"] == p["url"] for x in all_pastes):
            all_pastes.append(p)

    risk_data = calculate_breach_risk(all_breaches, all_pastes, k_anon, leak_res, commits_res)

    result["breaches"] = all_breaches
    result["pastes"] = all_pastes
    result["pwned_passwords_k_anonymity"] = k_anon
    result["leakcheck"] = leak_res
    result["commit_mentions"] = commits_res
    result["risk"] = risk_data
    result["risk_score"] = risk_data["score"]

    # Synthesize findings
    findings = [
        f"Assessed breach footprint for '{clean_q}' ({query_type.upper()}): Risk Rating {risk_data['level']} ({risk_data['score']}/100)."
    ]
    if k_anon.get("checked"):
        if k_anon.get("pwned"):
            findings.append(
                f"HIBP SHA-1 k-Anonymity proof [prefix {k_anon['hash_prefix']}***]: MATCH FOUND with {k_anon['occurrences']:,} leaked occurrences."
            )
        else:
            findings.append(
                f"HIBP SHA-1 k-Anonymity proof [prefix {k_anon['hash_prefix']}***]: CLEAN (0 known credential exposures)."
            )

    if all_breaches:
        b_names = [b["name"] for b in all_breaches[:8]]
        findings.append(
            f"Compromised in {len(all_breaches)} public breach archive(s): {', '.join(b_names)}{' ...' if len(all_breaches) > 8 else ''}."
        )

    if leak_res.get("fields"):
        findings.append(f"Exposed data attributes: {', '.join(leak_res['fields'][:10])}.")

    if all_pastes:
        findings.append(f"Located {len(all_pastes)} public paste or Gist dump(s) referencing target.")

    if commits_res:
        findings.append(
            f"Detected {len(commits_res)} public GitHub repository commit leaks mentioning target."
        )

    result["findings"] = findings

    # Synthesize entity graph
    nodes: List[Dict[str, Any]] = [
        {
            "id": "root",
            "label": clean_q,
            "type": query_type.upper(),
            "color": "#00d5ff",
            "pivot": clean_q,
        }
    ]
    edges: List[Dict[str, str]] = []

    if k_anon.get("pwned"):
        nodes.append(
            {
                "id": "hibp_k",
                "label": f"HIBP ({k_anon['occurrences']:,} hits)",
                "type": "INCIDENT",
                "color": "#ef4444",
                "pivot": f"k-anon:{k_anon['hash_prefix']}",
            }
        )
        edges.append({"from": "root", "to": "hibp_k", "label": "SHA1 PWNED"})

    for i, b in enumerate(all_breaches[:12]):
        bid = f"breach_{i}"
        nodes.append(
            {
                "id": bid,
                "label": b.get("name") or f"Breach #{i+1}",
                "type": "BREACH",
                "color": "#f43f5e",
                "pivot": b.get("domain") or b.get("name"),
            }
        )
        edges.append({"from": "root", "to": bid, "label": "EXPOSED IN"})

    for i, p in enumerate(all_pastes[:8]):
        pid = f"paste_{i}"
        nodes.append(
            {
                "id": pid,
                "label": p.get("title") or f"Paste #{i+1}",
                "type": "PASTE",
                "color": "#f97316",
                "pivot": p.get("url") or "",
            }
        )
        edges.append({"from": "root", "to": pid, "label": "PASTE DUMP"})

    for i, c in enumerate(commits_res[:6]):
        cid = f"commit_{i}"
        nodes.append(
            {
                "id": cid,
                "label": c.get("repo") or f"Commit #{i+1}",
                "type": "COMMIT",
                "color": "#a855f7",
                "pivot": c.get("url") or "",
            }
        )
        edges.append({"from": "root", "to": cid, "label": "CODE MENTION"})

    result["graph"] = {"nodes": nodes, "edges": edges}
    return result
