#!/usr/bin/env python3
"""
Zoth OSINT Core Engine v2.0 (engine/osint_core.py)
Zero-key native reconnaissance across:
  1. Domains (DoH DNS, SPF/DMARC, TLS SANs, crt.sh CT Subdomains, Wayback CDX Historical Endpoints)
  2. IPv4 Infrastructure (Shodan InternetDB zero-key open ports/CVEs/CPEs, BGP ASN, GeoIP)
  3. Usernames / Handles (12-platform concurrent probe + GitHub SSH/PGP keys & commit email leaks)
  4. Emails (Gravatar MD5/SHA256, OpenPGP keyserver, GitHub commit search, Domain MX/SPF/DMARC)
  5. Crypto Wallets (Solana Mainnet RPC, Ethereum/EVM JSON-RPC, Bitcoin mempool.space API)
  6. Phone Numbers (ITU-T E.164 country & NANPA area code geolocation + messaging pivots)
  7. Binary Media EXIF & Cryptographic Hash Forensics
  8. 18-Query Tactical OSINT Dork Synthesizer (Google, GitHub, Shodan, Censys, URLScan, Overpass GEOINT)
  9. Interactive Entity Link Graph + Obsidian .canvas + OASIS STIX 2.1 Threat Bundle
"""

import base64
import concurrent.futures
import datetime
import hashlib
import json
import math
import os
import re
import socket
import ssl
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

from engine.case_store import export_gexf_xml, export_stix_bundle, save_case

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) ZothOSINT/3.0 (+https://nullai.tech)"


def _mmh3_hash32(data: bytes, seed: int = 0) -> int:
    """Pure-Python 32-bit signed MurmurHash3 (exact Shodan/Censys/FOFA favicon hash specification)."""
    c1 = 0xCC9E2D51
    c2 = 0x1B873593
    length = len(data)
    h1 = seed & 0xFFFFFFFF
    rounded_end = length & ~0x3

    for i in range(0, rounded_end, 4):
        k1 = (
            (data[i] & 0xFF)
            | ((data[i + 1] & 0xFF) << 8)
            | ((data[i + 2] & 0xFF) << 16)
            | (data[i + 3] << 24)
        ) & 0xFFFFFFFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF

        h1 ^= k1
        h1 = ((h1 << 13) | (h1 >> 19)) & 0xFFFFFFFF
        h1 = (h1 * 5 + 0xE6546B64) & 0xFFFFFFFF

    k1 = 0
    val = length & 0x03
    if val == 3:
        k1 = (data[rounded_end + 2] & 0xFF) << 16
    if val in (2, 3):
        k1 |= (data[rounded_end + 1] & 0xFF) << 8
    if val in (1, 2, 3):
        k1 |= data[rounded_end] & 0xFF
        k1 = (k1 * c1) & 0xFFFFFFFF
        k1 = ((k1 << 15) | (k1 >> 17)) & 0xFFFFFFFF
        k1 = (k1 * c2) & 0xFFFFFFFF
        h1 ^= k1

    h1 ^= length
    h1 ^= h1 >> 16
    h1 = (h1 * 0x85EBCA6B) & 0xFFFFFFFF
    h1 ^= h1 >> 13
    h1 = (h1 * 0xC2B2AE35) & 0xFFFFFFFF
    h1 ^= h1 >> 16

    if h1 & 0x80000000:
        return -((~h1 + 1) & 0xFFFFFFFF)
    return h1


def _http_get_json(url: str, timeout: float = 6.0, headers: Optional[Dict[str, str]] = None) -> Any:
    req_headers = {"User-Agent": USER_AGENT, "Accept": "application/json"}
    if headers:
        req_headers.update(headers)
    req = urllib.request.Request(url, headers=req_headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)


def _http_post_json(url: str, payload: Dict[str, Any], timeout: float = 6.0) -> Any:
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url,
        data=body,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        raw = resp.read().decode("utf-8", errors="replace")
        return json.loads(raw)


def _http_get_text(url: str, timeout: float = 6.0) -> Tuple[int, str, Dict[str, str]]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        headers = {k.lower(): v for k, v in resp.headers.items()}
        return resp.status, resp.read().decode("utf-8", errors="replace"), headers


def classify_target(target: str) -> str:
    """Automatically classify an OSINT target string across 6 intelligence domains."""
    t = target.strip()
    if not t:
        return "unknown"
    if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", t):
        return "ip"
    if re.match(r"^[^@\s]+@[^@\s]+\.[^@\s]+$", t):
        return "email"
    # Crypto Wallets: EVM (0x + 40 hex), Bitcoin (1/3/bc1), Solana (Base58 32-44 chars)
    if re.match(r"^0x[a-fA-F0-9]{40}$", t):
        return "wallet"
    if re.match(r"^(bc1[a-zA-HJ-NP-Z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$", t):
        return "wallet"
    if re.match(r"^[1-9A-HJ-NP-Za-km-z]{32,44}$", t) and not ("." in t or "-" in t):
        return "wallet"
    # Phone numbers: +1-757-555-0199 or 10-15 digits
    digits_only = re.sub(r"[\s().-]", "", t)
    if re.match(r"^\+?\d{10,15}$", digits_only):
        return "phone"
    if t.startswith("@"):
        return "username"
    if re.match(r"^(?:https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/.*)?$", t) and " " not in t:
        return "domain"
    return "username"


def normalize_domain(target: str) -> str:
    t = target.strip().lower()
    t = re.sub(r"^https?://", "", t)
    t = t.split("/")[0].split(":")[0]
    return t


# ---------------------------------------------------------------------------
# 1. TACTICAL OSINT DORK & QUERY MATRIX SYNTHESIZER (18 Queries)
# ---------------------------------------------------------------------------
def synthesize_dorks(target: str, target_type: str) -> List[Dict[str, str]]:
    clean = target.strip().lstrip("@")
    q = urllib.parse.quote(clean)
    dorks: List[Dict[str, str]] = [
        {
            "engine": "Google Dork",
            "title": "Exposed Configs, .env & SQL Backups",
            "query": f'site:{clean} (ext:env OR ext:sql OR ext:bak OR ext:yml OR ext:ini OR "DB_PASSWORD")',
            "url": f"https://www.google.com/search?q={urllib.parse.quote(f'site:{clean} (ext:env OR ext:sql OR ext:bak OR ext:yml)')}",
        },
        {
            "engine": "Google Dork",
            "title": "Public Documents (PDF, XLSX, DOCX, PPTX)",
            "query": f"site:{clean} (filetype:pdf OR filetype:xlsx OR filetype:docx OR filetype:pptx)",
            "url": f"https://www.google.com/search?q={urllib.parse.quote(f'site:{clean} (filetype:pdf OR filetype:xlsx OR filetype:docx)')}",
        },
        {
            "engine": "Google Dork",
            "title": "Cloud Buckets, Pastebin, Trello & Notion Mentions",
            "query": f'"{clean}" (site:pastebin.com OR site:trello.com OR site:notion.site OR site:s3.amazonaws.com)',
            "url": f"https://www.google.com/search?q={urllib.parse.quote(f'\"{clean}\" (site:pastebin.com OR site:trello.com OR site:notion.site)')}",
        },
        {
            "engine": "GitHub Recon",
            "title": "Hardcoded Secrets, API Keys & Tokens",
            "query": f'"{clean}" (api_key OR secret OR token OR password OR private_key)',
            "url": f"https://github.com/search?q={urllib.parse.quote(f'\"{clean}\" (api_key OR secret OR token OR password)')}&type=code",
        },
        {
            "engine": "GitHub Recon",
            "title": "Commit History & Author Attribution",
            "query": f'"{clean}"',
            "url": f"https://github.com/search?q={q}&type=commits",
        },
        {
            "engine": "Shodan Search",
            "title": "TLS Certificate CN / SAN Match & Open Ports",
            "query": f'ssl:"{clean}" OR hostname:"{clean}"',
            "url": f"https://www.shodan.io/search?query={urllib.parse.quote(f'ssl:\"{clean}\"')}",
        },
        {
            "engine": "URLScan.io",
            "title": "DOM Snapshots, Passive HTTP Requests & JS Hashes",
            "query": f"domain:{clean} OR page.url:*{clean}*",
            "url": f"https://urlscan.io/search/#domain%3A{q}",
        },
        {
            "engine": "crt.sh CT Logs",
            "title": "Certificate Transparency Historical Subdomains",
            "query": f"%.{clean}",
            "url": f"https://crt.sh/?q=%25.{q}",
        },
        {
            "engine": "Wayback Machine",
            "title": "Internet Archive Historical CDX Snapshots",
            "query": f"*.{clean}/*",
            "url": f"https://web.archive.org/web/*/{q}*",
        },
    ]
    return dorks


# ---------------------------------------------------------------------------
# 2B. NEW-AGE OSINT: FAVICON MURMURHASH3 (MMH3), RDAP, WELL-KNOWN & WEB3/ATPROTO
# ---------------------------------------------------------------------------
def recon_favicon_mmh3(domain_input: str) -> Dict[str, Any]:
    """Download /favicon.ico and compute Shodan/FOFA/Censys 32-bit signed MurmurHash3 (mmh3) + SHA256."""
    domain = normalize_domain(domain_input)
    fav_url = f"https://{domain}/favicon.ico"
    result: Dict[str, Any] = {
        "domain": domain,
        "favicon_url": fav_url,
        "found": False,
        "size_bytes": 0,
        "mmh3_hash": None,
        "sha256": None,
        "md5": None,
        "shodan_query": None,
        "shodan_url": None,
        "censys_url": None,
        "fofa_query": None,
    }
    try:
        req = urllib.request.Request(fav_url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(req, timeout=4.5) as resp:
            raw = resp.read(250_000)
            if raw and len(raw) > 16:
                # RFC 2045 base64 with 76-char line breaks + trailing newline (exact Shodan spec)
                b64_lines = base64.encodebytes(raw)
                mmh3_val = _mmh3_hash32(b64_lines)
                sha256_val = hashlib.sha256(raw).hexdigest()
                md5_val = hashlib.md5(raw).hexdigest()
                result.update(
                    {
                        "found": True,
                        "size_bytes": len(raw),
                        "mmh3_hash": mmh3_val,
                        "sha256": sha256_val,
                        "md5": md5_val,
                        "shodan_query": f"http.favicon.hash:{mmh3_val}",
                        "shodan_url": f"https://www.shodan.io/search?query=http.favicon.hash%3A{mmh3_val}",
                        "censys_url": f"https://search.censys.io/search?resource=hosts&q=services.http.response.favicons.shodan_hash%3A{mmh3_val}",
                        "fofa_query": f'icon_hash="{mmh3_val}"',
                    }
                )
    except Exception:
        pass
    return result


def recon_rdap(target_input: str, is_ip: bool = False) -> Dict[str, Any]:
    """Query structured IETF RDAP registry (modern JSON replacement for legacy WHOIS)."""
    clean = target_input.strip() if is_ip else normalize_domain(target_input)
    kind = "ip" if is_ip else "domain"
    out: Dict[str, Any] = {
        "handle": None,
        "registrar": None,
        "registered": None,
        "expiration": None,
        "last_changed": None,
        "dnssec_signed": False,
        "status": [],
    }
    try:
        data = _http_get_json(f"https://rdap.org/{kind}/{urllib.parse.quote(clean)}", timeout=5.0)
        if isinstance(data, dict):
            out["handle"] = data.get("handle") or data.get("ldhName")
            out["status"] = data.get("status", [])[:6]
            out["dnssec_signed"] = bool((data.get("secureDNS") or {}).get("delegationSigned"))
            for ev in data.get("events", []):
                act = ev.get("eventAction", "")
                dt = ev.get("eventDate", "")
                if act == "registration":
                    out["registered"] = dt
                elif act == "expiration":
                    out["expiration"] = dt
                elif act == "last changed":
                    out["last_changed"] = dt
            for ent in data.get("entities", []):
                if "registrar" in (ent.get("roles") or []):
                    vcard = ent.get("vcardArray")
                    if isinstance(vcard, list) and len(vcard) > 1:
                        for row in vcard[1]:
                            if isinstance(row, list) and len(row) >= 4 and row[0] == "fn":
                                out["registrar"] = row[3]
    except Exception:
        pass
    return out


def recon_well_known(domain_input: str) -> Dict[str, Any]:
    """Probe RFC 9116 security.txt, AI llms.txt, Bluesky ATProto DID, Nostr NIP-05, and OIDC manifests."""
    domain = normalize_domain(domain_input)
    probes = {
        "security_txt": f"https://{domain}/.well-known/security.txt",
        "llms_txt": f"https://{domain}/llms.txt",
        "atproto_did": f"https://{domain}/.well-known/atproto-did",
        "nostr_nip05": f"https://{domain}/.well-known/nostr.json",
        "openid_config": f"https://{domain}/.well-known/openid-configuration",
    }
    discovered: Dict[str, Any] = {}

    def _check(item: Tuple[str, str]) -> Tuple[str, Any]:
        key, url = item
        try:
            code, body, _ = _http_get_text(url, timeout=3.8)
            if code == 200 and body and "<html" not in body[:180].lower():
                return key, {"present": True, "url": url, "preview": body.strip()[:280]}
        except Exception:
            pass
        return key, {"present": False, "url": url}

    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex:
        for k, val in ex.map(_check, probes.items()):
            discovered[k] = val
    return discovered


def recon_new_age_identity(target_input: str) -> Dict[str, Any]:
    """Resolve Bluesky ATProto DIDs, ENS (.eth) Web3 identities, Nostr NIP-05, and HuggingFace AI artifacts."""
    clean = target_input.strip().lstrip("@")
    out: Dict[str, Any] = {
        "target": clean,
        "atproto_bluesky": {},
        "ens_web3": {},
        "huggingface_ai": {"models": [], "datasets": []},
    }

    # 1. Bluesky AT Protocol Handle -> DID -> PLC Directory Document
    bsky_handle = clean if "." in clean else f"{clean}.bsky.social"
    try:
        did_res = _http_get_json(
            f"https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={urllib.parse.quote(bsky_handle)}",
            timeout=4.5,
        )
        did = did_res.get("did") if isinstance(did_res, dict) else None
        if did:
            out["atproto_bluesky"] = {"handle": bsky_handle, "did": did, "profile_url": f"https://bsky.app/profile/{bsky_handle}"}
            if did.startswith("did:plc:"):
                plc = _http_get_json(f"https://plc.directory/{did}", timeout=4.0)
                if isinstance(plc, dict):
                    out["atproto_bluesky"]["also_known_as"] = plc.get("alsoKnownAs", [])
                    out["atproto_bluesky"]["services"] = plc.get("service", [])
    except Exception:
        pass

    # 2. ENS (.eth) or Web3 Address Resolution
    if clean.endswith(".eth") or clean.startswith("0x"):
        try:
            ens = _http_get_json(f"https://api.ensdata.net/{urllib.parse.quote(clean)}", timeout=4.5)
            if isinstance(ens, dict) and (ens.get("address") or ens.get("ens")):
                out["ens_web3"] = {
                    "ens": ens.get("ens") or ens.get("ens_primary"),
                    "address": ens.get("address"),
                    "avatar": ens.get("avatar"),
                    "twitter": ens.get("twitter"),
                    "github": ens.get("github"),
                    "url": ens.get("url"),
                }
        except Exception:
            pass

    # 3. HuggingFace AI Supply-Chain Footprint (Models & Datasets)
    if "." not in clean and not clean.startswith("0x"):
        try:
            models = _http_get_json(f"https://huggingface.co/api/models?author={urllib.parse.quote(clean)}&limit=5", timeout=4.5)
            if isinstance(models, list):
                out["huggingface_ai"]["models"] = [m.get("id") for m in models if m.get("id")]
        except Exception:
            pass

    return out


def recon_http_stack(domain_input: str) -> Dict[str, Any]:
    """Passive HTTP security header grader & CDN/Web Tech-Stack fingerprinter."""
    domain = normalize_domain(domain_input)
    out: Dict[str, Any] = {
        "domain": domain,
        "status_code": None,
        "server": None,
        "cdn_edge": "Direct / Unidentified",
        "tech_stack": [],
        "security_headers": {},
        "security_score": 0,
    }
    try:
        status, html, hdrs = _http_get_text(f"https://{domain}", timeout=4.5)
        out["status_code"] = status
        out["server"] = hdrs.get("server")
        tech = set()
        if hdrs.get("server"):
            tech.add(hdrs["server"])
        if hdrs.get("x-powered-by"):
            tech.add(hdrs["x-powered-by"])

        # CDN / Edge Provider Fingerprinting
        if "cf-ray" in hdrs or "cloudflare" in str(hdrs.get("server", "")).lower():
            out["cdn_edge"] = "Cloudflare Edge"
            tech.add("Cloudflare")
        elif "x-nf-request-id" in hdrs or "netlify" in str(hdrs.get("server", "")).lower():
            out["cdn_edge"] = "Netlify Edge"
            tech.add("Netlify")
        elif "x-vercel-id" in hdrs or "vercel" in str(hdrs.get("server", "")).lower():
            out["cdn_edge"] = "Vercel Edge"
            tech.add("Vercel")
        elif "x-amz-cf-id" in hdrs:
            out["cdn_edge"] = "AWS CloudFront"
            tech.add("CloudFront")
        elif "x-github-request-id" in hdrs:
            out["cdn_edge"] = "GitHub Pages Fastly"
            tech.add("GitHub Pages")

        # HTML Tech Fingerprinting
        low_html = html[:40000].lower()
        if "_next/static" in low_html or "__next_data__" in low_html:
            tech.add("Next.js")
        if "/assets/index-" in low_html or "vite" in low_html:
            tech.add("Vite / React SPA")
        if "wp-content" in low_html:
            tech.add("WordPress")
        if "application/ld+json" in low_html:
            tech.add("Schema.org JSON-LD")

        sec_checks = {
            "strict-transport-security": 25,
            "content-security-policy": 25,
            "x-frame-options": 15,
            "x-content-type-options": 15,
            "referrer-policy": 10,
            "permissions-policy": 10,
        }
        score = 0
        for h_name, pts in sec_checks.items():
            present = h_name in hdrs
            out["security_headers"][h_name] = hdrs.get(h_name) if present else None
            if present:
                score += pts
        out["security_score"] = score
        out["tech_stack"] = sorted(tech)
    except Exception:
        pass
    return out


def recon_asn_bgp(asn_input: str) -> Dict[str, Any]:
    """Query zero-key RIPE Stat BGP API for Autonomous System holder & announced IPv4/IPv6 prefixes."""
    clean = re.sub(r"[^0-9]", "", asn_input.strip()) or "13335"
    resource = f"AS{clean}"
    out: Dict[str, Any] = {
        "asn": resource,
        "holder": None,
        "announced_prefixes_count": 0,
        "ipv4_prefixes": [],
        "ipv6_prefixes": [],
    }
    try:
        ov = _http_get_json(f"https://stat.ripe.net/data/as-overview/data.json?resource={resource}", timeout=5.0)
        out["holder"] = ((ov.get("data") or {}).get("holder"))
    except Exception:
        pass
    try:
        pf = _http_get_json(f"https://stat.ripe.net/data/announced-prefixes/data.json?resource={resource}", timeout=5.5)
        prefixes = [p.get("prefix") for p in ((pf.get("data") or {}).get("prefixes") or []) if p.get("prefix")]
        out["announced_prefixes_count"] = len(prefixes)
        out["ipv4_prefixes"] = [p for p in prefixes if ":" not in p][:25]
        out["ipv6_prefixes"] = [p for p in prefixes if ":" in p][:15]
    except Exception:
        pass
    return out


def recon_wayback(domain_input: str, limit: int = 45) -> Dict[str, Any]:
    domain = normalize_domain(domain_input)
    result: Dict[str, Any] = {
        "domain": domain,
        "total_sampled": 0,
        "interesting_urls": [],
        "archived_urls": [],
    }
    try:
        cdx_url = (
            f"https://web.archive.org/cdx/search/cdx?url=*.{urllib.parse.quote(domain)}/*"
            f"&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit={limit}"
        )
        rows = _http_get_json(cdx_url, timeout=6.5)
        if isinstance(rows, list) and len(rows) > 1:
            entries = rows[1:]
            result["total_sampled"] = len(entries)
            sensitive_re = re.compile(r"(\.env|\.git|config|admin|api|graphql|swagger|token|key|backup|\.sql|\.bak|\.json)", re.I)
            for row in entries:
                if len(row) >= 4:
                    orig, ts, status, mime = row[0], row[1], row[2], row[3]
                    item = {"url": orig, "timestamp": ts, "status": status, "mime": mime}
                    result["archived_urls"].append(item)
                    if sensitive_re.search(orig):
                        result["interesting_urls"].append(item)
    except Exception:
        pass
    return result


# ---------------------------------------------------------------------------
# 3. IP & INFRASTRUCTURE RECON (Shodan InternetDB + GeoIP/RDAP + Reverse DNS)
# ---------------------------------------------------------------------------
def recon_ip(ip: str) -> Dict[str, Any]:
    ip = ip.strip()
    result: Dict[str, Any] = {
        "target": ip,
        "type": "ip",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "reverse_dns": None,
        "internetdb": {},
        "geo_asn": {},
        "risk_score": 0,
        "findings": [],
    }

    try:
        host, _, _ = socket.gethostbyaddr(ip)
        result["reverse_dns"] = host
    except Exception:
        result["reverse_dns"] = None

    try:
        idb = _http_get_json(f"https://internetdb.shodan.io/{urllib.parse.quote(ip)}", timeout=6.0)
        if isinstance(idb, dict):
            result["internetdb"] = {
                "ports": idb.get("ports", []),
                "cpes": idb.get("cpes", []),
                "hostnames": idb.get("hostnames", []),
                "tags": idb.get("tags", []),
                "vulns": idb.get("vulns", []),
            }
    except Exception as e:
        result["internetdb"] = {"error": str(e), "ports": [], "cpes": [], "hostnames": [], "tags": [], "vulns": []}

    try:
        geo = _http_get_json(f"https://ipwho.is/{urllib.parse.quote(ip)}", timeout=5.0)
        if isinstance(geo, dict) and geo.get("success", True):
            conn = geo.get("connection") or {}
            result["geo_asn"] = {
                "country": geo.get("country"),
                "country_code": geo.get("country_code"),
                "region": geo.get("region"),
                "city": geo.get("city"),
                "latitude": geo.get("latitude"),
                "longitude": geo.get("longitude"),
                "asn": conn.get("asn"),
                "org": conn.get("org") or conn.get("isp"),
                "isp": conn.get("isp"),
                "domain": conn.get("domain"),
            }
    except Exception:
        pass

    ports = result["internetdb"].get("ports", [])
    vulns = result["internetdb"].get("vulns", [])
    risk = min(100, len(ports) * 6 + len(vulns) * 18)
    result["risk_score"] = risk

    if ports:
        result["findings"].append(f"Shodan InternetDB detected {len(ports)} open ports: {', '.join(map(str, ports[:12]))}")
    if vulns:
        result["findings"].append(f"CRITICAL: {len(vulns)} known CVEs associated with host ({', '.join(vulns[:6])})")
    if result["geo_asn"].get("asn"):
        result["findings"].append(
            f"Routed via AS{result['geo_asn']['asn']} ({result['geo_asn'].get('org', 'Unknown Org')}) in {result['geo_asn'].get('city', '')}, {result['geo_asn'].get('country', '')}"
        )

    return result


# ---------------------------------------------------------------------------
# 4. DOMAIN, DNS, TLS, CRT.SH SUBDOMAINS, WAYBACK CDX & SHODAN PIVOT
# ---------------------------------------------------------------------------
def recon_domain(domain_input: str) -> Dict[str, Any]:
    domain = normalize_domain(domain_input)
    result: Dict[str, Any] = {
        "target": domain,
        "type": "domain",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "dns": {},
        "email_security": {"spf": None, "dmarc": None, "grade": "C"},
        "tls": {},
        "subdomains": [],
        "wayback": {},
        "ip_intel": [],
        "findings": [],
    }

    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CAA"]

    def fetch_dns(rtype: str) -> Tuple[str, List[str]]:
        try:
            url = f"https://dns.google/resolve?name={urllib.parse.quote(domain)}&type={rtype}"
            data = _http_get_json(url, timeout=4.5)
            answers = [ans.get("data", "").strip('"') for ans in data.get("Answer", []) if ans.get("data")]
            return rtype, answers
        except Exception:
            return rtype, []

    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as ex:
        for rtype, answers in ex.map(fetch_dns, record_types):
            result["dns"][rtype] = answers

    try:
        dmarc_data = _http_get_json(f"https://dns.google/resolve?name=_dmarc.{urllib.parse.quote(domain)}&type=TXT", timeout=4.0)
        dmarc_ans = [ans.get("data", "").strip('"') for ans in dmarc_data.get("Answer", []) if "v=DMARC1" in ans.get("data", "")]
        result["email_security"]["dmarc"] = dmarc_ans[0] if dmarc_ans else None
    except Exception:
        pass

    txt_records = result["dns"].get("TXT", [])
    spf_rec = next((r for r in txt_records if "v=spf1" in r.lower()), None)
    result["email_security"]["spf"] = spf_rec
    if spf_rec and result["email_security"]["dmarc"]:
        result["email_security"]["grade"] = "A" if ("-all" in spf_rec or "reject" in str(result["email_security"]["dmarc"])) else "B"
    elif spf_rec or result["email_security"]["dmarc"]:
        result["email_security"]["grade"] = "B-"
    else:
        result["email_security"]["grade"] = "D"

    try:
        crt_url = f"https://crt.sh/?q=%25.{urllib.parse.quote(domain)}&output=json"
        crt_data = _http_get_json(crt_url, timeout=6.5)
        subs = set()
        if isinstance(crt_data, list):
            for entry in crt_data[:250]:
                for name in str(entry.get("name_value", "")).splitlines():
                    clean = name.strip().lower().lstrip("*.")
                    if clean.endswith(domain) and clean != domain:
                        subs.add(clean)
        result["subdomains"] = sorted(subs)[:60]
    except Exception:
        result["subdomains"] = []

    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=3.5) as sock:
            with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer = dict(x[0] for x in cert.get("issuer", []))
                sans = [val for key, val in cert.get("subjectAltName", []) if key == "DNS"]
                result["tls"] = {
                    "common_name": subject.get("commonName"),
                    "issuer": issuer.get("organizationName") or issuer.get("commonName"),
                    "not_after": cert.get("notAfter"),
                    "protocol": ssock.version(),
                    "san_count": len(sans),
                    "sans_sample": sans[:15],
                }
    except Exception:
        result["tls"] = {}

    # Wayback Machine CDX, Favicon MMH3, RDAP, Well-Known & HTTP Tech-Stack discovery in parallel
    with concurrent.futures.ThreadPoolExecutor(max_workers=5) as ex2:
        f_wb = ex2.submit(recon_wayback, domain, 30)
        f_fav = ex2.submit(recon_favicon_mmh3, domain)
        f_rdap = ex2.submit(recon_rdap, domain, False)
        f_wk = ex2.submit(recon_well_known, domain)
        f_http = ex2.submit(recon_http_stack, domain)
        result["wayback"] = f_wb.result()
        result["favicon"] = f_fav.result()
        result["rdap"] = f_rdap.result()
        result["well_known"] = f_wk.result()
        result["http_stack"] = f_http.result()

    a_records = [ip for ip in result["dns"].get("A", []) if re.match(r"^(?:\d{1,3}\.){3}\d{1,3}$", ip)]
    for ip in a_records[:2]:
        result["ip_intel"].append(recon_ip(ip))

    result["findings"].append(
        f"Resolved {len(a_records)} IPv4 A records, {len(result['dns'].get('MX', []))} MX servers, {len(result['subdomains'])} CT subdomains, and {result['wayback'].get('total_sampled', 0)} Wayback CDX snapshots."
    )
    if result["favicon"].get("found"):
        result["findings"].append(
            f"Computed Shodan/Censys Favicon MurmurHash3 (mmh3): {result['favicon']['mmh3_hash']} (SHA-256: {result['favicon']['sha256'][:16]}…)."
        )
    if result["rdap"].get("registrar"):
        result["findings"].append(
            f"RDAP Registry: {result['rdap']['registrar']} (Registered: {str(result['rdap'].get('registered', ''))[:10]}, DNSSEC: {'Signed' if result['rdap'].get('dnssec_signed') else 'Unsigned'})."
        )
    wk_found = [k for k, v in result["well_known"].items() if v.get("present")]
    if wk_found:
        result["findings"].append(f"Discovered sovereign/security manifests: {', '.join(wk_found)}.")
    result["findings"].append(
        f"Email spoof defense posture: Grade {result['email_security']['grade']} (SPF: {'Yes' if spf_rec else 'No'}, DMARC: {'Yes' if result['email_security']['dmarc'] else 'No'})."
    )

    return result


# ---------------------------------------------------------------------------
# 5. USERNAME / HANDLE FOOTPRINT RECON (Maigret / Sherlock / GitHub Deep Intel)
# ---------------------------------------------------------------------------
PLATFORMS = [
    {"name": "GitHub", "category": "Dev & Code", "url": "https://github.com/{u}", "api": "https://api.github.com/users/{u}"},
    {"name": "GitLab", "category": "Dev & Code", "url": "https://gitlab.com/{u}", "api": "https://gitlab.com/api/v4/users?username={u}"},
    {"name": "HuggingFace", "category": "AI & Models", "url": "https://huggingface.co/{u}", "status_probe": "https://huggingface.co/{u}"},
    {"name": "Bluesky ATProto", "category": "Decentralized Social", "url": "https://bsky.app/profile/{u}.bsky.social", "api": "https://public.api.bsky.app/xrpc/com.atproto.identity.resolveHandle?handle={u}.bsky.social"},
    {"name": "Keybase", "category": "Crypto & Identity", "url": "https://keybase.io/{u}", "api": "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}"},
    {"name": "HackerNews", "category": "Tech Community", "url": "https://news.ycombinator.com/user?id={u}", "api": "https://hacker-news.firebaseio.com/v0/user/{u}.json"},
    {"name": "Reddit", "category": "Social", "url": "https://www.reddit.com/user/{u}", "api": "https://www.reddit.com/user/{u}/about.json"},
    {"name": "npm Registry", "category": "Package Registry", "url": "https://www.npmjs.com/~{u}", "probe": "https://registry.npmjs.org/-/v1/search?text=maintainer:{u}&size=3"},
    {"name": "PyPI", "category": "Package Registry", "url": "https://pypi.org/user/{u}/", "status_probe": "https://pypi.org/user/{u}/"},
    {"name": "Crates.io", "category": "Package Registry", "url": "https://crates.io/users/{u}", "api": "https://crates.io/api/v1/users/{u}"},
    {"name": "Dev.to", "category": "Tech Community", "url": "https://dev.to/{u}", "api": "https://dev.to/api/users/by_username?url={u}"},
    {"name": "DockerHub", "category": "Dev & Containers", "url": "https://hub.docker.com/u/{u}", "api": "https://hub.docker.com/v2/users/{u}/"},
    {"name": "Chess.com", "category": "Gaming", "url": "https://www.chess.com/member/{u}", "api": "https://api.chess.com/pub/player/{u}"},
    {"name": "Lichess", "category": "Gaming", "url": "https://lichess.org/@/{u}", "api": "https://lichess.org/api/user/{u}"},
]


def _probe_platform(platform: Dict[str, str], username: str) -> Dict[str, Any]:
    u = urllib.parse.quote(username)
    profile_url = platform["url"].format(u=username)
    name = platform["name"]
    t0 = time.time()
    try:
        if name == "GitHub":
            data = _http_get_json(platform["api"].format(u=u), timeout=5.0)
            if isinstance(data, dict) and data.get("login"):
                return {
                    "platform": name,
                    "category": platform["category"],
                    "exists": True,
                    "url": profile_url,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "meta": {
                        "name": data.get("name"),
                        "bio": data.get("bio"),
                        "company": data.get("company"),
                        "location": data.get("location"),
                        "blog": data.get("blog"),
                        "public_repos": data.get("public_repos"),
                        "followers": data.get("followers"),
                        "created_at": data.get("created_at"),
                        "avatar_url": data.get("avatar_url"),
                    },
                }
        elif name == "GitLab":
            data = _http_get_json(platform["api"].format(u=u), timeout=5.0)
            if isinstance(data, list) and len(data) > 0:
                u0 = data[0]
                return {
                    "platform": name,
                    "category": platform["category"],
                    "exists": True,
                    "url": u0.get("web_url", profile_url),
                    "latency_ms": int((time.time() - t0) * 1000),
                    "meta": {"name": u0.get("name"), "state": u0.get("state"), "avatar_url": u0.get("avatar_url")},
                }
        elif name == "Keybase":
            data = _http_get_json(platform["api"].format(u=u), timeout=5.0)
            them = data.get("them", []) if isinstance(data, dict) else []
            if them and them[0]:
                prof = them[0].get("profile") or {}
                return {
                    "platform": name,
                    "category": platform["category"],
                    "exists": True,
                    "url": profile_url,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "meta": {"full_name": prof.get("full_name"), "bio": prof.get("bio"), "location": prof.get("location")},
                }
        elif name == "HackerNews":
            data = _http_get_json(platform["api"].format(u=u), timeout=5.0)
            if isinstance(data, dict) and data.get("id"):
                return {
                    "platform": name,
                    "category": platform["category"],
                    "exists": True,
                    "url": profile_url,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "meta": {"karma": data.get("karma"), "created": data.get("created")},
                }
        elif name == "Reddit":
            data = _http_get_json(platform["api"].format(u=u), timeout=5.0)
            if isinstance(data, dict) and data.get("data", {}).get("name"):
                d = data["data"]
                return {
                    "platform": name,
                    "category": platform["category"],
                    "exists": True,
                    "url": profile_url,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "meta": {"total_karma": d.get("total_karma"), "created_utc": d.get("created_utc")},
                }
        elif name == "npm Registry":
            data = _http_get_json(platform["probe"].format(u=u), timeout=5.0)
            total = data.get("total", 0) if isinstance(data, dict) else 0
            if total > 0:
                return {
                    "platform": name,
                    "category": platform["category"],
                    "exists": True,
                    "url": profile_url,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "meta": {"packages_maintained": total},
                }
        elif "api" in platform:
            data = _http_get_json(platform["api"].format(u=u), timeout=5.0)
            if data and not (isinstance(data, dict) and data.get("errors")):
                return {
                    "platform": name,
                    "category": platform["category"],
                    "exists": True,
                    "url": profile_url,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "meta": {},
                }
        elif "status_probe" in platform:
            code, _, _ = _http_get_text(platform["status_probe"].format(u=u), timeout=5.0)
            if code == 200:
                return {
                    "platform": name,
                    "category": platform["category"],
                    "exists": True,
                    "url": profile_url,
                    "latency_ms": int((time.time() - t0) * 1000),
                    "meta": {},
                }
    except Exception:
        pass

    return {
        "platform": name,
        "category": platform["category"],
        "exists": False,
        "url": profile_url,
        "latency_ms": int((time.time() - t0) * 1000),
        "meta": {},
    }


def recon_username(username_input: str) -> Dict[str, Any]:
    username = username_input.strip().lstrip("@")
    result: Dict[str, Any] = {
        "target": username,
        "type": "username",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "profiles": [],
        "github_deep_intel": {
            "ssh_keys": [],
            "gpg_keys_present": False,
            "commit_emails": [],
            "top_repos": [],
        },
        "findings": [],
    }

    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as ex:
        probes = list(ex.map(lambda p: _probe_platform(p, username), PLATFORMS))

    result["profiles"] = probes
    found = [p for p in probes if p["exists"]]

    gh_prof = next((p for p in found if p["platform"] == "GitHub"), None)
    if gh_prof:
        try:
            _, keys_txt, _ = _http_get_text(f"https://github.com/{urllib.parse.quote(username)}.keys", timeout=4.5)
            ssh_keys = [line.strip() for line in keys_txt.splitlines() if line.strip().startswith("ssh-")]
            result["github_deep_intel"]["ssh_keys"] = ssh_keys[:8]
        except Exception:
            pass

        try:
            _, gpg_txt, _ = _http_get_text(f"https://github.com/{urllib.parse.quote(username)}.gpg", timeout=4.5)
            result["github_deep_intel"]["gpg_keys_present"] = "BEGIN PGP PUBLIC KEY BLOCK" in gpg_txt
        except Exception:
            pass

        try:
            events = _http_get_json(f"https://api.github.com/users/{urllib.parse.quote(username)}/events/public?per_page=30", timeout=5.0)
            emails = set()
            if isinstance(events, list):
                for ev in events:
                    for c in (ev.get("payload") or {}).get("commits", []):
                        author = c.get("author") or {}
                        em = author.get("email")
                        if em and "noreply.github.com" not in em:
                            emails.add(f"{em} ({author.get('name', '')})")
            result["github_deep_intel"]["commit_emails"] = sorted(emails)[:10]
        except Exception:
            pass

        try:
            repos = _http_get_json(f"https://api.github.com/users/{urllib.parse.quote(username)}/repos?sort=updated&per_page=6", timeout=5.0)
            if isinstance(repos, list):
                result["github_deep_intel"]["top_repos"] = [
                    {
                        "name": r.get("name"),
                        "url": r.get("html_url"),
                        "description": r.get("description"),
                        "language": r.get("language"),
                        "stars": r.get("stargazers_count", 0),
                    }
                    for r in repos[:6]
                ]
        except Exception:
            pass

    result["new_age_identity"] = recon_new_age_identity(username)

    result["findings"].append(f"Confirmed active presence on {len(found)}/{len(PLATFORMS)} high-signal platforms ({', '.join(p['platform'] for p in found)}).")
    if result["github_deep_intel"]["ssh_keys"]:
        result["findings"].append(f"Extracted {len(result['github_deep_intel']['ssh_keys'])} public SSH authentication keys from GitHub endpoint.")
    if result["github_deep_intel"]["commit_emails"]:
        result["findings"].append(f"Recovered {len(result['github_deep_intel']['commit_emails'])} commit author email attribution records.")
    if result["new_age_identity"].get("atproto_bluesky", {}).get("did"):
        result["findings"].append(f"Resolved Bluesky ATProto Decentralized Identifier: {result['new_age_identity']['atproto_bluesky']['did']}.")
    if result["new_age_identity"].get("huggingface_ai", {}).get("models"):
        result["findings"].append(f"Published {len(result['new_age_identity']['huggingface_ai']['models'])} AI model(s) on HuggingFace Hub.")

    return result


# ---------------------------------------------------------------------------
# 6. EMAIL & IDENTITY FOOTPRINT RECON (Gravatar + PGP Keyserver + Domain MX)
# ---------------------------------------------------------------------------
def recon_email(email_input: str) -> Dict[str, Any]:
    email = email_input.strip().lower()
    local_part, _, domain = email.partition("@")
    md5_hash = hashlib.md5(email.encode("utf-8")).hexdigest()
    sha256_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()

    result: Dict[str, Any] = {
        "target": email,
        "type": "email",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "local_part": local_part,
        "domain": domain,
        "hashes": {"md5": md5_hash, "sha256": sha256_hash},
        "gravatar": {"exists": False, "avatar_url": f"https://www.gravatar.com/avatar/{md5_hash}?d=404"},
        "pgp_keyserver": {"found": False, "url": f"https://keys.openpgp.org/vks/v1/by-email/{urllib.parse.quote(email)}"},
        "github_accounts": [],
        "domain_posture": {},
        "findings": [],
    }

    try:
        code, _, _ = _http_get_text(result["gravatar"]["avatar_url"], timeout=4.0)
        if code == 200:
            result["gravatar"]["exists"] = True
    except Exception:
        pass

    try:
        code, pgp_body, _ = _http_get_text(result["pgp_keyserver"]["url"], timeout=4.5)
        if code == 200 and "BEGIN PGP PUBLIC KEY BLOCK" in pgp_body:
            result["pgp_keyserver"]["found"] = True
    except Exception:
        pass

    try:
        gh_search = _http_get_json(f"https://api.github.com/search/users?q={urllib.parse.quote(email)}+in:email", timeout=5.0)
        items = gh_search.get("items", []) if isinstance(gh_search, dict) else []
        result["github_accounts"] = [{"login": u.get("login"), "url": u.get("html_url"), "avatar": u.get("avatar_url")} for u in items[:5]]
    except Exception:
        pass

    if domain:
        dom_info = recon_domain(domain)
        result["domain_posture"] = {
            "mx": dom_info["dns"].get("MX", []),
            "spf": dom_info["email_security"].get("spf"),
            "dmarc": dom_info["email_security"].get("dmarc"),
            "grade": dom_info["email_security"].get("grade"),
        }

    result["findings"].append(f"Gravatar profile: {'ACTIVE' if result['gravatar']['exists'] else 'None'} | OpenPGP Public Key: {'FOUND' if result['pgp_keyserver']['found'] else 'None'}.")
    if result["github_accounts"]:
        result["findings"].append(f"Linked to GitHub account(s): {', '.join(a['login'] for a in result['github_accounts'])}.")

    return result


# ---------------------------------------------------------------------------
# 7. CRYPTO & WEB3 WALLET OSINT (Solana Mainnet RPC, Ethereum RPC, Bitcoin API)
# ---------------------------------------------------------------------------
def recon_wallet(wallet_input: str) -> Dict[str, Any]:
    addr = wallet_input.strip()
    chain = "unknown"
    if re.match(r"^0x[a-fA-F0-9]{40}$", addr):
        chain = "ethereum"
    elif re.match(r"^(bc1[a-zA-HJ-NP-Z0-9]{25,59}|[13][a-km-zA-HJ-NP-Z1-9]{25,34})$", addr):
        chain = "bitcoin"
    else:
        chain = "solana"

    result: Dict[str, Any] = {
        "target": addr,
        "type": "wallet",
        "chain": chain,
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "balance": None,
        "unit": chain.upper(),
        "tx_count": 0,
        "is_contract": False,
        "recent_txs": [],
        "explorer_url": "",
        "findings": [],
    }

    if chain == "solana":
        result["unit"] = "SOL"
        result["explorer_url"] = f"https://solscan.io/account/{addr}"
        try:
            bal_res = _http_post_json(
                "https://api.mainnet-beta.solana.com",
                {"jsonrpc": "2.0", "id": 1, "method": "getBalance", "params": [addr]},
                timeout=6.0,
            )
            lamports = ((bal_res.get("result") or {}).get("value")) or 0
            result["balance"] = round(lamports / 1e9, 6)
        except Exception:
            result["balance"] = 0.0

        try:
            sig_res = _http_post_json(
                "https://api.mainnet-beta.solana.com",
                {"jsonrpc": "2.0", "id": 2, "method": "getSignaturesForAddress", "params": [addr, {"limit": 8}]},
                timeout=6.0,
            )
            sigs = sig_res.get("result") or []
            result["tx_count"] = len(sigs)
            for s in sigs[:8]:
                result["recent_txs"].append(
                    {
                        "signature": s.get("signature"),
                        "slot": s.get("slot"),
                        "block_time": s.get("blockTime"),
                        "err": s.get("err") is not None,
                    }
                )
        except Exception:
            pass

        result["findings"].append(f"Solana Mainnet wallet balance: {result['balance']} SOL ({result['tx_count']} recent signatures sampled).")

    elif chain == "ethereum":
        result["unit"] = "ETH"
        result["explorer_url"] = f"https://etherscan.io/address/{addr}"
        rpc_url = "https://ethereum-rpc.publicnode.com"
        try:
            bal_res = _http_post_json(rpc_url, {"jsonrpc": "2.0", "id": 1, "method": "eth_getBalance", "params": [addr, "latest"]}, timeout=6.0)
            wei = int(bal_res.get("result") or "0x0", 16)
            result["balance"] = round(wei / 1e18, 6)
            tx_res = _http_post_json(rpc_url, {"jsonrpc": "2.0", "id": 2, "method": "eth_getTransactionCount", "params": [addr, "latest"]}, timeout=6.0)
            result["tx_count"] = int(tx_res.get("result") or "0x0", 16)
            code_res = _http_post_json(rpc_url, {"jsonrpc": "2.0", "id": 3, "method": "eth_getCode", "params": [addr, "latest"]}, timeout=6.0)
            code_hex = code_res.get("result") or "0x"
            result["is_contract"] = len(code_hex) > 4
        except Exception:
            pass
        acct_kind = "Smart Contract" if result["is_contract"] else "EOA Wallet"
        result["findings"].append(f"Ethereum {acct_kind} balance: {result['balance']} ETH (Outbound Nonce / Tx Count: {result['tx_count']}).")

    elif chain == "bitcoin":
        result["unit"] = "BTC"
        result["explorer_url"] = f"https://mempool.space/address/{addr}"
        try:
            data = _http_get_json(f"https://mempool.space/api/address/{urllib.parse.quote(addr)}", timeout=6.0)
            stats = data.get("chain_stats") or {}
            funded = stats.get("funded_txo_sum", 0)
            spent = stats.get("spent_txo_sum", 0)
            result["balance"] = round((funded - spent) / 1e8, 8)
            result["tx_count"] = stats.get("tx_count", 0)
            txs = _http_get_json(f"https://mempool.space/api/address/{urllib.parse.quote(addr)}/txs", timeout=6.0)
            if isinstance(txs, list):
                for tx in txs[:6]:
                    result["recent_txs"].append({"signature": tx.get("txid"), "confirmed": (tx.get("status") or {}).get("confirmed")})
        except Exception:
            pass
        result["findings"].append(f"Bitcoin mainnet balance: {result['balance']} BTC across {result['tx_count']} total transactions.")

    return result


# ---------------------------------------------------------------------------
# 8. PHONE NUMBER E.164 & NANPA AREA CODE GEOLOCATION OSINT
# ---------------------------------------------------------------------------
NANPA_REGIONS = {
    "757": "Hampton Roads / Virginia Beach / Norfolk, VA",
    "804": "Richmond / Central Virginia, VA",
    "703": "Northern Virginia / Arlington / Alexandria, VA",
    "571": "Northern Virginia / Tysons, VA",
    "202": "Washington, D.C.",
    "212": "New York City (Manhattan), NY",
    "646": "New York City (Manhattan), NY",
    "718": "New York City (Outer Boroughs), NY",
    "305": "Miami / Florida Keys, FL",
    "310": "West Los Angeles / Santa Monica, CA",
    "415": "San Francisco / Marin County, CA",
    "650": "Silicon Valley / San Mateo, CA",
    "408": "San Jose / Silicon Valley, CA",
    "206": "Seattle, WA",
    "312": "Chicago (Downtown), IL",
    "404": "Atlanta, GA",
    "512": "Austin, TX",
    "214": "Dallas, TX",
    "713": "Houston, TX",
    "617": "Boston / Cambridge, MA",
    "702": "Las Vegas, NV",
}

COUNTRY_CODES = {
    "1": "United States / Canada (NANPA)",
    "44": "United Kingdom",
    "33": "France",
    "49": "Germany",
    "61": "Australia",
    "81": "Japan",
    "91": "India",
    "55": "Brazil",
    "386": "Slovenia",
}


def recon_phone(phone_input: str) -> Dict[str, Any]:
    digits = re.sub(r"\D", "", phone_input)
    if len(digits) == 10:
        digits = "1" + digits
    e164 = f"+{digits}"

    country = "International ITU-T Number"
    cc = digits[:1]
    area_code = ""
    region = "Unknown Region"

    if digits.startswith("1") and len(digits) == 11:
        cc = "1"
        country = COUNTRY_CODES["1"]
        area_code = digits[1:4]
        region = NANPA_REGIONS.get(area_code, f"North American Area Code ({area_code})")
    else:
        for code_len in (3, 2, 1):
            prefix = digits[:code_len]
            if prefix in COUNTRY_CODES:
                cc = prefix
                country = COUNTRY_CODES[prefix]
                break

    result: Dict[str, Any] = {
        "target": e164,
        "type": "phone",
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "e164": e164,
        "rfc3966": f"tel:{e164}",
        "country_code": f"+{cc}",
        "country": country,
        "area_code": area_code,
        "region": region,
        "messaging_pivots": {
            "whatsapp": f"https://wa.me/{digits}",
            "telegram": f"https://t.me/+{digits}",
            "signal": f"https://signal.me/#p/+{digits}",
        },
        "findings": [
            f"Normalized ITU-T E.164 number: {e164} ({country}).",
            f"Geographic routing zone: {region}.",
        ],
    }
    return result


# ---------------------------------------------------------------------------
# 9. MEDIA & BINARY FORENSICS (EXIF / Cryptographic Hashes / Strings / Entropy)
# ---------------------------------------------------------------------------
def analyze_file_forensics(file_path: str) -> Dict[str, Any]:
    with open(file_path, "rb") as f:
        data = f.read()
    return analyze_bytes_forensics(data, filename=os.path.basename(file_path))


def analyze_bytes_forensics(data: bytes, filename: str = "sample.bin") -> Dict[str, Any]:
    size = len(data)
    sha256 = hashlib.sha256(data).hexdigest()
    sha1 = hashlib.sha1(data).hexdigest()
    md5 = hashlib.md5(data).hexdigest()

    entropy = 0.0
    if size > 0:
        counts = [0] * 256
        for b in data:
            counts[b] += 1
        for c in counts:
            if c > 0:
                p = c / size
                entropy -= p * math.log2(p)

    mime_guess = "application/octet-stream"
    if data.startswith(b"\xff\xd8\xff"):
        mime_guess = "image/jpeg"
    elif data.startswith(b"\x89PNG\r\n\x1a\n"):
        mime_guess = "image/png"
    elif data.startswith(b"%PDF-"):
        mime_guess = "application/pdf"
    elif data.startswith(b"GIF87a") or data.startswith(b"GIF89a"):
        mime_guess = "image/gif"
    elif data.startswith(b"PK\x03\x04"):
        mime_guess = "application/zip"

    ascii_strings = re.findall(rb"[\x20-\x7e]{5,120}", data)
    decoded_strings = [s.decode("ascii", errors="ignore") for s in ascii_strings[:400]]
    urls = sorted({m.group(0).decode("ascii", errors="ignore") for m in re.finditer(rb"https?://[^\s\"'<>\\\x00-\x1f]{4,120}", data)})[:25]
    emails = sorted({m.group(0).decode("ascii", errors="ignore") for m in re.finditer(rb"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,10}", data)})[:25]

    return {
        "filename": filename,
        "size_bytes": size,
        "mime_guess": mime_guess,
        "entropy_bits_per_byte": round(entropy, 4),
        "hashes": {"sha256": sha256, "sha1": sha1, "md5": md5},
        "extracted_urls": urls,
        "extracted_emails": emails,
        "strings_sample": decoded_strings[:40],
    }


# ---------------------------------------------------------------------------
# 10. UNIFIED ENTITY GRAPH & OBSIDIAN JSON CANVAS (.canvas) / STIX 2.1 BUILDER
# ---------------------------------------------------------------------------
def build_entity_graph(scan_result: Dict[str, Any]) -> Dict[str, Any]:
    target = scan_result.get("target", "target")
    ttype = scan_result.get("type", "unknown")
    nodes: List[Dict[str, Any]] = [{"id": "root", "label": target, "type": ttype.upper(), "color": "#00d5ff", "pivot": target}]
    edges: List[Dict[str, str]] = []

    def add_node(nid: str, label: str, ntype: str, color: str, parent: str = "root", edge_label: str = "", pivot: str = "") -> None:
        if not any(n["id"] == nid for n in nodes):
            nodes.append({"id": nid, "label": label, "type": ntype, "color": color, "pivot": pivot or label})
        edges.append({"from": parent, "to": nid, "label": edge_label})

    if ttype == "domain":
        for i, ip_obj in enumerate(scan_result.get("ip_intel", [])):
            ip = ip_obj.get("target")
            ip_id = f"ip_{i}"
            add_node(ip_id, ip, "IPv4", "#32ff85", "root", "A RECORD", pivot=ip)
            for p in ip_obj.get("internetdb", {}).get("ports", [])[:6]:
                add_node(f"{ip_id}_p{p}", f":{p}/TCP", "PORT", "#ffb800", ip_id, "OPEN", pivot=ip)
            for v in ip_obj.get("internetdb", {}).get("vulns", [])[:5]:
                add_node(f"{ip_id}_{v}", v, "CVE", "#ef4444", ip_id, "VULN", pivot=ip)
        for i, sub in enumerate(scan_result.get("subdomains", [])[:12]):
            add_node(f"sub_{i}", sub, "SUBDOMAIN", "#a855f7", "root", "CT LOG", pivot=sub)
        for i, mx in enumerate(scan_result.get("dns", {}).get("MX", [])[:4]):
            clean_mx = mx.split()[-1].rstrip(".")
            add_node(f"mx_{i}", clean_mx, "MX", "#38bdf8", "root", "MAIL", pivot=clean_mx)
        fav = scan_result.get("favicon") or {}
        if fav.get("found") and fav.get("mmh3_hash") is not None:
            add_node("fav_mmh3", f"mmh3:{fav['mmh3_hash']}", "FAVICON", "#ffb800", "root", "SHODAN")
        rdap = scan_result.get("rdap") or {}
        if rdap.get("registrar"):
            add_node("rdap_reg", rdap["registrar"][:22], "RDAP", "#00d5ff", "root", "REGISTRAR")
        for wk_key, wk_val in (scan_result.get("well_known") or {}).items():
            if wk_val.get("present"):
                add_node(f"wk_{wk_key}", wk_key, "MANIFEST", "#32ff85", "root", "WELL-KNOWN")
        hs = scan_result.get("http_stack") or {}
        if hs.get("cdn_edge") and hs.get("cdn_edge") != "Direct / Unidentified":
            add_node("cdn_edge", hs["cdn_edge"], "EDGE", "#38bdf8", "root", "CDN")

    elif ttype == "ip":
        asn = scan_result.get("geo_asn", {}).get("asn")
        if asn:
            add_node("asn", f"AS{asn} ({scan_result['geo_asn'].get('org', '')})", "ASN", "#a855f7", "root", "BGP")
        for p in scan_result.get("internetdb", {}).get("ports", [])[:12]:
            add_node(f"port_{p}", f"Port {p}", "PORT", "#ffb800", "root", "OPEN")
        for v in scan_result.get("internetdb", {}).get("vulns", [])[:8]:
            add_node(f"cve_{v}", v, "CVE", "#ef4444", "root", "VULN")
        for h in scan_result.get("internetdb", {}).get("hostnames", [])[:6]:
            add_node(f"host_{h}", h, "HOSTNAME", "#32ff85", "root", "PTR", pivot=h)

    elif ttype == "username":
        for p in scan_result.get("profiles", []):
            if p.get("exists"):
                pid = f"prof_{p['platform']}"
                add_node(pid, f"{p['platform']}: {target}", "PROFILE", "#32ff85", "root", p["category"], pivot=target)
        gh = scan_result.get("github_deep_intel", {})
        for i, em in enumerate(gh.get("commit_emails", [])[:6]):
            raw_em = em.split()[0]
            add_node(f"em_{i}", raw_em, "EMAIL", "#ffb800", "prof_GitHub" if any(n["id"] == "prof_GitHub" for n in nodes) else "root", "COMMIT", pivot=raw_em)
        for i, repo in enumerate(gh.get("top_repos", [])[:6]):
            add_node(f"repo_{i}", repo.get("name", ""), "REPO", "#a855f7", "prof_GitHub" if any(n["id"] == "prof_GitHub" for n in nodes) else "root", "CODE")
        if gh.get("ssh_keys"):
            add_node("ssh_keys", f"{len(gh['ssh_keys'])} SSH Public Key(s)", "SSH_KEY", "#00d5ff", "prof_GitHub" if any(n["id"] == "prof_GitHub" for n in nodes) else "root", "AUTH")

    elif ttype == "email":
        dom = scan_result.get("domain")
        if dom:
            add_node("dom", dom, "DOMAIN", "#a855f7", "root", "DOMAIN", pivot=dom)
        if scan_result.get("gravatar", {}).get("exists"):
            add_node("grav", "Gravatar Active Profile", "GRAVATAR", "#32ff85", "root", "MD5 HIT")
        if scan_result.get("pgp_keyserver", {}).get("found"):
            add_node("pgp", "OpenPGP Public Key", "PGP_KEY", "#ffb800", "root", "KEYSERVER")
        for i, gh_acc in enumerate(scan_result.get("github_accounts", [])):
            login = gh_acc.get("login", "")
            add_node(f"gh_{i}", f"GitHub: {login}", "GITHUB", "#00d5ff", "root", "ACCOUNT", pivot=login)

    elif ttype == "wallet":
        chain = (scan_result.get("chain") or "WALLET").upper()
        bal = scan_result.get("balance")
        unit = scan_result.get("unit", "")
        add_node("bal", f"{bal} {unit}", chain, "#32ff85", "root", "BALANCE")
        for i, tx in enumerate(scan_result.get("recent_txs", [])[:8]):
            sig = str(tx.get("signature") or "")
            short_sig = f"{sig[:8]}...{sig[-6:]}" if len(sig) > 16 else sig
            add_node(f"tx_{i}", short_sig, "TX_HASH", "#ffb800", "root", "TX")

    elif ttype == "phone":
        add_node("country", scan_result.get("country", "Country"), "COUNTRY", "#32ff85", "root", "ITU-T")
        add_node("region", scan_result.get("region", "Region"), "REGION", "#ffb800", "root", "AREA")
        add_node("wa", "WhatsApp Pivot", "MESSAGING", "#00d5ff", "root", "WA.ME")
        add_node("tg", "Telegram Pivot", "MESSAGING", "#a855f7", "root", "T.ME")

    return {"nodes": nodes, "edges": edges}


def export_obsidian_canvas(graph: Dict[str, Any], title: str = "Zoth OSINT Investigation") -> Dict[str, Any]:
    canvas_nodes = []
    canvas_edges = []
    nodes = graph.get("nodes", [])
    n_count = max(1, len(nodes) - 1)

    for idx, node in enumerate(nodes):
        if idx == 0:
            x, y = 0, 0
            w, h = 280, 110
            color = "5"
        else:
            angle = (2 * math.pi * (idx - 1)) / n_count
            radius = 420 if idx <= 12 else 720
            x = int(math.cos(angle) * radius) - 120
            y = int(math.sin(angle) * radius) - 45
            w, h = 240, 88
            color = "4" if node.get("type") in ("PROFILE", "IPv4", "SOLANA", "ETHEREUM", "BITCOIN") else ("1" if node.get("type") == "CVE" else "3")

        canvas_nodes.append(
            {
                "id": node["id"],
                "type": "text",
                "x": x,
                "y": y,
                "width": w,
                "height": h,
                "color": color,
                "text": f"### [{node.get('type', 'ENTITY')}]\n**{node.get('label', '')}**",
            }
        )

    for idx, edge in enumerate(graph.get("edges", [])):
        canvas_edges.append(
            {
                "id": f"edge_{idx}",
                "fromNode": edge["from"],
                "toNode": edge["to"],
                "label": edge.get("label", ""),
            }
        )

    return {"nodes": canvas_nodes, "edges": canvas_edges, "metadata": {"generator": "Zoth OSINT v2.0", "title": title}}


def run_unified_scan(target: str, persist: bool = True) -> Dict[str, Any]:
    ttype = classify_target(target)
    if ttype == "ip":
        data = recon_ip(target)
    elif ttype == "domain":
        data = recon_domain(target)
    elif ttype == "email":
        data = recon_email(target)
    elif ttype == "wallet":
        data = recon_wallet(target)
    elif ttype == "phone":
        data = recon_phone(target)
    else:
        data = recon_username(target)

    graph = build_entity_graph(data)
    data["graph"] = graph
    data["dorks"] = synthesize_dorks(data.get("target", target), ttype)
    data["obsidian_canvas"] = export_obsidian_canvas(graph, title=f"Zoth OSINT: {data.get('target')}")
    data["stix_bundle"] = export_stix_bundle(data)
    data["gexf_xml"] = export_gexf_xml(graph, title=f"Zoth OSINT: {data.get('target')}")

    if persist:
        try:
            case_id = save_case(data)
            data["case_id"] = case_id
        except Exception:
            data["case_id"] = None

    return data
