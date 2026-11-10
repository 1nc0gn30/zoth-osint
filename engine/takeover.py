#!/usr/bin/env python3
"""
Zoth OSINT Subdomain Takeover & Dangling DNS Engine (engine/takeover.py)
Audits active and passive subdomains for dangling CNAME pointers and 23+ vulnerable
SaaS fingerprints (GitHub Pages, AWS S3, Heroku, Netlify, Fastly, Ghost, Surge,
Shopify, Vercel, Bitbucket, Zendesk, HubSpot, WordPress, Tumblr, Unbounce, Azure,
Fly.io, Pantheon, ReadMe, Help Scout, Cargo, Render, Firebase) with zero pip dependencies.

Engineered by 1nc0gn30 (@1nc0gn30) • NullAI Platform
"""

import concurrent.futures
import datetime
import json
import re
import socket
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

USER_AGENT = "Mozilla/5.0 (X11; Linux x86_64) ZothOSINT/3.0 TakeoverScanner (+https://nullai.tech)"

# ---------------------------------------------------------------------------
# 1. COMPREHENSIVE SAAS TAKEOVER FINGERPRINT CATALOG
# ---------------------------------------------------------------------------
TAKEOVER_SIGNATURES: List[Dict[str, Any]] = [
    {
        "service": "GitHub Pages",
        "cname": ["github.io", "github.map.fastly.net"],
        "fingerprints": [
            "There isn't a GitHub Pages site here",
            "For root URLs (like http://example.com/) you must provide an index.html file",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to GitHub Pages but no repository is configured with this custom CNAME.",
    },
    {
        "service": "AWS S3",
        "cname": ["s3.amazonaws.com", "s3-website", "s3.dualstack", ".s3-", "s3-website-"],
        "fingerprints": [
            "<Code>NoSuchBucket</Code>",
            "The specified bucket does not exist",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unclaimed, deleted, or unconfigured Amazon S3 bucket.",
    },
    {
        "service": "Heroku",
        "cname": ["herokuapp.com", "herokussl.com", "herokudns.com"],
        "fingerprints": [
            "No such app",
            "herokucdn.com/error-pages/no-such-app.html",
            "There's nothing here, yet",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unallocated or terminated Heroku app.",
    },
    {
        "service": "Netlify",
        "cname": ["netlify.app", "netlify.com"],
        "fingerprints": [
            "Not Found - Request ID:",
            "page not found",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to Netlify but the domain is not claimed by any active site.",
    },
    {
        "service": "Fastly",
        "cname": ["fastly.net"],
        "fingerprints": [
            "Fastly error: unknown domain",
            "The Fastly VCL configuration for this domain",
        ],
        "severity": "MEDIUM",
        "discussion": "Dangling Fastly CNAME; Fastly CDN service is not configured for this hostname.",
    },
    {
        "service": "Ghost",
        "cname": ["ghost.io"],
        "fingerprints": [
            "The thing you were looking for is no longer here, or never was",
            "ghost.org/404",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to a Ghost(Pro) publication that has been removed or renamed.",
    },
    {
        "service": "Surge.sh",
        "cname": ["surge.sh"],
        "fingerprints": [
            "project not found",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to Surge.sh static hosting project that is unallocated.",
    },
    {
        "service": "Shopify",
        "cname": ["myshopify.com"],
        "fingerprints": [
            "Sorry, this shop is currently unavailable",
            "Only one step left!",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an inactive or unregistered Shopify storefront.",
    },
    {
        "service": "Vercel",
        "cname": ["vercel.app", "cname.vercel-dns.com", "vercel-dns.com"],
        "fingerprints": [
            "404: NOT_FOUND",
            "The deployment could not be found",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to Vercel without an active deployment or domain configuration.",
    },
    {
        "service": "Bitbucket",
        "cname": ["bitbucket.io"],
        "fingerprints": [
            "Repository not found",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unclaimed Bitbucket Cloud Pages repository.",
    },
    {
        "service": "Zendesk",
        "cname": ["zendesk.com"],
        "fingerprints": [
            "Help Center Closed",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an expired or unmapped Zendesk help center.",
    },
    {
        "service": "HubSpot",
        "cname": ["hubspot.net"],
        "fingerprints": [
            "Domain not found",
            "is not mapped to a connected domain",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to HubSpot without domain binding.",
    },
    {
        "service": "WordPress.com",
        "cname": ["wordpress.com"],
        "fingerprints": [
            "Do you want to register",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unregistered WordPress.com site.",
    },
    {
        "service": "Tumblr",
        "cname": ["tumblr.com"],
        "fingerprints": [
            "Whatever you were looking for doesn't seem to exist at this address",
        ],
        "severity": "MEDIUM",
        "discussion": "Subdomain points to an unclaimed Tumblr blog.",
    },
    {
        "service": "Unbounce",
        "cname": ["unbouncepages.com"],
        "fingerprints": [
            "The requested URL was not found on this server",
            "The requested page is not available",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unmapped Unbounce landing page.",
    },
    {
        "service": "Fly.io",
        "cname": ["fly.dev", "edgeapp.net"],
        "fingerprints": [
            "404 Not Found",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unclaimed Fly.io application.",
    },
    {
        "service": "Microsoft Azure",
        "cname": ["azurewebsites.net", "cloudapp.net", "trafficmanager.net", "blob.core.windows.net", "azureedge.net"],
        "fingerprints": [
            "404 Web Site not found",
            "The specified container does not exist",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to a deleted Microsoft Azure Web App, Storage Blob, or Traffic Manager.",
    },
    {
        "service": "Pantheon",
        "cname": ["pantheonsite.io"],
        "fingerprints": [
            "404 error unknown site!",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unprovisioned Pantheon site.",
    },
    {
        "service": "ReadMe.io",
        "cname": ["readme.io"],
        "fingerprints": [
            "Project doesnt exist",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unclaimed ReadMe.io documentation site.",
    },
    {
        "service": "Help Scout",
        "cname": ["helpscoutdocs.com"],
        "fingerprints": [
            "No settings were found for this company",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unmapped Help Scout Docs site.",
    },
    {
        "service": "Cargo Collective",
        "cname": ["cargocollective.com"],
        "fingerprints": [
            "If you're moving your domain to Cargo",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unassigned Cargo site.",
    },
    {
        "service": "Render",
        "cname": ["onrender.com"],
        "fingerprints": [
            "Render 404: Not Found",
            "This site is not available",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to a deleted or suspended Render service.",
    },
    {
        "service": "Firebase Hosting",
        "cname": ["firebaseapp.com", "web.app"],
        "fingerprints": [
            "Site Not Found",
        ],
        "severity": "HIGH",
        "discussion": "Subdomain points to an unclaimed or deleted Firebase Hosting project.",
    },
]

# ---------------------------------------------------------------------------
# 2. DNS-OVER-HTTPS (DoH) & SOCKET RESOLUTION HELPERS
# ---------------------------------------------------------------------------
def _resolve_cname(subdomain: str, timeout: float = 2.5) -> Tuple[Optional[str], Optional[int]]:
    """Resolve CNAME for a subdomain using Google DoH with pure-Python socket fallback."""
    sub = subdomain.strip().lower().rstrip(".")
    cname: Optional[str] = None
    status: Optional[int] = None

    # Step 1: Query Google DoH specifically for CNAME (Type 5)
    try:
        url = f"https://dns.google/resolve?name={urllib.parse.quote(sub)}&type=CNAME"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            status = data.get("Status")
            for ans in data.get("Answer", []):
                if ans.get("type") == 5:
                    cname = str(ans.get("data", "")).strip().rstrip(".")
                    break
                elif ans.get("data") and not re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", ans.get("data")):
                    cname = str(ans.get("data", "")).strip().rstrip(".")
    except Exception:
        pass

    # Step 2: Query Google DoH for A record (often returns CNAME chain in Answer)
    if not cname:
        try:
            url_a = f"https://dns.google/resolve?name={urllib.parse.quote(sub)}&type=A"
            req_a = urllib.request.Request(url_a, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
            with urllib.request.urlopen(req_a, timeout=timeout) as resp:
                data_a = json.loads(resp.read().decode("utf-8", errors="replace"))
                if status is None:
                    status = data_a.get("Status")
                for ans in data_a.get("Answer", []):
                    if ans.get("type") == 5:
                        cname = str(ans.get("data", "")).strip().rstrip(".")
                        break
        except Exception:
            pass

    # Step 3: Pure Python socket fallback
    if not cname:
        try:
            canonical, _, _ = socket.gethostbyname_ex(sub)
            if canonical and canonical.lower().rstrip(".") != sub:
                cname = canonical.lower().rstrip(".")
        except Exception:
            pass

    return cname, status


def _is_cname_target_nxdomain(cname_target: str, timeout: float = 2.0) -> bool:
    """Check if the CNAME destination host resolves to NXDOMAIN (Status 3)."""
    target = cname_target.strip().lower().rstrip(".")
    try:
        url = f"https://dns.google/resolve?name={urllib.parse.quote(target)}&type=A"
        req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "application/json"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8", errors="replace"))
            # Status 3 is NXDOMAIN; Status 0 with empty Answer can also indicate non-existent A records
            if data.get("Status") == 3:
                return True
            if data.get("Status") == 0 and not data.get("Answer"):
                return True
    except Exception:
        pass
    return False


def _probe_http(host: str, timeout: float = 2.5) -> Tuple[Optional[int], str, Dict[str, str]]:
    """Probe host over HTTPS and HTTP with relaxed SSL context to capture status code & body text."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    for scheme in ("https", "http"):
        url = f"{scheme}://{host}"
        req = urllib.request.Request(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
                status = resp.status
                body = resp.read(65536).decode("utf-8", errors="replace")
                headers = {k.lower(): v for k, v in resp.headers.items()}
                return status, body, headers
        except urllib.error.HTTPError as e:
            try:
                body = e.read(65536).decode("utf-8", errors="replace")
            except Exception:
                body = ""
            headers = {k.lower(): v for k, v in e.headers.items()} if hasattr(e, "headers") else {}
            return e.code, body, headers
        except Exception:
            continue
    return None, "", {}


# ---------------------------------------------------------------------------
# 3. SINGLE SUBDOMAIN AUDITOR
# ---------------------------------------------------------------------------
def audit_single_subdomain(subdomain: str, timeout: float = 3.0) -> Dict[str, Any]:
    """Audit a single subdomain for CNAME delegation, dangling pointers, and SaaS takeovers."""
    sub = subdomain.strip().lower().rstrip(".")
    if not sub:
        return {"subdomain": "", "has_cname": False, "status": "INVALID", "confidence": "NONE"}

    cname, dns_status = _resolve_cname(sub, timeout=min(2.5, timeout))

    if not cname:
        return {
            "subdomain": sub,
            "has_cname": False,
            "cname": None,
            "status": "SAFE",
            "service": None,
            "fingerprint_matched": None,
            "is_nxdomain": False,
            "http_status": None,
            "confidence": "SAFE",
            "severity": "NONE",
            "reason": "Direct A/AAAA record or unmapped host; no CNAME delegation.",
            "discussion": "No CNAME delegation found.",
        }

    # Match CNAME against known SaaS provider signatures
    cname_lower = cname.lower()
    matched_sig = next((sig for sig in TAKEOVER_SIGNATURES if any(pat in cname_lower for pat in sig["cname"])), None)

    # Check if target domain is an NXDOMAIN
    is_nxdomain = _is_cname_target_nxdomain(cname, timeout=min(2.0, timeout))

    # Probe HTTP on subdomain (and CNAME destination if subdomain is quiet)
    http_status, http_body, http_headers = _probe_http(sub, timeout=min(2.5, timeout))
    if not http_body and not is_nxdomain:
        cname_status, cname_body, cname_headers = _probe_http(cname, timeout=min(2.0, timeout))
        if cname_body:
            http_status = http_status or cname_status
            http_body = cname_body
            http_headers = http_headers or cname_headers

    # Check for known fingerprint strings
    matched_fp: Optional[str] = None
    matched_service_name: Optional[str] = matched_sig["service"] if matched_sig else None

    if matched_sig and http_body:
        for fp in matched_sig["fingerprints"]:
            if fp.lower() in http_body.lower():
                matched_fp = fp
                break

    # If no fingerprint matched with current service, check all signatures against body
    if not matched_fp and http_body:
        for sig in TAKEOVER_SIGNATURES:
            for fp in sig["fingerprints"]:
                if fp.lower() in http_body.lower():
                    matched_fp = fp
                    matched_service_name = sig["service"]
                    matched_sig = sig
                    break
            if matched_fp:
                break

    # Determine vulnerability status
    if matched_fp:
        status = "VULNERABLE"
        confidence = "CONFIRMED"
        severity = matched_sig["severity"] if matched_sig else "HIGH"
        reason = f"Confirmed {matched_service_name} takeover signature: '{matched_fp}'"
        action = matched_sig.get("discussion") or f"Claim orphaned resource on {matched_service_name} or remove CNAME."
    elif is_nxdomain:
        status = "DANGLING_NXDOMAIN"
        confidence = "HIGH"
        severity = "HIGH"
        matched_service_name = matched_service_name or "Dangling External CNAME"
        reason = f"CNAME target '{cname}' does not resolve (NXDOMAIN)"
        action = f"Remove stale CNAME pointing to non-existent domain '{cname}' to prevent orphan hijacking."
    elif matched_sig:
        status = "ACTIVE_SAAS"
        confidence = "LOW_RISK"
        severity = "INFO"
        reason = f"Points to {matched_sig['service']} ({cname}); responds normally with no orphan fingerprint."
        action = "Normal operation; tenant is actively provisioned."
    else:
        status = "EXTERNAL_CNAME"
        confidence = "SAFE"
        severity = "INFO"
        reason = f"Delegates via CNAME to external host '{cname}'."
        action = "Valid external delegation."

    return {
        "subdomain": sub,
        "has_cname": True,
        "cname": cname,
        "status": status,
        "service": matched_service_name,
        "fingerprint_matched": matched_fp,
        "is_nxdomain": is_nxdomain,
        "http_status": http_status,
        "confidence": confidence,
        "severity": severity,
        "reason": reason,
        "discussion": action,
    }


# ---------------------------------------------------------------------------
# 4. MULTI-SUBDOMAIN CONCURRENT TAKEOVER AUDITOR
# ---------------------------------------------------------------------------
def check_subdomain_takeovers(
    subdomains: Optional[List[str]] = None,
    target_domain: Optional[str] = None,
    max_workers: int = 10,
    timeout: float = 3.0,
) -> Dict[str, Any]:
    """
    Check subdomains for CNAME records, dangling pointers, and known SaaS takeover vulnerabilities.

    Parameters:
      subdomains: List of subdomains or single string.
      target_domain: Optional root domain (e.g. nullai.tech). If subdomains is empty, synthesizes candidates.
      max_workers: Concurrent worker threads for ThreadPoolExecutor.
      timeout: Max seconds per DNS / HTTP probe.
    """
    candidates: List[str] = []

    if isinstance(subdomains, str):
        candidates = [s.strip() for s in subdomains.split(",") if s.strip()]
    elif isinstance(subdomains, list):
        candidates = [str(s).strip() for s in subdomains if str(s).strip()]

    # If target_domain is supplied and candidates list is small, synthesize high-value targets
    if target_domain:
        td = target_domain.strip().lower()
        if not candidates:
            candidates = [td]
        common_prefixes = ["www", "api", "blog", "dev", "app", "docs", "status", "stage", "test", "cdn", "shop", "portal"]
        for p in common_prefixes:
            cand = f"{p}.{td}"
            if cand not in candidates and len(candidates) < 35:
                candidates.append(cand)

    # Normalize and deduplicate
    seen = set()
    clean_subs: List[str] = []
    for s in candidates:
        norm = s.lower().lstrip("*.")
        if norm and norm not in seen:
            seen.add(norm)
            clean_subs.append(norm)

    results: List[Dict[str, Any]] = []
    if clean_subs:
        worker_count = min(max_workers, max(1, len(clean_subs)))
        with concurrent.futures.ThreadPoolExecutor(max_workers=worker_count) as executor:
            future_to_sub = {executor.submit(audit_single_subdomain, sub, timeout): sub for sub in clean_subs}
            for future in concurrent.futures.as_completed(future_to_sub):
                try:
                    res = future.result()
                    results.append(res)
                except Exception as e:
                    sub_err = future_to_sub[future]
                    results.append({
                        "subdomain": sub_err,
                        "has_cname": False,
                        "status": "ERROR",
                        "error": str(e),
                        "confidence": "NONE",
                    })

    vulnerable = [r for r in results if r.get("status") == "VULNERABLE"]
    dangling = [r for r in results if r.get("status") == "DANGLING_NXDOMAIN"]
    all_cnames = [r for r in results if r.get("has_cname")]

    return {
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "target": target_domain or (clean_subs[0] if clean_subs else ""),
        "target_domain": target_domain or "",
        "total_checked": len(clean_subs),
        "vulnerable_count": len(vulnerable),
        "dangling_count": len(dangling),
        "cname_count": len(all_cnames),
        "signatures_count": len(TAKEOVER_SIGNATURES),
        "vulnerable": vulnerable,
        "dangling": dangling,
        "all_cnames": all_cnames,
        "results": results,
    }
