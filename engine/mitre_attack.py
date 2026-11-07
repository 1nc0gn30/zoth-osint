#!/usr/bin/env python3
"""
Zoth OSINT MITRE ATT&CK Enterprise Matrix & Defensive Countermeasures Engine
Module: engine/mitre_attack.py
Engineered by Neal Frazier Tech (@1nc0gn30) • NullAI Platform

Maps discovered reconnaissance findings, network telemetry, exposed secrets, and
infrastructure posture to formal MITRE ATT&CK Enterprise Matrix techniques (v14.1)
and synthesizes prioritized, tactical defensive countermeasures and OASIS STIX 2.1
threat intelligence objects.
"""

import datetime
import re
import uuid
from typing import Any, Dict, List, Optional, Set, Tuple


# ---------------------------------------------------------------------------
# MITRE ATT&CK Enterprise Tactic Catalog
# ---------------------------------------------------------------------------
TACTICS = {
    "TA0043": {"name": "Reconnaissance", "slug": "reconnaissance"},
    "TA0042": {"name": "Resource Development", "slug": "resource-development"},
    "TA0001": {"name": "Initial Access", "slug": "initial-access"},
    "TA0002": {"name": "Execution", "slug": "execution"},
    "TA0003": {"name": "Persistence", "slug": "persistence"},
    "TA0004": {"name": "Privilege Escalation", "slug": "privilege-escalation"},
    "TA0005": {"name": "Defense Evasion", "slug": "defense-evasion"},
    "TA0006": {"name": "Credential Access", "slug": "credential-access"},
    "TA0007": {"name": "Discovery", "slug": "discovery"},
    "TA0008": {"name": "Lateral Movement", "slug": "lateral-movement"},
    "TA0009": {"name": "Collection", "slug": "collection"},
    "TA0011": {"name": "Command and Control", "slug": "command-and-control"},
    "TA0010": {"name": "Exfiltration", "slug": "exfiltration"},
    "TA0040": {"name": "Impact", "slug": "impact"},
}


def _extract_ports(scan: Dict[str, Any], raw_findings: List[str]) -> Set[int]:
    """Extract all observed open TCP/UDP port numbers from scan data and findings."""
    ports: Set[int] = set()

    # Direct internetdb ports
    idb_ports = scan.get("internetdb", {}).get("ports") or []
    for p in idb_ports:
        if isinstance(p, (int, str)) and str(p).isdigit():
            ports.add(int(p))

    # Generic ports field
    for p in scan.get("ports") or []:
        if isinstance(p, (int, str)) and str(p).isdigit():
            ports.add(int(p))

    # Domain IP intel ports
    for ip_entry in scan.get("ip_intel", []):
        if isinstance(ip_entry, dict):
            for p in ip_entry.get("internetdb", {}).get("ports", []):
                if isinstance(p, (int, str)) and str(p).isdigit():
                    ports.add(int(p))

    # Findings text parsing
    for f in raw_findings:
        m = re.search(r"(?:open ports?|ports?):\s*([0-9,\s]+)", f, re.IGNORECASE)
        if m:
            for piece in m.group(1).split(","):
                piece = piece.strip()
                if piece.isdigit():
                    ports.add(int(piece))

    return ports


def _extract_cves(scan: Dict[str, Any], raw_findings: List[str]) -> List[str]:
    """Extract all discovered CVE identifiers from scan data and findings."""
    cves: Set[str] = set()

    # InternetDB vulns
    for v in scan.get("internetdb", {}).get("vulns", []):
        if isinstance(v, str) and v.startswith("CVE-"):
            cves.add(v.strip().upper())

    # Domain IP intel vulns
    for ip_entry in scan.get("ip_intel", []):
        if isinstance(ip_entry, dict):
            for v in ip_entry.get("internetdb", {}).get("vulns", []):
                if isinstance(v, str) and v.startswith("CVE-"):
                    cves.add(v.strip().upper())

    # Generic vulns field
    for v in scan.get("vulns", []):
        if isinstance(v, str) and v.startswith("CVE-"):
            cves.add(v.strip().upper())

    # Text regex
    cve_pattern = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)
    for f in raw_findings:
        for match in cve_pattern.findall(f):
            cves.add(match.upper())

    return sorted(cves)


def map_mitre_attack(
    findings_or_data: Any = None,
    scan_data: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Map discovered reconnaissance findings and OSINT scan telemetry to formal

    MITRE ATT&CK Enterprise Matrix techniques (v14.1) and synthesize prioritized
    tactical defensive countermeasures and mitigations.

    Supports signatures:
      - map_mitre_attack(scan_data: Dict[str, Any])
      - map_mitre_attack(findings: List[str], scan_data: Dict[str, Any])
      - map_mitre_attack(findings: List[str])
    """
    if isinstance(findings_or_data, dict) and scan_data is None:
        scan = dict(findings_or_data)
        raw_findings = list(scan.get("findings") or [])
    elif isinstance(findings_or_data, list):
        raw_findings = list(findings_or_data)
        scan = dict(scan_data or {})
        for f in scan.get("findings") or []:
            if f not in raw_findings:
                raw_findings.append(str(f))
    else:
        scan = dict(scan_data or {})
        raw_findings = list(scan.get("findings") or [])

    target = str(scan.get("target") or "target")
    target_type = str(scan.get("type") or "domain").lower()

    ports = _extract_ports(scan, raw_findings)
    cves = _extract_cves(scan, raw_findings)
    findings_text = " ".join(raw_findings).lower()

    techniques_detected: List[Dict[str, Any]] = []
    seen_technique_ids: Set[str] = set()
    countermeasures: List[Dict[str, Any]] = []
    seen_countermeasures: Set[Tuple[str, str]] = set()

    def add_technique(
        tech_id: str,
        name: str,
        tactic_id: str,
        severity: str,
        confidence: str,
        evidence: List[str],
        mitigations: List[Dict[str, str]],
    ) -> None:
        tactic_info = TACTICS.get(tactic_id, {"name": "Reconnaissance", "slug": "reconnaissance"})
        tactic_name = tactic_info["name"]

        if tech_id in seen_technique_ids:
            for item in techniques_detected:
                if item["id"] == tech_id:
                    for ev in evidence:
                        if ev not in item["evidence"]:
                            item["evidence"].append(ev)
                    sev_rank = {"INFORMATIONAL": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
                    if sev_rank.get(severity, 0) > sev_rank.get(item["severity"], 0):
                        item["severity"] = severity
            return

        seen_technique_ids.add(tech_id)
        url = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
        techniques_detected.append(
            {
                "id": tech_id,
                "name": name,
                "tactic": tactic_name,
                "tactic_id": tactic_id,
                "tactic_slug": tactic_info["slug"],
                "severity": severity,
                "confidence": confidence,
                "url": url,
                "evidence": evidence,
                "mitigations": mitigations,
            }
        )

        for m in mitigations:
            c_key = (m.get("id", "M1056"), m.get("action", ""))
            if c_key not in seen_countermeasures:
                seen_countermeasures.add(c_key)
                countermeasures.append(
                    {
                        "id": m.get("id", "M1056"),
                        "title": m.get("title", "Mitigation"),
                        "priority": "P1" if severity in ("CRITICAL", "HIGH") else ("P2" if severity == "MEDIUM" else "P3"),
                        "category": m.get("category", "General Defense"),
                        "recommendation": m.get("action", ""),
                        "associated_techniques": [tech_id],
                    }
                )
            else:
                for cm in countermeasures:
                    if cm.get("id") == m.get("id") and cm.get("recommendation") == m.get("action"):
                        if tech_id not in cm["associated_techniques"]:
                            cm["associated_techniques"].append(tech_id)

    # -----------------------------------------------------------------------
    # 1. KNOWN CVES & VULNERABILITY EXPLOITATION
    # -----------------------------------------------------------------------
    if cves:
        cve_sample = ", ".join(cves[:6])
        add_technique(
            tech_id="T1595.002",
            name="Active Scanning: Vulnerability Scanning",
            tactic_id="TA0043",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=[f"Host associated with {len(cves)} unpatched CVEs in Shodan InternetDB: {cve_sample}"],
            mitigations=[
                {
                    "id": "M1051",
                    "title": "Update Software",
                    "category": "Patch Management",
                    "action": "Prioritize emergency patching and version upgrades for all identified CVEs.",
                },
                {
                    "id": "M1050",
                    "title": "Exploit Protection",
                    "category": "Cloud WAF",
                    "action": "Enable virtual patching rules in edge WAF (Cloudflare/AWS) to filter exploit payloads targeting identified CVEs until patch cycle is complete.",
                },
            ],
        )
        add_technique(
            tech_id="T1190",
            name="Exploit Public-Facing Application",
            tactic_id="TA0001",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=[f"Remote attacker can target known vulnerabilities ({cve_sample}) on publicly accessible interface."],
            mitigations=[
                {
                    "id": "M1050",
                    "title": "Exploit Protection",
                    "category": "Cloud WAF",
                    "action": "Deploy Web Application Firewall (WAF) with signature blocking and zero-day behavioral heuristics.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 2. REMOTE ACCESS PORTS (SSH 22, RDP 3389, SMB 445/139, TELNET 23, FTP 21)
    # -----------------------------------------------------------------------
    if 22 in ports or "ssh" in findings_text:
        add_technique(
            tech_id="T1133",
            name="External Remote Services",
            tactic_id="TA0001",
            severity="HIGH",
            confidence="HIGH",
            evidence=["TCP Port 22 (SSH) exposed to public Internet."],
            mitigations=[
                {
                    "id": "M1037",
                    "title": "Filter Network Traffic",
                    "category": "Perimeter Hardening",
                    "action": "Restrict SSH (port 22) access at edge firewall to trusted IP whitelist or mandate WireGuard/Tailscale VPN.",
                },
                {
                    "id": "M1027",
                    "title": "Password Policies",
                    "category": "Authentication Security",
                    "action": "Enforce SSH key-only authentication (PasswordAuthentication no, PermitRootLogin no) and deploy Fail2ban / CrowdSec rate-limiting.",
                },
            ],
        )
        add_technique(
            tech_id="T1021.004",
            name="Remote Services: SSH",
            tactic_id="TA0008",
            severity="HIGH",
            confidence="HIGH",
            evidence=["Open SSH daemon enables adversary brute-force, password-spraying, or lateral pivot attempts."],
            mitigations=[
                {
                    "id": "M1032",
                    "title": "Multi-Factor Authentication",
                    "category": "Authentication Security",
                    "action": "Require hardware token (FIDO2 WebAuthn / Duo) MFA for interactive SSH sessions.",
                }
            ],
        )

    if 3389 in ports or "rdp" in findings_text or "remote desktop" in findings_text:
        add_technique(
            tech_id="T1133",
            name="External Remote Services",
            tactic_id="TA0001",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=["TCP Port 3389 (RDP - Remote Desktop Protocol) directly exposed to public WAN."],
            mitigations=[
                {
                    "id": "M1035",
                    "title": "Disable or Remove Feature/Program",
                    "category": "Remote Access Defense",
                    "action": "Immediately block public internet exposure of RDP port 3389; enforce Zero Trust Network Access (ZTNA) or corporate VPN gateway with mandatory MFA.",
                },
                {
                    "id": "M1032",
                    "title": "Multi-Factor Authentication",
                    "category": "Authentication Security",
                    "action": "Mandate Network Level Authentication (NLA) and multi-factor authentication on all remote desktop endpoints.",
                },
            ],
        )
        add_technique(
            tech_id="T1021.001",
            name="Remote Services: Remote Desktop Protocol",
            tactic_id="TA0008",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=["Public RDP port enables ransomware operators and external threat actors to conduct credential stuffing and brute-force campaigns."],
            mitigations=[
                {
                    "id": "M1037",
                    "title": "Filter Network Traffic",
                    "category": "Perimeter Hardening",
                    "action": "Place RDP behind corporate bastion host with strict IP access control lists and account lockout thresholds.",
                }
            ],
        )

    if 445 in ports or 139 in ports or "smb" in findings_text or "netbios" in findings_text:
        add_technique(
            tech_id="T1133",
            name="External Remote Services",
            tactic_id="TA0001",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=["TCP Port 445/139 (SMB / Windows File Sharing) reachable from public Internet."],
            mitigations=[
                {
                    "id": "M1037",
                    "title": "Filter Network Traffic",
                    "category": "Perimeter Hardening",
                    "action": "Block SMB ports (TCP 445, 139) from the public Internet to neutralize remote code execution (e.g. EternalBlue) and NTLM relay attacks.",
                }
            ],
        )
        add_technique(
            tech_id="T1021.002",
            name="Remote Services: SMB/Windows Admin Shares",
            tactic_id="TA0008",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=["Exposed SMB enables unauthorized share enumeration, anonymous null sessions, and lateral worm propagation."],
            mitigations=[
                {
                    "id": "M1035",
                    "title": "Disable or Remove Feature/Program",
                    "category": "Service Hardening",
                    "action": "Disable SMBv1 entirely; require SMBv3 with AES encryption and signing across internal networks.",
                }
            ],
        )

    if 21 in ports or 23 in ports or "telnet" in findings_text or "cleartext ftp" in findings_text:
        add_technique(
            tech_id="T1133",
            name="External Remote Services",
            tactic_id="TA0001",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=["Cleartext legacy administrative protocols (Telnet port 23 or FTP port 21) detected."],
            mitigations=[
                {
                    "id": "M1035",
                    "title": "Disable Cleartext Protocols",
                    "category": "Network Security",
                    "action": "Decommission legacy unencrypted Telnet (port 23) and FTP (port 21); replace exclusively with SSH and SFTP/TLS.",
                }
            ],
        )
        add_technique(
            tech_id="T1040",
            name="Network Sniffing",
            tactic_id="TA0006",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=["Unencrypted authentication traffic allows transit eavesdropping and plaintext credential harvesting."],
            mitigations=[
                {
                    "id": "M1041",
                    "title": "Encrypt Sensitive Information",
                    "category": "Cryptography",
                    "action": "Enforce mandatory TLS encryption for all ingress and data-in-transit communications.",
                }
            ],
        )

    # Database ports exposed to public
    db_ports = {3306: "MySQL", 5432: "PostgreSQL", 6379: "Redis", 27017: "MongoDB", 9200: "Elasticsearch"}
    open_dbs = [f"{db_ports[p]} ({p})" for p in db_ports if p in ports]
    if open_dbs:
        add_technique(
            tech_id="T1190",
            name="Exploit Public-Facing Application",
            tactic_id="TA0001",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=[f"Database listening sockets publicly exposed: {', '.join(open_dbs)}."],
            mitigations=[
                {
                    "id": "M1037",
                    "title": "Filter Network Traffic",
                    "category": "Database Security",
                    "action": "Bind database listening sockets strictly to 127.0.0.1 or isolated VPC subnet; terminate public internet exposure.",
                },
                {
                    "id": "M1027",
                    "title": "Password Policies",
                    "category": "Database Security",
                    "action": "Require strong mutual TLS authentication and revoke default or empty administrative credentials.",
                },
            ],
        )
        add_technique(
            tech_id="T1530",
            name="Data from Cloud Storage Object",
            tactic_id="TA0009",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=[f"Unauthenticated or exposed database instances ({', '.join(open_dbs)}) allow direct bulk data exfiltration."],
            mitigations=[
                {
                    "id": "M1026",
                    "title": "Privileged Account Management",
                    "category": "Data Protection",
                    "action": "Isolate database clusters inside private VPC security groups without public elastic IP assignments.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 3. WEB APPLICATIONS & HTTP SECURITY POSTURE
    # -----------------------------------------------------------------------
    web_ports = {80, 443, 8080, 8443, 8000, 3000, 5000}
    has_web_ports = bool(ports.intersection(web_ports)) or target_type in ("domain", "ip")
    if has_web_ports:
        http_stack = scan.get("http_stack") or {}
        sec_score = http_stack.get("security_score", 100)
        missing_sec = [k for k, v in http_stack.get("security_headers", {}).items() if not v]

        add_technique(
            tech_id="T1190",
            name="Exploit Public-Facing Application",
            tactic_id="TA0001",
            severity="HIGH" if sec_score < 40 else "MEDIUM",
            confidence="HIGH",
            evidence=[f"Public HTTP/HTTPS services reachable (HTTP Security Score: {sec_score}/100, Missing headers: {', '.join(missing_sec) if missing_sec else 'None'})."],
            mitigations=[
                {
                    "id": "M1050",
                    "title": "Exploit Protection",
                    "category": "Cloud WAF",
                    "action": "Deploy Cloudflare WAF or AWS WAF with origin cloaking and rate-limiting to prevent direct-to-origin bypass.",
                },
                {
                    "id": "M1038",
                    "title": "Execution Prevention",
                    "category": "Web Security",
                    "action": "Enforce strict HTTP security headers: Content-Security-Policy (CSP), HSTS (Strict-Transport-Security: max-age=31536000; includeSubDomains; preload), X-Frame-Options: SAMEORIGIN, and X-Content-Type-Options: nosniff.",
                },
            ],
        )

        server_hdr = http_stack.get("server")
        if server_hdr:
            add_technique(
                tech_id="T1592.002",
                name="Gather Victim Host Information: Software",
                tactic_id="TA0043",
                severity="LOW",
                confidence="HIGH",
                evidence=[f"HTTP response exposes exact server software banner: '{server_hdr}'."],
                mitigations=[
                    {
                        "id": "M1056",
                        "title": "Pre-compromise Hygiene",
                        "category": "Web Server Hardening",
                        "action": "Suppress server banners and version signatures (ServerTokens Prod in Apache, server_tokens off in Nginx).",
                    }
                ],
            )

    # -----------------------------------------------------------------------
    # 4. ACTIVE PORT SCANNING & RECONNAISSANCE
    # -----------------------------------------------------------------------
    if ports:
        port_list = sorted(ports)
        add_technique(
            tech_id="T1595",
            name="Active Scanning",
            tactic_id="TA0043",
            severity="HIGH" if len(ports) > 4 else "MEDIUM",
            confidence="HIGH",
            evidence=[f"Shodan InternetDB / port probes identified {len(ports)} open ports: {', '.join(map(str, port_list[:12]))}."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Surface Reduction",
                    "category": "Perimeter Hardening",
                    "action": "Close unnecessary ports and filter inbound traffic using an edge firewall (AWS Security Groups / Cloudflare / UFW).",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 5. EXPOSED SECRETS, .ENV, .GIT & SENSITIVE PATHS
    # -----------------------------------------------------------------------
    wb_interesting = (scan.get("wayback") or {}).get("interesting_urls", [])
    has_env_leak = any(".env" in str(u).lower() for u in wb_interesting) or ".env" in findings_text
    has_git_leak = any(".git" in str(u).lower() for u in wb_interesting) or ".git" in findings_text
    has_secrets_leak = has_env_leak or has_git_leak or bool(wb_interesting) or any(w in findings_text for w in ("exposed .env", "git commit leaks", "credentials"))

    if has_secrets_leak:
        leak_types = []
        if has_env_leak:
            leak_types.append("exposed .env configuration file")
        if has_git_leak:
            leak_types.append("exposed .git source control directory")
        if wb_interesting and not leak_types:
            leak_types.append(f"{len(wb_interesting)} sensitive archived URLs in Wayback Machine (admin/api/config/backup)")
        if not leak_types:
            leak_types.append("detected sensitive environment or repository leaks")

        add_technique(
            tech_id="T1552.001",
            name="Unsecured Credentials: Credentials In Files",
            tactic_id="TA0006",
            severity="CRITICAL",
            confidence="HIGH",
            evidence=[f"Adversary can harvest high-privilege credentials via {'; '.join(leak_types)}."],
            mitigations=[
                {
                    "id": "M1027",
                    "title": "Password Policies & Secret Rotation",
                    "category": "Secrets Hygiene",
                    "action": "Immediately revoke and rotate all leaked API tokens, database credentials, JWT secrets, and private keys.",
                },
                {
                    "id": "M1028",
                    "title": "Operating System Configuration",
                    "category": "Web Server Hardening",
                    "action": "Configure web server (Nginx/Apache) to deny all public requests to dotfiles (location ~ /\\. { deny all; }) and archive formats (.bak, .sql).",
                },
                {
                    "id": "M1056",
                    "title": "Pre-compromise Hygiene",
                    "category": "DevSecOps",
                    "action": "Deploy automated pre-commit hooks (Trufflehog, GitGuardian) to stop secrets from entering version control.",
                },
            ],
        )
        add_technique(
            tech_id="T1596",
            name="Search Open Technical Databases",
            tactic_id="TA0043",
            severity="HIGH",
            confidence="HIGH",
            evidence=["Adversaries query historical snapshots (Wayback CDX / Common Crawl) to uncover decommissioned but active endpoints, credentials, and API routes."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Surface Reduction",
                    "category": "Information Hygiene",
                    "action": "Submit exclusion requests to Internet Archive Wayback Machine for historically leaked sensitive URL endpoints.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 6. EMAIL SPOOFING POSTURE (MISSING OR WEAK SPF / DMARC)
    # -----------------------------------------------------------------------
    email_sec = scan.get("email_security") or {}
    spf_val = email_sec.get("spf")
    dmarc_val = email_sec.get("dmarc")
    grade = email_sec.get("grade", "C")
    is_domain = target_type == "domain"

    has_weak_email_sec = (
        is_domain
        and (
            not dmarc_val
            or "p=none" in str(dmarc_val).lower()
            or not spf_val
            or "+all" in str(spf_val)
            or "?all" in str(spf_val)
            or "~all" in str(spf_val)
            or grade in ("C", "D", "B-")
        )
    ) or ("dmarc" in findings_text and "missing" in findings_text) or ("spf" in findings_text and "missing" in findings_text)

    if has_weak_email_sec:
        dmarc_status = "Missing" if not dmarc_val else ("Monitoring-only (p=none)" if "p=none" in str(dmarc_val).lower() else "Present")
        spf_status = "Missing" if not spf_val else ("Softfail (~all)" if "~all" in str(spf_val) else "Present")
        add_technique(
            tech_id="T1566",
            name="Phishing",
            tactic_id="TA0001",
            severity="HIGH",
            confidence="HIGH",
            evidence=[f"Email authentication posture allows domain impersonation: DMARC: {dmarc_status}, SPF: {spf_status} (Grade: {grade})."],
            mitigations=[
                {
                    "id": "M1054",
                    "title": "Software Configuration",
                    "category": "Email Security",
                    "action": "Enforce strict DMARC reject policy: v=DMARC1; p=reject; sp=reject; pct=100; rua=mailto:dmarc-reports@domain.com to eliminate domain spoofing in CEO fraud & spearphishing campaigns.",
                },
                {
                    "id": "M1031",
                    "title": "Network Intrusion Prevention",
                    "category": "Email Security",
                    "action": "Configure strict SPF record with -all hardfail enforcement (v=spf1 ... -all) and mandate 2048-bit DKIM cryptographic signing.",
                },
            ],
        )
        add_technique(
            tech_id="T1589.002",
            name="Gather Victim Identity Information: Email Addresses",
            tactic_id="TA0043",
            severity="MEDIUM",
            confidence="HIGH",
            evidence=["Adversaries harvest organizational email addresses and weaponize spoofable domain records for spearphishing operations."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Hygiene",
                    "category": "Email Security",
                    "action": "Deploy Brand Indicators for Message Identification (BIMI) with Verified Mark Certificate (VMC) to ensure brand legitimacy.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 7. DEVELOPER FOOTPRINT, COMMIT LEAKS & PUBLIC SSH KEYS
    # -----------------------------------------------------------------------
    gh_intel = scan.get("github_deep_intel") or {}
    commit_emails = gh_intel.get("commit_emails", [])
    ssh_keys = gh_intel.get("ssh_keys", [])
    has_git_intel = bool(commit_emails) or bool(ssh_keys) or "commit author email" in findings_text or "public ssh authentication keys" in findings_text

    if has_git_intel:
        evidence_items = []
        if commit_emails:
            evidence_items.append(f"Recovered {len(commit_emails)} commit author emails ({', '.join(commit_emails[:4])})")
        if ssh_keys:
            evidence_items.append(f"Enumerated {len(ssh_keys)} public SSH authentication keys")

        add_technique(
            tech_id="T1589.002",
            name="Gather Victim Identity Information: Email Addresses",
            tactic_id="TA0043",
            severity="HIGH" if commit_emails else "MEDIUM",
            confidence="HIGH",
            evidence=evidence_items or ["Recovered developer commit author email records."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Hygiene",
                    "category": "Identity & Access",
                    "action": "Enable GitHub commit email privacy mask (noreply.github.com) and sanitize historical commit logs with git-filter-repo.",
                }
            ],
        )
        add_technique(
            tech_id="T1589.001",
            name="Gather Victim Identity Information: Credentials",
            tactic_id="TA0043",
            severity="MEDIUM",
            confidence="HIGH",
            evidence=[f"Public SSH keys extracted from developer repository profiles: {len(ssh_keys)} keys found."],
            mitigations=[
                {
                    "id": "M1027",
                    "title": "Password Policies",
                    "category": "Identity & Access",
                    "action": "Audit authorized_keys across server infrastructure; revoke unused or obsolete developer public SSH keys.",
                }
            ],
        )
        add_technique(
            tech_id="T1078",
            name="Valid Accounts",
            tactic_id="TA0001",
            severity="MEDIUM",
            confidence="HIGH",
            evidence=["Adversaries leverage identified developer identities and SSH key fingerprints to attempt account takeovers and SSH authorized_keys matches."],
            mitigations=[
                {
                    "id": "M1032",
                    "title": "Multi-Factor Authentication",
                    "category": "Identity & Access",
                    "action": "Mandate phishing-resistant hardware MFA (FIDO2 / YubiKey) across all GitHub, GitLab, and developer infrastructure accounts.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 8. CLOUD INFRASTRUCTURE & METADATA DISCOVERY
    # -----------------------------------------------------------------------
    cdn_edge = str((scan.get("http_stack") or {}).get("cdn_edge", ""))
    is_cloud = any(c in cdn_edge.lower() for c in ("cloudflare", "aws", "cloudfront", "netlify", "vercel")) or "cloud metadata" in findings_text
    if is_cloud:
        add_technique(
            tech_id="T1526",
            name="Cloud Service Discovery",
            tactic_id="TA0007",
            severity="MEDIUM",
            confidence="HIGH",
            evidence=[f"Discovered cloud infrastructure and edge provider: {cdn_edge or 'Cloud hosting provider'}."],
            mitigations=[
                {
                    "id": "M1054",
                    "title": "Software Configuration",
                    "category": "Cloud Security",
                    "action": "Enforce AWS IMDSv2 (hop limit 1, token required) to completely defeat Server-Side Request Forgery (SSRF) cloud metadata credential exfiltration.",
                },
                {
                    "id": "M1037",
                    "title": "Filter Network Traffic",
                    "category": "Cloud WAF",
                    "action": "Configure Cloudflare Authenticated Origin Pulls (mTLS) and IP restriction to ensure all origin requests pass through WAF.",
                },
            ],
        )
        add_technique(
            tech_id="T1590",
            name="Gather Victim Network Information",
            tactic_id="TA0043",
            severity="LOW",
            confidence="HIGH",
            evidence=[f"Identified edge distribution network and cloud routing posture: {cdn_edge}."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Surface Reduction",
                    "category": "Cloud Security",
                    "action": "Ensure direct origin host IP addresses are never disclosed in DNS history or outbound mail headers.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 9. BLOCKCHAIN / CRYPTOCURRENCY WALLETS
    # -----------------------------------------------------------------------
    is_wallet = target_type == "wallet" or "balance" in scan or "chain" in scan or "wallet" in findings_text or any(k in findings_text for k in ("solana", "ethereum", "bitcoin"))
    if is_wallet:
        chain = str(scan.get("chain") or "Blockchain").capitalize()
        bal = scan.get("balance", "Active")
        add_technique(
            tech_id="T1496",
            name="Resource Hijacking",
            tactic_id="TA0040",
            severity="HIGH" if bal not in (0, "0", None) else "MEDIUM",
            confidence="HIGH",
            evidence=[f"Cryptocurrency wallet identified on {chain} Mainnet (Balance: {bal}). Targets are exposed to private key theft, drainer contracts, and MEV front-running."],
            mitigations=[
                {
                    "id": "M1027",
                    "title": "Treasury & Key Security",
                    "category": "Web3 & Crypto Security",
                    "action": "Store treasury funds in multi-signature cold storage vaults (Squads Protocol on Solana, Safe on EVM) with hardware signer keys.",
                },
                {
                    "id": "M1056",
                    "title": "Pre-compromise Monitoring",
                    "category": "Web3 & Crypto Security",
                    "action": "Deploy real-time blockchain transaction monitoring webhooks to detect unauthorized address interactions.",
                },
            ],
        )
        add_technique(
            tech_id="T1596",
            name="Search Open Technical Databases",
            tactic_id="TA0043",
            severity="MEDIUM",
            confidence="HIGH",
            evidence=["Adversaries query public distributed ledgers and RPC nodes to trace wallet transactions, token approvals, and asset balances."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Hygiene",
                    "category": "Web3 & Crypto Security",
                    "action": "Segregate public-facing tipping/operational addresses from primary treasury reserve cold storage.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 10. SUBDOMAIN RECONNAISSANCE VIA CERTIFICATE TRANSPARENCY
    # -----------------------------------------------------------------------
    subs = scan.get("subdomains") or []
    if subs or "ct subdomains" in findings_text:
        add_technique(
            tech_id="T1596.003",
            name="Search Open Technical Databases: Digital Certificates",
            tactic_id="TA0043",
            severity="MEDIUM",
            confidence="HIGH",
            evidence=[f"Discovered {len(subs)} subdomains published in public Certificate Transparency logs (crt.sh)."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Surface Reduction",
                    "category": "DNS & PKI Hygiene",
                    "action": "Utilize wildcard TLS certificates (*.domain.com) to prevent leaking staging and internal hostnames into public Certificate Transparency logs.",
                },
                {
                    "id": "M1037",
                    "title": "Filter Network Traffic",
                    "category": "Network Security",
                    "action": "Ensure staging and development subdomains are restricted to private corporate VPN networks and not internet-routable.",
                },
            ],
        )
        add_technique(
            tech_id="T1592",
            name="Gather Victim Host Information",
            tactic_id="TA0043",
            severity="LOW",
            confidence="HIGH",
            evidence=[f"Adversary maps complete organizational attack surface via {len(subs)} enumerated hostnames."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Surface Reduction",
                    "category": "Perimeter Hardening",
                    "action": "Implement continuous external attack surface management (EASM) to monitor and decommission forgotten subdomains.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 11. SOCIAL MEDIA & DEVELOPER PLATFORMS (IDENTITY OSINT)
    # -----------------------------------------------------------------------
    platforms = scan.get("platforms") or []
    if platforms or target_type in ("username", "email") or "high-signal platforms" in findings_text:
        plat_names = [p.get("platform", p.get("name", "Platform")) for p in platforms if isinstance(p, dict)]
        add_technique(
            tech_id="T1593.001",
            name="Search Open Websites/Domains: Social Media",
            tactic_id="TA0043",
            severity="MEDIUM",
            confidence="HIGH",
            evidence=[f"Confirmed active profiles across public developer/social platforms ({', '.join(plat_names[:6]) if plat_names else 'Multiple Platforms'})."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Hygiene",
                    "category": "OPSEC & Identity",
                    "action": "Compartmentalize developer handles from sensitive production administrative identities.",
                }
            ],
        )
        add_technique(
            tech_id="T1589.003",
            name="Gather Victim Identity Information: Employee Names",
            tactic_id="TA0043",
            severity="MEDIUM",
            confidence="HIGH",
            evidence=["Adversaries correlate handles, public keys, and avatars across social platforms to profile organizational personnel."],
            mitigations=[
                {
                    "id": "M1032",
                    "title": "Multi-Factor Authentication",
                    "category": "Identity & Access",
                    "action": "Mandate hardware FIDO2 WebAuthn security keys across all public identity and developer accounts.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 12. BGP ROUTING & AUTONOMOUS SYSTEM INTELLIGENCE
    # -----------------------------------------------------------------------
    geo_asn = scan.get("geo_asn") or {}
    asn_num = geo_asn.get("asn") or scan.get("asn")
    if asn_num or "routed via as" in findings_text:
        add_technique(
            tech_id="T1590.005",
            name="Gather Victim Network Information: IP Addresses",
            tactic_id="TA0043",
            severity="INFORMATIONAL",
            confidence="HIGH",
            evidence=[f"Resolved Autonomous System routing data: AS{asn_num} ({geo_asn.get('org', 'ISP/Carrier')})."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Hygiene",
                    "category": "Network Routing",
                    "action": "Implement RPKI Route Origin Authorization (ROA) to protect announced IP prefixes from BGP hijackings.",
                }
            ],
        )

    # -----------------------------------------------------------------------
    # 13. WHOIS / RDAP & DNSSEC RECONNAISSANCE
    # -----------------------------------------------------------------------
    rdap = scan.get("rdap") or {}
    if rdap.get("registrar") or target_type == "domain":
        dnssec = rdap.get("dnssec_signed")
        dnssec_str = "Signed" if dnssec else "Unsigned"
        add_technique(
            tech_id="T1596.002",
            name="Search Open Technical Databases: WHOIS",
            tactic_id="TA0043",
            severity="LOW",
            confidence="HIGH",
            evidence=[f"RDAP registry queries reveal registrar ({rdap.get('registrar', 'Generic')}), creation dates, and DNSSEC status ({dnssec_str})."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Hygiene",
                    "category": "DNS Security",
                    "action": "Sign authoritative DNS zones with DNSSEC to protect clients against cache poisoning and DNS spoofing.",
                },
                {
                    "id": "M1056",
                    "title": "Pre-compromise Hygiene",
                    "category": "Domain Privacy",
                    "action": "Ensure registrar WHOIS privacy protection is enabled to shield administrative contact data.",
                },
            ],
        )

    # Fallback technique guarantee
    if not techniques_detected:
        add_technique(
            tech_id="T1592",
            name="Gather Victim Host Information",
            tactic_id="TA0043",
            severity="INFORMATIONAL",
            confidence="MEDIUM",
            evidence=[f"Passive OSINT reconnaissance conducted against target '{target}'."],
            mitigations=[
                {
                    "id": "M1056",
                    "title": "Pre-compromise Surface Reduction",
                    "category": "General Defense",
                    "action": "Maintain external perimeter scanning and minimize unnecessary public service exposure.",
                }
            ],
        )

    # Compute Tactics Summary
    tactics_summary: Dict[str, int] = {}
    for t in techniques_detected:
        tac = t["tactic"]
        tactics_summary[tac] = tactics_summary.get(tac, 0) + 1

    # Determine Overall Risk Level
    severities = [t["severity"] for t in techniques_detected]
    if "CRITICAL" in severities:
        risk_level = "CRITICAL"
    elif "HIGH" in severities:
        risk_level = "HIGH"
    elif "MEDIUM" in severities:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    # Compute Defensive Hardening Score (100 = heavily hardened, 15 = wide open)
    score = 100
    for t in techniques_detected:
        s = t["severity"]
        if s == "CRITICAL":
            score -= 22
        elif s == "HIGH":
            score -= 12
        elif s == "MEDIUM":
            score -= 6
        elif s == "LOW":
            score -= 2
    defensive_score = max(15, min(100, score))

    # Priority sort countermeasures: P1 -> P2 -> P3 -> P4
    prio_order = {"P1": 0, "P2": 1, "P3": 2, "P4": 3}
    countermeasures.sort(key=lambda c: prio_order.get(c.get("priority", "P3"), 2))

    return {
        "target": target,
        "target_type": target_type,
        "framework": "MITRE ATT&CK Enterprise Matrix v14.1",
        "defensive_score": defensive_score,
        "risk_level": risk_level,
        "total_techniques": len(techniques_detected),
        "tactics_summary": tactics_summary,
        "techniques_detected": techniques_detected,
        "countermeasures": countermeasures,
    }


def build_mitre_stix_objects(
    mitre_attack_data: Dict[str, Any],
    target_identity_id: str,
    now_iso: Optional[str] = None,
) -> List[Dict[str, Any]]:
    """Synthesize OASIS STIX 2.1 SDO 'attack-pattern', 'course-of-action', and SRO

    'relationship' objects for embedding into a STIX Cyber Threat Intelligence bundle.
    """
    now = now_iso or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    target = str(mitre_attack_data.get("target") or "unknown")
    objects: List[Dict[str, Any]] = []
    created_coa_ids: Set[str] = set()

    for tech in mitre_attack_data.get("techniques_detected", []):
        tech_id = str(tech.get("id", "T1592"))
        tech_name = str(tech.get("name", "Reconnaissance"))
        tactic = str(tech.get("tactic", "Reconnaissance"))
        tactic_slug = str(tech.get("tactic_slug") or tactic.lower().replace(" ", "-"))
        evidence = tech.get("evidence", [])
        mitigations = tech.get("mitigations", [])
        sev = str(tech.get("severity", "MEDIUM"))
        conf = str(tech.get("confidence", "HIGH"))

        ap_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mitre-attack:{target}:{tech_id}"))
        ap_stix_id = f"attack-pattern--{ap_uuid}"

        ev_summary = "; ".join(evidence) if evidence else "Attack surface observable"
        ap_obj: Dict[str, Any] = {
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": ap_stix_id,
            "created": now,
            "modified": now,
            "name": f"{tech_id}: {tech_name}",
            "description": f"MITRE ATT&CK {tech_id} ({tactic}) identified during OSINT reconnaissance against {target}. Evidence: {ev_summary}",
            "external_references": [
                {
                    "source_name": "mitre-attack",
                    "external_id": tech_id,
                    "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/",
                }
            ],
            "kill_chain_phases": [
                {
                    "kill_chain_name": "mitre-attack",
                    "phase_name": tactic_slug,
                }
            ],
            "confidence": 85 if conf == "HIGH" else 65,
            "custom_properties": {
                "x_zoth_severity": sev,
                "x_zoth_tactic": tactic,
                "x_zoth_evidence": evidence,
            },
        }
        objects.append(ap_obj)

        # Relationship: attack-pattern targets identity
        rel_target_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"zoth-rel-ap-target:{ap_stix_id}:{target_identity_id}"))
        objects.append(
            {
                "type": "relationship",
                "spec_version": "2.1",
                "id": f"relationship--{rel_target_uuid}",
                "created": now,
                "modified": now,
                "relationship_type": "targets",
                "source_ref": ap_stix_id,
                "target_ref": target_identity_id,
            }
        )

        # Course of Action (Mitigation) SDOs & relationships
        for m in mitigations:
            if not isinstance(m, dict):
                continue
            m_id = str(m.get("id", "M1056"))
            m_title = str(m.get("title", "Defensive Countermeasure"))
            m_action = str(m.get("action", ""))
            coa_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"mitre-coa:{m_id}:{m_title}"))
            coa_stix_id = f"course-of-action--{coa_uuid}"

            if coa_stix_id not in created_coa_ids:
                created_coa_ids.add(coa_stix_id)
                objects.append(
                    {
                        "type": "course-of-action",
                        "spec_version": "2.1",
                        "id": coa_stix_id,
                        "created": now,
                        "modified": now,
                        "name": f"{m_id}: {m_title}",
                        "description": m_action,
                        "external_references": [
                            {
                                "source_name": "mitre-attack",
                                "external_id": m_id,
                                "url": f"https://attack.mitre.org/mitigations/{m_id}/",
                            }
                        ],
                    }
                )

            # Relationship: course-of-action mitigates attack-pattern
            rel_mit_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"zoth-rel-coa-ap:{coa_stix_id}:{ap_stix_id}"))
            objects.append(
                {
                    "type": "relationship",
                    "spec_version": "2.1",
                    "id": f"relationship--{rel_mit_uuid}",
                    "created": now,
                    "modified": now,
                    "relationship_type": "mitigates",
                    "source_ref": coa_stix_id,
                    "target_ref": ap_stix_id,
                }
            )

    return objects
