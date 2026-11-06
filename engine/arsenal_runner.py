#!/usr/bin/env python3
"""
Zoth OSINT Open-Source Arsenal Catalog & Subprocess Orchestrator (engine/arsenal_runner.py)
Unites the 24 best open-source OSINT tools across Identity, Email/Breach, Domain/Subdomains,
IP/Infrastructure, GEOINT/Media Forensics, and Link Analysis — with live binary detection
and safe bounded subprocess execution on Linux/ZothOS.
"""

import shutil
import subprocess
import time
from typing import Any, Dict, List, Optional

OPEN_SOURCE_OSINT_ARSENAL: List[Dict[str, Any]] = [
    # 1. Identity & Username Enumeration
    {
        "id": "maigret",
        "name": "Maigret",
        "category": "Identity & Usernames",
        "repo": "https://github.com/soxoj/maigret",
        "stars": "14.5k+",
        "binary": "maigret",
        "install_cmd": "pipx install maigret",
        "cmd_template": "maigret {target} --timeout 10 --no-progressbar -J simple",
        "desc": "Collects a dossier on a person by username only, checking 3,000+ sites and recursively parsing profile metadata, links, and tags.",
    },
    {
        "id": "sherlock",
        "name": "Sherlock",
        "category": "Identity & Usernames",
        "repo": "https://github.com/sherlock-project/sherlock",
        "stars": "61k+",
        "binary": "sherlock",
        "install_cmd": "pipx install sherlock-project",
        "cmd_template": "sherlock {target} --timeout 5 --print-found",
        "desc": "Hunt down social media accounts by username across 400+ social networks with concurrent HTTP probing.",
    },
    {
        "id": "whatsmyname",
        "name": "WhatsMyName Web",
        "category": "Identity & Usernames",
        "repo": "https://github.com/WebBreacher/WhatsMyName",
        "stars": "6.2k+",
        "binary": None,
        "install_cmd": "git clone https://github.com/WebBreacher/WhatsMyName",
        "cmd_template": "curl -sL https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json | jq '.sites | length'",
        "desc": "Community-maintained JSON fingerprint dataset (`wmn-data.json`) powering high-accuracy username enumeration across 600+ platforms.",
    },
    {
        "id": "ghunt",
        "name": "GHunt",
        "category": "Identity & Usernames",
        "repo": "https://github.com/mxrch/GHunt",
        "stars": "16.5k+",
        "binary": "ghunt",
        "install_cmd": "pipx install ghunt",
        "cmd_template": "ghunt email {target}",
        "desc": "Offensive Google OSINT framework extracting Gaia IDs, Maps reviews, public photos, Calendar availability, and YouTube channels.",
    },
    # 2. Email, Breach & Account OSINT
    {
        "id": "holehe",
        "name": "Holehe",
        "category": "Email & Account Intel",
        "repo": "https://github.com/megadose/holehe",
        "stars": "8.8k+",
        "binary": "holehe",
        "install_cmd": "pipx install holehe",
        "cmd_template": "holehe {target} --only-used --no-color",
        "desc": "Checks if an email is attached to accounts on 120+ sites (Twitter, Instagram, Spotify, GitHub, Adobe) via non-alerting password reset flows.",
    },
    {
        "id": "theharvester",
        "name": "theHarvester",
        "category": "Email & Account Intel",
        "repo": "https://github.com/laramies/theHarvester",
        "stars": "12k+",
        "binary": "theHarvester",
        "install_cmd": "sudo apt install theharvester",
        "cmd_template": "theHarvester -d {target} -b crtsh,rapiddns,urlscan -l 100",
        "desc": "Gathers emails, names, subdomains, IPs, and URLs from 30+ public passive intelligence sources for pre-engagement recon.",
    },
    {
        "id": "h8mail",
        "name": "h8mail",
        "category": "Email & Account Intel",
        "repo": "https://github.com/khast3x/h8mail",
        "stars": "4.3k+",
        "binary": "h8mail",
        "install_cmd": "pipx install h8mail",
        "cmd_template": "h8mail -t {target}",
        "desc": "Email OSINT and password breach hunting tool supporting local breach compilations, Scylla, IntelX, and HaveIBeenPwned APIs.",
    },
    {
        "id": "git-commit-osint",
        "name": "Git Commit Email Harvester",
        "category": "Email & Account Intel",
        "repo": "https://github.com/NullAITech/zoth-osint",
        "stars": "In-House",
        "binary": "curl",
        "install_cmd": "Built-in to Zoth OSINT",
        "cmd_template": "curl -s https://api.github.com/users/{target}/events/public | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\\.[a-zA-Z]{2,}' | sort -u",
        "desc": "Extracts real developer email addresses and PGP/SSH key fingerprints from public GitHub push events and .patch commits.",
    },
    # 3. Domain, DNS & Subdomain Recon
    {
        "id": "subfinder",
        "name": "Subfinder (ProjectDiscovery)",
        "category": "Domain & Subdomains",
        "repo": "https://github.com/projectdiscovery/subfinder",
        "stars": "10.8k+",
        "binary": "subfinder",
        "install_cmd": "sudo apt install subfinder",
        "cmd_template": "subfinder -d {target} -silent",
        "desc": "Fast passive subdomain enumeration tool using Certificate Transparency, passive DNS, and security aggregator APIs.",
    },
    {
        "id": "amass",
        "name": "OWASP Amass",
        "category": "Domain & Subdomains",
        "repo": "https://github.com/owasp-amass/amass",
        "stars": "12.4k+",
        "binary": "amass",
        "install_cmd": "sudo apt install amass",
        "cmd_template": "amass enum -passive -d {target} -timeout 2",
        "desc": "In-depth attack surface mapping and external asset discovery using DNS, ASN, BGP, WHOIS, and Certificate Transparency graphs.",
    },
    {
        "id": "dig",
        "name": "ISC dig (DNS Telemetry)",
        "category": "Domain & Subdomains",
        "repo": "https://gitlab.isc.org/isc-projects/bind9",
        "stars": "Core Unix",
        "binary": "dig",
        "install_cmd": "sudo apt install dnsutils",
        "cmd_template": "dig +noall +answer {target} A AAAA MX TXT NS",
        "desc": "Direct authoritative and recursive DNS resolver interrogation across A, AAAA, MX, TXT, SPF, DMARC, and NS records.",
    },
    {
        "id": "whois",
        "name": "WHOIS / RDAP Registry",
        "category": "Domain & Subdomains",
        "repo": "https://github.com/rfc1036/whois",
        "stars": "Core Unix",
        "binary": "whois",
        "install_cmd": "sudo apt install whois",
        "cmd_template": "whois {target}",
        "desc": "Queries global ICANN registrars and RIRs (ARIN, RIPE, APNIC) for domain registration dates, abuse contacts, and ASN netblocks.",
    },
    # 4. IP, Ports & Vulnerability OSINT
    {
        "id": "internetdb",
        "name": "Shodan InternetDB (Zero-Key)",
        "category": "IP, Ports & Vulns",
        "repo": "https://internetdb.shodan.io",
        "stars": "Built-in",
        "binary": "curl",
        "install_cmd": "Built-in to Zoth OSINT",
        "cmd_template": "curl -s https://internetdb.shodan.io/{target}",
        "desc": "Fast, 100% free zero-key API by Shodan returning open ports, CPE software fingerprints, hostnames, tags, and CVEs for any IPv4.",
    },
    {
        "id": "shodan",
        "name": "Shodan CLI",
        "category": "IP, Ports & Vulns",
        "repo": "https://github.com/achillean/shodan-python",
        "stars": "3.1k+",
        "binary": "shodan",
        "install_cmd": "pip install shodan",
        "cmd_template": "shodan host {target}",
        "desc": "Official command-line interface to Shodan for banner grabbing, IoT/ICS device search, favicon hash hunting, and CVE filtering.",
    },
    {
        "id": "nmap",
        "name": "Nmap Service & Script Recon",
        "category": "IP, Ports & Vulns",
        "repo": "https://github.com/nmap/nmap",
        "stars": "10.5k+",
        "binary": "nmap",
        "install_cmd": "sudo apt install nmap",
        "cmd_template": "nmap -Pn -sV --top-ports 25 --open {target}",
        "desc": "Industry-standard network mapper and NSE script engine for service version detection, TLS cipher grading, and banner recon.",
    },
    {
        "id": "httpx",
        "name": "httpx (ProjectDiscovery)",
        "category": "IP, Ports & Vulns",
        "repo": "https://github.com/projectdiscovery/httpx",
        "stars": "8.2k+",
        "binary": "httpx",
        "install_cmd": "go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest",
        "cmd_template": "httpx -u {target} -title -tech-detect -status-code -silent",
        "desc": "Multi-purpose HTTP toolkit probing web servers for tech stacks, TLS certs, MurmurHash3 favicon hashes, and status codes.",
    },
    # 5. Media, Document & GEOINT Forensics
    {
        "id": "exiftool",
        "name": "ExifTool (Phil Harvey)",
        "category": "GEOINT & Media Forensics",
        "repo": "https://github.com/exiftool/exiftool",
        "stars": "3.8k+",
        "binary": "exiftool",
        "install_cmd": "sudo apt install libimage-exiftool-perl",
        "cmd_template": "exiftool -a -u -g1 {target}",
        "desc": "Gold-standard metadata reader/extractor for EXIF, GPS coordinates, XMP, IPTC, ICC profiles, PDF author history, and camera serials.",
    },
    {
        "id": "overpass-turbo",
        "name": "Overpass Turbo (OSM GEOINT)",
        "category": "GEOINT & Media Forensics",
        "repo": "https://github.com/tyrasd/overpass-turbo",
        "stars": "1.4k+",
        "binary": None,
        "install_cmd": "Web / API: https://overpass-turbo.eu",
        "cmd_template": "[out:json][timeout:25];(node[\"power\"=\"substation\"](around:5000,{target}););out body;>;out skel qt;",
        "desc": "OpenStreetMap spatial query language used by Bellingcat and GEOINT investigators to geolocate photos by road/building/power geometry.",
    },
    {
        "id": "bellingcat-archiver",
        "name": "Bellingcat Auto-Archiver",
        "category": "GEOINT & Media Forensics",
        "repo": "https://github.com/bellingcat/auto-archiver",
        "stars": "1.6k+",
        "binary": "auto-archiver",
        "install_cmd": "pipx install auto-archiver",
        "cmd_template": "auto-archiver --urls {target}",
        "desc": "Evidentiary preservation tool archiving social media posts, videos, Wayback snapshots, and SHA-256 chain-of-custody hashes.",
    },
    {
        "id": "photon",
        "name": "Photon Web Crawler",
        "category": "GEOINT & Media Forensics",
        "repo": "https://github.com/s0md3v/Photon",
        "stars": "11.5k+",
        "binary": "photon",
        "install_cmd": "git clone https://github.com/s0md3v/Photon",
        "cmd_template": "photon -u https://{target} -l 2 --keys --dns",
        "desc": "Lightning-fast OSINT web crawler extracting URLs, JS endpoints, API keys, emails, social accounts, and subdomains.",
    },
    # 6. Link Analysis & Automated OSINT Frameworks
    {
        "id": "spiderfoot",
        "name": "SpiderFoot HX Open Source",
        "category": "Link Analysis & Frameworks",
        "repo": "https://github.com/smicallef/spiderfoot",
        "stars": "13.2k+",
        "binary": "spiderfoot",
        "install_cmd": "git clone https://github.com/smicallef/spiderfoot",
        "cmd_template": "spiderfoot -s {target} -u passive",
        "desc": "Automated OSINT framework integrating 200+ threat intelligence, DNS, breach, dark web, and social modules into an entity graph.",
    },
    {
        "id": "recon-ng",
        "name": "Recon-ng",
        "category": "Link Analysis & Frameworks",
        "repo": "https://github.com/lanmaster53/recon-ng",
        "stars": "4.6k+",
        "binary": "recon-ng",
        "install_cmd": "sudo apt install recon-ng",
        "cmd_template": "recon-ng -w zoth_workspace -C 'db insert domains {target}'",
        "desc": "Modular Python web reconnaissance framework modeled after Metasploit with an integrated SQLite workspace database.",
    },
    {
        "id": "obsidian-canvas",
        "name": "Zoth Entity Graph -> Obsidian .canvas",
        "category": "Link Analysis & Frameworks",
        "repo": "https://github.com/NullAITech/zoth-osint",
        "stars": "In-House",
        "binary": "zoth-osint",
        "install_cmd": "Built-in to Zoth OSINT",
        "cmd_template": "zoth-osint scan {target} --canvas /tmp/{target}.canvas",
        "desc": "Native Zoth OSINT link-analysis synthesizer exporting discovered domains, IPs, ports, CVEs, and profiles directly to Obsidian Canvas.",
    },
    {
        "id": "wayback-cdx",
        "name": "Internet Archive Wayback CDX",
        "category": "Link Analysis & Frameworks",
        "repo": "https://github.com/internetarchive/wayback",
        "stars": "Built-in",
        "binary": "curl",
        "install_cmd": "Built-in to Zoth OSINT",
        "cmd_template": "curl -s 'https://web.archive.org/cdx/search/cdx?url=*.{target}/*&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=50'",
        "desc": "Queries the Wayback Machine CDX index to uncover historical endpoints, deleted pages, leaked `.env` files, and old subdomains.",
    },
]

EXTRA_SEARCH_PATHS = ["/usr/local/bin", "/usr/bin", "/bin", "/opt/zothos-ai-env/bin"]


def find_binary(binary_name: Optional[str]) -> Optional[str]:
    if not binary_name:
        return None
    if binary_name == "zoth-osint":
        return "/usr/local/bin/zoth-osint"
    found = shutil.which(binary_name)
    if found:
        return found
    for p in EXTRA_SEARCH_PATHS:
        candidate = f"{p}/{binary_name}"
        if shutil.which(candidate):
            return candidate
    return None


def get_arsenal_status(target: str = "nullai.tech") -> Dict[str, Any]:
    items = []
    installed_count = 0
    safe_target = target.strip() or "nullai.tech"
    for tool in OPEN_SOURCE_OSINT_ARSENAL:
        bin_path = find_binary(tool.get("binary"))
        is_installed = bin_path is not None or tool.get("install_cmd", "").startswith("Built-in")
        if is_installed:
            installed_count += 1
        items.append(
            {
                **tool,
                "installed": is_installed,
                "binary_path": bin_path or ("built-in" if is_installed else None),
                "ready_command": tool["cmd_template"].replace("{target}", safe_target),
            }
        )
    return {
        "total_tools": len(items),
        "installed_or_builtin": installed_count,
        "target": safe_target,
        "tools": items,
    }


ALLOWED_EXEC_TOOLS = {"sherlock", "subfinder", "dig", "whois", "nmap", "internetdb", "wayback-cdx", "git-commit-osint"}


def execute_arsenal_tool(tool_id: str, target: str, timeout_sec: int = 15) -> Dict[str, Any]:
    """Safely execute a local open-source OSINT tool with strict argument validation and timeout."""
    import re

    clean_target = re.sub(r"[^a-zA-Z0-9._@-]", "", target.strip())
    if not clean_target:
        return {"ok": False, "error": "Invalid target string"}

    tool = next((t for t in OPEN_SOURCE_OSINT_ARSENAL if t["id"] == tool_id), None)
    if not tool:
        return {"ok": False, "error": f"Unknown tool_id: {tool_id}"}

    if tool_id not in ALLOWED_EXEC_TOOLS:
        return {
            "ok": False,
            "error": f"Tool '{tool_id}' is cataloged for CLI copy; live subprocess execution is enabled for: {', '.join(sorted(ALLOWED_EXEC_TOOLS))}",
            "command": tool["cmd_template"].replace("{target}", clean_target),
        }

    bin_path = find_binary(tool.get("binary"))
    if not bin_path:
        return {"ok": False, "error": f"Binary '{tool.get('binary')}' not found on host", "install_cmd": tool.get("install_cmd")}

    if tool_id == "sherlock":
        cmd = [bin_path, clean_target.lstrip("@"), "--timeout", "4", "--print-found"]
    elif tool_id == "subfinder":
        cmd = [bin_path, "-d", clean_target, "-silent"]
    elif tool_id == "dig":
        cmd = [bin_path, "+noall", "+answer", clean_target, "A", "AAAA", "MX", "TXT", "NS"]
    elif tool_id == "whois":
        cmd = [bin_path, clean_target]
    elif tool_id == "nmap":
        cmd = [bin_path, "-Pn", "--top-ports", "20", "--open", clean_target]
    elif tool_id == "internetdb":
        cmd = [bin_path, "-s", f"https://internetdb.shodan.io/{clean_target}"]
    elif tool_id == "wayback-cdx":
        cmd = [
            bin_path,
            "-s",
            f"https://web.archive.org/cdx/search/cdx?url=*.{clean_target}/*&output=json&fl=original,timestamp,statuscode&collapse=urlkey&limit=25",
        ]
    elif tool_id == "git-commit-osint":
        cmd = [bin_path, "-s", f"https://api.github.com/users/{clean_target.lstrip('@')}/events/public?per_page=15"]
    else:
        return {"ok": False, "error": "Unsupported execution mapping"}

    t0 = time.time()
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout_sec, check=False)
        elapsed_ms = int((time.time() - t0) * 1000)
        stdout = (proc.stdout or "").strip()
        stderr = (proc.stderr or "").strip()
        return {
            "ok": proc.returncode == 0 or bool(stdout),
            "tool_id": tool_id,
            "target": clean_target,
            "command": " ".join(cmd),
            "elapsed_ms": elapsed_ms,
            "returncode": proc.returncode,
            "stdout": stdout[:12000],
            "stderr": stderr[:2000],
        }
    except subprocess.TimeoutExpired:
        return {
            "ok": False,
            "tool_id": tool_id,
            "target": clean_target,
            "command": " ".join(cmd),
            "error": f"Execution timed out after {timeout_sec}s",
        }
    except Exception as e:
        return {"ok": False, "tool_id": tool_id, "error": str(e)}
