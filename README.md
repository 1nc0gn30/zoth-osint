# Zoth OSINT (`zoth-osint` v3.0 — New-Age Sovereign Edition)

> **Sovereign Open-Source Intelligence Engine, Multi-Pivot Recon Workstation, MCP Server & 32-Tool OSINT Orchestrator**  
> Engineered by **Neal Frazier Tech (@1nc0gn30)** • [NullAI Platform](https://nullai.tech)

---

## What It Does

**Zoth OSINT (`zoth-osint` v3.0)** unites an **in-house zero-key reconnaissance engine** with a **live orchestrator for the 32 best classical and new-age open-source OSINT tools** plus a native **Model Context Protocol (MCP) Server**:

1. **In-House Multi-Pivot & New-Age Recon Engine (`engine/osint_core.py`)**:
   - **6-Way Auto-Target Classifier**: Automatically classifies `@username`, `domain.tld`, `IPv4`, `email@domain.tld`, `Solana / Ethereum / Bitcoin Wallet`, or `E.164 Phone Number`.
   - **New-Age Favicon MurmurHash3 (`mmh3`) Fingerprinting (`recon_favicon_mmh3`)**: Downloads `/favicon.ico` and computes the exact 32-bit signed MurmurHash3 (`mmh3`) + SHA-256 + MD5 used by Shodan (`http.favicon.hash:<mmh3>`), Censys, and FOFA to uncover origin servers behind Cloudflare/CDNs.
   - **IETF RDAP Structured Registry Lookup (`recon_rdap`)**: Queries `https://rdap.org` (modern JSON replacement for legacy WHOIS) for registrar attribution, registration/expiration dates, status locks, and `DNSSEC` delegation signing status.
   - **Sovereign & Security `.well-known` Manifest Probing (`recon_well_known`)**: Concurrent inspection of RFC 9116 `/.well-known/security.txt`, AI `/llms.txt`, Bluesky `/.well-known/atproto-did`, Nostr `/.well-known/nostr.json` (`NIP-05`), and OIDC `/.well-known/openid-configuration`.
   - **Decentralized Web3, ATProto & AI Supply-Chain Identity (`recon_new_age_identity`)**: Resolves Bluesky AT Protocol handles to `did:plc` Decentralized Identifiers and fetches full PLC Directory documents (`https://plc.directory/<did>`), resolves `.eth` ENS Web3 names, and enumerates published AI models on **HuggingFace Hub**.
   - **Identity & Username Recon**: Concurrent handle enumeration across 14 platforms (GitHub, GitLab, HuggingFace, Bluesky ATProto, Keybase, HackerNews, Reddit, npm, PyPI, Crates.io, Dev.to, DockerHub, Chess.com, Lichess) — plus **GitHub Deep Intel** (SSH keys, PGP keys, commit emails).
   - **Zero-Key IP & Vulnerability Recon (Shodan InternetDB + ASN)**: Queries `https://internetdb.shodan.io/<ip>` with zero API keys to retrieve open ports, CPEs, hostnames, and active CVEs alongside BGP/ASN geolocation.
   - **Blockchain & Crypto Wallet OSINT**: Zero-key live RPC balance and transaction inspection across **Solana Mainnet**, **Ethereum / EVM**, and **Bitcoin**.
   - **Phone Number E.164 & NANPA Geolocation**: ITU-T E.164 normalization, country & NANPA area code lookup (`757` Hampton Roads / Virginia Beach / Norfolk), and messaging pivot URLs.

2. **Top 32 Open-Source OSINT Arsenal & Subprocess Runner (`engine/arsenal_runner.py`)**:
   - Curates and detects local installation status (**17/32 available locally**) across 7 categories including **New-Age & Supply-Chain OSINT**: **BBOT**, **Blackbird**, **Nuclei**, **Katana**, **TruffleHog**, **Gitleaks**, **Maigret**, **Sherlock**, **WhatsMyName**, **GHunt**, **Holehe**, **theHarvester**, **h8mail**, **Subfinder**, **OWASP Amass**, **ISC dig**, **WHOIS/RDAP**, **Shodan InternetDB**, **Shodan CLI**, **Nmap**, **httpx**, **ExifTool**, **Overpass Turbo (OSM GEOINT)**, **Bellingcat Auto-Archiver**, **Photon**, **SpiderFoot**, **Recon-ng**, **Wayback CDX**, **Zoth Favicon MMH3**, **Zoth Web3/ATProto/RDAP**, and **Zoth Obsidian `.canvas`**.

3. **Native Model Context Protocol (MCP) Server (`mcp_server.py`)**:
   - Exposes `osint_scan`, `osint_favicon_mmh3`, `osint_web3_identity`, `osint_rdap`, `osint_wallet`, and `osint_wayback` over JSON-RPC 2.0 STDIO (`zoth-osint mcp`).

4. **Click-to-Pivot Entity Link Graph, SQLite Case Store & OASIS STIX 2.1 / Obsidian `.canvas` Export**:
   - Double-click any node on the 60 FPS Entity Link Graph to immediately pivot and scan that entity.
   - Automatically persists every scan in `~/.zoth-osint/cases.db` and exports to **Obsidian JSON Canvas (`.canvas`)**, **OASIS STIX 2.1 Cyber Threat Intelligence Bundles (`.json`)**, and **Markdown Dossiers (`.md`)**.

5. **Zero-Key Breach & Leak Intelligence Engine (`engine/breach_intel.py`)**:
   - **Mathematical k-Anonymity Credential Check**: Computes SHA-1 hash prefixes (first 5 characters) against Have I Been Pwned (HIBP) Pwned Passwords range endpoint with zero credential disclosure over the wire.
   - **XposedOrNot & LeakCheck Multi-Index Correlation**: Queries verified breach archives, exposed PII attributes (passwords, SSNs, phone numbers), and historical paste dumps without requiring third-party API keys.
   - **Public Paste & Code Mentions Prober**: Direct endpoint inspection across Rentry.co, Dpaste.org, GitHub user Gists, and public GitHub repository commit leaks.
   - **Deterministic Threat Risk Scorer (0-100)**: Synthesizes risk ratings (`CLEAN`, `LOW`, `MODERATE`, `HIGH`, `CRITICAL`) with prioritized vulnerability evidence.

6. **MITRE ATT&CK Enterprise Matrix & Defensive Countermeasures (`engine/mitre_attack.py`)**:
   - Automatically maps all discovered reconnaissance telemetry (open ports like 22 SSH, 80/443 HTTP, 3389 RDP, 445 SMB; exposed `.env` / `.git` secrets; missing DMARC/SPF; git commit leaks; crypto wallets; cloud metadata) directly to formal **MITRE ATT&CK Enterprise Matrix techniques** (e.g. `T1592`, `T1595`, `T1589`, `T1596`, `T1190`, `T1133`, `T1566`, `T1552.001`, `T1526`, `T1078`, `T1496`).
   - Computes an automated **Defensive Hardening Score (0-100)** and synthesizes prioritized tactical countermeasures (`P1` Critical through `P3` Medium) with concrete remediation actions (strict DMARC `p=reject`, SSH key-only auth & Fail2ban, secret rotation, Cloudflare WAF origin cloaking, IMDSv2 token enforcement).
   - Enriches all generated **OASIS STIX 2.1 Bundles** with standard SDO `attack-pattern` objects, `course-of-action` mitigation objects, and `targets`/`mitigates` relationship links.

7. **Active/Passive Subdomain Takeover & Dangling DNS Engine (`engine/takeover.py`)**:
   - Audits CNAME delegation records and queries Google DNS-over-HTTPS (DoH) with zero pip dependencies.
   - Evaluates dangling pointers against **23+ vulnerable SaaS fingerprints**: GitHub Pages, AWS S3 (`<Code>NoSuchBucket</Code>`), Heroku (`No such app`), Netlify (`Not Found`), Fastly (`Fastly error: unknown domain`), Ghost, Surge, Shopify, Vercel, Bitbucket, Zendesk, HubSpot, WordPress, Tumblr, Unbounce, Azure App Service, Fly.io, Pantheon, ReadMe, Help Scout, Cargo, Render, and Firebase Hosting.
   - Integrated into every domain recon scan and exposed via CLI (`zoth-osint takeover <domain>`), REST API (`/api/takeover`), and MCP tool (`osint_subdomain_takeovers`).

---

## ZothOS CLI & MCP Commands

```bash
# Auto-classify target, run full multi-pivot scan & export Obsidian .canvas + STIX 2.1 CTI bundle
zoth-osint scan 1nc0gn30 --canvas /tmp/1nc0gn30.canvas --stix /tmp/1nc0gn30.stix.json

# Zero-key breach, leak archive & pastebin/gist reconnaissance with HIBP k-anonymity
zoth-osint breach test@example.com
zoth-osint breach 1nc0gn30 --json

# Map reconnaissance findings to MITRE ATT&CK Enterprise Matrix & tactical countermeasures
zoth-osint mitre nullai.tech
zoth-osint mitre 1.1.1.1 --stix /tmp/mitre_bundle.stix.json
zoth-osint mitre 1nc0gn30 --json

# Subdomain takeover and dangling CNAME audit across 23+ SaaS signatures
zoth-osint takeover nullai.tech
zoth-osint takeover sub1.example.com,sub2.example.com --json

# Compute Shodan/Censys 32-bit signed Favicon MurmurHash3 (mmh3) & SHA256
zoth-osint favicon github.com

# Query IETF RDAP structured registry (registrar, dates, DNSSEC status)
zoth-osint rdap nullai.tech

# Resolve Bluesky ATProto DID (did:plc), ENS (.eth) Web3 identity & HuggingFace AI models
zoth-osint web3 bsky.app

# Blockchain Wallet RPC OSINT (Solana Mainnet, Ethereum EVM, Bitcoin)
zoth-osint wallet GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK

# Phone Number ITU-T E.164 & NANPA Area Code Geolocation
zoth-osint phone "+1-757-555-0199"

# Wayback Machine CDX Historical Endpoint Discovery
zoth-osint wayback nullai.tech

# Check all 32 open-source OSINT tools & local binary status
zoth-osint arsenal --target nullai.tech

# Start the JSON-RPC 2.0 Model Context Protocol (MCP) STDIO server for AI agents
zoth-osint mcp

# Launch the Web Workstation daemon on http://127.0.0.1:8149
zoth-osint serve --port 8149
```

---

## 100% Free & Open-Access Support

All tools and exports are **100% free and unlocked by default** with zero paywalls.
- **☕ Buy Us a Coffee**: [https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)
- **Solana Wallet Tip Jar**: `GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK`
