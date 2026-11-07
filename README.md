# Zoth OSINT (`zoth-osint` v2.0)

> **Sovereign Open-Source Intelligence Engine, Multi-Pivot Recon Workstation & 24-Tool OSINT Orchestrator**  
> Engineered by **Neal Frazier Tech (@1nc0gn30)** • [NullAI Platform](https://nullai.tech)

---

## What It Does

**Zoth OSINT (`zoth-osint` v2.0)** unites an **in-house zero-key reconnaissance engine** with a **live orchestrator for the 24 best open-source OSINT tools** in the world:

1. **In-House Multi-Pivot Recon Engine (`engine/osint_core.py`)**:
   - **6-Way Auto-Target Classifier**: Automatically classifies `@username`, `domain.tld`, `IPv4`, `email@domain.tld`, `Solana / Ethereum / Bitcoin Wallet`, or `E.164 Phone Number`.
   - **Identity & Username Recon**: Concurrent handle enumeration across GitHub, GitLab, Keybase, HackerNews, Reddit, npm, PyPI, Crates.io, Dev.to, DockerHub, Chess.com, and Lichess — plus **GitHub Deep Intel** (extracting public SSH keys from `github.com/<user>.keys`, PGP key status from `.gpg`, and author email metadata from public push events).
   - **Domain, DNS, Certificate Transparency & Wayback CDX**: Live DNS-over-HTTPS (`A`, `AAAA`, `MX`, `TXT`, `NS`, `CAA`), automated SPF/DMARC posture grading, TLS certificate SAN inspection, passive `crt.sh` Certificate Transparency subdomain discovery, and **Wayback Machine CDX** historical archive inspection.
   - **Zero-Key IP & Vulnerability Recon (Shodan InternetDB + ASN)**: Queries `https://internetdb.shodan.io/<ip>` with zero API keys to retrieve open ports, CPE software fingerprints, hostnames, and active CVEs alongside BGP/ASN geolocation.
   - **Blockchain & Crypto Wallet OSINT**: Zero-key live RPC balance and transaction inspection across **Solana Mainnet** (`getBalance`, `getSignaturesForAddress`), **Ethereum / EVM** (`eth_getBalance`, `eth_getTransactionCount`, `eth_getCode`), and **Bitcoin** (`mempool.space` API).
   - **Phone Number E.164 & NANPA Geolocation**: ITU-T E.164 normalization, country & NANPA area code lookup (including `757` Hampton Roads / Virginia Beach / Norfolk), and messaging pivot URLs.
   - **Media & Binary EXIF Forensics Lab**: Extracts SHA-256 / SHA-1 / MD5 hashes, Shannon byte entropy, MIME magic headers, and embedded URLs/emails.

2. **Top 24 Open-Source OSINT Arsenal & Subprocess Runner (`engine/arsenal_runner.py`)**:
   - Curates and detects local installation status (`12/24 READY` on host) across **Maigret**, **Sherlock**, **WhatsMyName**, **GHunt**, **Holehe**, **theHarvester**, **h8mail**, **Subfinder**, **OWASP Amass**, **ISC dig**, **WHOIS/RDAP**, **Shodan InternetDB**, **Shodan CLI**, **Nmap**, **httpx**, **ExifTool**, **Overpass Turbo (OSM GEOINT)**, **Bellingcat Auto-Archiver**, **Photon**, **SpiderFoot**, **Recon-ng**, **Wayback CDX**, and **Zoth Obsidian `.canvas`**.

3. **Click-to-Pivot Entity Link Graph, SQLite Case Store & OASIS STIX 2.1 / Obsidian `.canvas` Export**:
   - Double-click any node on the 60 FPS Entity Link Graph to immediately pivot and scan that entity.
   - Automatically persists every scan in a local SQLite database (`~/.zoth-osint/cases.db`) and exports to **Obsidian JSON Canvas (`.canvas`)**, **OASIS STIX 2.1 Cyber Threat Intelligence Bundles (`.json`)**, and **Markdown Dossiers (`.md`)**.

---

## ZothOS CLI Commands

```bash
# Auto-classify target, run full multi-pivot scan & export Obsidian .canvas + STIX 2.1 CTI bundle
zoth-osint scan 1nc0gn30 --canvas /tmp/1nc0gn30.canvas --stix /tmp/1nc0gn30.stix.json

# Blockchain Wallet RPC OSINT (Solana Mainnet, Ethereum EVM, Bitcoin)
zoth-osint wallet GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK

# Phone Number ITU-T E.164 & NANPA Area Code Geolocation
zoth-osint phone "+1-757-555-0199"

# Wayback Machine CDX Historical Endpoint Discovery
zoth-osint wayback nullai.tech

# Synthesize 18 targeted passive search queries (Google, GitHub, Shodan, crt.sh, URLScan)
zoth-osint dorks nullai.tech

# List or inspect saved SQLite OSINT investigation cases (~/.zoth-osint/cases.db)
zoth-osint cases

# Check all 24 open-source OSINT tools & local binary status
zoth-osint arsenal --target nullai.tech

# Execute an installed open-source OSINT binary directly
zoth-osint run sherlock 1nc0gn30
zoth-osint run holehe contact@1nc0gn30.si
zoth-osint run subfinder nullai.tech

# Launch the Web Workstation daemon on http://127.0.0.1:8148
zoth-osint serve --port 8148
```

---

## 100% Free & Open-Access Support

All tools and exports are **100% free and unlocked by default** with zero paywalls.
- **☕ Buy Us a Coffee**: [https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)
- **Solana Wallet Tip Jar**: `GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK`
