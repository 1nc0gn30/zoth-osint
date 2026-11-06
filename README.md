# Zoth OSINT (`zoth-osint` v1.0)

> **Sovereign Open-Source Intelligence Engine, Multi-Pivot Recon Workstation & 24-Tool OSINT Orchestrator**  
> Engineered by **Neal Frazier Tech (@1nc0gn30)** • [NullAI Platform](https://nullai.tech)

---

## What It Does

**Zoth OSINT (`zoth-osint`)** unites an **in-house zero-key reconnaissance engine** with a **live orchestrator for the 24 best open-source OSINT tools** in the world:

1. **In-House Multi-Pivot Recon Engine (`engine/osint_core.py`)**:
   - **Auto-Target Classifier**: Automatically classifies `@username`, `domain.tld`, `IPv4`, or `email@domain.tld`.
   - **Identity & Username Recon**: Concurrent handle enumeration across GitHub, GitLab, Keybase, HackerNews, Reddit, npm, PyPI, Crates.io, Dev.to, DockerHub, Chess.com, and Lichess — plus **GitHub Deep Intel** (extracting public SSH keys from `github.com/<user>.keys`, PGP key status from `.gpg`, and author email leaks from public push events).
   - **Domain, DNS & Certificate Transparency Recon**: Live DNS-over-HTTPS (`A`, `AAAA`, `MX`, `TXT`, `NS`, `CAA`), automated SPF/DMARC spoof-resistance grading, TLS certificate SAN inspection, and passive `crt.sh` Certificate Transparency subdomain discovery.
   - **Zero-Key IP & Vulnerability Recon (Shodan InternetDB + ASN)**: Queries `https://internetdb.shodan.io/<ip>` with zero API keys to retrieve open ports, CPE software fingerprints, hostnames, and active CVEs alongside BGP/ASN geolocation.
   - **Email & Cryptographic Identity Pivot**: Gravatar MD5/SHA256 profile verification, OpenPGP keyserver (`keys.openpgp.org`) lookup, GitHub email-to-account search, and domain mail posture.
   - **Media & Binary EXIF Forensics Lab**: Extracts SHA-256 / SHA-1 / MD5 hashes, Shannon byte entropy, MIME magic headers, and embedded URLs/emails.

2. **Top 24 Open-Source OSINT Arsenal & Subprocess Runner (`engine/arsenal_runner.py`)**:
   - Curates and detects local installation status across **Maigret**, **Sherlock**, **WhatsMyName**, **GHunt**, **Holehe**, **theHarvester**, **h8mail**, **Subfinder**, **OWASP Amass**, **ISC dig**, **WHOIS/RDAP**, **Shodan InternetDB**, **Shodan CLI**, **Nmap**, **httpx**, **ExifTool**, **Overpass Turbo (OSM GEOINT)**, **Bellingcat Auto-Archiver**, **Photon**, **SpiderFoot**, **Recon-ng**, **Wayback CDX**, and **Zoth Obsidian `.canvas`**.

3. **Interactive 60 FPS Entity Link Graph & Obsidian `.canvas` Exporter**:
   - Synthesizes every discovered pivot into an interactive force-directed graph and exports directly to **Obsidian JSON Canvas (`.canvas`)** or **Markdown Intelligence Dossiers (`.md`)**.

---

## ZothOS CLI Commands

```bash
# Auto-classify target, run full multi-pivot scan & export Obsidian .canvas
zoth-osint scan 1nc0gn30 --canvas /tmp/1nc0gn30.canvas

# Username / handle enumeration + GitHub SSH/PGP/commit email deep intel
zoth-osint username 1nc0gn30 --json

# Domain DNS, SPF/DMARC, TLS, crt.sh subdomains & Shodan InternetDB pivot
zoth-osint domain nullai.tech --json

# Zero-key Shodan InternetDB open ports, CVEs & BGP ASN lookup
zoth-osint ip 1.1.1.1 --json

# Check all 24 open-source OSINT tools & local binary status
zoth-osint arsenal --target nullai.tech

# Execute an installed open-source OSINT binary directly
zoth-osint run sherlock 1nc0gn30
zoth-osint run subfinder nullai.tech

# Launch the Web Workstation daemon on http://127.0.0.1:8148
zoth-osint serve --port 8148
```

---

## 100% Free & Open-Access Support

All tools and exports are **100% free and unlocked by default** with zero paywalls.
- **☕ Buy Us a Coffee**: [https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)
- **Solana Wallet Tip Jar**: `GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK`
