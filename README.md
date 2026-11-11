# Zoth OSINT (`zoth-osint`)

Zero-key multi-pivot Open-Source Intelligence (OSINT) engine, 32-tool reconnaissance orchestrator, HTTP workstation (`127.0.0.1:8149`), and JSON-RPC 2.0 Model Context Protocol (MCP) server (`zoth-osint mcp`).

---

## Core Modules

1. **Multi-Pivot Reconnaissance Engine (`engine/osint_core.py`)**:
   - **6-Way Target Classifier**: Classifies `@username`, `domain.tld`, `IPv4`, `email@domain.tld`, `Solana / EVM / Bitcoin wallet`, and ITU-T `E.164` phone numbers.
   - **Favicon MurmurHash3 (`mmh3`) Fingerprinting**: Computes 32-bit signed MurmurHash3 (`http.favicon.hash:<mmh3>`), SHA-256, and MD5 digests for Shodan, Censys, and FOFA origin pivoting.
   - **IETF RDAP & `.well-known` Probing**: Queries `rdap.org` structured domain metadata (`DNSSEC`, registrar, status locks) alongside `/.well-known/security.txt`, `/llms.txt`, `/.well-known/atproto-did`, `/.well-known/nostr.json`, and OIDC discovery manifests.
   - **Decentralized & Developer Identity**: Resolves Bluesky ATProto handles (`did:plc` via `plc.directory`), `.eth` ENS names, HuggingFace Hub repositories, and 14 developer platforms (including GitHub SSH/PGP keys).
   - **Infrastructure, Blockchain & Telecom**: Queries zero-key Shodan InternetDB (`internetdb.shodan.io`), BGP/ASN routing, Solana/EVM/Bitcoin public JSON-RPC endpoints, and NANPA/E.164 geolocation.
2. **Breach & Leak Correlation (`engine/breach_intel.py`)**:
   - SHA-1 5-character prefix k-anonymity range checks against HIBP Pwned Passwords, XposedOrNot/LeakCheck correlation, public Gist/paste checks, and 0-100 risk scoring.
3. **MITRE ATT&CK Mapping & STIX 2.1 Export (`engine/mitre_attack.py` & `engine/case_store.py`)**:
   - Maps discovered ports, missing SPF/DMARC policies, and secret exposures to MITRE ATT&CK Enterprise techniques (`T1592`, `T1595`, `T1190`, `T1552.001`, etc.), persists scan history in SQLite (`~/.zoth-osint/cases.db`), and exports OASIS STIX 2.1 bundles (`.stix.json`), GEXF graphs, and Obsidian JSON Canvas (`.canvas`) files.
4. **Subdomain Takeover Auditor (`engine/takeover.py`)**:
   - Audits CNAME delegations over DoH against 23+ dangling SaaS/cloud fingerprints (GitHub Pages, AWS S3, Heroku, Netlify, Fastly, Vercel, Render, Azure App Service, Firebase Hosting).
5. **32-Tool Local Arsenal Runner (`engine/arsenal_runner.py`)**:
   - Detects installed local binaries (`bbot`, `nuclei`, `katana`, `gitleaks`, `trufflehog`, `subfinder`, `amass`, `sherlock`, `maigret`, `nmap`, `exiftool`, `dig`, etc.) and executes scoped subprocess scans.

---

## Installation & Quick Start

```bash
git clone https://github.com/1nc0gn30/zoth-osint.git
cd zoth-osint

# Start the local web workstation on http://127.0.0.1:8149
python3 server.py --port 8149

# Start the JSON-RPC 2.0 MCP stdio server
python3 mcp_server.py
```

---

## CLI Reference (`bin/zoth-osint`)

```bash
# Unified multi-pivot scan with Obsidian .canvas and OASIS STIX 2.1 exports
./bin/zoth-osint scan 1nc0gn30 --canvas /tmp/1nc0gn30.canvas --stix /tmp/1nc0gn30.stix.json

# Breach & k-anonymity leak reconnaissance
./bin/zoth-osint breach test@example.com --json

# MITRE ATT&CK Enterprise mapping & defensive countermeasures
./bin/zoth-osint mitre nullai.tech --json

# Dangling CNAME / subdomain takeover audit
./bin/zoth-osint takeover nullai.tech --json

# Favicon 32-bit signed MurmurHash3, RDAP, Web3, Wallet, Phone, and Wayback pivots
./bin/zoth-osint favicon github.com
./bin/zoth-osint rdap nullai.tech
./bin/zoth-osint web3 bsky.app
./bin/zoth-osint wallet TokenkegQfeZyiNwAJbNbGKPFXCWuBvf9Ss623VQ5DA
./bin/zoth-osint phone "+1-757-555-0199"
./bin/zoth-osint wayback nullai.tech

# Inspect local installation status of all 32 open-source OSINT tools
./bin/zoth-osint arsenal --target nullai.tech
```

---

## Verification & Tests

```bash
python3 -m pytest -v
gitleaks detect --source . --no-banner --redact
```

---

## License & Support

- **Open Access**: 100% free and open-source with zero paywalls or locked exports.
- **Support**: [Buy Us a Coffee via Stripe](https://buy.stripe.com/3cIfZg27PdKo2D64Ocfw40X)

Engineered by **1nc0gn30** ([@1nc0gn30](https://github.com/1nc0gn30) · [1nc0gn30.si](https://1nc0gn30.si)) · [NullAI Platform](https://nullai.tech) · [Zoth Studio](https://zoth.nullai.tech)
