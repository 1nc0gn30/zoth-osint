# Sovereign OSINT Masterclass: Operational Tradecraft & Field Intelligence (v4.0)

> **Architected by Neal Frazier (@1nc0gn30) • NullAI Platform & Neal Frazier Tech**  
> *Zero-Telemetry, Sovereign Reconnaissance, Blockchain Forensics & Graph Intelligence*

---

## Curriculum Overview

This masterclass is a complete, real-world operational doctrine and training manual for modern **Open-Source Intelligence (OSINT)**, **Cyber Threat Intelligence (CTI)**, **Attack Surface Management (ASM)**, and **Decentralized Network Investigation**. 

Every module connects theory with execution, using open standards, zero-key infrastructure APIs, and the native **Zoth OSINT (`zoth-osint`)** engine.

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                       SOVEREIGN OSINT CURRICULUM                            │
├─────────────┬───────────────────────────────────────────────────────────────┤
│ Module 01   │ OSINT Fundamentals, Ethics & Sovereign OpSec Baseline        │
│ Module 02   │ Digital Identity, SOCMINT & Artifact Forensic Triangulation   │
│ Module 03   │ Infrastructure Recon, DNS-over-HTTPS, BGP & Port Telemetry    │
│ Module 04   │ Web Asset Fingerprinting: Favicon MMH3 & Certificate Trails   │
│ Module 05   │ Cryptographic Ledger OSINT: Solana, EVM & Bitcoin Forensics   │
│ Module 06   │ Telephony (E.164), Geolocation (GEOINT) & Overpass Spatial    │
│ Module 07   │ Time-Travel Recon: Wayback CDX Endpoint & Git Secret Hunting  │
│ Module 08   │ Link Analysis, OASIS STIX 2.1 CTI & Obsidian Graph Modeling   │
│ Module 09   │ Autonomous Tool Orchestration: 32 Open-Source Arsenal Tools   │
│ Module 10   │ Agentic AI & Model Context Protocol (MCP) in OSINT Workflows  │
└─────────────┴───────────────────────────────────────────────────────────────┘
```

---

## Module 01 // OSINT Fundamentals, Ethics & Sovereign OpSec Baseline

### 1.1 The Definition of Modern OSINT
Open-Source Intelligence is the collection, correlation, analysis, and synthesis of publicly available data to yield actionable tactical or strategic intelligence. 
Modern OSINT is divided into 4 tiers:
1. **Passive Reconnaissance**: Querying public aggregators, certificate transparency logs, distributed ledger nodes, and Internet caches without transmitting a single packet directly to target systems.
2. **Semi-Passive Reconnaissance**: Interrogating third-party intermediate authoritative servers (such as Google DNS-over-HTTPS or public BGP routers).
3. **Active Enumeration**: Direct connection handshakes, port probes, and HTTP asset header queries.
4. **Attribution & Link Synthesis**: Entity resolution connecting disparate handles, crypto wallets, and IP netblocks into an immutable knowledge graph.

### 1.2 The Sovereign Operational Security (OpSec) Checklist
Before executing any reconnaissance engagement:
- **Clean Browser Profile & Isolated Tunnels**: Never conduct OSINT from a personal identity browser context. Utilize dedicated Chromium / Tor contexts.
- **DNS Leak Prevention**: Enforce DNS-over-HTTPS (DoH) via Google (`https://dns.google/resolve`) or Cloudflare (`https://cloudflare-dns.com/dns-query`) to evade ISP DNS request interception.
- **Zero Third-Party Cloud Telemetry**: Avoid cloud SaaS OSINT services that log search targets into proprietary commercial databases. Prefer local-first engines with local SQLite databases (`~/.zoth-osint/cases.db`).

---

## Module 02 // Digital Identity, SOCMINT & Artifact Forensic Triangulation

### 2.1 The Username Enumeration Surface
A target identifier (handle) rarely exists on a single platform. Investigators track handles across platform categories:
- **Developer / Version Control**: GitHub, GitLab, Bitbucket, Keybase.
- **Package Ecosystems**: npm (`~username`), PyPI (`/user/username`), Crates.io, DockerHub (`/u/username`).
- **Technical Discourse**: HackerNews (`/user?id=username`), Reddit, Dev.to.
- **Decentralized Social**: Bluesky AT Protocol (`username.bsky.social`), Nostr (`npub...`).

### 2.2 Deep Artifact Extraction: GitHub Footprint
Public Git push activity leaks permanent historical telemetry:
1. **SSH Public Key Enumeration**:
   ```bash
   curl -s https://github.com/<username>.keys
   ```
   Reveals whether the target utilizes modern Ed25519 (`ssh-ed25519`) or RSA keys, establishing hardware and workstation patterns.
2. **PGP Key Extraction**:
   ```bash
   curl -s https://github.com/<username>.gpg
   ```
3. **Commit Email Leakage via Public Events API**:
   Even if an email address is set to private in user profiles, commits pushed to public repositories frequently contain real author emails in git commit author metadata:
   ```bash
   curl -s https://api.github.com/users/<username>/events/public | grep -oE '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}' | sort -u
   ```

### 2.3 Email & Cryptographic Verification
- **Gravatar Hash Triangulation**: Gravatar relies on the MD5 or SHA256 hash of an email address:
  ```python
  import hashlib
  email_hash = hashlib.md5("user@target.com".strip().lower().encode()).hexdigest()
  avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
  ```
- **OpenPGP Universal Keyserver**: Querying `https://keys.openpgp.org/vks/v1/by-email/<email>` validates ownership and retrieves PGP key fingerprints without alerting the user.

### 2.4 Zero-Key Breach & Leak Intelligence: HIBP SHA-1 k-Anonymity & Paste Recon
Exposing credential compromises without revealing target secrets to third parties:
- **Mathematical k-Anonymity via HIBP Pwned Passwords**:
  Instead of sending the password or full hash, compute `SHA-1(credential)`:
  Send only the first 5 characters (prefix) to `https://api.pwnedpasswords.com/range/{prefix}`.
  The server returns a block of ~500 hash suffixes and occurrence counts. Search the returned list locally for the remaining 35 characters. This guarantees mathematical zero-knowledge proof.
- **XposedOrNot Public API & LeakCheck**:
  Querying `https://api.xposedornot.com/v1/breach-analytics?email={email}` yields exposure records, breach event dates, and PII classes (plain passwords, salted hashes, phone numbers, corporate affiliations).
- **Tactical Paste Probes**:
  Scan active pastebin dumps and public GitHub Gists via direct raw slug resolution (`rentry.co/api/raw/{query}`, `dpaste.org/{query}.txt`).

---

## Module 03 // Infrastructure Recon, DNS-over-HTTPS, BGP & Port Telemetry

### 3.1 Passive DNS Resolution via DNS-over-HTTPS (DoH)
Direct `dig` or `nslookup` queries leak target domains to your local network and upstream recursive resolvers. Standardize on structured DoH:
```bash
# Query A, AAAA, MX, TXT, and CAA records
curl -s "https://dns.google/resolve?name=example.com&type=A"
curl -s "https://dns.google/resolve?name=example.com&type=MX"
curl -s "https://dns.google/resolve?name=example.com&type=TXT"
```

### 3.2 Email Defense Posture & Spoof-Resistance Grading
An organization's email configuration signals maturity:
- **SPF (`v=spf1`)**: Defines allowed sending IP addresses. A softfail `~all` permits spoofing in some mail clients; hardfail `-all` enforces strict dropping.
- **DMARC (`_dmarc.domain.com`)**: Defines quarantine (`p=quarantine`) or reject (`p=reject`) policies. Missing DMARC represents an actionable domain impersonation risk.

### 3.3 Zero-Key Port & CVE Recon: Shodan InternetDB
Shodan maintains a free, zero-key REST endpoint returning open ports, CPEs, and active CVEs for any IPv4 address:
```bash
curl -s https://internetdb.shodan.io/1.1.1.1
```
Output schema:
```json
{
  "cpes": [],
  "hostnames": ["one.one.one.one"],
  "ip": "1.1.1.1",
  "ports": [53, 80, 443, 853],
  "tags": [],
  "vulns": []
}
```

### 3.4 Autonomous System (ASN) & BGP Route Intelligence
Using RIPE Stat's zero-key JSON API, investigators resolve the BGP ASN holder and announced CIDR netblocks:
```bash
# AS Overview
curl -s "https://stat.ripe.net/data/as-overview/data.json?resource=AS13335"
# Announced BGP Prefixes
curl -s "https://stat.ripe.net/data/announced-prefixes/data.json?resource=AS13335"
```

---

## Module 04 // Web Asset Fingerprinting: Favicon MMH3 & Certificate Trails

### 4.1 Favicon MurmurHash3 (mmh3) Origin Unmasking
When organizations deploy Cloudflare, Fastly, or Akamai in front of web infrastructure, origin server IPs are masked. However, backend staging, QA, and origin servers often host the exact same `/favicon.ico`.

1. Download `/favicon.ico`.
2. Encode raw bytes into RFC 2045 Base64 with 76-character line breaks and a trailing newline.
3. Compute 32-bit signed MurmurHash3 (`mmh3`).
4. Query Shodan: `http.favicon.hash:<hash>` or Censys: `services.http.response.favicons.shodan_hash:<hash>`.

```python
import base64
import urllib.request

def calculate_favicon_mmh3(url):
    raw = urllib.request.urlopen(url).read()
    b64 = base64.encodebytes(raw)
    # Pure Python MurmurHash3_x86_32 implementation
    return mmh3_32(b64)
```

### 4.2 Certificate Transparency (CT) Subdomain Harvesting
Under the CA/Browser Forum rules, every publicly trusted TLS certificate is logged to public append-only CT logs. Investigators harvest forgotten subdomains, VPN gateways, and admin portals:
```bash
curl -s "https://crt.sh/?q=%.target.com&output=json" | jq -r '.[].name_value' | sort -u
```

### 4.3 Passive HTTP Security Stack & Tech Fingerprinting
Analyzing HTTP response headers reveals infrastructure layers without active vulnerability exploitation:
- `Server`: Identifies reverse proxies (e.g. `nginx`, `Caddy`, `cloudflare`).
- `X-Powered-By` & Edge Headers: Detects hosting fabrics (`x-nf-request-id` = Netlify, `x-vercel-id` = Vercel, `cf-ray` = Cloudflare).
- `Strict-Transport-Security`, `Content-Security-Policy`, `X-Frame-Options`: Scored across a 0–100 posture matrix to determine organizational hardening.

### 4.4 Subdomain Takeover & Dangling DNS Fingerprinting
Subdomain takeover occurs when a DNS record (typically a CNAME) points to an external cloud or SaaS resource that has been deleted or unclaimed:
- **Dangling CNAME Resolution**: Use DoH to resolve CNAMEs. If the target returns `NXDOMAIN` (RCODE 3), the pointer is dangling.
- **SaaS Signature Fingerprinting**: Inspect HTTP error responses against known provider fingerprints:
  - **GitHub Pages**: `"There isn't a GitHub Pages site here"` (`*.github.io`)
  - **AWS S3**: `"<Code>NoSuchBucket</Code>"` (`*.s3.amazonaws.com`)
  - **Heroku**: `"No such app"` (`*.herokuapp.com`)
  - **Netlify**: `"Not Found - Request ID:"` (`*.netlify.app`)
  - **Fastly**: `"Fastly error: unknown domain"` (`*.fastly.net`)
- **Remediation**: Remove dangling CNAMEs immediately or register the orphan bucket/app in the tenant account before adversaries claim it.

---

## Module 05 // Cryptographic Ledger OSINT: Solana, EVM & Bitcoin Forensics

Public blockchain ledgers are transparent, append-only financial logs. OSINT investigators correlate pseudo-anonymous wallet addresses with on-chain balance, transaction velocity, and smart contract bindings.

### 5.1 Solana Mainnet-Beta RPC Interrogation (Zero-Key)
Using the public Solana JSON-RPC cluster (`https://api.mainnet-beta.solana.com`):
```bash
# Balance Check
curl -s https://api.mainnet-beta.solana.com -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0", "id": 1, "method": "getBalance",
  "params": ["GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK"]
}'

# Recent Transaction Signatures
curl -s https://api.mainnet-beta.solana.com -X POST -H "Content-Type: application/json" -d '{
  "jsonrpc": "2.0", "id": 2, "method": "getSignaturesForAddress",
  "params": ["GG2eQbVh8ut1BK6j1A2tz7pSySdLpD38BgyEhGcxdXoK", {"limit": 10}]
}'
```

### 5.2 Ethereum & EVM Architecture
Querying public node RPCs (`https://ethereum-rpc.publicnode.com`):
- `eth_getBalance`: Returns raw balance in Wei.
- `eth_getTransactionCount`: Returns outbound nonces (confirming whether a wallet has initiated transactions).
- `eth_getCode`: Returns contract bytecode. If bytecode > 2 characters (`0x`), the address is an immutable **Smart Contract** rather than an Externally Owned Account (EOA).

### 5.3 Bitcoin On-Chain Forensics: Mempool.space
Querying zero-key mempool endpoints:
```bash
curl -s https://mempool.space/api/address/<btc_address>
curl -s https://mempool.space/api/address/<btc_address>/txs
```
Returns total funded satoshis, spent satoshis, unconfirmed mempool transactions, and UTXO history.

---

## Module 06 // Telephony (E.164), Geolocation (GEOINT) & Overpass Spatial

### 6.1 ITU-T E.164 Telephony Normalization
Raw phone numbers arrive in unstandardized formats (`(757) 555-0199`, `+1 757.555.0199`). Normalization follows ITU-T standards:
1. Strip non-digit characters.
2. Prepend country code (`+1` for North American Numbering Plan).
3. Generate RFC 3966 URI (`tel:+17575550199`).
4. Resolve regional routing prefixes (e.g. `757` = Hampton Roads / Virginia Beach / Norfolk, VA; `212` = Manhattan, NY).
5. Generate verified deep-links for messaging registration probing:
   - WhatsApp: `https://wa.me/<digits>`
   - Telegram: `https://t.me/+<digits>`
   - Signal: `https://signal.me/#p/+<digits>`

### 6.2 Spatial GEOINT via OpenStreetMap Overpass Turbo
Rather than relying on proprietary mapping engines, open-source investigators execute spatial geometry queries via Overpass QL to locate physical installations (substations, telecommunication masts, road configurations):
```overpassql
[out:json][timeout:25];
(
  node["telecom"="antenna"](around:2500, 36.8529, -75.9780);
);
out body;
>;
out skel qt;
```

---

## Module 07 // Time-Travel Recon: Wayback CDX Endpoint & Git Secret Hunting

### 7.1 Internet Archive Wayback Machine CDX API
The Wayback Machine provides a machine-readable index (CDX) capable of wildcard endpoint matching:
```bash
curl -s "https://web.archive.org/cdx/search/cdx?url=*.target.com/*&output=json&fl=original,timestamp,statuscode,mimetype&collapse=urlkey&limit=50"
```
Filter for high-value sensitive leaks:
- Environment configuration: `.env`, `.git/config`, `config.json`
- Database backups: `.sql`, `.bak`, `.dump`
- Internal API documentation: `/api/v1`, `/swagger.json`, `/graphql`

### 7.2 Binary Forensics & Shannon Entropy
Analyzing unknown artifacts:
- **Shannon Entropy**: Measures randomness on a scale of 0.0 to 8.0 bits per byte. Plaintext code rates ~4.5–5.5; packed or encrypted binaries / encrypted archives rate >7.5.
- **ASCII/Unicode String Extraction**: Extract embedded URLs, credentials, and email addresses from compiled binaries without dynamic execution.

---

## Module 08 // Link Analysis, OASIS STIX 2.1 CTI & Obsidian Graph Modeling

Raw intelligence data is useless without relationship modeling. Standardize intelligence on two interoperable formats:

### 8.1 OASIS STIX 2.1 Cyber Threat Intelligence (CTI)
STIX (Structured Threat Information Expression) defines formal Cyber Threat Intelligence objects:
- **STIX Domain Objects (SDOs)**: `identity`, `ipv4-addr`, `domain-name`, `vulnerability`, `grouping`.
- **STIX Relationship Objects (SROs)**: `relationship` linking source and destination objects via explicit types (`related-to`, `resolves-to`, `communicates-with`).
- Every entity receives a deterministic UUID5:
  ```python
  import uuid
  stix_id = f"ipv4-addr--{uuid.uuid5(uuid.NAMESPACE_DNS, 'zoth-osint:1.1.1.1')}"
  ```

### 8.2 Obsidian JSON Canvas (`.canvas`)
Export intelligence investigations directly into visual spatial canvas files for knowledge bases:
```json
{
  "nodes": [
    { "id": "node_1", "type": "text", "text": "### [DOMAIN]\n**nullai.tech**", "x": 0, "y": 0, "width": 280, "height": 110, "color": "5" }
  ],
  "edges": [
    { "id": "edge_1", "fromNode": "node_1", "toNode": "node_2", "label": "A RECORD" }
  ]
}
```

### 8.3 Gephi / Cytoscape GEXF 1.3 XML Export
Export multi-target supergraphs into `.gexf` format to run force-directed network layouts (ForceAtlas2) and detect network modularity clusters.

### 8.4 MITRE ATT&CK Enterprise Matrix Mapping & Defensive Countermeasures
Modern OSINT bridges threat surface discovery with standard defensive cybersecurity taxonomies:
- **MITRE ATT&CK Mapping (v14.1)**:
  - `T1595.002` (Vulnerability Scanning) ← Shodan open ports and known CVEs.
  - `T1190` (Exploit Public-Facing Application) ← Web servers with exposed services or unpatched CVEs.
  - `T1133` (External Remote Services) ← Exposed SSH (22), RDP (3389), SMB (445), and unauthenticated databases (Redis 6379, MongoDB 27017).
  - `T1566` (Phishing / Domain Impersonation) ← Missing or permissive DMARC (`p=none`) and SPF records.
  - `T1552.001` (Unsecured Credentials: In Files) ← Exposed `.env`, `.git`, or backup files in historical snapshots.
  - `T1589.001` (Credentials) ← Compromised emails and passwords in public breaches.
- **Automated STIX 2.1 SDO Synthesis**:
  Every detected technique is automatically packaged as a STIX `attack-pattern` linked to defensive `course-of-action` recommendations.

---

## Module 09 // Autonomous Tool Orchestration: 32 Open-Source Arsenal Tools

Mastering the best specialized open-source tools on Linux:

| Tool | Focus | Command Example |
| :--- | :--- | :--- |
| **Sherlock** | Social handles across 400+ sites | `sherlock target --timeout 5 --print-found` |
| **Holehe** | Silent email account registration | `holehe target@domain.com --only-used` |
| **Subfinder** | Passive subdomain enumeration | `subfinder -d target.com -silent` |
| **OWASP Amass** | Attack surface mapping | `amass enum -passive -d target.com` |
| **Nmap** | Service versioning & NSE scripts | `nmap -Pn -sV --top-ports 25 target.com` |
| **httpx** | Tech stack probing & title grabs | `httpx -u target.com -title -tech-detect` |
| **Nuclei** | Vulnerability template scanning | `nuclei -u https://target.com -tags exposure` |
| **Katana** | Next-gen JS crawling & endpoints | `katana -u https://target.com -jc -d 2` |
| **TruffleHog** | Leaked credentials in git/buckets | `trufflehog github --org=target --only-verified` |
| **Gitleaks** | Git commit history secret scanner| `gitleaks detect --source . -v` |
| **ExifTool** | Media metadata & GPS extraction  | `exiftool -a -u -g1 sample.jpg` |
| **BBOT** | Recursive modular OSINT scanner  | `bbot -t target.com -p subdomain-enum` |

---

## Module 10 // Agentic AI & Model Context Protocol (MCP) in OSINT Workflows

The cutting edge of intelligence workflows is **Agentic OSINT**: enabling AI agents to autonomously plan investigations, run multi-pivot queries, and synthesize findings via structured RPC.

### 10.1 The Model Context Protocol (MCP) STDIO Architecture
The `zoth-osint` MCP server (`mcp_server.py`) operates via JSON-RPC 2.0 over standard I/O, exposing native tool definitions:
- `osint_scan`: Autonomous multi-pivot target resolution.
- `osint_favicon_mmh3`: MurmurHash3 favicon calculation.
- `osint_web3_identity`: Bluesky ATProto & ENS identity resolution.
- `osint_rdap`: IETF RDAP registry telemetry.
- `osint_wallet`: Crypto ledger transaction analysis.
- `osint_wayback`: Time-travel endpoint discovery.

### 10.2 Invoking Zoth OSINT from Agentic AI
AI coding agents or custom agents connect to the server by executing:
```bash
zoth-osint mcp
```
Sending:
```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "tools/call",
  "params": {
    "name": "osint_scan",
    "arguments": { "target": "nullai.tech" }
  }
}
```

---

## Practical Laboratory & CLI Exercises

### Lab Exercise 1: Multi-Pivot Target Resolution
```bash
zoth-osint scan 1nc0gn30 --canvas /tmp/1nc0gn30.canvas --stix /tmp/1nc0gn30.stix.json
```
1. Observe the automated classifier identifying the target as `USERNAME`.
2. Inspect the synthesized Obsidian Canvas (`.canvas`) and OASIS STIX 2.1 CTI bundle.

### Lab Exercise 2: Infrastructure Origin Unmasking
```bash
zoth-osint favicon github.com
zoth-osint tech nullai.tech
zoth-osint rdap nullai.tech
```
1. Observe the 32-bit signed MurmurHash3 calculation.
2. Note the automated HTTP security header grading and CDN edge identification.

### Lab Exercise 3: Cross-Case Supergraph Correlation
```bash
zoth-osint correlate target1.com target2.com --gexf /tmp/correlation.gexf
```
1. Merge multiple independent investigations into a single graph.
2. Highlight shared pivots across targets.

---

*This document and course curriculum are licensed under open sovereign architecture for Neal Frazier Tech (@1nc0gn30) and the NullAI Platform.*
