---
name: urlscan-pivot
description: URLScan.io integration for adversary infrastructure hunting. Use when validating C2 servers by retrieving expected payloads from known URLs, tracking phishing kits and JavaScript files across infrastructure, searching for infrastructure by SSL certificate subjects or HTTP server headers, confirming BeaverTail/Lazarus Group infrastructure via payload hash lookup, tracking Scattered Spider OKTA phishing via filename search, or pivoting on page content and ASN combinations. URLScan passively observes web infrastructure without alerting threat actors.
license: Complete terms in LICENSE.txt
---

# URLScan Pivot Skill

## Executable Script

Always use the script instead of writing raw API calls inline:

```bash
source myenv/bin/activate
python .claude/skills/urlscan-pivot/scripts/urlscan.py search 'page.ip:"162.0.230.185"'
python .claude/skills/urlscan-pivot/scripts/urlscan.py search 'filename:"FMAPP"'
python .claude/skills/urlscan-pivot/scripts/urlscan.py search 'page.server:"Werkzeug" AND page.asn:"AS22612"'
python .claude/skills/urlscan-pivot/scripts/urlscan.py ip 162.0.230.185
python .claude/skills/urlscan-pivot/scripts/urlscan.py domain promoverse.org
python .claude/skills/urlscan-pivot/scripts/urlscan.py result <uuid>
```


## PASSIVE INTEL CONSTRAINT

All URLScan usage must be **passive** — querying URLScan's existing database of historical scans only.

**Do NOT use `submit_url()`** in an intelligence context. Submitting a URL causes URLScan to actively probe the target infrastructure, which:
- Alerts the threat actor that their server is being observed
- Constitutes active interaction with adversary-controlled infrastructure
- May trigger defensive responses or infrastructure rotation

**Permitted**: `search()`, `get_result()` on scans others have already submitted, `search_by_ip()`, `search_by_ssl_cert()`, `search_by_server()`, `search_by_title()`, `search_by_domain()`, `search_by_asn_and_server()`, `search_by_asn_and_port()`

**Not permitted in hunting context**: `submit_url()` — only reference existing scan results

---

## Overview

URLScan.io serves multiple roles in adversary infrastructure hunting — all through its existing database of historical scans:

1. **C2 Payload Validation** — confirm that a discovered server served the expected malicious payload in a past scan
2. **Phishing Kit Tracking** — find phishing pages by JavaScript filename, page title, or SSL cert
3. **Historical Infrastructure Observation** — review what URLScan recorded when others scanned the infrastructure
4. **Hash-based Pivoting** — find all scans where a specific resource hash was observed
5. **ASN + attribute combinations** — search for infrastructure patterns within specific ASNs

---

## API Integration

```python
BASE_URL = "https://urlscan.io/api/v1"
Headers: { "API-Key": "{URLSCAN_API_KEY}" }

# Submit URL for scanning
POST /scan/
Body: { "url": "http://target.com", "visibility": "public" }
Returns: { "uuid": "scan-id", "result": "https://urlscan.io/result/{uuid}/" }

# Get scan result
GET /result/{uuid}/

# Search URLScan database
GET /search/?q={QUERY}&size={SIZE}
```

**Free tier limitations**:
- Hash-based searches (`hash:`) require a paid plan
- Use alternative pivots: SSL cert, server header, page title, ASN + port

---

## Search Syntax Reference

### Field Queries

| Query | Description | Example |
|---|---|---|
| `domain:` | Search by domain | `domain:evil.com` |
| `page.ip:` | Search by IP address | `page.ip:1.2.3.4` |
| `page.asn:` | Search by ASN | `page.asn:AS20473` |
| `page.port:` | Search by port | `page.port:1224` |
| `page.title:` | Page title search | `page.title:"Gophish"` |
| `page.server:` | HTTP Server header | `page.server:"Apache/2.4.46"` |
| `page.tlsIssuer:` | TLS certificate issuer | `page.tlsIssuer:"O=Gophish"` |
| `page.tlsSubject:` | TLS certificate subject | `page.tlsSubject:"CN=evil.com"` |
| `filename:` | Resource filename | `filename:"okta-sign-in.min.js"` |
| `hash:` | Resource SHA256 hash | `hash:6a104f07...` (paid only) |
| `task.url:` | Exact URL scanned | `task.url:"http://evil.com/path"` |

### Boolean Operators
```
AND, OR, NOT
page.asn:AS20473 AND page.server:"Apache"
filename:"okta-sign-in.min.js" NOT page.domain:"okta.com"
```

---

## Core Pivot Workflows

### Workflow 1: BeaverTail C2 Payload Validation (Lazarus Group)

After identifying candidate IPs via Censys FTP banner + ASN pivot, search URLScan's **existing scan history** to see if the expected Python executable was already observed by others.

**Known behavior from threat intel**: BeaverTail downloads Python from `http://{ip}:1224/pdown`

**Step 1 — Search URLScan history for past scans of the candidate IPs**:
```python
# Search existing scans — do NOT submit new scans
for ip in candidate_ips:
    results = await urlscan_client.search_by_ip(ip, size=50)
    # Look for past scans that captured port 1224
```

**Step 2 — Retrieve an existing scan result by UUID** (from historical search):
```python
result = await urlscan_client.get_result(existing_uuid)
```

**Step 3 — Check if the Python payload hash was observed in that historical scan**:
```python
resources = result.get('data', {}).get('requests', [])
for req in resources:
    response_hash = req.get('response', {}).get('hash')
    # Look for: 6a104f07ab6c5711b6bc8bf6ff956ab8cd597a388002a966e980c5ec9678b5b0
    if response_hash == expected_python_hash:
        print(f"CONFIRMED BeaverTail C2 (historical): {ip}")
```

**Step 4 — Pivot on the known hash across URLScan's database** (paid tier):
```python
results = await urlscan_client.search(
    query=f"hash:{expected_python_hash}",
    size=100
)
```

---

### Workflow 2: Scattered Spider Phishing Infrastructure

Scattered Spider deploys fake OKTA portals with a distinctive JavaScript file.

**Primary hunt query**:
```python
results = await urlscan_client.search(
    query='filename:"okta-sign-in.min.js" page.asn:AS20473',
    size=100
)
```

**Alternative — using known page hash** (when JS hash is known):
```python
results = await urlscan_client.search(
    query='hash:0acb0fc9762e4359f562794011d77317c78f7b68cec08b715d98ed16ba761fac page.asn:AS20473',
    size=100
)
```

**Extract discovered phishing domains**:
```python
for scan in results.get('results', []):
    page = scan.get('page', {})
    domain = page.get('domain')
    ip = page.get('ip')
    title = page.get('title')
    # Filter for OKTA impersonation patterns: [company]-okta.com, [company]-hr.com
```

---

### Workflow 3: APT28 Infrastructure Tracking

APT28 uses blurred document lures with distinctive image hashes.

**Image hash pivot**:
```python
results = await urlscan_client.search(
    query='hash:0b5b388c8edfeb4bf0efd7ba1873ec9f2fc611d78a6c59e93eec52131bd20a88',
    size=50
)
```

**Interactsh callback tracking**:
```python
results = await urlscan_client.search(
    query='domain:*.oast.me OR domain:*.interactsh.com',
    size=100
)
```

---

### Workflow 4: Evilginx Phishing Kit Tracking

Evilginx phishing pages have distinctive JavaScript fingerprints.

```python
results = await urlscan_client.search(
    query='hash:405893b0bf0b3e87141e7048e1cb6665ca5593fea1b159ca0ce90e77d049c51a OR hash:2fc77b4a0620f5dca2d3cae6d917af3acdeb3b2e5558ba1727f8d651351fc692',
    size=100
)
```

---

### Workflow 5: SSL Certificate Pivoting (Free Tier Compatible)

When hash search is unavailable (free tier), pivot via TLS certificate attributes:

```python
# Find other servers with same certificate issuer as known C2
results = await urlscan_client.search_by_ssl_cert(cert_subject="O=Gophish")

# Find servers with same HTTP Server header
results = await urlscan_client.search_by_server("Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.2.33")

# Find C2 panels by title
results = await urlscan_client.search_by_title("Welcome to SimpleHelp")
```

---

### Workflow 6: ASN + Attribute Combination

Target infrastructure within a known threat actor ASN:

```python
# Kimsuky on Choopa (AS20473) with specific server
results = await urlscan_client.search_by_asn_and_server(
    asn="AS20473",
    server="Apache/2.4.46 (Win64)"
)

# Lazarus on Leaseweb Singapore with non-standard port
results = await urlscan_client.search_by_asn_and_port(
    asn="AS59253",
    port=1224
)
```

---

## URLScan API Usage in hunt_intel_complete.py

The codebase implements multiple search methods:

**`urlscan_client.submit_url(url, visibility)`**
- Submits URL for scanning
- Returns `uuid` for result retrieval
- `visibility`: `"public"` (default), `"unlisted"`, `"private"`
- Wait ~30 seconds before retrieving result

**`urlscan_client.get_result(scan_uuid)`**
- Retrieves completed scan
- Key fields: `verdicts.overall.malicious`, `verdicts.overall.score`, `data.requests[]`

**`urlscan_client.search(query, size)`**
- Full-text search of URLScan database
- Returns `results[]` array of past scans
- Size: default 100, max 10000

**`urlscan_client.search_by_ip(ip, size)`**
- Convenience wrapper: `page.ip:{ip}`

**`urlscan_client.search_by_ssl_cert(cert_subject, size)`**
- Convenience wrapper: `page.tlsIssuer:"{cert_subject}"`
- Free tier compatible

**`urlscan_client.search_by_server(server_header, size)`**
- Convenience wrapper: `page.server:"{server_header}"`
- Free tier compatible

**`urlscan_client.search_by_title(title, size)`**
- Convenience wrapper: `page.title:"{title}"`
- Free tier compatible

**`urlscan_client.search_by_asn_and_server(asn, server, size)`**
- Convenience wrapper: `page.asn:{asn} AND page.server:"{server}"`
- Free tier compatible

**`urlscan_client.search_by_asn_and_port(asn, port, size)`**
- Convenience wrapper: `page.asn:{asn} AND page.port:{port}`
- Free tier compatible

**`urlscan_client.search_by_domain(domain, size)`**
- Convenience wrapper: `domain:{domain}`

**Note**: `search_by_hash()` is implemented but returns empty results on free tier. This is handled gracefully — it does not cause errors.

---

## URLScan Result Interpretation

### Scan Result Structure
```json
{
  "verdicts": {
    "overall": {
      "score": 0,
      "malicious": false,
      "hasVerdicts": true
    }
  },
  "page": {
    "ip": "1.2.3.4",
    "domain": "evil.com",
    "title": "Login",
    "server": "Apache",
    "asn": "AS20473",
    "tlsSubject": "CN=evil.com",
    "tlsIssuer": "O=Attacker"
  },
  "data": {
    "requests": [
      {
        "request": { "url": "http://evil.com/okta-sign-in.min.js" },
        "response": {
          "hash": "sha256:abc123...",
          "status": 200
        }
      }
    ]
  }
}
```

**Key extraction points**:
- `page.ip` — actual server IP (resolves CDN obfuscation for some cases)
- `page.server` — HTTP Server header value
- `page.tlsIssuer` — for pivoting via certificate
- `data.requests[].response.hash` — SHA256 of each loaded resource (for payload validation)
- `verdicts.overall.malicious` — URLScan's verdict (use as signal, not definitive)

---

## Threat Actor-Specific URLScan Patterns

| Threat Actor | URLScan Query | What to Look For |
|---|---|---|
| Scattered Spider | `filename:"okta-sign-in.min.js" page.asn:AS20473` | OKTA phishing portals |
| Lazarus BeaverTail | `page.port:1224 page.asn:AS59253` | Python downloader endpoints |
| APT28 | `hash:{document_image_hash}` | Blurred document lure pages |
| Evilginx | `hash:{evilginx_js_hash}` | AiTM phishing kits |
| Gophish | `page.tlsIssuer:"O=Gophish"` | Phishing campaign infrastructure |
| Kimsuky | `page.server:"Apache/2.4.46 (Win64)" page.asn:AS20473` | K2 servers |

---

## Best Practices

1. **Query existing scans only** — never use `submit_url()` in a hunting context; always search URLScan's historical database
2. **Use free-tier compatible methods first** — SSL cert, server header, title, ASN+port searches work on free tier
3. **Cross-reference resource hashes with VirusTotal** — hashes from URLScan scan results can be looked up in VT
4. **URLScan confirms, search engines discover** — use URLScan to validate what Shodan/Censys finds against historical evidence
5. **Track phishing by JavaScript filename** — phishing kits often include distinctive JS files (okta-sign-in.min.js, etc.)
6. **Historical evidence is sufficient** — if URLScan has no prior scan of an IP, that absence is itself a data point (recently deployed or low-profile infrastructure); do not submit to fill the gap
