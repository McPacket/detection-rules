---
name: shodan-hunt
description: Shodan search engine integration for adversary infrastructure hunting. Use when building or executing Shodan hunt rules, pivoting on indicators via Shodan, using Shodan Facet Analysis to reduce false positives, or querying for C2 frameworks, HTTP headers, JARM fingerprints, favicon hashes, SSL certificates, or ASN-based filtering. Covers Shodan API search and host info queries.
license: Complete terms in LICENSE.txt
---

# Shodan Hunt Skill

## Executable Script

Always use the script instead of writing raw API calls inline:

```bash
# Run from project root: /home/user1/adversary_hunting/
source myenv/bin/activate
python .claude/skills/shodan-hunt/scripts/shodan.py search "http.html_hash:-2118050146"
python .claude/skills/shodan-hunt/scripts/shodan.py host 162.0.230.185 [--history]
python .claude/skills/shodan-hunt/scripts/shodan.py facets "ssl.jarm:27d40d..." --facets org,country,port
```

## Overview

Shodan is the primary internet search engine for adversary infrastructure hunting. It excels at:
- **Facet Analysis** — distribution breakdowns to identify false positive patterns
- **Visualization** — geographic and organizational distribution for reporting
- **Maltego integration** — 69 transforms for graph-based pivot investigations
- **HTTP hash features** — `http.headers_hash` and `http.html_hash` for precise C2 matching

**Limitation**: Some threat actors actively block Shodan scanners. Shodan has slower scanning frequency than Censys or FOFA.

---

## API Integration

```python
# Search endpoint
GET https://api.shodan.io/shodan/host/search
params: key={API_KEY}, query={QUERY}, page={PAGE}

# Host info endpoint
GET https://api.shodan.io/shodan/host/{IP}
params: key={API_KEY}
# Add history=true for historical service data
```

Response structure:
- `matches[]` — array of host records
- Each match: `ip_str`, `port`, `transport`, `data` (banner), `http`, `ssl`, `jarm`, `asn`, `org`, `isp`

---

## Search Syntax Reference

### Basic Field Filters

| Filter | Description | Example |
|---|---|---|
| `ip:` | Search by IP or CIDR | `ip:192.168.1.0/24` |
| `port:` | Filter by port number | `port:8443` |
| `org:` | Hosting organization | `org:"M247 LTD"` |
| `asn:` | Autonomous system number | `asn:AS20473` |
| `country:` | Two-letter country code | `country:"KR"` |
| `hostname:` | Reverse DNS hostname | `hostname:"vpn"` |
| `os:` | Operating system | `os:"Ubuntu"` |
| `product:` | Service product name | `product:"Apache httpd"` |
| `version:` | Service version | `version:"2.4.46"` |

### HTTP-Specific Filters

| Filter | Description | Example |
|---|---|---|
| `http.title:` | HTML page title | `http.title:"Gophish"` |
| `http.html:` | Content in HTML body | `http.html:"cobalt strike"` |
| `http.html_hash:` | Murmur3 hash of HTML body | `http.html_hash:182674321` |
| `http.headers_hash:` | Hash of HTTP response headers | `http.headers_hash:144518609` |
| `http.favicon.hash:` | Murmur3 hash of favicon | `http.favicon.hash:-859291042` |
| `http.status:` | HTTP response status code | `http.status:200` |
| `http.component:` | Detected web technology | `http.component:"jQuery"` |

### SSL/TLS Filters

| Filter | Description | Example |
|---|---|---|
| `ssl:` | Full-text SSL cert search | `ssl:"O=Gophish"` |
| `ssl.cert.subject.cn:` | Certificate Common Name | `ssl.cert.subject.cn:"Mythic"` |
| `ssl.cert.issuer.cn:` | Certificate Issuer CN | `ssl.cert.issuer.cn:"Let's Encrypt"` |
| `ssl.jarm:` | JARM TLS fingerprint | `ssl.jarm:07d02d09d29d29d07c42d43d000000` |
| `ssl.cert.fingerprint:` | Certificate fingerprint | `ssl.cert.fingerprint:"AA:BB:CC..."` |
| `ssl.cert.pubkey.bits:` | Public key size | `ssl.cert.pubkey.bits:4096` |
| `ssl.cert.serial:` | Certificate serial number | `ssl.cert.serial:"12345"` |

### Service / Banner Filters

| Filter | Description | Example |
|---|---|---|
| (free text) | Banner full-text search | `"220 pyftpdlib based ftpd ready"` |
| `ssh.hostkey.fingerprint:` | SSH host key fingerprint | `ssh.hostkey.fingerprint:"abc123"` |

---

## Core Pivot Workflows

### Workflow 1: HTTP Header Pivoting

Starting from a known malicious IP, extract its HTTP banner and build a cluster rule.

**Step 1 — Capture the banner** (remove date lines):
```
HTTP/1.1 404 Not Found
Server: Google Frontend
Content-Length: 0
Keep-Alive: timeout=10, max=100
Connection: Keep-Alive
Content-Type: text/plain
```

**Step 2 — Build initial rule**:
```
HTTP/1.1 404 Not Found Server: Google Frontend Content-Length: 0 Keep-Alive: timeout=10, max=100 Content-Type: text/plain
```

**Step 3 — Reduce false positives using header hash**:
In Shodan UI, click the `http.headers_hash` value from a known-good hit. Add to query:
```
http.headers_hash:144518609
```

**Step 4 — Add HTML hash if needed**:
```
http.headers_hash:144518609 http.html_hash:182674321
```

**Step 5 — Layer in ASN/org filter**:
```
http.headers_hash:144518609 http.html_hash:182674321 org:"M247 LTD"
```

> IMPORTANT: Always remove date/time values from HTTP headers before building rules — these change per request and will produce zero results.

---

### Workflow 2: JARM + Header Combination

Never use JARM alone — it generates too many false positives.

**Correct pattern**:
```
ssl.jarm:40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202 http.headers_hash:144518609
```

**Wrong pattern** (too many false positives):
```
ssl.jarm:40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202
```

---

### Workflow 3: Hypothesis-Driven Cold Hunt

Build from behavioral assumptions without an IOC.

**Example — Redirector detection**:
```
# Hypothesis: Threat actors redirect to Google to evade detection, prefer M247, run Ubuntu
HTTP/1.1 302 Found  Location: google.com org:"M247 LTD Copenhagen Infrastructure" Server: Ubuntu
```

**Progression**:
1. `Location:` — All redirectors (22M+ results, too broad)
2. `HTTP/1.1 302 Found Location: google.com` — Google redirectors
3. + `org:"M247 LTD"` — Narrow to known bulletproof provider
4. + `Server: Ubuntu` — Narrow to actor-preferred OS

---

### Workflow 4: Facet Analysis for False Positive Reduction

Use Shodan Facet Analysis (web UI or API) to understand result distribution:
- `facets=org` — Which organizations host most results? Remove CDNs, cloud providers
- `facets=country` — Geographic distribution; add `country:"XX"` to target actor geography
- `facets=port` — Which ports cluster results? Narrow to non-standard ports
- `facets=asn` — Which ASNs dominate? Use to include or exclude

```python
# API facet query
GET /shodan/host/search/facets
params: query={QUERY}, facets=org,country,port
```

---

### Workflow 5: SSL Certificate Pivoting

**Impersonation detection** (threat actor spoofing Microsoft Defender):
```
ssl:Microsoft ssl:Windows ssl:LOCALHOST ssl:2048
```

**Actor-specific cert pattern** (Pikabot — random words, 4096-bit, self-signed):
```
ssl.cert.pubkey.bits:4096 ssl.cert.serial:"[serial]" port:1194
```

**Cobalt Strike behind CloudFlare**:
```
ssl:"cloudflare" http.headers_hash:[cs_header_hash] port:2052,2053,2082,2083,2086,2087,2095,2096,8880
```

---

## C2 Framework Hunt Rules

### Cobalt Strike
```
HTTP/1.1 404 Not Found Server: Apache Content-Length: 0 Keep-Alive: timeout=10, max=100 Content-Type: text/plain
```
With watermark-specific beacon config:
```
http.html:"987654321"
```

### Brute Ratel C4
```
http.headers_hash:144518609 http.html_hash:182674321
```
Combined with JARM (from known node):
```
ssl.jarm:40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202 http.headers_hash:144518609
```

### Mythic C2
```
ssl:"Mythic" port:7443
```
or by favicon:
```
http.favicon.hash:-859291042
```

### Gophish
```
ssl:"O=Gophish"
```
or modified instances (using JARM):
```
ssl.jarm:28d28d28d00028d00041d28d28d41dd279b0cf765af27fa62e66d7c8281124
```

### Evilginx
```
http.html:"youtube.com/watch?v=dQw4w9WgXcQ" port:80
```
Admin panel:
```
http.title:"evilginx" port:3000
```

### RedWarden Redirectors
```
http.headers_hash:1538445002
```

### MuddyWater SimpleHelp RMM
```
http.title:"Welcome to SimpleHelp" org:"M247"
```

### Rhysida PortStarter
```
"Server: BaseHTTP/0.6 Python/3.8.10" port:55555
```

### Kimsuky (APT43)
```
http.html_hash:-2091072850 country:"KR"
```
or detailed HTTP header rule:
```
Server: Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.2.33 Content-Length: 227 Content-Type: text/html; charset=UTF-8
```

---

## Shodan API Usage in hunt_intel_complete.py

The existing codebase implements two Shodan methods:

**`shodan_client.search(query, page)`**
- Executes any Shodan search query
- Returns `matches[]` array with host records
- Use for broad infrastructure cluster searches

**`shodan_client.host_info(ip, history=False)`**
- Retrieves all service data for a specific IP
- Set `history=True` to get historical scan data
- Use to extract banner details, certificates, JARM from a known IOC

### Query Construction from IOC
When given an IP as starting point:
1. Call `host_info(ip)` to get all services
2. Extract: JARM, HTTP headers, SSL cert CN/O/fingerprint, SSH key fingerprint, banner text
3. Remove date values from headers
4. Build search query combining 2+ unique attributes
5. Call `search(query)` to identify the cluster
6. Validate each result IP against VirusTotal

---

## Facet Analysis via API

```python
# Get distribution of results for false positive analysis
GET /shodan/host/search/facets
params:
  key: {API_KEY}
  query: {HUNT_RULE}
  facets: org,country,port,asn
```

Use results to:
- Identify CDN/cloud noise (AWS, Cloudflare, Akamai) and exclude with `org!="Amazon"` etc.
- Confirm geographic alignment with actor's known base of operations
- Identify unexpected port distributions that signal additional infrastructure

---

## Best Practices

1. **Never build a rule on a single attribute** — minimum 2 combined
2. **Always strip dates from HTTP headers** before including in a rule
3. **Start with `http.headers_hash`** rather than raw headers for precision
4. **Use Facet Analysis** before claiming false positive rates
5. **Validate with VirusTotal** — check `malicious` count and `communicating_files`
6. **Note result counts** — document the hunt rule's specificity (low result count = high precision)
7. **Iterate from broad to narrow** — start broad to ensure you're not missing infrastructure
