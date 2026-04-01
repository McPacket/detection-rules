---
name: fofa-hunt
description: FOFA internet search engine integration for adversary infrastructure hunting. Use when hunting non-standard ports, needing historical HTTP response data, tracking malware on webpages and hosting platforms (Magecart, phishing kits, compromised WordPress), pivoting on JARM fingerprints combined with certificate attributes, or when Shodan and Censys return insufficient results. FOFA consistently returns more results than other platforms and has superior non-standard port coverage.
license: Complete terms in LICENSE.txt
---

# FOFA Hunt Skill

## Executable Script

Always use the script instead of writing raw API calls inline. Query is auto base64-encoded:

```bash
source myenv/bin/activate
python .claude/skills/fofa-hunt/scripts/fofa.py search 'jarm="27d40d40..." && asn="AS22612"'
python .claude/skills/fofa-hunt/scripts/fofa.py search 'port="10443" && server="Werkzeug"' --size 200
python .claude/skills/fofa-hunt/scripts/fofa.py search 'ip="162.0.230.185"'
```


## Overview

FOFA (en.fofa.info) consistently outperforms Shodan and Censys in specific scenarios:
- **Volume of results** — FOFA frequently returns more hits for the same query
- **Non-standard port coverage** — best platform for malware using unusual ports (e.g., Rhysida port 55555)
- **Webpage scanning** — scans web content on hosting platforms (enables Magecart and phishing kit tracking)
- **Historical data** — better retention of historical HTTP headers and service data than Shodan
- **Domain/URL coverage** — tracks domains and web pages beyond just IP:port combinations

**Limitations**: No Maltego integration. Slightly more complex syntax. No autofill search.

---

## API Integration

```python
# Search endpoint
GET https://fofa.info/api/v1/search/all
params:
  email: {FOFA_EMAIL}
  key: {FOFA_API_KEY}
  qbase64: {BASE64_ENCODED_QUERY}
  size: 100
  fields: ip,port,host,domain,protocol,cert,jarm,server,title
```

**Critical**: FOFA requires the query to be **base64-encoded** in `qbase64` parameter.

```python
import base64
query = 'jarm="40d1db40..." && port="443"'
qbase64 = base64.b64encode(query.encode()).decode()
```

Response structure:
- `results[]` — array of `[ip, port, host, domain, protocol, cert, jarm, server, title]`
- `size` — total matching records
- `error` — boolean error flag
- `errmsg` — error message if `error=True`

Fields returned per result (in order matching `fields` param):
`ip`, `port`, `host`, `domain`, `protocol`, `cert`, `jarm`, `server`, `title`

---

## Search Syntax Reference

### Basic Operators

| Operator | Description | Example |
|---|---|---|
| `=` | Exact match | `port="443"` |
| `==` | Exact match (strict) | `title=="Login"` |
| `!=` | Not equal | `port!="443"` |
| `&&` | AND | `jarm="abc" && port="443"` |
| `\|\|` | OR | `port="80" \|\| port="443"` |
| `()` | Grouping | `(port="80" \|\| port="443") && country="US"` |

### Core Field Filters

| Filter | Description | Example |
|---|---|---|
| `ip=` | IP address | `ip="192.168.1.1"` |
| `port=` | Port number | `port="55555"` |
| `host=` | Hostname/domain | `host="evil.com"` |
| `domain=` | Domain name | `domain="malicious.io"` |
| `protocol=` | Protocol | `protocol="ftp"` |
| `country=` | Country code | `country="KR"` |
| `region=` | Region/state | `region="California"` |
| `city=` | City | `city="Amsterdam"` |
| `asn=` | ASN number | `asn="20473"` |
| `org=` | Organization | `org="M247"` |
| `os=` | Operating system | `os="Ubuntu"` |
| `server=` | HTTP Server header | `server="Apache"` |
| `title=` | Page title | `title="SimpleHelp"` |

### TLS/Certificate Filters

| Filter | Description | Example |
|---|---|---|
| `cert=` | Full-text certificate search | `cert="Gophish"` |
| `cert.subject=` | Certificate subject | `cert.subject="O=Gophish"` |
| `cert.issuer=` | Certificate issuer | `cert.issuer="Let's Encrypt"` |
| `cert.is_valid=` | Validity status | `cert.is_valid=true` |
| `jarm=` | JARM fingerprint | `jarm="07d14d16..."` |

### HTTP/Banner Filters

| Filter | Description | Example |
|---|---|---|
| `header=` | HTTP response header content | `header="X-Havoc: true"` |
| `banner=` | Full service banner | `banner="220 pyftpdlib"` |
| `body=` | HTTP response body | `body="cobalt strike"` |
| `icon_hash=` | Favicon MurmurHash | `icon_hash="-859291042"` |

### Advanced Filters

| Filter | Description | Example |
|---|---|---|
| `after=` | Only results after date | `after="2024-01-01"` |
| `before=` | Only results before date | `before="2024-06-01"` |
| `status_code=` | HTTP status code | `status_code="200"` |
| `fid=` | FOFA rule ID | (internal FOFA rule) |

---

## Core Pivot Workflows

### Workflow 1: JARM + Certificate Combination

For offline or recently taken-down infrastructure, FOFA retains historical data better than Shodan.

**Step 1 — Get JARM from FOFA historical data**:
Search the known offline IP in FOFA to retrieve its historical banner:
```
ip="54.70.52.38"
```
FOFA shows historical HTTP headers and JARM even for offline hosts.

**Step 2 — Build hunt rule combining JARM + headers**:
```
jarm="40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202" && header="Content-Length: 14" && header="Content-Type: text/plain; charset=utf-8"
```

**Step 3 — Add certificate pattern if impersonating legitimate entity**:
```
jarm="40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202" && cert="Microsoft" && cert="Windows"
```

---

### Workflow 2: Non-Standard Port C2 Detection

FOFA is the best tool when C2 uses non-standard ports because it scans more port ranges.

**Rhysida PortStarter** (port 55555):
```
header="Server: BaseHTTP/0.6 Python/3.8.10 Www-Authenticate: Basic realm=Demo Realm" && port="55555"
```

**Pikabot** (ports 1194, 2078, 2222):
```
jarm="21d19d00021d21d21c21d19d21d21dd188f9fdeea4d1b361be3a6ec494b2d2" && cert="Signature Algorithm: SHA256-RSA (self-signed)" && cert="4096 bits" && port!="443" && server=="nginx" && cert!="R3"
```

**BeaverTail FTP on non-standard hosts**:
```
banner="220 pyftpdlib based ftpd ready" && asn="59253"
```

---

### Workflow 3: Magecart and Phishing Kit Tracking

FOFA scans webpages on hosting platforms — unique capability for tracking malicious web injections.

**Magecart skimmer detection** (look for injected JavaScript patterns):
```
body="document.createElement('script')" && body="fromCharCode" && (port="80" || port="443")
```

**Compromised WordPress pages** (with injected skimmer):
```
body="wp-content/plugins" && body="eval(atob(" && server="nginx"
```

**Phishing kit landing pages** (fake login forms):
```
title="Microsoft" && body="password" && body="username" && cert!="microsoft.com" && host!="microsoft.com"
```

---

### Workflow 4: Historical Data for Offline Infrastructure

When Shodan shows a host as offline, FOFA may retain its historical configuration.

**Query the offline IP**:
```
ip="54.70.52.38"
```

**Use date range for historical context**:
```
ip="54.70.52.38" && after="2024-01-01" && before="2024-12-31"
```

**Extract JARM and header from historical view**, then pivot to find active infrastructure:
```
jarm="{extracted_jarm}" && header="HTTP/1.1 200 OK" && header="Content-Length: 14"
```

---

### Workflow 5: Geo-Targeting for Attribution

When actor has known geographic infrastructure preferences:

**Russia-hosted C2** (combined with redirector pattern):
```
header="Location: google.com" && country="RU" && status_code="302"
```

**Korea-hosted infrastructure** (APT43/Kimsuky pattern):
```
server="Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.2.33" && country="KR"
```

**Singapore-hosted BeaverTail**:
```
banner="220 pyftpdlib based ftpd ready" && asn="59253" && country="SG"
```

---

## C2 Framework Hunt Rules (FOFA Syntax)

### Brute Ratel C4
```
jarm="40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202" && header="Content-Length: 14" && header="Content-Type: text/plain; charset=utf-8"
```

### Cobalt Strike (default malleable profile)
```
header="HTTP/1.1 404 Not Found" && header="Keep-Alive: timeout=10, max=100" && header="Content-Type: text/plain" && header="Content-Length: 0"
```

### Mythic C2
```
cert="Mythic" && (port="7443" || port="8443" || port="9443")
```

### Gophish
```
cert.subject="O=Gophish"
```
or modified instances:
```
jarm="28d28d28d00028d00041d28d28d41dd279b0cf765af27fa62e66d7c8281124"
```

### Evilginx
```
status_code="302" && header="Location: https://www.youtube.com" && header="Content-Length: 46"
```

### Havoc C2
```
header="X-Havoc: true" && port="40056"
```

### Pikabot (full rule)
```
jarm="21d19d00021d21d21c21d19d21d21dd188f9fdeea4d1b361be3a6ec494b2d2" && cert="Signature Algorithm: SHA256-RSA (self-signed)" && cert="4096 bits" && port!="443" && server=="nginx" && cert!="R3"
```

### Rhysida PortStarter
```
Header="Server: BaseHTTP/0.6 Python/3.8.10 Www-Authenticate: Basic realm=Demo Realm" && Port="55555"
```

### RedWarden Redirectors
```
header="Location: https://google.com" && header="Cache-Control: no-cache" && header="Content-Encoding: identity" && server="nginx" && status_code="301"
```

### MuddyWater SimpleHelp
```
title="Welcome to SimpleHelp" && org="M247"
```

### APT43 Kimsuky (Apache Win64 stack)
```
server="Apache/2.4.46 (Win64) OpenSSL/1.1.1g PHP/7.2.33" && country="KR"
```

---

## FOFA API Usage in hunt_intel_complete.py

The codebase implements `fofa_client.search(query, size)`:

```python
# Query is base64-encoded automatically by the client
results = await fofa_client.search(query="jarm='abc123' && port='443'", size=100)

# Results structure
for result in results.get('results', []):
    ip, port, host, domain, protocol, cert, jarm, server, title = result
```

**Fields available** (configured in the client):
- `ip` — IPv4 or IPv6 address
- `port` — Port number
- `host` — Hostname (may include domain)
- `domain` — Domain name
- `protocol` — Protocol (`http`, `https`, `ftp`, `ssh`, etc.)
- `cert` — Certificate data (raw text)
- `jarm` — JARM fingerprint
- `server` — HTTP Server header value
- `title` — HTML page title

---

## Key Decision Points: When to Use FOFA

| Situation | Use FOFA |
|---|---|
| Infrastructure uses non-standard ports | Yes — FOFA scans wider port ranges |
| Target host is offline | Yes — FOFA retains historical data |
| Hunting Magecart or phishing on web hosting | Yes — FOFA scans web content |
| Shodan/Censys returned 0 or very few results | Yes — FOFA often finds more |
| Need domain-level visibility (not just IP) | Yes — FOFA includes domain data |
| Need Maltego integration for visual pivoting | No — use Shodan instead |
| Need SSH host key fingerprint pivoting | No — use Censys instead |
| Need Facet Analysis to understand result distribution | No — use Shodan instead |

---

## Best Practices

1. **Base64-encode all queries** — FOFA API requires `qbase64` not raw query
2. **Use `&&` not `AND`** — FOFA uses `&&` for AND, `||` for OR
3. **Quote all values** in double quotes: `port="443"` not `port=443`
4. **Prefer FOFA for non-standard ports** — most likely to return results for uncommon ports
5. **Check historical data first** when starting from an offline IOC — view the IP directly in FOFA
6. **Combine JARM + certificate attributes** as primary pivot pair for TLS-enabled C2
7. **Use `cert!="R3"`** to exclude Let's Encrypt certificates when hunting self-signed infrastructure
8. **Filter by `port!="443"`** when hunting C2 on non-standard ports to avoid CDN noise
