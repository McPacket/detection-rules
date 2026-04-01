---
name: validin-hunt
description: Validin platform integration for adversary infrastructure hunting. Use when analyzing offline or historical infrastructure that is no longer visible in Shodan or Censys, de-cloaking CloudFlare-protected C2 to find origin IPs, performing forward DNS analysis to find all domains resolving to a suspicious IP, tracking certificate fingerprint changes over time, or when needing HTTP response data with better historical retention than other platforms. Validin uniquely captures proactive daily DNS records for all domains and links CloudFlare-hosted infrastructure to its origin servers.
license: Complete terms in LICENSE.txt
---

# Validin Hunt Skill

## Executable Script

Always use the script instead of writing raw API calls inline:

```bash
source myenv/bin/activate
python .claude/skills/validin-hunt/scripts/validin.py host 162.0.230.185        # all data
python .claude/skills/validin-hunt/scripts/validin.py responses 162.0.230.185   # historical HTTP
python .claude/skills/validin-hunt/scripts/validin.py connections 162.0.230.185 # JARM/certs
python .claude/skills/validin-hunt/scripts/validin.py forward-dns 162.0.230.185 # domains→IP
python .claude/skills/validin-hunt/scripts/validin.py reverse-dns promoverse.org
```

**Note**: Add `VALIDIN_API_KEY=<key>` to `/home/user1/adversary_hunting/.env` before use.


## Overview

Validin is a threat intelligence platform specializing in:
1. **Historical infrastructure data** — retains HTTP headers, certificates, and JARM data better than Shodan or Censys
2. **Forward DNS** — proactively queries DNS for ALL domains daily, building a historical DNS database
3. **CloudFlare origin de-cloaking** — links CloudFlare IP ranges back to their origin servers
4. **Host connection mapping** — shows JARM, certificate, and HTTP response relationships across infrastructure
5. **Timeline analysis** — tracks when services appeared and disappeared on specific IPs

Validin is the platform to use when:
- Infrastructure is offline (no longer visible in live scan results)
- You need to de-anonymize CloudFlare-protected C2
- You need forward DNS history (which domains resolved to a suspicious IP over time)
- You need to track certificate fingerprint rotation across a campaign

---

## Key Features

### 1. Forward DNS

Validin performs **proactive daily DNS queries** for all known domains, not just passively observing DNS traffic. This creates a comprehensive historical record.

Use cases:
- Given a suspicious IP, find all domains that have ever resolved to it
- Given a domain, see its full resolution history and when it changed
- Identify domain clustering (multiple C2 domains resolving to same IP over time)

### 2. Host Responses

Validin captures HTTP response headers and bodies for observed hosts.

Use cases:
- Retrieve the HTTP headers from an IP that is now offline
- Track when headers changed (indicating infrastructure modification or evasion)
- Extract JARM fingerprints from historical scan data

### 3. Host Connections

Shows relationships between hosts based on shared attributes:
- JARM fingerprints
- SSL certificate fingerprints
- HTTP response patterns

Use cases:
- Given a JARM, find all IPs that have ever shared it
- Build infrastructure clusters from certificate fingerprint relationships

### 4. Historical Data Retention

Validin retains historical data longer than Shodan or Censys for offline infrastructure.

Use cases:
- Infrastructure taken down before you started hunting → Validin may still have records
- Track how threat actor modified headers over time to evade detection
- Establish timeline of infrastructure deployment

---

## CloudFlare Origin De-cloaking

This is Validin's most unique capability for adversary infrastructure hunting.

### How CloudFlare Protection Works

1. Threat actor registers domain, sets DNS to CloudFlare nameservers
2. Domain resolves to CloudFlare anycast IP ranges (not the actual C2)
3. Browser sees CloudFlare-issued TLS certificate, not the origin certificate
4. Origin server communicates with CloudFlare via a separate path

### How Validin De-cloaks CloudFlare

1. Validin observes the CloudFlare-hosted IP (what users see)
2. Validin also scans origin servers directly
3. When origin servers present CloudFlare-issued certificates (Origin Certificates), Validin links them
4. Result: CloudFlare-hosted domain → CloudFlare IP → Origin IP

### De-cloaking Workflow

**Step 1 — Identify CloudFlare-protected C2**:
- Domain resolves to `104.16.x.x`, `172.67.x.x`, or other CloudFlare IP ranges
- Cobalt Strike is operating behind CloudFlare (common evasion technique)
- Shodan/Censys only show CloudFlare IP, not C2 origin

**Step 2 — Query Validin with the domain**:
- Validin shows the CloudFlare IP (what DNS returns)
- Validin also shows the origin IP (the actual C2 server)
- This is visible because CloudFlare Origin Certificates have a distinctive fingerprint

**Step 3 — Pivot on origin IP**:
- The origin IP can now be searched in Shodan/Censys/FOFA
- Build hunt rules based on the actual C2 server attributes
- The origin IP may be reused across multiple CloudFlare-protected domains

### CloudFlare Detection Indicators in Cobalt Strike
- CloudFlare-issued certificate visible to the browser
- Non-standard ports allowed by CloudFlare: 2052, 2053, 2082, 2083, 2086, 2087, 2095, 2096, 8880, 8443
- C2 traffic tunneled via HTTP/HTTPS through CloudFlare

**Shodan rule to find Cobalt Strike behind CloudFlare** (after de-cloaking):
```
services.banner="HTTP/1.1 404 Not Found..." and services.port:{2052,2053,2082,2083,2086,2087,2095,2096,8880}
```

---

## Historical Infrastructure Analysis Workflow

### Workflow 1: Offline Infrastructure Recovery

**Scenario**: IOC from a 6-month-old report, IP is offline in Shodan/Censys.

**Step 1 — Query the offline IP in Validin**:
- Navigate to Host Responses for the IP
- Retrieve historical HTTP headers from when the server was active
- Extract JARM fingerprint from historical scan data

**Step 2 — Build hunt rule from recovered attributes**:
```
JARM recovered: 40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202
HTTP headers recovered:
  Content-Length: 14
  Content-Type: text/plain; charset=utf-8
```

**Step 3 — Search FOFA for active infrastructure using recovered data**:
```
jarm="40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202" && header="Content-Length: 14"
```

**Step 4 — Cross-reference Shodan with combined rule**:
```
ssl.jarm:40d1db40d0000001dc43d1db1db43d76e1f79b8645e08ae7fa8f07eb5e4202 http.headers_hash:144518609
```

### Workflow 2: Forward DNS Cluster Discovery

**Scenario**: Known malicious domain, want to find related domains and infrastructure.

**Step 1 — Query forward DNS for the domain**:
- Validin shows current and historical IP resolutions
- Identify all IPs the domain has pointed to

**Step 2 — For each IP, query forward DNS in reverse**:
- Validin shows all domains that have resolved to that IP
- Look for domain naming patterns (actor tends to follow patterns)

**Step 3 — Identify naming patterns**:
```
Example patterns from discovered domains:
- [company]-okta[.]com
- [company]-hr[.]com
- [company]-vpn[.]io
```

**Step 4 — Use pattern to hunt for pre-operational domains**:
- Search in Shodan/Censys for servers with these domains in SSL certs
- Search URLScan for these domain patterns

### Workflow 3: Certificate Fingerprint Tracking

**Scenario**: Threat actor rotating certificates to evade detection rules.

**Step 1 — Collect historical certificate fingerprints from Validin**:
- Query Host Connections for the known C2 IP
- Extract all SSL certificate fingerprints over time

**Step 2 — For each certificate, find other IPs using same cert**:
- Validin links IPs that share certificate fingerprints
- This reveals the full cluster even across different hosting providers

**Step 3 — Analyze certificate patterns**:
- Are they self-signed? Using random CN values?
- Specific key sizes? Signature algorithms?
- Organization names matching known actor impersonation targets?

**Step 4 — Build Shodan rule from certificate pattern**:
```
ssl.cert.subject.cn:"[impersonation target]" ssl.cert.pubkey.bits:2048 port:4433
```

---

## Infrastructure Modification Evasion Tracking

Validin is particularly useful when tracking how threat actors modify infrastructure to evade detection rules.

### Common Evasion Techniques (detectable via Validin)

**1. Header modification**:
- Actor notices their C2 is being detected via a specific header
- Changes `Server: Apache` to `Server: nginx`
- Validin shows the before/after: previous header → new header → detection bypass

**2. Port shifting**:
- Actor moves C2 from port 443 to port 8443 or custom port
- Validin timestamp data shows when port changed
- Allows you to track the infrastructure through the change

**3. Certificate rotation**:
- Actor replaces self-signed cert with Let's Encrypt cert
- Validin tracks certificate fingerprint history
- Old fingerprint → new fingerprint, both pointing to same IP cluster

**4. JARM changes**:
- Actor updates TLS configuration (e.g., changes cipher suites)
- JARM fingerprint changes
- Validin links old JARM → new JARM via IP overlap

### Response to Evasion

When an actor modifies infrastructure to evade a rule:
1. Use Validin historical data to see what changed
2. Identify the new attribute values
3. Update hunt rule with new attribute OR pivot to a more stable attribute

---

## Integration with hunt_intel_complete.py

Validin is referenced in the codebase as a recommended tool. A dedicated Validin API client can be built following the pattern of other clients in the file.

**Key API endpoints to implement**:
```python
# Host responses (historical HTTP data)
GET https://api.validin.com/api/v1/host/{ip}/responses

# Host connections (JARM/cert relationships)
GET https://api.validin.com/api/v1/host/{ip}/connections

# Forward DNS (domains resolving to IP)
GET https://api.validin.com/api/v1/dns/forward/{ip}

# Reverse DNS (IPs a domain has resolved to)
GET https://api.validin.com/api/v1/dns/reverse/{domain}
```

**Authentication**: API key via header `Authorization: Bearer {VALIDIN_API_KEY}`

---

## Comparison with Other Tools for Historical Data

| Capability | Validin | FOFA | Shodan | Censys |
|---|---|---|---|---|
| Historical HTTP headers | Excellent | Good | Limited | Limited |
| Historical JARM | Excellent | Good | Poor | Poor |
| Forward DNS (all domains→IP) | Excellent | Poor | Poor | Good |
| CloudFlare de-cloaking | Excellent | Poor | Poor | Poor |
| Offline infrastructure | Excellent | Good | Poor | Poor |
| Certificate history | Excellent | Poor | Poor | Good |
| Current live scanning | Limited | Excellent | Excellent | Excellent |

**Decision rule**: Use Validin when other tools show no data for an IP/domain, or when you need historical context.

---

## Best Practices

1. **Use Validin for offline infrastructure first** — before spending time with Shodan/Censys on an offline IP, check Validin for historical data
2. **De-cloak CloudFlare before hunting** — always check if a domain is behind CloudFlare and use Validin to find the origin IP before building hunt rules
3. **Use forward DNS to expand domain scope** — a single malicious IP may have hosted 20+ malicious domains over time
4. **Track certificate fingerprints across campaigns** — actors reuse certificate parameters even when rotating individual certs
5. **Check Validin when hunt rules stop working** — actor modified infrastructure; Validin shows what changed and when
6. **Combine Validin historical JARM with FOFA** — extract JARM from Validin, then search FOFA for currently active infrastructure
7. **Document timestamps** — Validin timestamps tell you when infrastructure was first seen and last seen, critical for campaign timeline reconstruction
