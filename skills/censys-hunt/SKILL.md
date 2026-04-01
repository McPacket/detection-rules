---
name: censys-hunt
description: Censys internet search engine integration for adversary infrastructure hunting. Use when pivoting via SSH host key fingerprints, FTP banners, service-level attributes, open directory hunting, or when needing regex-based search and better hostname data. Covers Censys Platform API v3 syntax, SSH/FTP/HTTP pivoting, autonomous system filtering, and label-based open directory detection.
license: Complete terms in LICENSE.txt
---

# Censys Hunt Skill

## Executable Script

Always use the script instead of writing raw API calls inline:

```bash
source myenv/bin/activate
python .claude/skills/censys-hunt/scripts/censys.py search 'services.port=9999 and autonomous_system.asn=22612'
python .claude/skills/censys-hunt/scripts/censys.py search 'services.ssh.server_host_key.fingerprint_sha256="abc..."'
python .claude/skills/censys-hunt/scripts/censys.py search 'services.labels="open-dir"'
python .claude/skills/censys-hunt/scripts/censys.py host 162.0.230.185
```


## Overview

Censys excels at adversary infrastructure hunting in specific scenarios:
- **SSH host key fingerprint pivoting** — discovering clusters sharing the same SSH key
- **FTP banner pivoting** — identifying C2 clusters via service banners
- **Open directory hunting** — `labels:'open-dir'` label is a unique Censys capability
- **Regex search** — unlike Shodan, Censys supports regex patterns
- **Hostname data** — consistently includes hostname/DNS data in results
- **Scanning frequency** — scans more frequently than Shodan, so recently deployed infrastructure appears sooner
- **Historical data** — retains historical service data per host with timestamps

**Limitation**: Longer, more verbose query syntax. No Facet Analysis equivalent.

---

## API Integration (Platform API v3)

```python
# Search endpoint (POST)
POST https://api.platform.censys.io/v3/global/search/query
Headers:
  Authorization: Bearer {PERSONAL_ACCESS_TOKEN}
  Accept: application/vnd.censys.api.v3.host.v1+json
  Content-Type: application/json
Body:
  { "query": "...", "per_page": 50, "cursor": null }

# Host info endpoint (GET)
GET https://api.platform.censys.io/v3/global/asset/host/{IP}
Headers:
  Authorization: Bearer {PERSONAL_ACCESS_TOKEN}
```

Response structure:
- `result.hits[]` — array of matching host records
- Each hit: `ip`, `services[]`, `autonomous_system`, `labels[]`
- Each service: `port`, `transport_protocol`, `service_name`, `banner`, `ssh`, `http`, `tls`

---

## Search Syntax Reference

### Service-Level Filters

| Filter | Description | Example |
|---|---|---|
| `services.port` | Port number | `services.port=22` |
| `services.transport_protocol` | TCP or UDP | `services.transport_protocol="TCP"` |
| `services.service_name` | Service type | `services.service_name="SSH"` |
| `services.banner` | Raw service banner text | `services.banner="220 pyftpdlib"` |
| `services.software.product` | Detected software | `services.software.product="Linux"` |
| `services.software.version` | Software version | `services.software.version="Ubuntu"` |

### SSH-Specific Filters

| Filter | Description | Example |
|---|---|---|
| `services.ssh.server_host_key.fingerprint_sha256` | SHA256 host key fingerprint | `services.ssh.server_host_key.fingerprint_sha256="8d1798..."` |
| `services.ssh.server_host_key.rsa_public_key.length` | RSA key length | `services.ssh.server_host_key.rsa_public_key.length=2048` |
| `services.ssh.kex_init_message.kex_algorithms` | Key exchange algorithms | |

### HTTP-Specific Filters

| Filter | Description | Example |
|---|---|---|
| `services.http.response.status_code` | HTTP status code | `services.http.response.status_code=200` |
| `services.http.response.headers` | HTTP response headers | `services.http.response.headers: (key: \`Server\` and value.headers: \`Apache\`)` |
| `services.http.response.html_tags` | HTML tag content | `services.http.response.html_tags="<title>Welcome to SimpleHelp</title>"` |
| `services.http.response.body` | HTTP response body | `services.http.response.body="cobalt strike"` |
| `services.http.response.body_hash` | Body hash | `services.http.response.body_hash="sha256:abc123"` |

### TLS/SSL Filters

| Filter | Description | Example |
|---|---|---|
| `services.tls.certificates.leaf_data.subject_dn` | Certificate subject DN | `services.tls.certificates.leaf_data.subject_dn="CN=Mythic"` |
| `services.tls.certificates.leaf_data.issuer_dn` | Certificate issuer DN | `services.tls.certificates.leaf_data.issuer_dn="O=Gophish"` |
| `services.tls.certificates.leaf_data.fingerprint` | Certificate fingerprint | |
| `services.tls.certificates.leaf_data.pubkey_bit_size` | Public key size | `services.tls.certificates.leaf_data.pubkey_bit_size=4096` |
| `services.tls.certificates.leaf_data.names` | SANs / certificate names | `services.tls.certificates.leaf_data.names="evil.com"` |
| `services.jarm.fingerprint` | JARM fingerprint | `services.jarm.fingerprint="2ad2ad16..."` |

### ASN / Hosting Filters

| Filter | Description | Example |
|---|---|---|
| `autonomous_system.name` | ASN organization name | `autonomous_system.name=\`M247\`` |
| `autonomous_system.asn` | ASN number | `autonomous_system.asn=20473` |
| `autonomous_system.country_code` | Country of ASN | `autonomous_system.country_code="KR"` |
| `ip` | IP or CIDR | `ip=192.168.0.0/24` |

### Label Filters

| Filter | Description |
|---|---|
| `labels='open-dir'` | Servers hosting open directories |
| `labels='remote-access'` | Remote access software detected |
| `labels='c2'` | Command and control infrastructure (Censys-classified) |
| `labels='honeypot'` | Likely honeypots — useful for exclusion |

**Syntax note**: Use backtick-quoted strings for `autonomous_system.name` to match exact values.

---

## Core Pivot Workflows

### Workflow 1: SSH Host Key Fingerprint Pivoting

This is Censys's strongest differentiator. Threat actors reuse SSH keys across their infrastructure.

**Step 1 — Extract SSH fingerprint from known node**:
```
https://search.censys.io/hosts/{IP}/data/table#22-TCP-SSH
```
Click on `service.ssh.server_host_key_fingerprint_sha256` to get the value.

**Step 2 — Build initial SSH cluster query**:
```
services.ssh.server_host_key.fingerprint_sha256="8d1798c27b2381fcbffb19abb5bac757052f4fa9da8b246969392c7f4a6b34fd"
```

**Step 3 — Narrow with additional attributes** (reduce false positives from shared hosting):
Add the ASN of the known actor's preferred provider:
```
(services.ssh.server_host_key.fingerprint_sha256="8d1798c27b2381fcbffb19abb5bac757052f4fa9da8b246969392c7f4a6b34fd") and autonomous_system.name=`M247`
```

**Step 4 — Add application-layer filter** (confirm the same tool is running):
```
((services.ssh.server_host_key.fingerprint_sha256="8d1798c27b2381fcbffb19abb5bac757052f4fa9da8b246969392c7f4a6b34fd") and autonomous_system.name=`M247`) and services.http.response.html_tags="<title>Welcome to SimpleHelp</title>"
```

**Attribution logic**: SSH fingerprints shared across IPs on the same ASN running the same tool = high confidence same operator.

> Note: SSH pivoting gives **low-to-medium confidence** initially. Some hosting providers deploy VMs with identical SSH keys. Always add a second attribute (HTML title, ASN, application behavior).

---

### Workflow 2: FTP Banner Pivoting

FTP banners reveal server software configurations that threat actors leave as-is.

**Step 1 — Capture FTP banner from known node**:
```
services.banner="220 pyftpdlib based ftpd ready.\r\n"
```

**Step 2 — Note that this is too broad** (500+ results, mostly false positives):
- Use Censys result breakdown to identify which ASNs dominate
- Look for the actor's known preferred provider

**Step 3 — Narrow with ASN**:
```
(services.banner="220 pyftpdlib based ftpd ready.\r\n") and autonomous_system.name=`LEASEWEB-APAC-SIN-11 LEASEWEB SINGAPORE PTE. LTD.`
```

**Step 4 — Validate via URLScan**:
- For Lazarus BeaverTail: check if `http://{IP}:1224/pdown` returns Python executable
- Hash: `6a104f07ab6c5711b6bc8bf6ff956ab8cd597a388002a966e980c5ec9678b5b0`

---

### Workflow 3: Open Directory Hunting

Censys uniquely provides an `open-dir` label that identifies servers exposing directory listings.

**Basic open directory search**:
```
labels='open-dir'
```

**Targeted file extension hunting** (for offensive tooling):
```
labels='open-dir' and services.http.response.body=".exe"
```

**Tool name targeting**:
```
labels='open-dir' and services.http.response.body="cobalt strike"
```

**Combined approach**:
```
labels='open-dir' and (services.http.response.body=".ps1" or services.http.response.body=".dll" or services.http.response.body="payload")
```

**Manual filter criteria** (apply after initial results):
- Suspicious ASNs or hosting providers
- Non-standard ports
- Files matching known malware tool names: Cobalt Strike, Sliver, Meterpreter, Bloodhound

---

### Workflow 4: RDP Certificate Pivoting (Nation-State)

APT38 (Bluenoroff) uses identifiable RDP certificate patterns.

**Known pattern** (CN follows `hwc-hwp-{numbers}` format):
```
services.tls.certificates.leaf_data.subject_dn="CN=hwc-hwp-7779700" and services.port=`3389`
```

**Cluster entire APT38 RDP cert pattern**:
```
services.tls.certificates.leaf_data.subject.common_name:/hwc-hwp-[0-9]+/ and services.port=`3389`
```
(Note: regex requires Censys regex support — use `/pattern/` syntax)

---

### Workflow 5: Evilginx Detection

Evilginx leaves a distinctive service pattern: SSH, SMTP, DNS, and HTTP all running together.

```
(services.port="53" and services.http.response.headers: (key: `Content-Length` and value.headers: `46`) and services.http.response.status_code="302") and services.software.product=`Linux` and labels=`remote-access`
```

---

## C2 Framework Hunt Rules (Censys Syntax)

### MuddyWater SimpleHelp
```
((services.ssh.server_host_key.fingerprint_sha256="{fingerprint}") and autonomous_system.name=`M247`) and services.http.response.html_tags="<title>Welcome to SimpleHelp</title>"
```

### Cobalt Strike (via banner)
```
services.http.response.body="HTTP/1.1 404 Not Found" and services.http.response.headers: (key: `Keep-Alive` and value.headers: `timeout=10, max=100`)
```

### Pikabot / Qakbot Proxy (4096-bit self-signed certs on non-443 ports)
```
services.tls.certificates.leaf_data.pubkey_bit_size=4096 and services.port={1194,2078,2222} and services.tls.certificates.leaf_data.issuer.organization:/[A-Z][a-z]+ [A-Z][a-z]+/
```

### APT43 Kimsuky (JARM + Apache config)
```
services.jarm.fingerprint="2ad2ad16d2ad2ad22c42d42d0000006f254909a73bf62f6b28507e9fb451b5" and autonomous_system.asn=20473
```

---

## Censys API Usage in hunt_intel_complete.py

The codebase implements two Censys methods:

**`censys_client.search(query, per_page)`**
- POST to Platform API v3 `/global/search/query`
- Returns `result.hits[]` array
- Use for infrastructure cluster searches

**`censys_client.host_info(ip)`**
- GET to `/global/asset/host/{ip}`
- Returns full service tree for a specific IP
- Handles 404/422 gracefully (IP not in Censys database)
- Use to extract SSH fingerprint, FTP banner, HTTP headers, TLS cert from a starting IOC

### SSH Pivot Workflow in Code
```python
# 1. Get host info for starting IP
host_data = await censys_client.host_info(starting_ip)

# 2. Extract SSH fingerprint
for service in host_data.get('result', {}).get('services', []):
    if service.get('service_name') == 'SSH':
        fingerprint = service['ssh']['server_host_key']['fingerprint_sha256']

# 3. Build Censys query
query = f'services.ssh.server_host_key.fingerprint_sha256="{fingerprint}"'

# 4. (Optional) Add ASN
asn_name = host_data['result']['autonomous_system']['name']
query += f' and autonomous_system.name=`{asn_name}`'

# 5. Search for cluster
results = await censys_client.search(query)
```

---

## Best Practices

1. **SSH pivoting requires corroboration** — always add ASN or application-layer filter
2. **FTP banners are a starting point** — narrow with ASN or additional service attributes
3. **Use `labels='open-dir'`** for hunting exposed threat actor staging servers
4. **Backtick-quote ASN names** exactly as they appear in Censys (`autonomous_system.name=\`EXACT NAME\``)
5. **Censys for fresh infrastructure** — more frequent scanning catches newly deployed C2s faster than Shodan
6. **Check `services[]` array** carefully — Censys returns per-service data, not per-port like Shodan
7. **Validate 404/422 responses** from host_info as "not indexed" rather than clean — the host may exist but not be in Censys's database
