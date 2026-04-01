---
name: virustotal-pivot
description: VirusTotal integration for adversary infrastructure hunting validation. Use when validating discovered IPs or domains against vendor detections, looking up communicating malware files to confirm C2 attribution, checking community comments for threat actor context, enriching hunt findings with historical detection data, or analyzing URL reports to confirm phishing infrastructure. VirusTotal is the primary validation layer after search engine discovery.
license: Complete terms in LICENSE.txt
---

# VirusTotal Pivot Skill

## Executable Script

Always use the script instead of writing raw API calls inline:

```bash
source myenv/bin/activate
python .claude/skills/virustotal-pivot/scripts/virustotal.py ip 162.0.230.185
python .claude/skills/virustotal-pivot/scripts/virustotal.py domain promoverse.org
python .claude/skills/virustotal-pivot/scripts/virustotal.py file <sha256>
python .claude/skills/virustotal-pivot/scripts/virustotal.py communicating 162.0.230.185
python .claude/skills/virustotal-pivot/scripts/virustotal.py resolutions 162.0.230.185
python .claude/skills/virustotal-pivot/scripts/virustotal.py dns promoverse.org
```


## Overview

VirusTotal serves as the **validation and enrichment layer** in adversary infrastructure hunting. It is used:
1. **After** discovering infrastructure via Shodan/Censys/FOFA to confirm malicious nature
2. To identify **communicating malware samples** — files that have been observed connecting to discovered IPs
3. To read **community comments** — other researchers often leave attribution notes
4. To extract **historical detection context** — when was this IP first flagged and by whom

VirusTotal does NOT replace search engines — it validates and enriches what search engines find.

---

## API Integration

```python
BASE_URL = "https://www.virustotal.com/api/v3"
Headers: { "x-apikey": "{VT_API_KEY}" }

# IP report
GET /ip_addresses/{ip}

# Domain report
GET /domains/{domain}

# URL report (URL must be base64url-encoded, no padding)
url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
GET /urls/{url_id}

# File report
GET /files/{sha256_hash}

# Communicating files for an IP
GET /ip_addresses/{ip}/communicating_files

# Communicating files for a domain
GET /domains/{domain}/communicating_files
```

---

## Validation Workflow

### Step 1: IP Report — Quick Triage

When a search engine returns a cluster of IPs, run each through VirusTotal:

```python
report = await vt_client.get_ip_report(ip)
attributes = report['data']['attributes']
stats = attributes['last_analysis_stats']

malicious = stats['malicious']    # Number of vendors flagging as malicious
suspicious = stats['suspicious']   # Number flagging as suspicious
harmless = stats['harmless']
undetected = stats['undetected']
```

**Interpretation**:
| Detection Count | Confidence Level |
|---|---|
| 0 malicious, 0 suspicious | Not yet flagged — could be newly deployed C2 (valuable!) |
| 1-3 malicious | Low — likely pre-operational or recently deployed |
| 4-10 malicious | Medium — active or recently active infrastructure |
| 10+ malicious | High — known malicious, may be in threat intel feeds |

> **Key insight**: 0 detections on VirusTotal is NOT confirmation of legitimacy. Newly deployed C2 servers will have 0 detections. This is when infrastructure hunting adds the most value — you are ahead of the detection curve.

### Step 2: Community Comments

Community comments often contain attribution by other researchers:

```python
attributes = report['data']['attributes']
community_comments = attributes.get('community_notes', [])
# Also check 'tags' and 'last_analysis_results' for vendor categorization
```

Look for:
- Threat actor names (Lazarus, APT28, Scattered Spider)
- Malware family names (Cobalt Strike, BeaverTail, PortStarter)
- Campaign references
- Links to external threat intel reports

### Step 3: Communicating Files

Communicating files are the gold standard for confirming C2 attribution.

```python
GET /ip_addresses/{ip}/communicating_files
```

For each communicating file:
- Extract `sha256`, `meaningful_name`, `type_description`
- Check `last_analysis_stats` for detection rates
- Look for YARA rule matches in `last_analysis_results` (e.g., THOR APT scanner hits)
- Cross-reference against known malware families

**What to look for**:
- High detection count + known malware name = confirmed C2
- Low detection count + unique YARA hits = likely novel/custom malware
- 0 detections but correct file type = possible undetected payload (high value finding)

### Step 4: Domain Report (for domain-based C2)

```python
report = await vt_client.get_domain_report(domain)
attributes = report['data']['attributes']

# Key fields
creation_date = attributes.get('creation_date')        # When registered
last_dns_records = attributes.get('last_dns_records')  # Current DNS
last_analysis_stats = attributes.get('last_analysis_stats')
categories = attributes.get('categories', {})           # Vendor categorizations
```

Check:
- **Creation date** — recently registered domains are suspicious
- **Registrar** — bulletproof registrars signal malicious intent
- **DNS records** — does it resolve to an IP in your discovered cluster?
- **Categories** — vendor categorizations (malware, phishing, C2, etc.)

---

## Hunt Validation Patterns

### Pattern 1: Confirm C2 Cluster

After discovering 10 IPs via Shodan query:

```python
validation_results = []
for ip in discovered_ips:
    report = await vt_client.get_ip_report(ip)
    malicious = report['data']['attributes']['last_analysis_stats']['malicious']

    # Get communicating files
    files = await vt_client.get_communicating_files(ip)

    validation_results.append({
        'ip': ip,
        'malicious_vendors': malicious,
        'communicating_files': len(files),
        'confirmed': malicious > 0 or len(files) > 0
    })
```

If 7 of 10 IPs have confirming evidence, the 3 undetected IPs are likely pre-operational.

### Pattern 2: Reverse C2 Identification from File

When you have a malware sample hash and want to find its C2 servers:

```python
file_report = await vt_client.get_file_report(sha256)
contacted_ips = file_report['data']['attributes'].get('contacted_ips', [])
contacted_domains = file_report['data']['attributes'].get('contacted_domains', [])
```

Then pivot each contacted IP through Shodan/Censys to identify the full infrastructure cluster.

### Pattern 3: URLScan-to-VirusTotal Bridge (Lazarus BeaverTail)

From URLScan, you confirm a Python executable is available at `http://{ip}:1224/pdown`.
Use VirusTotal to validate the hash of the executable:

```python
# Hash confirmed from URLScan result
python_hash = "6a104f07ab6c5711b6bc8bf6ff956ab8cd597a388002a966e980c5ec9678b5b0"
file_report = await vt_client.get_file_report(python_hash)

# Check communicating IPs from this file
# All IPs that downloaded this Python binary are part of the same C2 cluster
```

### Pattern 4: False Positive Elimination

From a Shodan query returning 50 IPs, check each against VirusTotal:
- IPs with 0 detections AND no communicating files → likely false positive
- IPs with 0 detections BUT community comments citing threat actor → pre-operational C2 (keep)
- IPs with any malicious detection → confirmed malicious infrastructure

**Decision logic**:
```
if malicious > 0 OR suspicious > 3 OR communicating_files_with_known_malware > 0:
    → Confirmed infrastructure
elif community_comments_with_attribution:
    → Medium confidence infrastructure
else:
    → Likely false positive, remove from cluster
```

---

## Key VirusTotal Insights for Common Threat Actors

### Cobalt Strike Infrastructure
- Look for communicating files flagged with "CobaltStrike" in detection names
- YARA rules: `CobaltStrike_Beacon`, `CS_Payload`, `win.cobalt_strike`
- Watermark `987654321` appears in beacon configs extracted by some vendors

### Brute Ratel C4
- THOR APT scanner YARA rule: `BruteRatel_Badger`
- Detection name pattern: `Trojan.BruteRatel`, `HackTool.BruteRatel`
- File type: PE executable (Windows DLL or EXE)

### Lazarus Group / BeaverTail
- Community comments often reference "Hidden Cobra" (Trend Micro's label for Lazarus)
- Communicating files include BeaverTail JavaScript, InvisibleFerret Python backdoor
- Detection names: `Trojan.BeaverTail`, `Backdoor.InvisibleFerret`

### Scattered Spider / Phishing Infrastructure
- Domains flagged as phishing targeting Microsoft, Okta, Salesforce
- Categories: `phishing`, `malicious-activity`
- Communicating files may be absent (phishing kit, no payload)

---

## VirusTotal API Usage in hunt_intel_complete.py

Three methods are implemented:

**`vt_client.get_ip_report(ip)`**
- Returns full IP analysis report
- Key extraction: `data.attributes.last_analysis_stats`, `data.attributes.community_notes`
- Logged with malicious/suspicious counts

**`vt_client.get_domain_report(domain)`**
- Returns full domain analysis report
- Key extraction: creation date, DNS records, detection stats, categories

**`vt_client.get_url_report(url)`**
- URL is base64url-encoded (no padding) for the API
- Returns scan results for a specific URL
- Use for validating phishing pages or C2 callback URLs

---

## Attribution via VirusTotal

**Maltego + VirusTotal integration**:
- In Maltego, run "Communicating Files" transform on IP entities
- This bulk-queries VirusTotal for all IPs at once (saves manual work)
- Resulting file entities can be further analyzed for attribution

**Manual workflow**:
```
IP Address → VT IP Report → Communicating Files → File Hashes
→ VT File Report → Contacted IPs/Domains
→ Cross-reference with Shodan/Censys cluster → Attribution
```

---

## Best Practices

1. **Check VirusTotal AFTER search engine discovery** — do not rely on VT as a discovery tool
2. **0 detections is not clean** — it may mean newly deployed, pre-operational infrastructure (the most valuable finding)
3. **Always check communicating files** — these confirm C2 attribution definitively
4. **Read community comments** — they contain attribution from other researchers
5. **Use VT for false positive elimination** — filter out IPs with 0 detections AND no other signals
6. **Cross-reference hashes from URLScan** — use URLScan-discovered hashes in VT file lookup
7. **Rate limit awareness** — VT free tier limits API calls; cache results to avoid re-querying
8. **Record detection vendor names** — specific vendor detection names (e.g., THOR/YARA rule names) are strong attribution signals
