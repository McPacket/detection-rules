#!/usr/bin/env python3
"""
VirusTotal pivot script for adversary infrastructure hunting.

Usage:
  python virustotal.py ip 162.0.230.185
  python virustotal.py domain promoverse.org
  python virustotal.py file e25892603c42e34bd7ba0d8ea73be600d898cadc290e3417a82c04d6281b743b
  python virustotal.py communicating 162.0.230.185      # files communicating with IP
  python virustotal.py resolutions 162.0.230.185        # domains that resolved to IP
  python virustotal.py dns promoverse.org               # DNS records for domain
"""

import argparse
import json
import sys
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parents[4] / ".env")

BASE_URL = "https://www.virustotal.com/api/v3"
API_KEY = os.getenv("VIRUSTOTAL_API_KEY")


def die(msg: str):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(1)


def _headers() -> dict:
    if not API_KEY:
        die("VIRUSTOTAL_API_KEY not set in .env")
    return {"x-apikey": API_KEY}


def _stats_summary(stats: dict) -> dict:
    return {
        "malicious": stats.get("malicious", 0),
        "suspicious": stats.get("suspicious", 0),
        "undetected": stats.get("undetected", 0),
        "harmless": stats.get("harmless", 0),
        "total": sum(stats.values()),
    }


def ip_report(ip: str) -> dict:
    """Get VT IP address report with detection summary."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/ip_addresses/{ip}", headers=_headers())
        if r.status_code == 404:
            return {"ip": ip, "error": "not found"}
        r.raise_for_status()
        d = r.json().get("data", {})
        attrs = d.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "ip": ip,
            "detections": _stats_summary(stats),
            "asn": attrs.get("asn"),
            "as_owner": attrs.get("as_owner"),
            "country": attrs.get("country"),
            "continent": attrs.get("continent"),
            "network": attrs.get("network"),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags", []),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "last_modification_date": attrs.get("last_modification_date"),
            "whois": attrs.get("whois", "")[:1000],
            "total_votes": attrs.get("total_votes", {}),
        }


def domain_report(domain: str) -> dict:
    """Get VT domain report with detection summary."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/domains/{domain}", headers=_headers())
        if r.status_code == 404:
            return {"domain": domain, "error": "not found"}
        r.raise_for_status()
        d = r.json().get("data", {})
        attrs = d.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "domain": domain,
            "detections": _stats_summary(stats),
            "registrar": attrs.get("registrar"),
            "creation_date": attrs.get("creation_date"),
            "last_update_date": attrs.get("last_update_date"),
            "last_dns_records": attrs.get("last_dns_records", []),
            "reputation": attrs.get("reputation"),
            "tags": attrs.get("tags", []),
            "categories": attrs.get("categories", {}),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "whois": attrs.get("whois", "")[:1000],
        }


def file_report(hash_value: str) -> dict:
    """Get VT file report by hash (MD5/SHA1/SHA256)."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/files/{hash_value}", headers=_headers())
        if r.status_code == 404:
            return {"hash": hash_value, "error": "not found — file not submitted to VT"}
        r.raise_for_status()
        d = r.json().get("data", {})
        attrs = d.get("attributes", {})
        stats = attrs.get("last_analysis_stats", {})
        return {
            "sha256": attrs.get("sha256"),
            "sha1": attrs.get("sha1"),
            "md5": attrs.get("md5"),
            "name": attrs.get("meaningful_name"),
            "names": attrs.get("names", [])[:10],
            "type": attrs.get("type_description"),
            "size": attrs.get("size"),
            "detections": _stats_summary(stats),
            "first_submission": attrs.get("first_submission_date"),
            "last_analysis_date": attrs.get("last_analysis_date"),
            "tags": attrs.get("tags", []),
            "signature_info": attrs.get("signature_info", {}),
            "pe_info": {
                "imphash": attrs.get("pe_info", {}).get("imphash"),
                "compilation_timestamp": attrs.get("pe_info", {}).get("timestamp"),
            } if attrs.get("pe_info") else None,
        }


def communicating_files(ip: str, limit: int = 20) -> dict:
    """Get files that communicate with an IP address."""
    with httpx.Client(timeout=30) as client:
        r = client.get(
            f"{BASE_URL}/ip_addresses/{ip}/communicating_files",
            headers=_headers(),
            params={"limit": limit},
        )
        if r.status_code == 404:
            return {"ip": ip, "files": [], "error": "not found"}
        r.raise_for_status()
        data = r.json()
        files = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            files.append({
                "sha256": attrs.get("sha256"),
                "name": attrs.get("meaningful_name"),
                "names": attrs.get("names", [])[:5],
                "type": attrs.get("type_description"),
                "size": attrs.get("size"),
                "detections": _stats_summary(stats),
                "first_submission": attrs.get("first_submission_date"),
                "last_analysis_date": attrs.get("last_analysis_date"),
                "tags": attrs.get("tags", []),
            })
    return {
        "ip": ip,
        "file_count": len(files),
        "files": files,
        "meta": data.get("meta", {}),
    }


def resolutions(ip: str, limit: int = 40) -> dict:
    """Get domains that historically resolved to an IP."""
    with httpx.Client(timeout=30) as client:
        r = client.get(
            f"{BASE_URL}/ip_addresses/{ip}/resolutions",
            headers=_headers(),
            params={"limit": limit},
        )
        if r.status_code == 404:
            return {"ip": ip, "resolutions": []}
        r.raise_for_status()
        data = r.json()
        recs = []
        for item in data.get("data", []):
            attrs = item.get("attributes", {})
            recs.append({
                "hostname": attrs.get("host_name"),
                "last_resolved": attrs.get("date"),
                "ip_address": attrs.get("ip_address"),
            })
    return {"ip": ip, "resolution_count": len(recs), "resolutions": recs}


def dns_records(domain: str) -> dict:
    """Get current DNS records for a domain."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/domains/{domain}", headers=_headers())
        if r.status_code == 404:
            return {"domain": domain, "error": "not found"}
        r.raise_for_status()
        attrs = r.json().get("data", {}).get("attributes", {})
        return {
            "domain": domain,
            "last_dns_records": attrs.get("last_dns_records", []),
            "last_dns_records_date": attrs.get("last_dns_records_date"),
        }


def main():
    parser = argparse.ArgumentParser(
        description="VirusTotal adversary infrastructure pivoting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ip = sub.add_parser("ip", help="IP address report")
    p_ip.add_argument("ip")

    p_dom = sub.add_parser("domain", help="Domain report")
    p_dom.add_argument("domain")

    p_file = sub.add_parser("file", help="File report by MD5/SHA1/SHA256")
    p_file.add_argument("hash")

    p_comm = sub.add_parser("communicating", help="Files that communicate with an IP")
    p_comm.add_argument("ip")
    p_comm.add_argument("--limit", type=int, default=20)

    p_res = sub.add_parser("resolutions", help="Domains that resolved to an IP")
    p_res.add_argument("ip")
    p_res.add_argument("--limit", type=int, default=40)

    p_dns = sub.add_parser("dns", help="DNS records for a domain")
    p_dns.add_argument("domain")

    args = parser.parse_args()

    if args.command == "ip":
        result = ip_report(args.ip)
    elif args.command == "domain":
        result = domain_report(args.domain)
    elif args.command == "file":
        result = file_report(args.hash)
    elif args.command == "communicating":
        result = communicating_files(args.ip, args.limit)
    elif args.command == "resolutions":
        result = resolutions(args.ip, args.limit)
    elif args.command == "dns":
        result = dns_records(args.domain)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
