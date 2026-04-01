#!/usr/bin/env python3
"""
Validin hunt script for adversary infrastructure hunting.

Best used for: offline/historical infrastructure, CloudFlare de-cloaking,
forward DNS (all domains pointing to an IP), certificate history.

Usage:
  python validin.py responses 162.0.230.185          # historical HTTP responses
  python validin.py connections 162.0.230.185         # JARM/cert relationships
  python validin.py forward-dns 162.0.230.185         # all domains resolving to IP
  python validin.py reverse-dns promoverse.org        # all IPs a domain resolved to
  python validin.py host 162.0.230.185                # all data for an IP

Note: Add VALIDIN_API_KEY to your .env file.
"""

import argparse
import json
import sys
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parents[4] / ".env")

BASE_URL = "https://api.validin.com/api/v1"
API_KEY = os.getenv("VALIDIN_API_KEY")


def die(msg: str):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(1)


def _headers() -> dict:
    if not API_KEY:
        die("VALIDIN_API_KEY not set in .env — add it to /home/user1/adversary_hunting/.env")
    return {"Authorization": f"Bearer {API_KEY}"}


def host_responses(ip: str) -> dict:
    """Get historical HTTP responses captured for an IP."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/host/{ip}/responses", headers=_headers())
        if r.status_code == 404:
            return {"ip": ip, "responses": [], "note": "no historical data"}
        r.raise_for_status()
        return {"ip": ip, "responses": r.json()}


def connections(ip: str) -> dict:
    """Get JARM fingerprints and certificate relationships for an IP."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/host/{ip}/connections", headers=_headers())
        if r.status_code == 404:
            return {"ip": ip, "connections": [], "note": "no data"}
        r.raise_for_status()
        return {"ip": ip, "connections": r.json()}


def forward_dns(ip: str) -> dict:
    """Get all domains that have resolved to this IP (forward DNS)."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/dns/forward/{ip}", headers=_headers())
        if r.status_code == 404:
            return {"ip": ip, "domains": [], "note": "no DNS records"}
        r.raise_for_status()
        data = r.json()
        return {"ip": ip, "domain_count": len(data) if isinstance(data, list) else 0, "domains": data}


def reverse_dns(domain: str) -> dict:
    """Get all IPs a domain has historically resolved to (reverse DNS)."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/dns/reverse/{domain}", headers=_headers())
        if r.status_code == 404:
            return {"domain": domain, "ips": [], "note": "no DNS records"}
        r.raise_for_status()
        data = r.json()
        return {"domain": domain, "ip_count": len(data) if isinstance(data, list) else 0, "ips": data}


def host_all(ip: str) -> dict:
    """Aggregate all Validin data for an IP in one call."""
    with httpx.Client(timeout=60) as client:
        results = {"ip": ip}
        for endpoint, key in [("responses", "responses"), ("connections", "connections")]:
            r = client.get(f"{BASE_URL}/host/{ip}/{endpoint}", headers=_headers())
            results[key] = r.json() if r.status_code == 200 else []

        r = client.get(f"{BASE_URL}/dns/forward/{ip}", headers=_headers())
        data = r.json() if r.status_code == 200 else []
        results["forward_dns"] = {"domain_count": len(data) if isinstance(data, list) else 0, "domains": data}

    return results


def main():
    parser = argparse.ArgumentParser(
        description="Validin historical infrastructure pivoting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_resp = sub.add_parser("responses", help="Historical HTTP responses for an IP")
    p_resp.add_argument("ip")

    p_conn = sub.add_parser("connections", help="JARM/cert relationships for an IP")
    p_conn.add_argument("ip")

    p_fwd = sub.add_parser("forward-dns", help="All domains resolving to an IP")
    p_fwd.add_argument("ip")

    p_rev = sub.add_parser("reverse-dns", help="All IPs a domain has resolved to")
    p_rev.add_argument("domain")

    p_host = sub.add_parser("host", help="All Validin data for an IP (responses + connections + forward DNS)")
    p_host.add_argument("ip")

    args = parser.parse_args()

    if args.command == "responses":
        result = host_responses(args.ip)
    elif args.command == "connections":
        result = connections(args.ip)
    elif args.command == "forward-dns":
        result = forward_dns(args.ip)
    elif args.command == "reverse-dns":
        result = reverse_dns(args.domain)
    elif args.command == "host":
        result = host_all(args.ip)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
