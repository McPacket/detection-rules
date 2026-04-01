#!/usr/bin/env python3
"""
Censys hunt script for adversary infrastructure hunting.

Usage:
  python censys.py search 'services.port=9999 and autonomous_system.asn=22612'
  python censys.py search 'services.ssh.server_host_key.fingerprint_sha256="abc..."'
  python censys.py search 'services.http.response.headers.server="Werkzeug" and services.port=10443'
  python censys.py search 'services.labels="open-dir"'
  python censys.py host 162.0.230.185
"""

import argparse
import json
import sys
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parents[4] / ".env")

BASE_URL = "https://api.platform.censys.io/v3/global"
API_TOKEN = os.getenv("CENSYS_API_TOKEN")


def die(msg: str):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(1)


def _headers() -> dict:
    if not API_TOKEN:
        die("CENSYS_API_TOKEN not set in .env")
    return {
        "Authorization": f"Bearer {API_TOKEN}",
        "Accept": "application/vnd.censys.api.v3.host.v1+json",
        "Content-Type": "application/json",
    }


def _extract_service(svc: dict) -> dict:
    return {
        "port": svc.get("port"),
        "transport": svc.get("transport_protocol"),
        "service_name": svc.get("service_name"),
        "labels": svc.get("labels", []),
        "ssh": {
            "fingerprint": svc.get("ssh", {}).get("server_host_key", {}).get("fingerprint_sha256"),
            "banner": svc.get("ssh", {}).get("server", {}).get("server_id", {}).get("version"),
        } if svc.get("ssh") else None,
        "http": {
            "title": svc.get("http", {}).get("response", {}).get("html_title"),
            "server": (svc.get("http", {}).get("response", {}).get("headers") or {}).get("server", [None])[0],
            "status": svc.get("http", {}).get("response", {}).get("status_code"),
        } if svc.get("http") else None,
        "tls": {
            "jarm": svc.get("tls", {}).get("jarm_hash"),
            "cn": svc.get("tls", {}).get("certificate", {}).get("parsed", {}).get("subject", {}).get("common_name", [None])[0],
            "issuer_cn": svc.get("tls", {}).get("certificate", {}).get("parsed", {}).get("issuer", {}).get("common_name", [None])[0],
        } if svc.get("tls") else None,
        "banner": svc.get("banner", "")[:300] if svc.get("banner") else None,
    }


def search(query: str, per_page: int = 50, cursor: str = None) -> dict:
    """Search Censys for hosts matching a query."""
    body = {"query": query, "per_page": per_page}
    if cursor:
        body["cursor"] = cursor

    with httpx.Client(timeout=30) as client:
        r = client.post(f"{BASE_URL}/search/query", headers=_headers(), json=body)
        if r.status_code == 422:
            return {"error": "invalid query syntax", "detail": r.json()}
        r.raise_for_status()
        data = r.json()

    hits = data.get("result", {}).get("hits", [])
    return {
        "query": query,
        "total": data.get("result", {}).get("total", 0),
        "returned": len(hits),
        "next_cursor": data.get("result", {}).get("links", {}).get("next"),
        "results": [
            {
                "ip": h.get("ip"),
                "asn": h.get("autonomous_system", {}).get("asn"),
                "as_name": h.get("autonomous_system", {}).get("name"),
                "bgp_prefix": h.get("autonomous_system", {}).get("bgp_prefix"),
                "country": h.get("location", {}).get("country"),
                "country_code": h.get("location", {}).get("country_code"),
                "city": h.get("location", {}).get("city"),
                "labels": h.get("labels", []),
                "services": [_extract_service(s) for s in h.get("services", [])],
            }
            for h in hits
        ],
    }


def host(ip: str) -> dict:
    """Get full service data for a specific IP from Censys."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/asset/host/{ip}", headers=_headers())
        if r.status_code == 404:
            return {"ip": ip, "error": "not found in Censys"}
        r.raise_for_status()
        data = r.json().get("result", {})

    return {
        "ip": data.get("ip"),
        "asn": data.get("autonomous_system", {}).get("asn"),
        "as_name": data.get("autonomous_system", {}).get("name"),
        "bgp_prefix": data.get("autonomous_system", {}).get("bgp_prefix"),
        "country": data.get("location", {}).get("country"),
        "city": data.get("location", {}).get("city"),
        "labels": data.get("labels", []),
        "last_updated": data.get("last_updated_at"),
        "services": [_extract_service(s) for s in data.get("services", [])],
    }


def main():
    parser = argparse.ArgumentParser(
        description="Censys adversary infrastructure hunting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser("search", help="Search Censys by query")
    p_search.add_argument("query")
    p_search.add_argument("--per-page", type=int, default=50)
    p_search.add_argument("--cursor", help="Pagination cursor from previous result")

    p_host = sub.add_parser("host", help="Get full host data for an IP")
    p_host.add_argument("ip")

    args = parser.parse_args()

    if args.command == "search":
        result = search(args.query, args.per_page, args.cursor)
    elif args.command == "host":
        result = host(args.ip)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
