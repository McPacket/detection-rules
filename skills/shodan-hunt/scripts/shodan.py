#!/usr/bin/env python3
"""
Shodan hunt script for adversary infrastructure hunting.

Usage:
  python shodan.py search "http.html_hash:-2118050146" [--page 1] [--limit 100]
  python shodan.py host 162.0.230.185 [--history]
  python shodan.py facets "ssl.jarm:27d40d..." --facets org,country,port
"""

import argparse
import json
import sys
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parents[4] / ".env")

BASE_URL = "https://api.shodan.io"
API_KEY = os.getenv("SHODAN_API_KEY")


def die(msg: str):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(1)


def search(query: str, page: int = 1, limit: int = 100) -> dict:
    """Execute a Shodan search query."""
    if not API_KEY:
        die("SHODAN_API_KEY not set in .env")

    params = {"key": API_KEY, "query": query, "page": page}
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/shodan/host/search", params=params)
        r.raise_for_status()
        data = r.json()

    matches = data.get("matches", [])[:limit]
    return {
        "query": query,
        "total": data.get("total", 0),
        "returned": len(matches),
        "page": page,
        "results": [
            {
                "ip": m.get("ip_str"),
                "port": m.get("port"),
                "transport": m.get("transport"),
                "org": m.get("org"),
                "asn": m.get("asn"),
                "isp": m.get("isp"),
                "country": m.get("location", {}).get("country_name"),
                "city": m.get("location", {}).get("city"),
                "os": m.get("os"),
                "hostnames": m.get("hostnames", []),
                "domains": m.get("domains", []),
                "tags": m.get("tags", []),
                "timestamp": m.get("timestamp"),
                "banner": m.get("data", "")[:500],
                "http": {
                    "title": m.get("http", {}).get("title"),
                    "server": m.get("http", {}).get("server"),
                    "status": m.get("http", {}).get("status"),
                    "html_hash": m.get("http", {}).get("html_hash"),
                    "headers_hash": m.get("http", {}).get("headers_hash"),
                } if m.get("http") else None,
                "ssl": {
                    "cn": m.get("ssl", {}).get("cert", {}).get("subject", {}).get("CN"),
                    "issuer_cn": m.get("ssl", {}).get("cert", {}).get("issuer", {}).get("CN"),
                    "jarm": m.get("ssl", {}).get("jarm"),
                    "fingerprint": m.get("ssl", {}).get("cert", {}).get("fingerprint", {}).get("sha256"),
                } if m.get("ssl") else None,
                "ssh": {
                    "fingerprint": m.get("ssh", {}).get("fingerprint"),
                    "type": m.get("ssh", {}).get("type"),
                } if m.get("ssh") else None,
            }
            for m in matches
        ],
    }


def host(ip: str, history: bool = False) -> dict:
    """Get full service data for a specific IP."""
    if not API_KEY:
        die("SHODAN_API_KEY not set in .env")

    params = {"key": API_KEY}
    if history:
        params["history"] = "true"

    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/shodan/host/{ip}", params=params)
        if r.status_code == 404:
            return {"ip": ip, "error": "not found in Shodan"}
        r.raise_for_status()
        return r.json()


def facets(query: str, facet_fields: str = "org,country,port,asn") -> dict:
    """Run Shodan facet analysis on a query to identify false positive patterns."""
    if not API_KEY:
        die("SHODAN_API_KEY not set in .env")

    params = {"key": API_KEY, "query": query, "facets": facet_fields}
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/shodan/host/search/facets", params=params)
        r.raise_for_status()
        return {"query": query, "facets": r.json()}


def main():
    parser = argparse.ArgumentParser(
        description="Shodan adversary infrastructure hunting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser("search", help="Execute a Shodan search query")
    p_search.add_argument("query", help='Shodan query e.g. "http.html_hash:-2118050146"')
    p_search.add_argument("--page", type=int, default=1)
    p_search.add_argument("--limit", type=int, default=100, help="Max results to return")

    p_host = sub.add_parser("host", help="Get all service data for an IP")
    p_host.add_argument("ip")
    p_host.add_argument("--history", action="store_true", help="Include historical scan data")

    p_facets = sub.add_parser("facets", help="Facet analysis for false positive reduction")
    p_facets.add_argument("query")
    p_facets.add_argument("--facets", default="org,country,port,asn", help="Comma-separated facet fields")

    args = parser.parse_args()

    if args.command == "search":
        result = search(args.query, args.page, args.limit)
    elif args.command == "host":
        result = host(args.ip, args.history)
    elif args.command == "facets":
        result = facets(args.query, args.facets)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
