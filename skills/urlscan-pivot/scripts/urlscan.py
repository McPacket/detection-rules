#!/usr/bin/env python3
"""
URLScan.io pivot script for adversary infrastructure hunting.

Usage:
  python urlscan.py search 'page.ip:"162.0.230.185"' [--size 50]
  python urlscan.py search 'filename:"FMAPP"'
  python urlscan.py search 'page.domain:promoverse.org'
  python urlscan.py search 'page.server:"Werkzeug" AND page.asn:"AS22612"'
  python urlscan.py result <UUID>
  python urlscan.py ip 162.0.230.185            # shorthand: search by IP
  python urlscan.py domain promoverse.org       # shorthand: search by domain
"""

import argparse
import json
import sys
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parents[4] / ".env")

BASE_URL = "https://urlscan.io/api/v1"
API_KEY = os.getenv("URLSCAN_API_KEY")


def die(msg: str):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(1)


def _headers() -> dict:
    h = {"Content-Type": "application/json"}
    if API_KEY:
        h["API-Key"] = API_KEY
    return h


def search(query: str, size: int = 100) -> dict:
    """Search URLScan historical scan database."""
    with httpx.Client(timeout=30) as client:
        r = client.get(
            f"{BASE_URL}/search/",
            headers=_headers(),
            params={"q": query, "size": size},
        )
        if r.status_code == 429:
            die("URLScan rate limit hit — wait 60s and retry")
        r.raise_for_status()
        data = r.json()

    results = []
    for scan in data.get("results", []):
        page = scan.get("page", {})
        task = scan.get("task", {})
        results.append({
            "uuid": scan.get("_id"),
            "url": task.get("url"),
            "time": task.get("time"),
            "ip": page.get("ip"),
            "domain": page.get("domain"),
            "asn": page.get("asn"),
            "asnname": page.get("asnname"),
            "country": page.get("country"),
            "server": page.get("server"),
            "title": page.get("title"),
            "status": page.get("status"),
            "screenshot": f"https://urlscan.io/screenshots/{scan.get('_id')}.png",
            "result_url": f"https://urlscan.io/result/{scan.get('_id')}/",
        })

    return {
        "query": query,
        "total": data.get("total", 0),
        "returned": len(results),
        "results": results,
    }


def result(uuid: str) -> dict:
    """Retrieve full scan result for a specific UUID."""
    with httpx.Client(timeout=30) as client:
        r = client.get(f"{BASE_URL}/result/{uuid}/", headers=_headers())
        if r.status_code == 404:
            return {"uuid": uuid, "error": "scan result not found"}
        r.raise_for_status()
        data = r.json()

    page = data.get("page", {})
    task = data.get("task", {})
    lists = data.get("lists", {})
    stats = data.get("stats", {})

    return {
        "uuid": uuid,
        "url": task.get("url"),
        "time": task.get("time"),
        "page": {
            "ip": page.get("ip"),
            "domain": page.get("domain"),
            "asn": page.get("asn"),
            "asnname": page.get("asnname"),
            "country": page.get("country"),
            "server": page.get("server"),
            "title": page.get("title"),
            "status": page.get("status"),
            "mime_type": page.get("mimeType"),
        },
        "ips": lists.get("ips", []),
        "domains": lists.get("domains", []),
        "urls": lists.get("urls", [])[:20],
        "hashes": lists.get("hashes", []),
        "certificates": [
            {
                "subject": c.get("subjectName"),
                "issuer": c.get("issuer"),
                "valid_from": c.get("validFrom"),
                "valid_to": c.get("validTo"),
            }
            for c in lists.get("certificates", [])[:5]
        ],
        "stats": {
            "requests": stats.get("requests", 0),
            "ip_count": stats.get("ipStats", {}).get("count", 0) if isinstance(stats.get("ipStats"), dict) else 0,
        },
        "screenshot": f"https://urlscan.io/screenshots/{uuid}.png",
    }


def search_ip(ip: str, size: int = 50) -> dict:
    return search(f'page.ip:"{ip}"', size)


def search_domain(domain: str, size: int = 50) -> dict:
    return search(f'page.domain:"{domain}"', size)


def main():
    parser = argparse.ArgumentParser(
        description="URLScan.io adversary infrastructure pivoting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser("search", help="Search URLScan historical database")
    p_search.add_argument("query", help='URLScan query e.g. \'filename:"FMAPP"\'')
    p_search.add_argument("--size", type=int, default=100)

    p_result = sub.add_parser("result", help="Get full scan result by UUID")
    p_result.add_argument("uuid")

    p_ip = sub.add_parser("ip", help="Search scans by IP address")
    p_ip.add_argument("ip")
    p_ip.add_argument("--size", type=int, default=50)

    p_domain = sub.add_parser("domain", help="Search scans by domain")
    p_domain.add_argument("domain")
    p_domain.add_argument("--size", type=int, default=50)

    args = parser.parse_args()

    if args.command == "search":
        result_data = search(args.query, args.size)
    elif args.command == "result":
        result_data = result(args.uuid)
    elif args.command == "ip":
        result_data = search_ip(args.ip, args.size)
    elif args.command == "domain":
        result_data = search_domain(args.domain, args.size)

    print(json.dumps(result_data, indent=2, default=str))


if __name__ == "__main__":
    main()
