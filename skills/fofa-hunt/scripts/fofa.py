#!/usr/bin/env python3
"""
FOFA hunt script for adversary infrastructure hunting.

Usage:
  python fofa.py search 'jarm="27d40d40d00040d00042d43d000000b5ce48eb9aaa95d750e8df42b900e12b"'
  python fofa.py search 'port="10443" && server="Werkzeug"' [--size 100]
  python fofa.py search 'ip="162.0.230.185"'
  python fofa.py search 'domain="promoverse.org"'

FOFA requires queries to be base64-encoded — this script handles that automatically.
"""

import argparse
import base64
import json
import sys
import os
from pathlib import Path

import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).parents[4] / ".env")

BASE_URL = "https://fofa.info/api/v1/search/all"
FOFA_EMAIL = os.getenv("FOFA_EMAIL")
FOFA_API_KEY = os.getenv("FOFA_API_KEY")

DEFAULT_FIELDS = "ip,port,host,domain,protocol,cert,jarm,server,title,country,as_number,as_org"


def die(msg: str):
    print(json.dumps({"error": msg}), file=sys.stderr)
    sys.exit(1)


def search(query: str, size: int = 100, fields: str = DEFAULT_FIELDS) -> dict:
    """Execute a FOFA search query (query is auto base64-encoded)."""
    if not FOFA_EMAIL or not FOFA_API_KEY:
        die("FOFA_EMAIL and FOFA_API_KEY must be set in .env")

    qbase64 = base64.b64encode(query.encode()).decode()
    field_list = [f.strip() for f in fields.split(",")]

    params = {
        "email": FOFA_EMAIL,
        "key": FOFA_API_KEY,
        "qbase64": qbase64,
        "size": size,
        "fields": fields,
    }

    with httpx.Client(timeout=30) as client:
        r = client.get(BASE_URL, params=params)
        r.raise_for_status()
        data = r.json()

    if data.get("error"):
        return {"error": data.get("errmsg", "FOFA API error"), "query": query}

    raw_results = data.get("results", [])
    results = []
    for row in raw_results:
        record = {}
        for i, field in enumerate(field_list):
            record[field] = row[i] if i < len(row) else None
        results.append(record)

    return {
        "query": query,
        "query_base64": qbase64,
        "total": data.get("size", 0),
        "returned": len(results),
        "mode": data.get("mode"),
        "results": results,
    }


def main():
    parser = argparse.ArgumentParser(
        description="FOFA adversary infrastructure hunting",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser("search", help="Execute a FOFA search query")
    p_search.add_argument("query", help='FOFA query e.g. \'jarm="27d40d..." && port="443"\'')
    p_search.add_argument("--size", type=int, default=100, help="Max results (default 100)")
    p_search.add_argument("--fields", default=DEFAULT_FIELDS, help="Comma-separated fields to return")

    args = parser.parse_args()

    if args.command == "search":
        result = search(args.query, args.size, args.fields)

    print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
