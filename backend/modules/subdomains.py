# ─────────────────────────────────────────────────────────────────────────────
# subdomains.py — Subdomain Discovery via Certificate Transparency
# ─────────────────────────────────────────────────────────────────────────────
#
# APIs USED (all 100% FREE, no key needed):
#   1. crt.sh  — https://crt.sh
#      - Public certificate transparency log search
#      - No API key, no rate limits, completely free
#
#   2. HackerTarget  — https://hackertarget.com/find-dns-host-records/
#      - Free tier: 100 requests/day, no key needed
#
# ─────────────────────────────────────────────────────────────────────────────

import requests
import json


def get_subdomains(domain: str) -> dict:
    """
    Discovers subdomains using certificate transparency logs (crt.sh)
    and HackerTarget DNS brute-force results.
    """

    result = {
        "domain": domain,
        "subdomains": [],
        "total_found": 0,
        "sources": [],
        "error": None
    }

    subdomains_set = set()

    # ── Source 1: crt.sh Certificate Transparency ─────────────────────────────
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=15, headers={"User-Agent": "DeepFinder/1.0"})

        if resp.status_code == 200 and resp.text:
            entries = resp.json()
            for entry in entries:
                name = entry.get("name_value", "")
                # crt.sh can return multiple names separated by newlines
                for sub in name.split("\n"):
                    sub = sub.strip().lower()
                    # Filter wildcards and only keep subdomains of target
                    if sub and not sub.startswith("*") and sub.endswith(domain) and sub != domain:
                        subdomains_set.add(sub)

            result["sources"].append("crt.sh")

    except Exception as e:
        result["error"] = f"crt.sh error: {str(e)}"

    # ── Source 2: HackerTarget ────────────────────────────────────────────────
    try:
        url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
        resp = requests.get(url, timeout=10, headers={"User-Agent": "DeepFinder/1.0"})

        if resp.status_code == 200 and "error" not in resp.text.lower():
            for line in resp.text.strip().split("\n"):
                parts = line.split(",")
                if parts:
                    sub = parts[0].strip().lower()
                    if sub and sub.endswith(domain) and sub != domain:
                        subdomains_set.add(sub)

            result["sources"].append("HackerTarget")

    except Exception as e:
        existing_error = result.get("error", "")
        result["error"] = f"{existing_error} | HackerTarget error: {str(e)}".strip(" |")

    # ── Sort and deduplicate ──────────────────────────────────────────────────
    result["subdomains"] = sorted(list(subdomains_set))
    result["total_found"] = len(result["subdomains"])

    return result