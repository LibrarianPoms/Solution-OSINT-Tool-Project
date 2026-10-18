# ─────────────────────────────────────────────────────────────────────────────
# threat_intel.py — Threat Intelligence OSINT
# ─────────────────────────────────────────────────────────────────────────────
#
# APIs USED:
#   1. VirusTotal (virustotal.com)
#      - Free tier: 500 requests/day, 4 requests/minute
#      - Sign up at: https://www.virustotal.com/gui/join-us
#      - Add to .env: VIRUSTOTAL_API_KEY=your_key_here
#
#   2. AbuseIPDB (abuseipdb.com)
#      - Free tier: 1000 requests/day
#      - Sign up at: https://www.abuseipdb.com/register
#      - Add to .env: ABUSEIPDB_API_KEY=your_key_here
#
#   3. AlienVault OTX (otx.alienvault.com)
#      - Completely FREE, generous limits
#      - Sign up at: https://otx.alienvault.com/accounts/register
#      - Add to .env: OTX_API_KEY=your_key_here
#
#   4. URLScan.io
#      - Free tier: 100 searches/hour, no key needed for search
#      - Sign up (optional) at: https://urlscan.io/user/signup
#      - Add to .env: URLSCAN_API_KEY=your_key_here (optional)
#
# ─────────────────────────────────────────────────────────────────────────────

import requests
import os
import socket


def _get_ip(domain: str) -> str:
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None


def check_virustotal(target: str, target_type: str = "domain") -> dict:
    """Query VirusTotal for domain or IP reputation."""
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not set in .env"}

    try:
        if target_type == "domain":
            url = f"https://www.virustotal.com/api/v3/domains/{target}"
        else:
            url = f"https://www.virustotal.com/api/v3/ip_addresses/{target}"

        headers = {"x-apikey": api_key}
        resp = requests.get(url, headers=headers, timeout=10)

        # FIX: don't silently treat error responses as "0 detections = CLEAN"
        if resp.status_code == 401:
            return {"error": "Invalid VirusTotal API key"}
        if resp.status_code == 404:
            return {
                "malicious": 0, "suspicious": 0, "clean": 0, "undetected": 0,
                "reputation_score": 0, "categories": [],
                "verdict": "UNKNOWN",
                "note": "Not yet indexed by VirusTotal"
            }
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit hit (4 req/min on free tier)"}
        if resp.status_code != 200:
            return {"error": f"VirusTotal returned status {resp.status_code}"}

        data = resp.json()
        stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
        reputation = data.get("data", {}).get("attributes", {}).get("reputation", 0)
        categories = data.get("data", {}).get("attributes", {}).get("categories", {})

        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "clean": stats.get("harmless", 0),
            "undetected": stats.get("undetected", 0),
            "reputation_score": reputation,
            "categories": list(categories.values())[:5],
            "verdict": "MALICIOUS" if stats.get("malicious", 0) > 2 else
                       "SUSPICIOUS" if stats.get("suspicious", 0) > 0 else "CLEAN"
        }
    except requests.exceptions.Timeout:
        return {"error": "VirusTotal request timed out"}
    except Exception as e:
        return {"error": str(e)}


def check_abuseipdb(ip: str) -> dict:
    """Check if an IP has been reported for abuse."""
    api_key = os.getenv("ABUSEIPDB_API_KEY")
    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not set in .env"}

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": api_key, "Accept": "application/json"}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": True}
        resp = requests.get(url, headers=headers, params=params, timeout=10)

        # FIX: surface real errors instead of defaulting to score 0 / CLEAN
        if resp.status_code == 401:
            return {"error": "Invalid AbuseIPDB API key"}
        if resp.status_code == 422:
            return {"error": "Invalid IP address format"}
        if resp.status_code == 429:
            return {"error": "AbuseIPDB rate limit hit"}
        if resp.status_code != 200:
            return {"error": f"AbuseIPDB returned status {resp.status_code}"}

        data = resp.json().get("data", {})

        return {
            "ip": ip,
            "abuse_score": data.get("abuseConfidenceScore", 0),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "total_reports": data.get("totalReports", 0),
            "last_reported": data.get("lastReportedAt"),
            "is_tor": data.get("isTor", False),
            "verdict": "MALICIOUS" if data.get("abuseConfidenceScore", 0) > 50 else
                       "SUSPICIOUS" if data.get("abuseConfidenceScore", 0) > 10 else "CLEAN"
        }
    except requests.exceptions.Timeout:
        return {"error": "AbuseIPDB request timed out"}
    except Exception as e:
        return {"error": str(e)}


def check_otx(target: str, target_type: str = "domain") -> dict:
    """Check AlienVault OTX threat feeds."""
    api_key = os.getenv("OTX_API_KEY")
    if not api_key:
        return {"error": "OTX_API_KEY not set in .env"}

    try:
        base = "https://otx.alienvault.com/api/v1/indicators"
        if target_type == "domain":
            url = f"{base}/domain/{target}/general"
        else:
            url = f"{base}/IPv4/{target}/general"

        headers = {"X-OTX-API-KEY": api_key}
        resp = requests.get(url, headers=headers, timeout=10)

        # FIX: surface real errors instead of defaulting to 0 pulses / CLEAN
        if resp.status_code == 403:
            return {"error": "Invalid OTX API key"}
        if resp.status_code == 404:
            return {"pulse_count": 0, "threat_tags": [], "in_threat_feeds": False, "verdict": "UNKNOWN"}
        if resp.status_code != 200:
            return {"error": f"OTX returned status {resp.status_code}"}

        data = resp.json()
        pulse_count = data.get("pulse_info", {}).get("count", 0)
        pulses = data.get("pulse_info", {}).get("pulses", [])
        tags = []
        for p in pulses[:5]:
            tags.extend(p.get("tags", []))

        return {
            "pulse_count": pulse_count,
            "threat_tags": list(set(tags))[:10],
            "in_threat_feeds": pulse_count > 0,
            "verdict": "MALICIOUS" if pulse_count > 5 else
                       "SUSPICIOUS" if pulse_count > 0 else "CLEAN"
        }
    except requests.exceptions.Timeout:
        return {"error": "OTX request timed out"}
    except Exception as e:
        return {"error": str(e)}


def check_urlscan(domain: str) -> dict:
    """Search URLScan.io for recent scans of a domain."""
    try:
        url = f"https://urlscan.io/api/v1/search/?q=domain:{domain}&size=5"
        headers = {"User-Agent": "DeepFinder/1.0"}
        api_key = os.getenv("URLSCAN_API_KEY")
        if api_key:
            headers["API-Key"] = api_key

        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code == 429:
            return {"error": "URLScan rate limit hit (100/hour on free tier)"}
        if resp.status_code != 200:
            return {"error": f"URLScan returned status {resp.status_code}"}

        data = resp.json()
        results = data.get("results", [])

        scans = []
        for r in results[:5]:
            page = r.get("page", {})
            verdicts = r.get("verdicts", {}).get("overall", {})
            scans.append({
                "url": page.get("url"),
                "ip": page.get("ip"),
                "country": page.get("country"),
                "date": r.get("task", {}).get("time"),
                "malicious": verdicts.get("malicious", False),
                "score": verdicts.get("score", 0),
                "report_url": r.get("result")
            })

        return {
            "total_scans": data.get("total", 0),
            "recent_scans": scans
        }
    except requests.exceptions.Timeout:
        return {"error": "URLScan request timed out"}
    except Exception as e:
        return {"error": str(e)}


def get_threat_intelligence(target: str, target_type: str = "domain") -> dict:
    """
    Master function — runs all threat intel checks on a domain or IP.
    target_type: "domain" or "ip"
    """
    result = {
        "target": target,
        "target_type": target_type,
        "ip": None,
        "virustotal": {},
        "abuseipdb": {},
        "otx": {},
        "urlscan": {},
        "overall_verdict": "UNKNOWN"
    }

    # Resolve IP if domain
    if target_type == "domain":
        ip = _get_ip(target)
        result["ip"] = ip
    else:
        ip = target

    result["virustotal"] = check_virustotal(target, target_type)
    result["otx"] = check_otx(target, target_type)
    result["urlscan"] = check_urlscan(target) if target_type == "domain" else {}

    if ip:
        result["abuseipdb"] = check_abuseipdb(ip)
    else:
        # FIX: don't leave this as an empty dict — domain didn't resolve
        result["abuseipdb"] = {"error": "Could not resolve an IP address for this domain"}

    # Aggregate verdict
    verdicts = [
        result["virustotal"].get("verdict"),
        result["abuseipdb"].get("verdict"),
        result["otx"].get("verdict")
    ]
    valid_verdicts = [v for v in verdicts if v]

    if "MALICIOUS" in valid_verdicts:
        result["overall_verdict"] = "MALICIOUS"
    elif "SUSPICIOUS" in valid_verdicts:
        result["overall_verdict"] = "SUSPICIOUS"
    elif valid_verdicts and all(v == "CLEAN" for v in valid_verdicts):
        # FIX: only call it CLEAN if at least one check actually ran
        result["overall_verdict"] = "CLEAN"
    else:
        result["overall_verdict"] = "UNKNOWN"

    return result