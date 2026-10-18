# ─────────────────────────────────────────────────────────────────────────────
# company_lookup.py — Company / Organization OSINT
# ─────────────────────────────────────────────────────────────────────────────
#
# API USED (free):
#   AbstractAPI — Company Enrichment API
#      - Free tier: 100 requests total (not monthly), 1 request/second
#      - Sign up at: https://app.abstractapi.com/users/signup?target=/api/company-enrichment/pricing/select
#      - No credit card required
#      - Add to .env: ABSTRACT_COMPANY_API_KEY=your_key_here
#      - Used for: company profile, logo, industry, employee count,
#        location, social links, public emails/phone numbers
#
#   NOTE: This replaces Hunter.io + Clearbit Logo API (the latter was
#   permanently shut down in Dec 2025). AbstractAPI returns a logo URL
#   directly, so no separate logo provider is needed.
#
# ─────────────────────────────────────────────────────────────────────────────

import requests
import os

ABSTRACT_BASE_URL = "https://companyenrichment.abstractapi.com/v2"


def lookup_company(domain: str) -> dict:
    """
    Aggregates public company information from AbstractAPI's
    Company Enrichment API.
    """

    result = {
        "domain": domain,
        "company_name": None,
        "description": None,
        "industry": None,
        "employee_count": None,
        "country": None,
        "state": None,
        "city": None,
        "logo_url": None,
        "social_links": {},
        "emails_found": [],
        "email_pattern": None,
        "technologies": [],
        "source": [],
        "error": None
    }

    api_key = os.getenv("ABSTRACT_COMPANY_API_KEY")
    if not api_key:
        result["error"] = "ABSTRACT_COMPANY_API_KEY not set in .env — add it to enable company enrichment"
        return result

    try:
        resp = requests.get(
            ABSTRACT_BASE_URL,
            params={"api_key": api_key, "domain": domain},
            timeout=10
        )

        # AbstractAPI free-tier specific status codes
        if resp.status_code == 401:
            result["error"] = "AbstractAPI error: invalid or missing API key"
            return result
        if resp.status_code == 422:
            result["error"] = "AbstractAPI error: free-tier quota reached (100 request limit)"
            return result
        if resp.status_code == 429:
            result["error"] = "AbstractAPI error: rate limited (max 1 request/second on free tier)"
            return result

        data = resp.json()

        result["company_name"]   = data.get("company_name")
        result["description"]    = data.get("description")
        result["industry"]       = data.get("industry")
        result["employee_count"] = data.get("employee_count") or data.get("employee_range")
        result["country"]        = data.get("country")
        result["state"]          = data.get("state")
        result["city"]           = data.get("city")
        result["logo_url"]       = data.get("logo")
        result["technologies"]   = data.get("technologies", [])

        # Social links
        linkedin  = data.get("linkedin_url")
        facebook  = data.get("facebook_url")
        twitter   = data.get("twitter_url")
        instagram = data.get("instagram_url")
        if linkedin:  result["social_links"]["linkedin"]  = linkedin
        if facebook:  result["social_links"]["facebook"]  = facebook
        if twitter:   result["social_links"]["twitter"]   = twitter
        if instagram: result["social_links"]["instagram"] = instagram

        # Public contact emails (AbstractAPI returns generic company emails,
        # not per-employee emails like Hunter did)
        emails = data.get("email_addresses", [])
        result["emails_found"] = [{"value": e, "type": "generic"} for e in emails]
        if emails:
            # crude pattern guess from the first generic email found
            local_part = emails[0].split("@")[0]
            result["email_pattern"] = f"{local_part}@{domain}"

        result["source"].append("AbstractAPI")

    except requests.exceptions.Timeout:
        result["error"] = "AbstractAPI error: request timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = f"AbstractAPI error: {str(e)}"
    except ValueError:
        result["error"] = "AbstractAPI error: invalid JSON response"

    return result