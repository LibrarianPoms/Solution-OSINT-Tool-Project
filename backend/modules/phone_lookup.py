# ─────────────────────────────────────────────────────────────────────────────
# phone_lookup.py — Phone Number OSINT (validation / carrier / region only)
# ─────────────────────────────────────────────────────────────────────────────
#
# API USED (free):
#   AbstractAPI — Phone Intelligence API
#      - Free tier available, some fields (carrier name, line_type,
#        risk signals) may come back empty/"unknown" unless upgraded —
#        this is an AbstractAPI free-tier limit, not a bug here.
#      - Sign up / dashboard: https://app.abstractapi.com
#      - Add to .env: ABSTRACTAPI_PHONE_KEY=your_key_here
#      - NOTE: this key is separate from the Company Enrichment key —
#        each AbstractAPI product issues its own key, even on one account.
#
#   SCOPE NOTE: this module deliberately does NOT attempt reverse lookup
#   (resolving a number to a person's name/address). That data sits
#   behind paid people-search providers with restrictive ToS, or isn't
#   legally/freely available at all. This module only returns what's
#   publicly and legitimately derivable from the number itself: validity,
#   format, country, region, carrier, and line type.
#
# ─────────────────────────────────────────────────────────────────────────────

import requests
import os

ABSTRACT_PHONE_URL = "https://phoneintelligence.abstractapi.com/v1/"


def lookup_phone(phone_number: str) -> dict:
    """
    Validates a phone number and returns publicly derivable format/carrier/
    region info via AbstractAPI's Phone Intelligence endpoint. Does not
    attempt to resolve owner identity.
    """

    # Clean input — remove spaces, dashes, parentheses
    cleaned = phone_number.replace(" ", "").replace("-", "").replace("(", "").replace(")", "")
    if cleaned.startswith("+"):
        cleaned = cleaned[1:]  # this endpoint expects digits only, no leading +

    result = {
        "input": phone_number,
        "cleaned": cleaned,
        "valid": None,
        "line_status": None,     # active / disconnected / unknown
        "is_voip": None,
        "minimum_age": None,
        "risk_level": None,      # low / medium / high (network risk, not identity)
        "is_disposable": None,
        "is_abuse_detected": None,
        "country": None,
        "country_code": None,
        "country_prefix": None,
        "region": None,
        "city": None,
        "timezone": None,
        "carrier": None,
        "line_type": None,       # mobile / landline / voip / unknown
        "mcc": None,
        "mnc": None,
        "sms_domain": None,
        "sms_email": None,
        "location": None,        # kept for backwards-compat with older UI rows
        "international_format": None,
        "local_format": None,
        "source": None,
        "error": None
        # NOTE: deliberately not exposing AbstractAPI's "phone_registration"
        # (owner name) or "phone_breaches" fields, even though the raw API
        # may return them on higher tiers. Surfacing a name tied to a phone
        # number is reverse-lookup/people-search territory, which this
        # project intentionally does not do — see module docstring.
    }

    api_key = os.getenv("ABSTRACTAPI_PHONE_KEY")
    if not api_key:
        result["error"] = "ABSTRACTAPI_PHONE_KEY not set in .env — add it to enable phone lookup"
        return result

    try:
        resp = requests.get(
            ABSTRACT_PHONE_URL,
            params={"api_key": api_key, "phone": cleaned},
            timeout=10
        )

        if resp.status_code == 401:
            result["error"] = "AbstractAPI error: invalid or missing API key"
            return result
        if resp.status_code == 422:
            result["error"] = "AbstractAPI error: free-tier quota reached"
            return result
        if resp.status_code == 429:
            result["error"] = "AbstractAPI error: rate limited (free tier allows limited req/sec)"
            return result
        if resp.status_code != 200:
            result["error"] = f"AbstractAPI error: unexpected status {resp.status_code}"
            return result

        data = resp.json()

        phone_format    = data.get("phone_format") or {}
        phone_carrier   = data.get("phone_carrier") or {}
        phone_location  = data.get("phone_location") or {}
        phone_messaging = data.get("phone_messaging") or {}
        phone_valid     = data.get("phone_validation") or {}
        phone_risk      = data.get("phone_risk") or {}
        # phone_registration and phone_breaches are intentionally never
        # read here — see NOTE in the result dict above.

        # carrier name / line_type can legitimately come back "" or "unknown"
        # on the free tier — normalize empty string to None for consistency
        carrier_name = phone_carrier.get("name") or None
        line_type    = phone_carrier.get("line_type")
        if line_type in (None, "", "unknown"):
            line_type = "unknown"

        line_status = phone_valid.get("line_status")
        if line_status in (None, ""):
            line_status = "unknown"

        def _clean(v):
            # normalize "" / "unknown" string sentinels to None for consistency
            return None if v in (None, "", "unknown") else v

        city   = _clean(phone_location.get("city"))
        region = _clean(phone_location.get("region"))

        result.update({
            "valid": phone_valid.get("is_valid"),
            "line_status": line_status,
            "is_voip": phone_valid.get("is_voip"),
            "minimum_age": phone_valid.get("minimum_age"),
            "risk_level": phone_risk.get("risk_level"),
            "is_disposable": phone_risk.get("is_disposable"),
            "is_abuse_detected": phone_risk.get("is_abuse_detected"),
            "country": phone_location.get("country_name"),
            "country_code": phone_location.get("country_code"),
            "country_prefix": phone_location.get("country_prefix"),
            "region": region,
            "city": city,
            "timezone": phone_location.get("timezone"),
            "carrier": carrier_name,
            "line_type": line_type,
            "mcc": _clean(phone_carrier.get("mcc")),
            "mnc": _clean(phone_carrier.get("mnc")),
            "sms_domain": _clean(phone_messaging.get("sms_domain")),
            "sms_email": _clean(phone_messaging.get("sms_email")),
            "location": city or region,  # backwards-compat single field
            "international_format": phone_format.get("international"),
            "local_format": phone_format.get("national"),
            "source": "AbstractAPI"
        })

    except requests.exceptions.Timeout:
        result["error"] = "AbstractAPI error: request timed out"
    except requests.exceptions.RequestException as e:
        result["error"] = f"AbstractAPI error: {str(e)}"
    except ValueError:
        result["error"] = "AbstractAPI error: invalid JSON response"

    return result