import whois

def get_whois(domain):
    try:
        w = whois.whois(domain)
        return {
            "domain_name": str(w.domain_name) if w.domain_name else "N/A",
            "registrar": str(w.registrar) if w.registrar else "N/A",
            "creation_date": str(w.creation_date) if w.creation_date else "N/A",
            "expiration_date": str(w.expiration_date) if w.expiration_date else "N/A",
            "country": str(w.country) if w.country else "N/A",
            "emails": str(w.emails) if w.emails else "N/A",
        }
    except Exception as e:
        return {"error": str(e)}