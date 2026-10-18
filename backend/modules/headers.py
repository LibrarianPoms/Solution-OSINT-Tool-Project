import requests

def get_headers(domain):
    try:
        url = f"https://{domain}"
        response = requests.get(url, timeout=10, allow_redirects=True)
        headers = dict(response.headers)

        # En-têtes de sécurité à vérifier
        security_headers = {
            "Strict-Transport-Security": "Protège contre les attaques HTTP",
            "Content-Security-Policy": "Protège contre les attaques XSS",
            "X-Frame-Options": "Protège contre le clickjacking",
            "X-Content-Type-Options": "Protège contre le MIME sniffing",
            "Referrer-Policy": "Contrôle les infos de référence",
            "Permissions-Policy": "Contrôle les permissions du navigateur",
        }

        present = {}
        missing = {}

        for header, description in security_headers.items():
            if header in headers:
                present[header] = {
                    "value": headers[header],
                    "description": description
                }
            else:
                missing[header] = {
                    "description": description
                }

        return {
            "url": url,
            "status_code": response.status_code,
            "server": headers.get("Server", "N/A"),
            "security_headers_present": present,
            "security_headers_missing": missing,
            "missing_count": len(missing),
            "present_count": len(present)
        }

    except Exception as e:
        return {"error": str(e)}