import requests
import socket

def get_geolocation(domain):
    try:
        # Résoudre le domaine en IP
        try:
            ip = socket.gethostbyname(domain)
        except socket.gaierror:
            return {"error": f"Could not resolve domain: {domain}"}

        # Appel à ip-api.com (gratuit, sans clé API)
        response = requests.get(f"http://ip-api.com/json/{ip}", timeout=10)
        data = response.json()

        if data['status'] == 'success':
            return {
                "ip": ip,
                "country": data.get('country', 'N/A'),
                "country_code": data.get('countryCode', 'N/A'),
                "region": data.get('regionName', 'N/A'),
                "city": data.get('city', 'N/A'),
                "isp": data.get('isp', 'N/A'),
                "org": data.get('org', 'N/A'),
                "lat": data.get('lat', 'N/A'),
                "lon": data.get('lon', 'N/A'),
            }
        else:
            return {"error": "Géolocalisation échouée", "ip": ip}

    except Exception as e:
        return {"error": str(e)}