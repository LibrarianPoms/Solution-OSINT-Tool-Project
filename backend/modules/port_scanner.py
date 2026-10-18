import shodan
import socket
import os
from dotenv import load_dotenv

load_dotenv()

def scan_ports(domain):
    try:
        # Résoudre le domaine en adresse IP
        ip = socket.gethostbyname(domain)

        api_key = os.getenv("SHODAN_API_KEY")
        api = shodan.Shodan(api_key)

        # Chercher par IP (gratuit)
        host = api.host(ip)

        open_ports = []
        for item in host.get('data', []):
            open_ports.append({
                "port": item['port'],
                "service": item.get('_shodan', {}).get('module', 'unknown'),
                "ip": ip
            })

        return {
            "ip": ip,
            "open_ports": open_ports,
            "total": len(open_ports)
        }

    except Exception as e:
        return {"error": str(e)}