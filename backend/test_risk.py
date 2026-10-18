from modules.risk import calculate_risk
import json

# Test avec des données simulées
whois = {'expiration_date': 'N/A'}
dns = {'MX': [], 'TXT': []}
ports = {'open_ports': [{'port': 22, 'service': 'ssh'}, {'port': 3306, 'service': 'mysql'}]}
headers = {'missing_count': 4}
tech = {}

result = calculate_risk(whois, dns, ports, headers, tech)
print(json.dumps(result, indent=2))