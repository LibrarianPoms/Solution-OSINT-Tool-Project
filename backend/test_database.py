from database import init_db, save_scan, get_all_scans, get_scan_by_id
import json

# Initialiser la base de données
init_db()
print("✅ Base de données créée !")

# Sauvegarder un scan test
scan_id = save_scan(
    domain="example.com",
    whois={"registrar": "IANA"},
    dns={"A": ["93.184.216.34"]},
    ports={"open_ports": [{"port": 80, "service": "http"}]},
    headers={"missing_count": 3},
    tech={"cdn": ["Cloudflare"]},
    geo={"country": "United States", "city": "Norwell"},
    risk={"score": 8, "level": "MEDIUM"}
)
print(f"✅ Scan sauvegardé avec l'ID : {scan_id}")

# Récupérer tous les scans
scans = get_all_scans()
print(f"✅ Nombre de scans en base : {len(scans)}")
print(json.dumps(scans, indent=2))