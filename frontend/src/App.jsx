
import os
import json
import sqlite3
import socket
import datetime
import threading
import concurrent.futures
from flask import Flask, request, jsonify
from flask_cors import CORS

# ─────────────────────────────────────────────
#  Chargement optionnel des dépendances OSINT
# ─────────────────────────────────────────────
try:
    import whois as python_whois
    WHOIS_AVAILABLE = True
except ImportError:
    WHOIS_AVAILABLE = False
    print("[WARN] python-whois non installé — module WHOIS désactivé")

try:
    import dns.resolver
    import dns.exception
    DNS_AVAILABLE = True
except ImportError:
    DNS_AVAILABLE = False
    print("[WARN] dnspython non installé — module DNS désactivé")

try:
    import requests as http_requests
    REQUESTS_AVAILABLE = True
except ImportError:
    REQUESTS_AVAILABLE = False
    print("[WARN] requests non installé — modules HTTP désactivés")

try:
    import nmap
    NMAP_AVAILABLE = True
except ImportError:
    NMAP_AVAILABLE = False
    print("[WARN] python-nmap non installé — module scan de ports désactivé")

try:
    import builtwith
    BUILTWITH_AVAILABLE = True
except ImportError:
    BUILTWITH_AVAILABLE = False
    print("[WARN] builtwith non installé — module empreinte tech désactivé")

# ─────────────────────────────────────────────
#  Configuration Flask
# ─────────────────────────────────────────────
app = Flask(__name__)
CORS(app)

DATABASE = "osint_history.db"

# Clés API (à définir dans .env ou variables d'environnement)
SECURITYTRAILS_API_KEY = os.environ.get("SECURITYTRAILS_API_KEY", "")
SHODAN_API_KEY         = os.environ.get("SHODAN_API_KEY", "")
CLAUDE_API_KEY         = os.environ.get("CLAUDE_API_KEY", "")


# ─────────────────────────────────────────────
#  Base de données SQLite
# ─────────────────────────────────────────────
def init_db():
    """Initialise la base de données SQLite."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("""
        CREATE TABLE IF NOT EXISTS analyses (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            domain    TEXT NOT NULL,
            timestamp TEXT NOT NULL,
            results   TEXT NOT NULL,
            risk_score INTEGER DEFAULT 0
        )
    """)
    conn.commit()
    conn.close()

def save_analysis(domain: str, results: dict, risk_score: int):
    """Sauvegarde une analyse dans SQLite."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute(
        "INSERT INTO analyses (domain, timestamp, results, risk_score) VALUES (?, ?, ?, ?)",
        (domain, datetime.datetime.utcnow().isoformat(), json.dumps(results), risk_score)
    )
    conn.commit()
    conn.close()

def get_history():
    """Récupère l'historique complet des analyses."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id, domain, timestamp, risk_score FROM analyses ORDER BY id DESC LIMIT 50")
    rows = c.fetchall()
    conn.close()
    return [{"id": r[0], "domain": r[1], "timestamp": r[2], "risk_score": r[3]} for r in rows]

def get_analysis_by_id(analysis_id: int):
    """Récupère une analyse complète par ID."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT id, domain, timestamp, results, risk_score FROM analyses WHERE id = ?", (analysis_id,))
    row = c.fetchone()
    conn.close()
    if row:
        return {"id": row[0], "domain": row[1], "timestamp": row[2], "results": json.loads(row[3]), "risk_score": row[4]}
    return None


# ─────────────────────────────────────────────
#  Modules OSINT
# ─────────────────────────────────────────────

def module_whois(domain: str) -> dict:
    """Module WHOIS : propriétaire, registrar, dates."""
    if not WHOIS_AVAILABLE:
        return {"status": "unavailable", "error": "python-whois non installé"}
    try:
        w = python_whois.whois(domain)
        creation = w.creation_date
        expiration = w.expiration_date
        updated = w.updated_date

        def fmt(d):
            if isinstance(d, list): d = d[0]
            return d.isoformat() if hasattr(d, "isoformat") else str(d) if d else None

        return {
            "status": "success",
            "registrar":       w.registrar,
            "registrant_name": w.name,
            "registrant_org":  w.org,
            "registrant_email": w.emails[0] if isinstance(w.emails, list) and w.emails else w.emails,
            "creation_date":   fmt(creation),
            "expiration_date": fmt(expiration),
            "updated_date":    fmt(updated),
            "name_servers":    list(w.name_servers) if w.name_servers else [],
            "status_flags":    list(w.status) if isinstance(w.status, list) else [w.status] if w.status else [],
        }
    except Exception as e:
        return {"status": "error", "error": str(e)}


def module_dns(domain: str) -> dict:
    """Module DNS : tous les enregistrements majeurs."""
    if not DNS_AVAILABLE:
        return {"status": "unavailable", "error": "dnspython non installé"}

    results = {"status": "success"}
    record_types = ["A", "AAAA", "MX", "TXT", "NS", "CNAME", "SOA", "CAA"]

    for rtype in record_types:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            results[rtype] = [str(r) for r in answers]
        except (dns.exception.DNSException, Exception):
            results[rtype] = []

    # Vérification DNSSEC (présence de DNSKEY)
    try:
        dns.resolver.resolve(domain, "DNSKEY", lifetime=5)
        results["dnssec"] = True
    except Exception:
        results["dnssec"] = False

    return results


def module_subdomains(domain: str) -> dict:
    """Module découverte de sous-domaines via SecurityTrails ou liste intégrée."""
    found = []

    # Tentative via SecurityTrails
    if SECURITYTRAILS_API_KEY and REQUESTS_AVAILABLE:
        try:
            url = f"https://api.securitytrails.com/v1/domain/{domain}/subdomains"
            headers = {"APIKEY": SECURITYTRAILS_API_KEY}
            resp = http_requests.get(url, headers=headers, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                subdomains_raw = data.get("subdomains", [])
                for sub in subdomains_raw[:50]:
                    subdomain = f"{sub}.{domain}"
                    try:
                        ip = socket.gethostbyname(subdomain)
                        found.append({"subdomain": subdomain, "ip": ip, "status": "active"})
                    except socket.gaierror:
                        found.append({"subdomain": subdomain, "ip": None, "status": "unresolvable"})
                return {"status": "success", "source": "securitytrails", "subdomains": found}
        except Exception as e:
            pass  # fallback vers brute-force

    # Fallback : liste de sous-domaines communs
    common_subs = [
        "www", "mail", "ftp", "remote", "blog", "webmail", "server",
        "ns1", "ns2", "smtp", "secure", "vpn", "m", "shop", "api",
        "dev", "staging", "test", "admin", "portal", "cdn", "app",
        "support", "docs", "status", "login", "auth"
    ]
    for sub in common_subs:
        subdomain = f"{sub}.{domain}"
        try:
            ip = socket.gethostbyname(subdomain)
            found.append({"subdomain": subdomain, "ip": ip, "status": "active"})
        except socket.gaierror:
            pass

    return {"status": "success", "source": "bruteforce", "subdomains": found}


def module_port_scan(domain: str) -> dict:
    """Module scan de ports via Nmap ou Shodan."""
    # Tentative via Shodan
    if SHODAN_API_KEY and REQUESTS_AVAILABLE:
        try:
            ip = socket.gethostbyname(domain)
            url = f"https://api.shodan.io/shodan/host/{ip}?key={SHODAN_API_KEY}"
            resp = http_requests.get(url, timeout=10)
            if resp.status_code == 200:
                data = resp.json()
                ports = []
                for item in data.get("data", []):
                    ports.append({
                        "port":     item.get("port"),
                        "protocol": item.get("transport", "tcp"),
                        "service":  item.get("_shodan", {}).get("module", "unknown"),
                        "banner":   item.get("data", "")[:200],
                        "state":    "open"
                    })
                return {
                    "status": "success",
                    "source": "shodan",
                    "ip": ip,
                    "org": data.get("org", ""),
                    "os": data.get("os", ""),
                    "ports": ports,
                    "vulns": list(data.get("vulns", {}).keys())
                }
        except Exception:
            pass

    # Fallback : Nmap sur ports courants
    if NMAP_AVAILABLE:
        try:
            ip = socket.gethostbyname(domain)
            nm = nmap.PortScanner()
            nm.scan(ip, "21-25,53,80,110,143,443,445,3306,3389,5432,6379,8080,8443,8888,27017",
                    arguments="-T4 --open")
            ports = []
            for host in nm.all_hosts():
                for proto in nm[host].all_protocols():
                    for port, data in nm[host][proto].items():
                        if data["state"] == "open":
                            ports.append({
                                "port":     port,
                                "protocol": proto,
                                "service":  data.get("name", "unknown"),
                                "version":  data.get("version", ""),
                                "state":    "open"
                            })
            return {"status": "success", "source": "nmap", "ip": ip, "ports": ports}
        except Exception as e:
            return {"status": "error", "error": str(e)}

    # Fallback minimal : socket connect sur ports critiques
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        return {"status": "error", "error": "Impossible de résoudre le domaine"}

    critical_ports = {80: "http", 443: "https", 22: "ssh", 21: "ftp",
                      25: "smtp", 3306: "mysql", 5432: "postgres", 6379: "redis",
                      27017: "mongodb", 3389: "rdp", 8080: "http-alt", 8443: "https-alt"}
    open_ports = []
    for port, service in critical_ports.items():
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1)
            result = sock.connect_ex((ip, port))
            sock.close()
            if result == 0:
                open_ports.append({"port": port, "protocol": "tcp", "service": service, "state": "open"})
        except Exception:
            pass

    return {"status": "success", "source": "socket", "ip": ip, "ports": open_ports}


def module_tech_fingerprint(domain: str) -> dict:
    """Module empreinte technologique via builtwith ou analyse des en-têtes."""
    technologies = {}

    if BUILTWITH_AVAILABLE:
        try:
            info = builtwith.parse(f"https://{domain}")
            technologies = {k: v for k, v in info.items() if v}
        except Exception:
            pass

    # Complément via en-têtes HTTP
    if REQUESTS_AVAILABLE:
        for scheme in ["https", "http"]:
            try:
                resp = http_requests.get(f"{scheme}://{domain}", timeout=8,
                                         headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
                server  = resp.headers.get("Server", "")
                powered = resp.headers.get("X-Powered-By", "")
                via     = resp.headers.get("Via", "")
                generator = ""
                if "wp-content" in resp.text or "wordpress" in resp.text.lower():
                    generator = "WordPress"
                elif "drupal" in resp.text.lower():
                    generator = "Drupal"
                elif "joomla" in resp.text.lower():
                    generator = "Joomla"

                technologies.update({k: v for k, v in {
                    "server": server,
                    "x_powered_by": powered,
                    "via": via,
                    "cms": generator,
                }.items() if v})
                break
            except Exception:
                continue

    return {"status": "success", "technologies": technologies}


def module_http_headers(domain: str) -> dict:
    """Analyse des en-têtes de sécurité HTTP."""
    if not REQUESTS_AVAILABLE:
        return {"status": "unavailable", "error": "requests non installé"}

    security_headers = [
        "Strict-Transport-Security",
        "Content-Security-Policy",
        "X-Frame-Options",
        "X-Content-Type-Options",
        "Referrer-Policy",
        "Permissions-Policy",
        "X-XSS-Protection",
        "Access-Control-Allow-Origin",
    ]

    for scheme in ["https", "http"]:
        try:
            resp = http_requests.get(f"{scheme}://{domain}", timeout=8,
                                     headers={"User-Agent": "Mozilla/5.0"}, allow_redirects=True)
            present = {}
            missing = []
            for header in security_headers:
                val = resp.headers.get(header)
                if val:
                    present[header] = val
                else:
                    missing.append(header)

            return {
                "status":       "success",
                "scheme_used":  scheme,
                "status_code":  resp.status_code,
                "present":      present,
                "missing":      missing,
                "https_forced": scheme == "https" or resp.url.startswith("https"),
                "cookies":      [
                    {
                        "name":     c.name,
                        "secure":   c.secure,
                        "httponly": c.has_nonstandard_attr("HttpOnly"),
                        "samesite": c.get_nonstandard_attr("SameSite", ""),
                    }
                    for c in resp.cookies
                ]
            }
        except Exception:
            continue

    return {"status": "error", "error": "Impossible de joindre le domaine"}


def module_geolocation(domain: str) -> dict:
    """Module géolocalisation IP via ip-api.com."""
    if not REQUESTS_AVAILABLE:
        return {"status": "unavailable", "error": "requests non installé"}
    try:
        ip = socket.gethostbyname(domain)
        resp = http_requests.get(f"http://ip-api.com/json/{ip}?fields=66846719", timeout=8)
        if resp.status_code == 200:
            data = resp.json()
            return {
                "status":      "success",
                "ip":          ip,
                "country":     data.get("country"),
                "country_code":data.get("countryCode"),
                "region":      data.get("regionName"),
                "city":        data.get("city"),
                "isp":         data.get("isp"),
                "org":         data.get("org"),
                "as":          data.get("as"),
                "hosting":     data.get("hosting", False),
                "proxy":       data.get("proxy", False),
                "lat":         data.get("lat"),
                "lon":         data.get("lon"),
            }
    except Exception as e:
        return {"status": "error", "error": str(e)}
    return {"status": "error", "error": "Réponse invalide de ip-api.com"}


# ─────────────────────────────────────────────
#  Calcul du score de risque
# ─────────────────────────────────────────────

def compute_risk_score(results: dict) -> dict:
    """
    Calcule un score de risque global (0–100) basé sur tous les modules.
    Retourne le score et la liste des facteurs détectés.
    """
    score   = 0
    factors = []

    # ── Ports dangereux exposés
    dangerous_ports = {21: "FTP", 23: "Telnet", 3306: "MySQL", 5432: "PostgreSQL",
                       6379: "Redis", 27017: "MongoDB", 3389: "RDP", 445: "SMB"}
    ports_data = results.get("port_scan", {}).get("ports", [])
    for p in ports_data:
        if p["port"] in dangerous_ports:
            score += 15
            factors.append(f"Port sensible ouvert : {dangerous_ports[p['port']]} ({p['port']})")

    # ── En-têtes de sécurité manquants
    missing_headers = results.get("http_headers", {}).get("missing", [])
    critical_missing = ["Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"]
    for h in critical_missing:
        if h in missing_headers:
            score += 8
            factors.append(f"En-tête de sécurité manquant : {h}")

    # ── Pas de HTTPS
    if not results.get("http_headers", {}).get("https_forced", True):
        score += 10
        factors.append("HTTPS non forcé — trafic HTTP en clair possible")

    # ── Cookies non sécurisés
    cookies = results.get("http_headers", {}).get("cookies", [])
    for c in cookies:
        if not c.get("secure"):
            score += 5
            factors.append(f"Cookie non sécurisé : {c['name']}")
            break

    # ── Sous-domaines actifs exposés
    subdomains = results.get("subdomains", {}).get("subdomains", [])
    active = [s for s in subdomains if s.get("status") == "active"]
    if len(active) > 10:
        score += 10
        factors.append(f"{len(active)} sous-domaines actifs exposés")
    elif len(active) > 4:
        score += 5
        factors.append(f"{len(active)} sous-domaines actifs détectés")

    # ── DNSSEC absent
    if not results.get("dns", {}).get("dnssec", True):
        score += 5
        factors.append("DNSSEC non activé")

    # ── Domaine expire bientôt
    exp_str = results.get("whois", {}).get("expiration_date")
    if exp_str:
        try:
            exp = datetime.datetime.fromisoformat(exp_str)
            days_left = (exp - datetime.datetime.utcnow()).days
            if days_left < 30:
                score += 15
                factors.append(f"Domaine expire dans {days_left} jours !")
            elif days_left < 90:
                score += 5
                factors.append(f"Domaine expire dans {days_left} jours")
        except Exception:
            pass

    # ── Vulnérabilités Shodan
    vulns = results.get("port_scan", {}).get("vulns", [])
    if vulns:
        score += min(len(vulns) * 10, 30)
        factors.append(f"{len(vulns)} CVE référencés par Shodan : {', '.join(vulns[:3])}")

    score = min(score, 100)

    if score >= 70:
        level = "CRITIQUE"
        color = "#ef4444"
    elif score >= 45:
        level = "ÉLEVÉ"
        color = "#f97316"
    elif score >= 20:
        level = "MODÉRÉ"
        color = "#eab308"
    else:
        level = "FAIBLE"
        color = "#22c55e"

    return {"score": score, "level": level, "color": color, "factors": factors}


# ─────────────────────────────────────────────
#  Synthèse IA via Claude API
# ─────────────────────────────────────────────

def module_ai_synthesis(domain: str, results: dict, risk: dict) -> dict:
    """Génère une synthèse de la surface d'attaque via l'API Claude."""
    if not CLAUDE_API_KEY or not REQUESTS_AVAILABLE:
        return {"status": "unavailable", "summary": "Clé API Claude non configurée."}

    # Préparer un résumé compact pour le prompt
    open_ports    = [p["port"] for p in results.get("port_scan", {}).get("ports", [])]
    subdomains_ct = len([s for s in results.get("subdomains", {}).get("subdomains", [])
                         if s.get("status") == "active"])
    missing_hdrs  = results.get("http_headers", {}).get("missing", [])
    tech          = results.get("tech_fingerprint", {}).get("technologies", {})

    prompt = f"""Tu es un expert en cybersécurité offensive (Red Team). Analyse la surface d'attaque suivante pour le domaine {domain} et génère une synthèse concise en français (300 mots max).

Données collectées :
- Score de risque : {risk['score']}/100 ({risk['level']})
- Ports ouverts : {open_ports}
- Sous-domaines actifs : {subdomains_ct}
- En-têtes de sécurité manquants : {missing_hdrs}
- Technologies détectées : {list(tech.values())[:5]}
- Facteurs de risque : {risk['factors']}

Structure ta réponse en 3 parties :
1. **Résumé de l'exposition** (2-3 phrases)
2. **Vecteurs d'attaque prioritaires** (liste de 3 max)
3. **Recommandations immédiates** (liste de 3 max)

Sois précis, factuel et actionnable."""

    try:
        resp = http_requests.post(
            "https://api.anthropic.com/v1/messages",
            headers={
                "x-api-key":         CLAUDE_API_KEY,
                "anthropic-version": "2023-06-01",
                "Content-Type":      "application/json"
            },
            json={
                "model":      "claude-opus-4-5",
                "max_tokens": 600,
                "messages":   [{"role": "user", "content": prompt}]
            },
            timeout=30
        )
        if resp.status_code == 200:
            text = resp.json()["content"][0]["text"]
            return {"status": "success", "summary": text}
        else:
            return {"status": "error", "summary": f"Erreur API : {resp.status_code}"}
    except Exception as e:
        return {"status": "error", "summary": str(e)}


# ─────────────────────────────────────────────
#  Routes Flask
# ─────────────────────────────────────────────

@app.route("/api/health", methods=["GET"])
def health():
    """Endpoint de vérification du serveur."""
    return jsonify({
        "status": "ok",
        "modules": {
            "whois":    WHOIS_AVAILABLE,
            "dns":      DNS_AVAILABLE,
            "requests": REQUESTS_AVAILABLE,
            "nmap":     NMAP_AVAILABLE,
            "builtwith":BUILTWITH_AVAILABLE,
            "shodan":   bool(SHODAN_API_KEY),
            "securitytrails": bool(SECURITYTRAILS_API_KEY),
            "claude":   bool(CLAUDE_API_KEY),
        }
    })


@app.route("/api/analyze", methods=["POST"])
def analyze():
    """Lance une analyse OSINT complète sur un domaine."""
    data = request.get_json()
    if not data or not data.get("domain"):
        return jsonify({"error": "Paramètre 'domain' manquant"}), 400

    domain = data["domain"].strip().lower()
    # Nettoyer le domaine (supprimer http/https/www si présents)
    domain = domain.replace("https://", "").replace("http://", "").split("/")[0]

    # Validation basique
    if len(domain) < 4 or "." not in domain:
        return jsonify({"error": "Domaine invalide"}), 400

    results = {}

    # Exécution parallèle des modules OSINT
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            "whois":           executor.submit(module_whois, domain),
            "dns":             executor.submit(module_dns, domain),
            "subdomains":      executor.submit(module_subdomains, domain),
            "port_scan":       executor.submit(module_port_scan, domain),
            "tech_fingerprint":executor.submit(module_tech_fingerprint, domain),
            "http_headers":    executor.submit(module_http_headers, domain),
            "geolocation":     executor.submit(module_geolocation, domain),
        }
        for key, future in futures.items():
            try:
                results[key] = future.result(timeout=25)
            except concurrent.futures.TimeoutError:
                results[key] = {"status": "timeout", "error": "Module trop lent (>25s)"}
            except Exception as e:
                results[key] = {"status": "error", "error": str(e)}

    # Calcul du score de risque
    risk = compute_risk_score(results)
    results["risk_score"] = risk

    # Synthèse IA (uniquement si clé configurée)
    if CLAUDE_API_KEY:
        results["ai_synthesis"] = module_ai_synthesis(domain, results, risk)

    # Sauvegarde en base
    save_analysis(domain, results, risk["score"])

    return jsonify({
        "domain":  domain,
        "results": results,
        "risk":    risk,
    })


@app.route("/api/history", methods=["GET"])
def history():
    """Retourne la liste des analyses récentes."""
    return jsonify(get_history())


@app.route("/api/history/<int:analysis_id>", methods=["GET"])
def history_detail(analysis_id):
    """Retourne le détail complet d'une analyse par ID."""
    item = get_analysis_by_id(analysis_id)
    if not item:
        return jsonify({"error": "Analyse introuvable"}), 404
    return jsonify(item)


@app.route("/api/history/<int:analysis_id>", methods=["DELETE"])
def delete_analysis(analysis_id):
    """Supprime une analyse de l'historique."""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("DELETE FROM analyses WHERE id = ?", (analysis_id,))
    conn.commit()
    conn.close()
    return jsonify({"status": "deleted", "id": analysis_id})


# ─────────────────────────────────────────────
#  Point d'entrée
# ─────────────────────────────────────────────
if __name__ == "__main__":
    init_db()
    print("─" * 50)
    print("  CDC OSINT Tool — Backend Flask")
    print("  http://localhost:5000")
    print("─" * 50)
    app.run(debug=True, host="0.0.0.0", port=5000)