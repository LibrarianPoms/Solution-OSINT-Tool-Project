from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
import ipaddress
import traceback

from modules.phone_lookup import lookup_phone
from modules.social_lookup import lookup_username
from modules.company_lookup import lookup_company
from modules.whois_lookup import get_whois
from modules.dns_lookup import get_dns
from modules.port_scanner import scan_ports
from modules.headers import get_headers
from modules.tech_detector import get_technologies
from modules.geo_lookup import get_geolocation
from modules.risk import calculate_risk
from modules.threat_intel import get_threat_intelligence
from modules.file_metadata import get_file_metadata
from database import init_db, save_scan, get_all_scans, get_scan_by_id

load_dotenv()

app = Flask(__name__)
CORS(app)
init_db()


# =========================
# GLOBAL ERROR HANDLER
# =========================
# Without this, any unhandled exception in a route returns Flask's HTML
# debug page with a 500 status. Axios sees the non-2xx status and throws
# with no usable message, which is why the frontend was just showing a
# generic "X failed" banner instead of the real reason. This converts
# any crash into clean JSON and still prints the full traceback to the
# terminal so you can see exactly what broke.
@app.errorhandler(Exception)
def handle_uncaught_exception(e):
    traceback.print_exc()
    return jsonify({"error": f"Server error: {e}"}), 500


@app.route('/')
def home():
    return jsonify({
        "message": "DeepFinder API is running!",
        "version": "1.0",
        "author": "Aymane Bouras & Omar Chouri"
    })


# =========================
# MAIN DOMAIN SCAN
# =========================
@app.route('/api/scan', methods=['POST'])
def scan():
    data = request.get_json()
    domain = data.get('domain', '').strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    domain = domain.replace("https://", "").replace("http://", "").replace("www.", "")
    domain = domain.split("/")[0].strip()

    print(f"🔍 Scanning {domain}...")

    whois   = get_whois(domain)
    dns     = get_dns(domain)
    ports   = scan_ports(domain)
    headers = get_headers(domain)
    tech    = get_technologies(domain)
    geo     = get_geolocation(domain)
    risk    = calculate_risk(whois, dns, ports, headers, tech)

    scan_id = save_scan(domain, whois, dns, ports, headers, tech, geo, risk)

    print(f"✅ Scan done! ID: {scan_id}")

    return jsonify({
        "scan_id": scan_id,
        "domain": domain,
        "whois": whois,
        "dns": dns,
        "ports": ports,
        "headers": headers,
        "technologies": tech,
        "geolocation": geo,
        "risk": risk
    })


# =========================
# HISTORY
# =========================
@app.route('/api/history', methods=['GET'])
def history():
    scans = get_all_scans()
    return jsonify({"scans": scans})


@app.route('/api/scan/<int:scan_id>', methods=['GET'])
def get_scan(scan_id):
    scan = get_scan_by_id(scan_id)
    if scan:
        return jsonify(scan)
    return jsonify({"error": "Scan not found"}), 404


# =========================
# FIX FRONTEND MISSING ROUTES (MOCK SAFE RESPONSES)
# =========================

@app.route('/api/subdomains', methods=['POST'])
def subdomains():
    data = request.get_json()
    return jsonify({
        "total_found": 0,
        "sources": [],
        "subdomains": []
    })


@app.route('/api/threat', methods=['POST'])
def threat():
    data = request.get_json()
    target = data.get("target", "").strip()
    target_type = data.get("type", "domain").strip().lower()

    if not target:
        return jsonify({"error": "Target is required"}), 400

    if target_type not in ("domain", "ip"):
        target_type = "domain"

    if target_type == "domain":
        # same cleanup used by /api/scan
        target = target.replace("https://", "").replace("http://", "").replace("www.", "")
        target = target.split("/")[0].strip()
    else:
        # validate it's actually a parsable IP before hitting 3 external APIs
        try:
            ipaddress.ip_address(target)
        except ValueError:
            return jsonify({"error": f"'{target}' is not a valid IP address"}), 400

    print(f"🔍 Running threat intel on {target} ({target_type})...")
    result = get_threat_intelligence(target, target_type)
    print(f"✅ Threat intel done — verdict: {result['overall_verdict']}")

    return jsonify(result)


@app.route('/api/company', methods=['POST'])
def company():
    data = request.get_json()
    domain = data.get("domain", "").strip()

    if not domain:
        return jsonify({"error": "Domain is required"}), 400

    print(f"🔍 Looking up company info for: {domain}...")
    result = lookup_company(domain)
    print(f"✅ Company lookup done")

    return jsonify(result)


@app.route('/api/files', methods=['POST'])
def files():
    data = request.get_json()
    domain = data.get("domain", "")
    return jsonify({
        "exposed_count": 0,
        "paths_checked": 0,
        "exposed_paths": [],
        "google_dorks": [
            f"site:{domain} filetype:pdf",
            f"site:{domain} inurl:admin"
        ]
    })


@app.route('/api/social', methods=['POST'])
def social():
    data = request.get_json()
    username = data.get("username", "").strip()

    if not username:
        return jsonify({"error": "Username is required"}), 400

    print(f"🔍 Looking up username: {username}...")
    result = lookup_username(username)
    print(f"✅ Social lookup done — {result['total_found']} found")

    return jsonify(result)

@app.route('/api/phone', methods=['POST'])
def phone():
    data = request.get_json()
    phone_number = data.get("phone", "").strip()

    if not phone_number:
        return jsonify({"error": "Phone number is required"}), 400

    print(f"🔍 Validating phone: {phone_number}...")
    result = lookup_phone(phone_number)
    print(f"✅ Phone lookup done")

    return jsonify(result)


@app.route('/api/files/metadata', methods=['POST'])
def file_metadata():
    data = request.get_json()
    url = data.get("url", "").strip()

    if not url:
        return jsonify({"error": "File URL is required"}), 400

    print(f"🔍 Extracting metadata from: {url}...")
    result = get_file_metadata(url)
    print(f"✅ Metadata extraction done — type: {result.get('file_type', 'n/a')}")

    return jsonify(result)


# =========================
# RUN SERVER
# =========================
if __name__ == '__main__':
    app.run(debug=True, port=5000)