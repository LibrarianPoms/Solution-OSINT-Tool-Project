import sqlite3
import json
from datetime import datetime

DB_PATH = "deepfinder.db"

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            domain TEXT NOT NULL,
            date TEXT NOT NULL,
            risk_score INTEGER,
            risk_level TEXT
        )
    ''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER,
            whois TEXT,
            dns TEXT,
            ports TEXT,
            headers TEXT,
            technologies TEXT,
            geolocation TEXT,
            risk TEXT,
            FOREIGN KEY (scan_id) REFERENCES scans(id)
        )
    ''')

    conn.commit()
    conn.close()

def save_scan(domain, whois, dns, ports, headers, tech, geo, risk):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    # Sauvegarder le scan principal
    cursor.execute('''
        INSERT INTO scans (domain, date, risk_score, risk_level)
        VALUES (?, ?, ?, ?)
    ''', (
        domain,
        datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        risk.get("score", 0),
        risk.get("level", "UNKNOWN")
    ))

    scan_id = cursor.lastrowid

    # Sauvegarder les résultats détaillés
    cursor.execute('''
        INSERT INTO results (scan_id, whois, dns, ports, headers, technologies, geolocation, risk)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (
        scan_id,
        json.dumps(whois),
        json.dumps(dns),
        json.dumps(ports),
        json.dumps(headers),
        json.dumps(tech),
        json.dumps(geo),
        json.dumps(risk)
    ))

    conn.commit()
    conn.close()
    return scan_id

def get_all_scans():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT id, domain, date, risk_score, risk_level
        FROM scans
        ORDER BY date DESC
    ''')

    scans = []
    for row in cursor.fetchall():
        scans.append({
            "id": row[0],
            "domain": row[1],
            "date": row[2],
            "risk_score": row[3],
            "risk_level": row[4]
        })

    conn.close()
    return scans

def get_scan_by_id(scan_id):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()

    cursor.execute('''
        SELECT s.domain, s.date, s.risk_score, s.risk_level,
               r.whois, r.dns, r.ports, r.headers, r.technologies, r.geolocation, r.risk
        FROM scans s
        JOIN results r ON s.id = r.scan_id
        WHERE s.id = ?
    ''', (scan_id,))

    row = cursor.fetchone()
    conn.close()

    if row:
        return {
            "domain": row[0],
            "date": row[1],
            "risk_score": row[2],
            "risk_level": row[3],
            "whois": json.loads(row[4]),
            "dns": json.loads(row[5]),
            "ports": json.loads(row[6]),
            "headers": json.loads(row[7]),
            "technologies": json.loads(row[8]),
            "geolocation": json.loads(row[9]),
            "risk": json.loads(row[10])
        }
    return None