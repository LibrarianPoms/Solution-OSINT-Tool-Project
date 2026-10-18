def calculate_risk(whois_data, dns_data, ports_data, headers_data, tech_data):
    score = 0
    details = []

    # ── WHOIS ──────────────────────────────────────────────
    if "error" not in whois_data:
        if whois_data.get("expiration_date") == "N/A":
            score += 2
            details.append({
                "category": "WHOIS",
                "issue": "Date d'expiration inconnue",
                "points": 2,
                "severity": "medium"
            })

    # ── PORTS ──────────────────────────────────────────────
    dangerous_ports = {
        21: "FTP - Transfert de fichiers non chiffré",
        22: "SSH - Accès distant exposé",
        23: "Telnet - Protocole non sécurisé",
        3306: "MySQL - Base de données exposée",
        5432: "PostgreSQL - Base de données exposée",
        6379: "Redis - Base de données exposée",
        27017: "MongoDB - Base de données exposée",
    }

    if "open_ports" in ports_data:
        for port_info in ports_data["open_ports"]:
            port = port_info["port"]
            if port in dangerous_ports:
                score += 3
                details.append({
                    "category": "Ports",
                    "issue": f"Port {port} ouvert - {dangerous_ports[port]}",
                    "points": 3,
                    "severity": "high"
                })

    # ── HEADERS ────────────────────────────────────────────
    if "missing_count" in headers_data:
        missing = headers_data["missing_count"]
        points = missing * 2
        score += points
        if missing > 0:
            details.append({
                "category": "Headers HTTP",
                "issue": f"{missing} en-têtes de sécurité manquants",
                "points": points,
                "severity": "high" if missing >= 4 else "medium"
            })

    # ── DNS ────────────────────────────────────────────────
    if "error" not in dns_data:
        if not dns_data.get("MX"):
            score += 1
            details.append({
                "category": "DNS",
                "issue": "Pas d'enregistrement MX - Email non configuré",
                "points": 1,
                "severity": "low"
            })
        if not dns_data.get("TXT"):
            score += 2
            details.append({
                "category": "DNS",
                "issue": "Pas d'enregistrement SPF/DMARC",
                "points": 2,
                "severity": "medium"
            })

    # ── NIVEAU DE RISQUE ───────────────────────────────────
    if score <= 5:
        level = "LOW"
        color = "green"
    elif score <= 10:
        level = "MEDIUM"
        color = "orange"
    elif score <= 20:
        level = "HIGH"
        color = "red"
    else:
        level = "CRITICAL"
        color = "darkred"

    return {
        "score": score,
        "level": level,
        "color": color,
        "details": details,
        "total_issues": len(details)
    }