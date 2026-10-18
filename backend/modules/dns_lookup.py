import dns.resolver

def get_dns(domain):
    try:
        results = {}
        record_types = ['A', 'MX', 'TXT', 'NS', 'CNAME']

        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                results[record_type] = [str(r) for r in answers]
            except Exception:
                results[record_type] = []

        return results

    except Exception as e:
        return {"error": str(e)}