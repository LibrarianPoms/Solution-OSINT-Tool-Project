import builtwith

def get_technologies(domain):
    try:
        url = f"https://{domain}"
        results = builtwith.parse(url)

        technologies = {}
        for category, techs in results.items():
            technologies[category] = techs

        return {
            "domain": domain,
            "technologies": technologies,
            "total_categories": len(technologies)
        }

    except Exception as e:
        return {"error": str(e)}