import requests
from concurrent.futures import ThreadPoolExecutor, as_completed


PLATFORMS = {
    "GitHub":        ("https://github.com/{}", "Not Found"),
    "Reddit":        ("https://www.reddit.com/user/{}", "Sorry, nobody on Reddit goes by that name"),
    "Twitter/X":     ("https://twitter.com/{}", "This account doesn’t exist"),
    "Instagram":     ("https://www.instagram.com/{}/", "Sorry, this page isn't available"),
    "TikTok":        ("https://www.tiktok.com/@{}", "Couldn't find this account"),
    "Pinterest":     ("https://www.pinterest.com/{}/", None),
    "Twitch":        ("https://www.twitch.tv/{}", None),
    "YouTube":       ("https://www.youtube.com/@{}", None),
    "LinkedIn":      ("https://www.linkedin.com/in/{}", "Page not found"),
    "DevTo":         ("https://dev.to/{}", None),
    "HackerNews":    ("https://news.ycombinator.com/user?id={}", "No such user"),
    "Keybase":       ("https://keybase.io/{}", "Not found"),
    "Pastebin":      ("https://pastebin.com/u/{}", None),
    "GitLab":        ("https://gitlab.com/{}", None),
    "Medium":        ("https://medium.com/@{}", None),
    "Stackoverflow": ("https://stackoverflow.com/users?tab=reputation&search={}", None),
}

HEADERS = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/122.0 Safari/537.36",
    "Accept-Language": "en-US,en;q=0.9",
    "Accept": "text/html,application/xhtml+xml"
}


def _check_platform(platform: str, url_template: str, not_found_str, username: str) -> dict:
    url = url_template.format(username)

    try:
        resp = requests.get(url, headers=HEADERS, timeout=10, allow_redirects=True)
        text = resp.text.lower()

        # -------------------------
        # NOT FOUND
        # -------------------------
        if resp.status_code == 404:
            status = "not_found"

        # -------------------------
        # BLOCKED / RATE LIMITED
        # -------------------------
        elif resp.status_code in [401, 403, 429]:
            status = "blocked"

        # -------------------------
        # OK RESPONSE
        # -------------------------
        elif resp.status_code == 200:

            if not_found_str and not_found_str.lower() in text:
                status = "not_found"

            else:
                # extra platform-specific safety checks
                if platform == "GitHub":
                    if "not found" in text or "page not found" in text:
                        status = "not_found"
                    else:
                        status = "found"

                elif platform == "Reddit":
                    if "page not found" in text or "sorry, nobody" in text:
                        status = "not_found"
                    else:
                        status = "found"

                elif platform == "Twitter/X":
                    if "this account doesn’t exist" in text or "account doesn't exist" in text:
                        status = "not_found"
                    else:
                        status = "found"

                elif platform == "Instagram":
                    if "sorry, this page isn't available" in text:
                        status = "not_found"
                    else:
                        status = "found"

                else:
                    status = "found"

        else:
            status = f"unknown ({resp.status_code})"

    except requests.exceptions.Timeout:
        status = "timeout"

    except requests.exceptions.RequestException:
        status = "error"

    return {
        "platform": platform,
        "url": url,
        "status": status
    }


def lookup_username(username: str) -> dict:
    username = username.strip().lstrip("@")

    results = {
        "username": username,
        "found": [],
        "not_found": [],
        "blocked": [],
        "unknown": [],
        "total_found": 0
    }

    with ThreadPoolExecutor(max_workers=10) as executor:
        futures = [
            executor.submit(_check_platform, name, tpl, nf, username)
            for name, (tpl, nf) in PLATFORMS.items()
        ]

        for future in as_completed(futures):
            res = future.result()

            if res["status"] == "found":
                results["found"].append(res)
            elif res["status"] == "not_found":
                results["not_found"].append(res)
            elif res["status"] == "blocked":
                results["blocked"].append(res)
            else:
                results["unknown"].append(res)

    results["found"].sort(key=lambda x: x["platform"])
    results["total_found"] = len(results["found"])

    return results