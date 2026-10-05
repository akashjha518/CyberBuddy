URL_INDICATOR_WEIGHTS = {
    "URL does not use HTTPS": 10,
    "IP address used instead of a domain name": 25,
    "Unusually long URL": 10,
    "Multiple subdomains detected": 10,
    "Username or password embedded in URL": 30,
    "At-sign detected in URL": 20,
    "Percent-encoded characters detected": 10,
}


def calculate_url_risk(indicators: list[str]) -> dict:
    """
    Calculate a deterministic risk score for a URL.

    The score is capped at 100.
    """

    score = 0

    for indicator in indicators:
        if indicator.startswith("Security-sensitive keyword(s) detected:"):
            score += 5
        else:
            score += URL_INDICATOR_WEIGHTS.get(indicator, 0)

    score = min(score, 100)

    if score >= 75:
        level = "CRITICAL"
    elif score >= 50:
        level = "HIGH"
    elif score >= 25:
        level = "MEDIUM"
    else:
        level = "LOW"

    return {
        "score": score,
        "level": level,
    }