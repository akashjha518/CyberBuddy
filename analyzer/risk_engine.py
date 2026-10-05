INDICATOR_WEIGHTS = {
    "Urgent or pressure-based language detected": 10,
    "Credential or verification information requested": 30,
    "Financial or payment information requested": 25,
    "Account access threat detected": 20,
    "Message encourages the user to interact with a link": 15,
    "URL detected": 10,
}


def calculate_risk(indicators: list[str]) -> dict:
    """
    Calculate a deterministic risk score from detected indicators.

    The score is capped at 100.
    """

    score = 0

    for indicator in indicators:
        if "URL(s) detected" in indicator:
            score += 10
        else:
            score += INDICATOR_WEIGHTS.get(indicator, 0)
        
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