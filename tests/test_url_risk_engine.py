from analyzer.url_risk_engine import calculate_url_risk


def test_low_url_risk():
    result = calculate_url_risk([])

    assert result["score"] == 0
    assert result["level"] == "LOW"


def test_medium_url_risk():
    result = calculate_url_risk(
        [
            "URL does not use HTTPS",
            "IP address used instead of a domain name",
        ]
    )

    assert result["score"] == 35
    assert result["level"] == "MEDIUM"


def test_high_url_risk():
    result = calculate_url_risk(
        [
            "IP address used instead of a domain name",
            "Username or password embedded in URL",
        ]
    )

    assert result["score"] == 55
    assert result["level"] == "HIGH"


def test_critical_url_risk():
    result = calculate_url_risk(
        [
            "URL does not use HTTPS",
            "IP address used instead of a domain name",
            "Username or password embedded in URL",
            "At-sign detected in URL",
            "Percent-encoded characters detected",
        ]
    )

    assert result["score"] == 95
    assert result["level"] == "CRITICAL"


def test_security_keyword_weight():
    result = calculate_url_risk(
        [
            "Security-sensitive keyword(s) detected: login, verify"
        ]
    )

    assert result["score"] == 5
    assert result["level"] == "LOW"


def test_score_is_capped_at_100():
    result = calculate_url_risk(
        [
            "URL does not use HTTPS",
            "IP address used instead of a domain name",
            "Unusually long URL",
            "Multiple subdomains detected",
            "Username or password embedded in URL",
            "At-sign detected in URL",
            "Percent-encoded characters detected",
            "Security-sensitive keyword(s) detected: login",
        ]
    )

    assert result["score"] == 100