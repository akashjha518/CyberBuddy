from analyzer.risk_engine import calculate_risk


def test_low_risk():
    result = calculate_risk([])

    assert result["score"] == 0
    assert result["level"] == "LOW"


def test_medium_risk():
    result = calculate_risk(
        [
            "Urgent or pressure-based language detected",
            "Message encourages the user to interact with a link",
        ]
    )

    assert result["score"] == 25
    assert result["level"] == "MEDIUM"


def test_high_risk():
    result = calculate_risk(
        [
            "Credential or verification information requested",
            "Financial or payment information requested",
        ]
    )

    assert result["score"] == 55
    assert result["level"] == "HIGH"


def test_critical_risk():
    result = calculate_risk(
        [
            "Credential or verification information requested",
            "Financial or payment information requested",
            "Account access threat detected",
            "Message encourages the user to interact with a link",
        ]
    )

    assert result["score"] == 90
    assert result["level"] == "CRITICAL"


def test_score_is_capped_at_100():
    result = calculate_risk(
        [
            "Credential or verification information requested",
            "Credential or verification information requested",
            "Credential or verification information requested",
            "Credential or verification information requested",
        ]
    )

    assert result["score"] == 100