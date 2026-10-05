from analyzer.message_analyzer import (
    analyze_message,
    detect_account_threat,
    detect_credential_request,
    detect_financial_request,
    detect_suspicious_link_language,
    detect_urgency,
)


def test_detects_url():
    result = analyze_message(
        "Please visit https://example.com immediately."
    )

    assert "https://example.com" in result["urls"]
    assert "1 URL(s) detected" in result["indicators"]


def test_detects_urgency():
    result = analyze_message(
        "URGENT! Your account requires immediate action."
    )

    assert "Urgent or pressure-based language detected" in result["indicators"]


def test_detects_credential_request():
    result = analyze_message(
        "Please provide your password and OTP."
    )

    assert (
        "Credential or verification information requested"
        in result["indicators"]
    )


def test_detects_financial_request():
    result = analyze_message(
        "Please confirm your bank account and payment details."
    )

    assert (
        "Financial or payment information requested"
        in result["indicators"]
    )


def test_detects_account_threat():
    result = analyze_message(
        "Your account will be blocked unless you verify it."
    )

    assert "Account access threat detected" in result["indicators"]


def test_detects_suspicious_link_language():
    result = analyze_message(
        "Click this link to verify your account."
    )

    assert (
        "Message encourages the user to interact with a link"
        in result["indicators"]
    )


def test_empty_message():
    try:
        analyze_message("")
        assert False, "Expected ValueError"
    except ValueError:
        assert True


def test_clean_message_has_no_security_indicators():
    result = analyze_message(
        "Hi, are we still meeting for lunch today?"
    )

    assert result["urls"] == []
    assert result["indicators"] == []


def test_individual_detectors():
    message = "URGENT! Please provide your OTP immediately."

    assert detect_urgency(message)
    assert detect_credential_request(message)
    assert not detect_financial_request(message)
    assert not detect_account_threat(message)
    assert not detect_suspicious_link_language(message)


def test_full_message_analysis():
    result = analyze_message(
        "URGENT! Your account will be blocked. "
        "Please provide your OTP immediately "
        "at https://example.com/login"
    )

    assert result["risk"] == "HIGH"
    assert result["score"] == 70
    assert len(result["urls"]) == 1
    assert len(result["indicators"]) == 4

def test_classifies_phishing_message():
    result = analyze_message(
        "URGENT! Your account will be blocked. "
        "Please provide your OTP immediately at "
        "https://example.com/login"
    )

    assert result["possible_attack"] == "Phishing"


def test_generates_credential_recommendation():
    result = analyze_message(
        "Please provide your OTP to verify your account."
    )

    assert any(
        "passwords, OTPs" in recommendation
        for recommendation in result["recommended_actions"]
    )


def test_generates_financial_recommendation():
    result = analyze_message(
        "Please send your bank account and payment details."
    )

    assert any(
        "banking or card information" in recommendation
        for recommendation in result["recommended_actions"]
    )


def test_clean_message_has_safe_result():
    result = analyze_message(
        "Hey, are we still meeting for lunch today?"
    )

    assert result["possible_attack"] == "No obvious attack pattern detected"
    assert len(result["recommended_actions"]) == 1

