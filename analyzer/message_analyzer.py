import re
from analyzer.risk_engine import calculate_risk

URL_PATTERN = re.compile(
    r"https?://[^\s<>\"]+",
    re.IGNORECASE,
)


URGENCY_PATTERNS = [
    r"\burgent\b",
    r"\bimmediately\b",
    r"\baction required\b",
    r"\bact now\b",
    r"\bexpires?\b",
    r"\blast warning\b",
    r"\bas soon as possible\b",
]


CREDENTIAL_PATTERNS = [
    r"\bpassword\b",
    r"\bpasscode\b",
    r"\bpin\b",
    r"\botp\b",
    r"\bverification code\b",
    r"\bsecurity code\b",
    r"\blogin credentials?\b",
]


FINANCIAL_PATTERNS = [
    r"\bpayment\b",
    r"\btransfer\b",
    r"\bbank details?\b",
    r"\bbank account\b",
    r"\bcredit card\b",
    r"\bdebit card\b",
    r"\bcard details?\b",
]


ACCOUNT_THREAT_PATTERNS = [
    r"\baccount (?:will be|has been|is being) blocked\b",
    r"\baccount (?:will be|has been|is being) suspended\b",
    r"\baccount (?:will be|has been|is being) terminated\b",
    r"\baccess (?:will be|has been|is being) revoked\b",
    r"\baccount locked\b",
]


SUSPICIOUS_LINK_PATTERNS = [
    r"\bclick (?:this|the) link\b",
    r"\bclick here\b",
    r"\bverify (?:your|the) account\b",
    r"\blogin here\b",
    r"\blog in here\b",
    r"\bconfirm (?:your|the) account\b",
]


def extract_urls(message: str) -> list[str]:
    """Extract HTTP/HTTPS URLs from a message."""
    return URL_PATTERN.findall(message)


def _detect_patterns(
    message: str,
    patterns: list[str],
    finding: str,
) -> list[str]:
    """Return a finding when any pattern in a group matches."""
    for pattern in patterns:
        if re.search(pattern, message, re.IGNORECASE):
            return [finding]

    return []


def detect_urgency(message: str) -> list[str]:
    """Detect pressure or urgency-based language."""
    return _detect_patterns(
        message,
        URGENCY_PATTERNS,
        "Urgent or pressure-based language detected",
    )


def detect_credential_request(message: str) -> list[str]:
    """Detect requests involving credentials or verification codes."""
    return _detect_patterns(
        message,
        CREDENTIAL_PATTERNS,
        "Credential or verification information requested",
    )


def detect_financial_request(message: str) -> list[str]:
    """Detect financial or payment-related requests."""
    return _detect_patterns(
        message,
        FINANCIAL_PATTERNS,
        "Financial or payment information requested",
    )


def detect_account_threat(message: str) -> list[str]:
    """Detect threats involving account access."""
    return _detect_patterns(
        message,
        ACCOUNT_THREAT_PATTERNS,
        "Account access threat detected",
    )


def detect_suspicious_link_language(message: str) -> list[str]:
    """Detect language encouraging the user to interact with a link."""
    return _detect_patterns(
        message,
        SUSPICIOUS_LINK_PATTERNS,
        "Message encourages the user to interact with a link",
    )

def classify_message(indicators: list[str]) -> str:
    """Classify the most likely message-based attack type."""

    indicator_text = " ".join(indicators).lower()

    if (
        "credential or verification" in indicator_text
        or "message encourages" in indicator_text
        or "account access threat" in indicator_text
    ):
        return "Phishing"

    if "financial or payment" in indicator_text:
        return "Potential Financial Scam"

    if "urgent or pressure" in indicator_text:
        return "Potential Social Engineering"

    return "No obvious attack pattern detected"

def get_recommendations(indicators: list[str]) -> list[str]:
    """Generate deterministic safety recommendations."""

    recommendations = []

    indicator_text = " ".join(indicators).lower()

    if "url(s) detected" in indicator_text:
        recommendations.append(
            "Do not click the link until you have verified it."
        )

    if "credential or verification" in indicator_text:
        recommendations.append(
            "Do not provide passwords, OTPs, PINs, or verification codes."
        )

    if "financial or payment" in indicator_text:
        recommendations.append(
            "Do not send money or share banking or card information."
        )

    if "account access threat" in indicator_text:
        recommendations.append(
            "Verify the account warning through the organization's "
            "official website or app."
        )

    if not recommendations:
        recommendations.append(
            "No immediate security action was identified."
        )

    return recommendations

def analyze_message(message: str) -> dict:
    """Perform deterministic security analysis on a message."""

    if not message or not message.strip():
        raise ValueError("Message cannot be empty.")

    urls = extract_urls(message)

    indicators = []

    indicators.extend(detect_urgency(message))
    indicators.extend(detect_credential_request(message))
    indicators.extend(detect_financial_request(message))
    indicators.extend(detect_account_threat(message))
    indicators.extend(detect_suspicious_link_language(message))

    if urls:
        indicators.append(f"{len(urls)} URL(s) detected")

    risk = calculate_risk(indicators)

    attack_type = classify_message(indicators)
    recommendations = get_recommendations(indicators)

    return {
        "input_type": "message",
        "risk": risk["level"],
        "score": risk["score"],
        "possible_attack": attack_type,
        "urls": urls,
        "indicators": indicators,
        "recommended_actions": recommendations,
    }
