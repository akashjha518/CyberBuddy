import ipaddress
import re
from urllib.parse import urlparse
from analyzer.url_risk_engine import calculate_url_risk

SUSPICIOUS_KEYWORDS = [
    "login",
    "verify",
    "verification",
    "secure",
    "account",
    "update",
    "confirm",
    "password",
    "signin",
]


SUSPICIOUS_CHARACTERS = [
    "@",
]


def is_ip_address(hostname: str) -> bool:
    """Check whether a hostname is an IPv4 or IPv6 address."""

    if not hostname:
        return False

    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def count_subdomains(hostname: str) -> int:
    """Count subdomain labels in a hostname."""

    if not hostname:
        return 0

    parts = hostname.split(".")

    if len(parts) <= 2:
        return 0

    return len(parts) - 2


def detect_suspicious_keywords(url: str) -> list[str]:
    """Detect security-related keywords commonly seen in suspicious URLs."""

    url_lower = url.lower()
    matches = [
        keyword
        for keyword in SUSPICIOUS_KEYWORDS
        if keyword in url_lower
    ]

    if matches:
        return [
            "Security-sensitive keyword(s) detected: "
            + ", ".join(matches)
        ]

    return []


def analyze_url(url: str) -> dict:
    """Perform deterministic security analysis on a URL."""

    if not url or not url.strip():
        raise ValueError("URL cannot be empty.")

    url = url.strip()

    if len(url) > 2048:
        raise ValueError("URL exceeds the maximum supported length.")

    parsed = urlparse(url)

    if parsed.scheme not in {"http", "https"}:
        raise ValueError(
            "URL must use HTTP or HTTPS."
        )

    if not parsed.hostname:
        raise ValueError("URL must contain a valid hostname.")

    indicators = []

    hostname = parsed.hostname

    if parsed.scheme == "http":
        indicators.append(
            "URL does not use HTTPS"
        )

    if is_ip_address(hostname):
        indicators.append(
            "IP address used instead of a domain name"
        )

    if len(url) > 150:
        indicators.append(
            "Unusually long URL"
        )

    if count_subdomains(hostname) >= 3:
        indicators.append(
            "Multiple subdomains detected"
        )

    if parsed.username or parsed.password:
        indicators.append(
            "Username or password embedded in URL"
        )

    if "@" in url:
        indicators.append(
            "At-sign detected in URL"
        )

    if re.search(r"%[0-9a-fA-F]{2}", url):
        indicators.append(
            "Percent-encoded characters detected"
        )

    indicators.extend(
        detect_suspicious_keywords(url)
    )

    risk = calculate_url_risk(indicators)

    return {
        "input_type": "url",
        "url": url,
        "hostname": hostname,
        "scheme": parsed.scheme,
        "risk": risk["level"],
        "score": risk["score"],
        "indicators": indicators,
    }