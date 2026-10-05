import pytest

from analyzer.url_analyzer import (
    analyze_url,
    count_subdomains,
    is_ip_address,
)


def test_https_url():
    result = analyze_url("https://example.com")

    assert result["scheme"] == "https"
    assert result["hostname"] == "example.com"
    assert "URL does not use HTTPS" not in result["indicators"]


def test_http_url():
    result = analyze_url("http://example.com")

    assert "URL does not use HTTPS" in result["indicators"]


def test_ip_address_url():
    result = analyze_url("http://192.168.1.10/login")

    assert "IP address used instead of a domain name" in result["indicators"]


def test_long_url():
    url = "https://example.com/" + ("a" * 150)

    result = analyze_url(url)

    assert "Unusually long URL" in result["indicators"]


def test_multiple_subdomains():
    result = analyze_url(
        "https://a.b.c.example.com/login"
    )

    assert "Multiple subdomains detected" in result["indicators"]


def test_embedded_credentials():
    result = analyze_url(
        "https://user:password@example.com/login"
    )

    assert (
        "Username or password embedded in URL"
        in result["indicators"]
    )


def test_at_sign():
    result = analyze_url(
        "https://example.com@evil.example/login"
    )

    assert "At-sign detected in URL" in result["indicators"]


def test_percent_encoding():
    result = analyze_url(
        "https://example.com/%6cogin"
    )

    assert (
        "Percent-encoded characters detected"
        in result["indicators"]
    )


def test_suspicious_keywords():
    result = analyze_url(
        "https://example.com/verify-account"
    )

    assert any(
        "Security-sensitive keyword" in indicator
        for indicator in result["indicators"]
    )


def test_ip_detection():
    assert is_ip_address("192.168.1.1")
    assert not is_ip_address("example.com")


def test_subdomain_count():
    assert count_subdomains("example.com") == 0
    assert count_subdomains("login.example.com") == 1
    assert count_subdomains("a.b.example.com") == 2


def test_empty_url():
    with pytest.raises(ValueError):
        analyze_url("")


def test_invalid_scheme():
    with pytest.raises(ValueError):
        analyze_url("ftp://example.com")

def test_full_url_analysis():
    result = analyze_url(
        "http://192.168.1.10/login"
    )

    assert result["risk"] == "MEDIUM"
    assert result["score"] == 40
    assert result["hostname"] == "192.168.1.10"
    assert len(result["indicators"]) == 3

