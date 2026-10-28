
"""
EWB Phishing URL Awareness Checker
Defensive learning project.

Text-only analysis: this program never opens or visits submitted URLs.
Risk scores are heuristic indicators, not proof of maliciousness.
"""

import ipaddress
import re
from urllib.parse import urlparse


def inspect_url(raw_url):
    """Check visible URL text for selected warning signs."""
    url = raw_url.strip()
    findings = []

    if not url:
        return ["No URL entered."]

    # Check for whitespace or control characters inside the URL
    if any(char.isspace() or ord(char) < 32 for char in url):
        findings.append("Contains whitespace or control characters.")

    candidate = url if "://" in url else "http://" + url

    try:
        parsed = urlparse(candidate)
    except (ValueError, UnicodeError):
        return ["This text is not a valid URL format."]

    host = (parsed.hostname or "").lower()

    if not host:
        return ["Could not identify a hostname."]

    # 1. Check for @ symbol
    if "@" in candidate:
        findings.append("Contains an @ symbol; inspect carefully.")

    # 2. Check for unusually long URL (over 100 characters)
    if len(url) > 100:
        findings.append("Unusually long URL (over 100 characters).")

    # 3. Check for IP address as hostname
    is_ip = False
    try:
        ipaddress.ip_address(host)
        is_ip = True
    except ValueError:
        if re.fullmatch(r"(?:\d{1,3}\.){3}\d{1,3}", host):
            is_ip = True

    if is_ip:
        findings.append("Uses an IP address instead of a familiar domain.")

    # 4. Check for many hostname segments/subdomains (5 or more parts)
    host_without_dot = host.rstrip(".")
    labels = [part for part in host_without_dot.split(".") if part]
    if len(labels) >= 5:
        findings.append("Contains many hostname segments/subdomains.")

    # 5. Check for punycode-style hostname (xn--)
    if "xn--" in host or any(label.startswith("xn--") for label in labels):
        findings.append("Contains a punycode-style hostname.")

    # 6. Check for HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        findings.append("Uses HTTP. HTTPS alone does not prove trust.")

    if not findings:
        findings.append("No listed warning signs found. This does NOT prove safety.")

    return findings


def calculate_risk(warnings):
    """Calculate an illustrative heuristic score from 0 to 100."""
    score = 0

    weights = {
        "Contains an @ symbol; inspect carefully.": 25,
        "Unusually long URL (over 100 characters).": 15,
        "Uses an IP address instead of a familiar domain.": 25,
        "Contains many hostname segments/subdomains.": 20,
        "Contains a punycode-style hostname.": 20,
        "Uses HTTP. HTTPS alone does not prove trust.": 10,
        "Contains whitespace or control characters.": 10,
        "This text is not a valid URL format.": 30,
        "Could not identify a hostname.": 20,
    }

    for warning in set(warnings):
        score += weights.get(warning, 0)

    return min(score, 100)


def risk_label(score):
    """Map the heuristic score to an explanatory category."""
    if score >= 50:
        return "High"
    if score >= 20:
        return "Medium"
    return "Low"


def main():
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")

    raw_url = input("Enter a sample URL to inspect: ")
    findings = inspect_url(raw_url)
    score = calculate_risk(findings)

    print("\nResult:")
    for item in findings:
        print(f"- {item}")

    print(f"\nHeuristic risk score: {score}/100")
    print(f"Risk category: {risk_label(score)}")
    print("\nNever enter passwords from unexpected links.")


if __name__ == "__main__":
    main()

