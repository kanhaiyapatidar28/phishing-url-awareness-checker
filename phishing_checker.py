#!/usr/bin/env python3
"""EWB Phishing URL Awareness Checker.

Text checks only: this program does not open URLs or verify whether a site is safe.
Uses only Python's standard library.
"""

import ipaddress
from urllib.parse import urlsplit


def inspect_url(raw_url: str) -> list[str]:
    """Return warning messages for the URL's visible structure."""
    url = raw_url.strip()
    if not url:
        return ["Please enter a URL."]

    # urlsplit works best when a scheme is present. Keep parsing local: no requests.
    candidate = url if "://" in url else f"//{url}"
    try:
        parts = urlsplit(candidate)
        hostname = parts.hostname
        netloc = parts.netloc
    except ValueError:
        return ["Could not parse this URL. Check its format."]

    if not hostname:
        return ["Could not find a hostname. Check the URL format."]

    warnings = []

    # An @ in the authority section can make the part before it look like the
    # site name even though the browser uses the hostname after @.
    if "@" in netloc or "@" in url:
        warnings.append("Contains an @ symbol; inspect carefully.")

    try:
        ipaddress.ip_address(hostname)
    except ValueError:
        pass
    else:
        warnings.append("Uses an IP address instead of a familiar domain.")

    scheme = parts.scheme.lower()
    if scheme == "http":
        warnings.append("Uses HTTP. HTTPS alone does not prove trust.")
    elif not scheme:
        # No scheme was provided; don't infer that the URL is secure.
        pass

    labels = hostname.rstrip(".").split(".")
    if len(labels) >= 6:
        warnings.append("Contains many hostname segments/subdomains.")

    if any(label.lower().startswith("xn--") for label in labels):
        warnings.append("Contains a punycode-style hostname.")

    if not warnings:
        warnings.append("No listed warning signs found. This does NOT prove safety.")

    return warnings


def main() -> None:
    print("EWB Phishing URL Awareness Checker")
    print("Text checks only - this program does not open URLs.")
    try:
        url = input("Enter a sample URL to inspect: ").strip()
    except (EOFError, KeyboardInterrupt):
        print("\nInput cancelled.")
        return

    print("\nResult:")
    for warning in inspect_url(url):
        print(f"- {warning}")
    print("\nNever enter passwords from unexpected links.")


if __name__ == "__main__":
    main()
