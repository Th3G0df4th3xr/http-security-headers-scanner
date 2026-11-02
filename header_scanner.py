#!/usr/bin/env python3
"""
HTTP Security Headers Scanner
Checks a target URL's response headers against common security best practices
(OWASP Secure Headers Project recommendations).
"""

import sys
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking via iframes",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks",
    "Referrer-Policy": "Controls how much referrer info is leaked",
    "Permissions-Policy": "Restricts browser feature access (camera, mic, etc.)",
}

def scan(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    try:
        response = requests.get(url, timeout=10)
    except requests.exceptions.RequestException as e:
        print(f"[!] Could not reach {url}: {e}")
        sys.exit(1)

    print(f"\nScanning: {url}")
    print(f"Status Code: {response.status_code}\n")
    print(f"{'Header':<30}{'Status':<10}Description")
    print("-" * 80)

    missing_count = 0
    for header, description in SECURITY_HEADERS.items():
        present = header in response.headers
        status = "Present" if present else "Missing"
        if not present:
            missing_count += 1
        print(f"{header:<30}{status:<10}{description}")

    print("\n" + "-" * 80)
    print(f"Summary: {len(SECURITY_HEADERS) - missing_count}/{len(SECURITY_HEADERS)} recommended headers present")

    if missing_count > 0:
        print(f"{missing_count} header(s) missing — review for hardening opportunities.")
    else:
        print("All checked headers are present.")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Usage: python3 header_scanner.py <url>")
        sys.exit(1)
    scan(sys.argv[1])
