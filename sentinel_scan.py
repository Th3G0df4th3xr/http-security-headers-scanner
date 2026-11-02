#!/usr/bin/env python3
"""
SentinelScan — Multi-Stage Adaptive Web Security Recon Tool
Each stage's findings determine what gets checked next (conditional
escalation logic), rather than running a fixed checklist.
"""

import sys
import argparse
import requests
from urllib.parse import urljoin

SECURITY_HEADERS = {
    "Strict-Transport-Security": "Enforces HTTPS connections (HSTS)",
    "Content-Security-Policy": "Mitigates XSS and data injection attacks",
    "X-Frame-Options": "Prevents clickjacking via iframes",
    "X-Content-Type-Options": "Prevents MIME-sniffing attacks",
    "Referrer-Policy": "Controls how much referrer info is leaked",
    "Permissions-Policy": "Restricts browser feature access",
}

SENSITIVE_PATHS = [".git/config", ".env", "robots.txt", "wp-config.php.bak", ".well-known/security.txt"]


class Finding:
    def __init__(self, severity, title, detail):
        self.severity = severity
        self.title = title
        self.detail = detail


class SentinelScan:
    def __init__(self, url):
        self.url = url if url.startswith(("http://", "https://")) else "https://" + url
        self.findings = []
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "SentinelScan/1.0 (security research)"})
        self.response = None

    def log(self, msg):
        print(f"  → {msg}")

    def add(self, severity, title, detail):
        self.findings.append(Finding(severity, title, detail))

    def stage_baseline(self):
        print(f"\n[Stage 1] Baseline recon on {self.url}")
        try:
            self.response = self.session.get(self.url, timeout=10)
        except requests.exceptions.RequestException as e:
            print(f"  [!] Could not reach target: {e}")
            sys.exit(1)
        self.log(f"Status {self.response.status_code}, server: {self.response.headers.get('Server', 'unknown')}")

    def stage_headers(self):
        print("\n[Stage 2] Security header audit")
        missing = []
        for header, desc in SECURITY_HEADERS.items():
            if header in self.response.headers:
                self.log(f"{header}: present")
            else:
                self.log(f"{header}: MISSING")
                missing.append(header)
                self.add("Medium", f"Missing {header}", desc)
        return missing

    def stage_inline_script_check(self):
        print("\n[Stage 3] CSP missing → checking for inline scripts (conditional escalation)")
        body = self.response.text
        inline_count = body.count("<script>") + body.count("<script ")
        if inline_count > 0:
            self.log(f"Found {inline_count} inline <script> tag(s) with no CSP to restrict them")
            self.add("High", "Inline scripts without CSP",
                      f"{inline_count} inline script tag(s) detected. Without CSP, "
                      "injected scripts would execute unrestricted.")
        else:
            self.log("No inline scripts found — lower XSS risk despite missing CSP")

    def stage_https_redirect_check(self):
        print("\n[Stage 4] HSTS missing → checking HTTP→HTTPS redirect behavior (conditional escalation)")
        http_url = self.url.replace("https://", "http://")
        try:
            r = self.session.get(http_url, timeout=10, allow_redirects=False)
            if r.status_code in (301, 302, 307, 308) and r.headers.get("Location", "").startswith("https"):
                self.log("HTTP does redirect to HTTPS (mitigates missing HSTS partially)")
            else:
                self.log("HTTP does NOT cleanly redirect to HTTPS")
                self.add("High", "No forced HTTPS redirect",
                          "Site allows plain HTTP without redirecting — combined with missing HSTS, "
                          "this makes downgrade/MITM attacks easier.")
        except requests.exceptions.RequestException:
            self.log("HTTP endpoint unreachable (not necessarily bad)")

    def stage_cookies(self):
        print("\n[Stage 5] Cookie security check")
        if not self.response.cookies:
            self.log("No cookies set on initial response")
            return
        for cookie in self.response.cookies:
            flags = []
            if not cookie.secure:
                flags.append("missing Secure")
            if not cookie.has_nonstandard_attr("HttpOnly"):
                flags.append("missing HttpOnly")
            if flags:
                self.log(f"Cookie '{cookie.name}': {', '.join(flags)}")
                self.add("Medium", f"Weak cookie flags on '{cookie.name}'",
                          f"Issues: {', '.join(flags)}. Risk of theft via XSS or network sniffing.")
            else:
                self.log(f"Cookie '{cookie.name}': flags OK")

    def stage_sensitive_paths(self):
        print("\n[Stage 6] High-severity finding present → probing common exposed paths (conditional escalation)")
        for path in SENSITIVE_PATHS:
            test_url = urljoin(self.url, path)
            try:
                r = self.session.get(test_url, timeout=6)
                if r.status_code == 200 and len(r.text) > 0:
                    self.log(f"{path}: accessible (200) — needs manual review")
                    self.add("Low", f"Exposed path: {path}", "Returned 200 — verify it doesn't leak sensitive data.")
                else:
                    self.log(f"{path}: {r.status_code}")
            except requests.exceptions.RequestException:
                self.log(f"{path}: unreachable")

    def run(self):
        self.stage_baseline()
        missing_headers = self.stage_headers()

        if "Content-Security-Policy" in missing_headers:
            self.stage_inline_script_check()

        if "Strict-Transport-Security" in missing_headers:
            self.stage_https_redirect_check()

        self.stage_cookies()

        high_findings = [f for f in self.findings if f.severity == "High"]
        if high_findings:
            self.stage_sensitive_paths()

        self.report()

    def report(self):
        print("\n" + "=" * 80)
        print(f"SENTINELSCAN REPORT — {self.url}")
        print("=" * 80)

        if not self.findings:
            print("No issues found across all stages.")
            return

        order = {"High": 0, "Medium": 1, "Low": 2, "Info": 3}
        for f in sorted(self.findings, key=lambda x: order[x.severity]):
            print(f"\n[{f.severity}] {f.title}")
            print(f"  {f.detail}")

        high = sum(1 for f in self.findings if f.severity == "High")
        med = sum(1 for f in self.findings if f.severity == "Medium")
        low = sum(1 for f in self.findings if f.severity == "Low")
        print("\n" + "-" * 80)
        print(f"Total: {len(self.findings)} findings — {high} High, {med} Medium, {low} Low")


def main():
    parser = argparse.ArgumentParser(description="SentinelScan — multi-stage adaptive web security recon")
    parser.add_argument("url", help="Target URL (e.g. example.com)")
    args = parser.parse_args()

    scanner = SentinelScan(args.url)
    scanner.run()


if __name__ == "__main__":
    main()
