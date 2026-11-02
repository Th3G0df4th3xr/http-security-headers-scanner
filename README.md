# SentinelScan — Multi-Stage Adaptive Web Security Recon Tool

SentinelScan performs staged security reconnaissance where each stage's findings determine what gets checked next — conditional escalation logic rather than a fixed checklist.

## How it works
- Missing CSP → automatically checks for inline scripts (XSS exposure)
- Missing HSTS → automatically checks whether HTTP cleanly redirects to HTTPS
- Any High-severity finding → automatically probes common exposed paths (`.git/config`, `.env`, etc.)
- Produces a prioritized findings report (High/Medium/Low)

## Usage
```bash
pip3 install requests
python3 sentinel_scan.py example.com
```

## Legacy script
`header_scanner.py` is the original static header checker, kept for reference.

## Disclaimer
For educational and authorized security research only. Only scan targets you own or have explicit permission to test.
