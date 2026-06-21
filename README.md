# Phishing URL Detector

A small offline cybersecurity project that analyzes URLs and explains why a link may be risky. It is built with Python standard-library modules only, so it does not need internet access or package installation.

## Features

- URL normalization for links without a scheme
- Risk score from 0 to 100
- Human-readable verdict: low, medium, or high risk
- Checks for suspicious TLDs, raw IP hosts, URL shorteners, punycode domains, userinfo tricks, long URLs, encoded characters, risky file extensions, suspicious keywords, and brand impersonation
- CLI output and JSON output
- Unit tests included

## Run

```powershell
python phishing_detector.py "http://paypal-login-security-update.example.xyz/verify/account"
```

Analyze multiple URLs:

```powershell
python phishing_detector.py --file sample_urls.txt
```

JSON output:

```powershell
python phishing_detector.py --file sample_urls.txt --json
```

Run tests:

```powershell
python -m unittest test_phishing_detector.py
```

## Example Output

```text
URL: http://paypal-login-security-update.example.xyz/verify/account
Normalized: http://paypal-login-security-update.example.xyz/verify/account
Host: paypal-login-security-update.example.xyz
Registered domain: example.xyz
Score: 64/100
Verdict: High risk
Findings:
  - [MEDIUM] +12: No HTTPS - Login or payment pages should use HTTPS.
  - [MEDIUM] +10: Risky top-level domain - The '.xyz' TLD appears often in low-reputation campaigns.
  - [MEDIUM] +14: Multiple suspicious keywords - Found phishing-themed words: account, login, security, update, verify.
  - [HIGH] +28: Possible brand impersonation - Mentions 'paypal' while using domain 'example.xyz', not an official known domain.
```

## How It Works

The detector uses explainable heuristics instead of live threat intelligence. That makes it useful as a learning project because every score can be traced back to visible URL features.

This is not a replacement for browser protections, DNS filtering, email security gateways, or real threat-intelligence feeds. Treat the result as a triage signal, not a final security decision.

## Safe Use

Only analyze URLs as text. Do not open suspicious links in your browser. If you expand this project later, use a controlled lab environment and avoid fetching unknown pages directly.

