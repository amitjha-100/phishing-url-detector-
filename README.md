
# Phishing URL Detector  


An offline phishing URL risk analyzer written in Python.

## Features

* URL normalization
* Suspicious TLD detection
* Brand impersonation detection
* Typosquatting detection
* URL shortener detection
* Punycode detection
* Executable download detection
* Risk scoring

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/phishing-url-detector.git
cd phishing-url-detector
python phishing_detector.py google.com
```

## Example

```bash
python phishing_detector.py https://paypal-login.xyz/login
```

Output:

```text
Score: 68/100
Verdict: High risk
```

## Disclaimer

This project uses heuristic analysis and is intended for educational purposes. It is not a replacement for commercial threat intelligence feeds.
