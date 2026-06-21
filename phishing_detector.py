#!/usr/bin/env python3
"""
Phishing URL Detector

A small, offline URL risk analyzer for portfolio and learning use.
It uses transparent heuristics instead of a live threat feed so the output is
easy to explain in interviews and safe to run locally.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import re
from dataclasses import asdict, dataclass
from typing import Iterable
from urllib.parse import parse_qs, unquote, urlparse


SUSPICIOUS_KEYWORDS = {
    "account",
    "bank",
    "billing",
    "confirm",
    "crypto",
    "free",
    "gift",
    "login",
    "password",
    "secure",
    "security",
    "signin",
    "support",
    "update",
    "verify",
    "wallet",
}

SUSPICIOUS_TLDS = {
    "biz",
    "cf",
    "click",
    "ga",
    "gq",
    "link",
    "ml",
    "mom",
    "rest",
    "ru",
    "tk",
    "top",
    "work",
    "xyz",
    "zip",
}

BRAND_DOMAINS = {
    "amazon": {"amazon.com", "amazon.in"},
    "apple": {"apple.com"},
    "chase": {"chase.com"},
    "facebook": {"facebook.com", "fb.com"},
    "google": {"google.com", "google.co.in"},
    "instagram": {"instagram.com"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "outlook.com"},
    "netflix": {"netflix.com"},
    "paypal": {"paypal.com"},
    "whatsapp": {"whatsapp.com"},
}

SHORTENER_DOMAINS = {
    "bit.ly",
    "cutt.ly",
    "goo.gl",
    "is.gd",
    "ow.ly",
    "rebrand.ly",
    "shorturl.at",
    "t.co",
    "tinyurl.com",
}

EXECUTABLE_EXTENSIONS = {
    ".apk",
    ".bat",
    ".cmd",
    ".exe",
    ".js",
    ".msi",
    ".scr",
    ".vbs",
    ".zip",
}


@dataclass(frozen=True)
class Finding:
    severity: str
    points: int
    title: str
    detail: str


@dataclass(frozen=True)
class Analysis:
    url: str
    normalized_url: str
    score: int
    verdict: str
    host: str
    registered_domain: str
    findings: list[Finding]


def normalize_url(raw_url: str) -> str:
    raw_url = raw_url.strip()
    if not raw_url:
        return raw_url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", raw_url):
        return f"http://{raw_url}"
    return raw_url


def get_host(parsed_url) -> str:
    host = parsed_url.hostname or ""
    return host.rstrip(".").lower()


def registered_domain(host: str) -> str:
    if is_ip_address(host):
        return host
    parts = [part for part in host.split(".") if part]
    if len(parts) < 2:
        return host
    return ".".join(parts[-2:])


def tld_of(host: str) -> str:
    parts = [part for part in host.split(".") if part]
    return parts[-1] if parts else ""


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address(host.strip("[]"))
        return True
    except ValueError:
        return False


def levenshtein_distance(left: str, right: str) -> int:
    if left == right:
        return 0
    if not left:
        return len(right)
    if not right:
        return len(left)

    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        for j, right_char in enumerate(right, start=1):
            insert_cost = current[j - 1] + 1
            delete_cost = previous[j] + 1
            replace_cost = previous[j - 1] + (left_char != right_char)
            current.append(min(insert_cost, delete_cost, replace_cost))
        previous = current
    return previous[-1]


def add(finding_list: list[Finding], severity: str, points: int, title: str, detail: str) -> None:
    finding_list.append(Finding(severity=severity, points=points, title=title, detail=detail))


def detect_brand_impersonation(host: str, parsed_url, root_domain: str) -> list[Finding]:
    findings: list[Finding] = []
    searchable_text = f"{host} {unquote(parsed_url.path)} {unquote(parsed_url.query)}".lower()
    host_labels = [label for label in host.split(".") if label]
    root_label = root_domain.split(".")[0] if root_domain else ""

    for brand, allowed_domains in BRAND_DOMAINS.items():
        if root_domain in allowed_domains:
            continue

        if brand in searchable_text:
            add(
                findings,
                "high",
                28,
                "Possible brand impersonation",
                f"Mentions '{brand}' while using domain '{root_domain}', not an official known domain.",
            )
            continue

        for label in host_labels:
            if abs(len(label) - len(brand)) <= 1 and levenshtein_distance(label, brand) == 1:
                add(
                    findings,
                    "high",
                    25,
                    "Possible typosquatting",
                    f"Domain label '{label}' is very close to the brand name '{brand}'.",
                )
                break

        if root_label and brand in root_label and root_label != brand:
            add(
                findings,
                "medium",
                12,
                "Brand-like domain label",
                f"The registered domain starts with or contains '{brand}' but is not in the allowlist.",
            )

    return findings


def analyze_url(raw_url: str) -> Analysis:
    normalized = normalize_url(raw_url)
    parsed = urlparse(normalized)
    host = get_host(parsed)
    root_domain = registered_domain(host)
    findings: list[Finding] = []

    if not raw_url.strip():
        add(findings, "high", 100, "Empty input", "No URL was provided.")
        return build_analysis(raw_url, normalized, host, root_domain, findings)

    if not parsed.scheme or not host:
        add(findings, "high", 70, "Malformed URL", "The input could not be parsed as a valid URL.")
        return build_analysis(raw_url, normalized, host, root_domain, findings)

    if parsed.scheme not in {"http", "https"}:
        add(findings, "medium", 15, "Unusual scheme", f"URL uses '{parsed.scheme}' instead of http or https.")

    if parsed.scheme == "http":
        add(findings, "medium", 12, "No HTTPS", "Login or payment pages should use HTTPS.")

    if "@" in parsed.netloc:
        add(findings, "high", 30, "Userinfo trick", "Text before '@' can hide the real destination host.")

    if is_ip_address(host):
        add(findings, "high", 25, "IP address host", "Phishing links often use raw IP addresses instead of domains.")

    if host.startswith("xn--") or ".xn--" in host:
        add(findings, "medium", 18, "Punycode domain", "Internationalized domains can be used for lookalike attacks.")

    tld = tld_of(host)
    if tld in SUSPICIOUS_TLDS:
        add(findings, "medium", 10, "Risky top-level domain", f"The '.{tld}' TLD appears often in low-reputation campaigns.")

    if root_domain in SHORTENER_DOMAINS:
        add(findings, "medium", 15, "URL shortener", "Short links hide the final destination.")

    if len(normalized) > 120:
        add(findings, "medium", 15, "Very long URL", "Long URLs can hide suspicious parameters or misleading text.")
    elif len(normalized) > 75:
        add(findings, "low", 7, "Long URL", "The URL is longer than typical human-readable links.")

    host_parts = [part for part in host.split(".") if part]
    if len(host_parts) >= 5:
        add(findings, "medium", 12, "Many subdomains", "Deep subdomain chains can obscure the real registered domain.")

    root_label = root_domain.split(".")[0] if root_domain else ""
    if root_label and not is_ip_address(host) and "-" in root_label:
        add(findings, "low", 6, "Hyphenated domain", "Hyphens are common in disposable or impersonation domains.")

    if root_label and not is_ip_address(host) and any(char.isdigit() for char in root_label):
        add(findings, "low", 6, "Digits in domain", "Numbers can be used to imitate letters in brand names.")

    decoded_path = unquote(parsed.path).lower()
    if any(decoded_path.endswith(ext) for ext in EXECUTABLE_EXTENSIONS):
        add(findings, "high", 28, "Downloadable executable/archive", "The URL points to a file type commonly abused for malware delivery.")

    if "%" in normalized:
        add(findings, "low", 6, "Encoded characters", "Encoded characters can make a destination harder to inspect.")

    if "//" in parsed.path:
        add(findings, "low", 5, "Extra slashes in path", "Repeated slashes can be used to make URLs harder to read.")

    query_params = parse_qs(parsed.query, keep_blank_values=True)
    if len(query_params) >= 6:
        add(findings, "low", 7, "Many query parameters", "Large query strings can hide redirect or tracking behavior.")

    searchable_text = f"{host} {decoded_path} {unquote(parsed.query).lower()}"
    keyword_hits = sorted(keyword for keyword in SUSPICIOUS_KEYWORDS if keyword in searchable_text)
    if len(keyword_hits) >= 3:
        add(
            findings,
            "medium",
            14,
            "Multiple suspicious keywords",
            f"Found phishing-themed words: {', '.join(keyword_hits[:6])}.",
        )
    elif keyword_hits:
        add(
            findings,
            "low",
            5,
            "Suspicious keyword",
            f"Found phishing-themed word(s): {', '.join(keyword_hits)}.",
        )

    findings.extend(detect_brand_impersonation(host, parsed, root_domain))

    if not findings:
        add(findings, "info", 0, "No obvious red flags", "No heuristic checks were triggered.")

    return build_analysis(raw_url, normalized, host, root_domain, findings)


def build_analysis(raw_url: str, normalized: str, host: str, root_domain: str, findings: list[Finding]) -> Analysis:
    score = min(100, sum(finding.points for finding in findings))
    if score >= 60:
        verdict = "High risk"
    elif score >= 30:
        verdict = "Medium risk"
    else:
        verdict = "Low risk"

    return Analysis(
        url=raw_url,
        normalized_url=normalized,
        score=score,
        verdict=verdict,
        host=host,
        registered_domain=root_domain,
        findings=findings,
    )


def format_report(analysis: Analysis) -> str:
    lines = [
        f"URL: {analysis.url}",
        f"Normalized: {analysis.normalized_url}",
        f"Host: {analysis.host or '(none)'}",
        f"Registered domain: {analysis.registered_domain or '(none)'}",
        f"Score: {analysis.score}/100",
        f"Verdict: {analysis.verdict}",
        "Findings:",
    ]
    for finding in analysis.findings:
        lines.append(f"  - [{finding.severity.upper()}] +{finding.points}: {finding.title} - {finding.detail}")
    return "\n".join(lines)


def iter_input_urls(args: argparse.Namespace) -> Iterable[str]:
    if args.url:
        yield args.url
    if args.file:
        with open(args.file, "r", encoding="utf-8") as handle:
            for line in handle:
                stripped = line.strip()
                if stripped and not stripped.startswith("#"):
                    yield stripped


def main() -> int:
    parser = argparse.ArgumentParser(description="Offline phishing URL risk analyzer.")
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("-f", "--file", help="Text file with one URL per line")
    parser.add_argument("--json", action="store_true", help="Print JSON output")
    args = parser.parse_args()

    urls = list(iter_input_urls(args))
    if not urls:
        parser.error("provide a URL or use --file")

    analyses = [analyze_url(url) for url in urls]
    if args.json:
        print(json.dumps([asdict(analysis) for analysis in analyses], indent=2))
        return 0

    for index, analysis in enumerate(analyses):
        if index:
            print("\n" + "-" * 72 + "\n")
        print(format_report(analysis))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
