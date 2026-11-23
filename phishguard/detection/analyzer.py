"""Heuristic phishing analyzer for the awareness/defense side of PhishGuard.

The analyzer scores URLs and raw email messages for indicators commonly
associated with phishing. It intentionally avoids machine learning so that
every finding is explainable — useful when the output is used to teach people
*why* something looks suspicious.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional
from urllib.parse import urlparse

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq", "top", "xyz", "click", "download", "zip",
    "review", "work", "rest", "link", "buzz", "icu", "monster", "country",
    "stream", "racing", "accountant", "date", "faith", "loan", "men", "win",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "rb.gy", "cutt.ly", "is.gd",
    "buff.ly", "ow.ly", "s.id", "rebrand.ly", "shorturl.at",
}

TRUSTED_BRANDS = {
    "paypal", "microsoft", "apple", "amazon", "google", "netflix", "facebook",
    "instagram", "linkedin", "dropbox", "adobe", "bankofamerica", "wellsfargo",
    "chase", "dhl", "fedex", "ups", "irs", "office365", "outlook",
}

BRAND_DOMAINS = {
    "paypal": "paypal.com",
    "microsoft": "microsoft.com",
    "apple": "apple.com",
    "amazon": "amazon.com",
    "google": "google.com",
    "netflix": "netflix.com",
    "facebook": "facebook.com",
    "instagram": "instagram.com",
    "linkedin": "linkedin.com",
    "dropbox": "dropbox.com",
    "adobe": "adobe.com",
    "bankofamerica": "bankofamerica.com",
    "wellsfargo": "wellsfargo.com",
    "chase": "chase.com",
    "dhl": "dhl.com",
    "fedex": "fedex.com",
    "ups": "ups.com",
    "irs": "irs.gov",
    "office365": "office365.com",
    "outlook": "outlook.com",
}

URGENCY_PATTERNS = [
    r"act(?:ion)?\s+(?:now|immediately)",
    r"within\s+\d+\s*hours?",
    r"within\s+\d+\s*days?",
    r"your\s+account\s+(?:will\s+be|has\s+been)\s+(?:suspended|locked|closed|limited)",
    r"verify\s+(?:your\s+)?account",
    r"update\s+(?:your\s+)?(?:password|payment|billing)",
    r"confirm\s+(?:your\s+)?(?:identity|details)",
    r"suspicious\s+(?:activity|login|sign-?in)",
    r"unusual\s+(?:activity|login|sign-?in)",
    r"expire[sd]?\s+soon",
    r"final\s+(?:warning|notice)",
    r"urgent",
]

RISKY_ATTACHMENT_EXTS = {".exe", ".scr", ".js", ".vbs", ".vbe", ".iso", ".docm",
                        ".xlsm", ".pptm", ".hta", ".jar", ".bat", ".cmd", ".ps1"}

SEVERITY_WEIGHTS = {"critical": 70, "high": 30, "medium": 20, "low": 10, "info": 0}


@dataclass
class Finding:
    severity: str
    message: str


@dataclass
class AnalysisResult:
    score: int = 0
    findings: List[Finding] = field(default_factory=list)
    verdict: str = "Likely Safe"

    def as_dict(self) -> Dict:
        return {
            "score": self.score,
            "verdict": self.verdict,
            "findings": [
                {"severity": f.severity, "message": f.message} for f in self.findings
            ],
        }


class _Scorer:
    def __init__(self) -> None:
        self.score = 0
        self.findings: List[Finding] = []

    def add(self, severity: str, message: str, weight: Optional[int] = None) -> None:
        self.findings.append(Finding(severity, message))
        self.score += weight if weight is not None else SEVERITY_WEIGHTS.get(severity, 0)

    def result(self) -> AnalysisResult:
        self.score = min(self.score, 100)
        if self.score >= 70:
            verdict = "Likely Phishing"
        elif self.score >= 40:
            verdict = "Suspicious"
        else:
            verdict = "Likely Safe"
        return AnalysisResult(score=self.score, findings=self.findings, verdict=verdict)


def analyze_url(url: str) -> AnalysisResult:
    s = _Scorer()
    url = (url or "").strip()
    if not url:
        s.add("info", "No URL provided")
        return s.result()

    try:
        parsed = urlparse(url if "://" in url else f"http://{url}")
    except ValueError:
        s.add("high", "Malformed URL")
        return s.result()

    host = parsed.hostname or ""
    host_lower = host.lower()
    tld = host_lower.rsplit(".", 1)[-1] if "." in host_lower else ""

    if parsed.scheme == "http":
        s.add("low", "Uses plain HTTP instead of HTTPS")

    if host and _is_ip(host):
        s.add("critical", "Uses a raw IP address instead of a domain name")

    if parsed.username or "@" in url:
        s.add("high", "URL contains '@' (userinfo trick can hide the real domain)")

    if host_lower.startswith("xn--"):
        s.add("high", "Uses a punycode/IDN homograph domain")

    if tld in SUSPICIOUS_TLDS:
        s.add("medium", f"Uncommon top-level domain (.{tld})")

    if host_lower in URL_SHORTENERS:
        s.add("medium", "Uses a known URL shortener (destination is hidden)", weight=40)

    is_ip_host = _is_ip(host)
    if not is_ip_host:
        subdomains = host_lower.count(".") - (0 if tld else 1)
        if subdomains >= 3:
            s.add("low", f"Many subdomains ({subdomains})")

        if len(host_lower) > 50:
            s.add("low", "Unusually long hostname")

        brand = _brand_in_host(host_lower)
        if brand:
            official = BRAND_DOMAINS.get(brand)
            if official and official not in host_lower:
                # e.g. "paypal.secure-login.com" or "paypal-security.example.com"
                s.add("critical", f"Domain impersonates '{brand}' (official domain is '{official}')")

    return s.result()


def analyze_email(headers: Dict[str, str], body: str = "", links: Optional[List[str]] = None) -> AnalysisResult:
    s = _Scorer()

    subject = headers.get("Subject", "")
    from_header = headers.get("From", "")
    reply_to = headers.get("Reply-To", "")
    spf = headers.get("Authentication-Results", "") or headers.get("Received-SPF", "")

    text = f"{subject}\n{body}".lower()
    for pattern in URGENCY_PATTERNS:
        if re.search(pattern, text):
            s.add("medium", f"Urgency/pressure language: {pattern}")
            break

    if re.search(r"dear\s+(customer|user|member|client|sir|madam)", text):
        s.add("low", "Generic greeting (not addressed by name)")

    if re.search(r"(log\s*in|verify|confirm|password|credential|banking|payment)", text):
        s.add("medium", "Requests sensitive action or credentials")

    if reply_to and _extract_domain(from_header) != _extract_domain(reply_to):
        s.add("high", "Reply-To domain differs from From domain")

    if _display_name_domain_mismatch(from_header):
        s.add("high", "Display name domain does not match the actual From domain")

    if spf:
        auth_failures = re.findall(r"(spf|dkim|dmarc)=fail", spf, re.IGNORECASE)
        if auth_failures:
            if set(auth_failures) >= {"spf", "dkim", "dmarc"}:
                s.add("critical", "Email failed SPF, DKIM, and DMARC authentication")
            else:
                s.add("high", f"Email failed authentication: {', '.join(auth_failures)}")
    else:
        s.add("info", "No SPF/DKIM/DMARC authentication headers present")

    for link in links or []:
        result = analyze_url(link)
        s.findings.extend(result.findings)
        s.score = min(s.score + result.score, 100)

    for att in _attachment_extensions(body):
        if att in RISKY_ATTACHMENT_EXTS:
            s.add("high", f"Risky attachment type detected ({att})")

    if not (links or []):
        s.add("info", "No links found in message body")

    return s.result()


def _is_ip(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _brand_in_host(host: str) -> Optional[str]:
    for brand in TRUSTED_BRANDS:
        if brand in host:
            return brand
    return None


def _extract_domain(address: str) -> str:
    match = re.search(r"@([^@\s>]+)", address)
    if match:
        return match.group(1).lower()
    return (address or "").lower()


def _display_name_domain_mismatch(from_header: str) -> bool:
    match = re.match(r'^\s*"?([^"@<]+?)"?\s*<([^>]+)>', from_header or "")
    if not match:
        return False
    display_name = match.group(1)
    email = match.group(2)
    brand = _brand_in_host(display_name.lower())
    if not brand:
        return False
    email_domain = _extract_domain(email)
    official = BRAND_DOMAINS.get(brand)
    return official is not None and official not in email_domain


def _attachment_extensions(body: str) -> List[str]:
    found = set()
    for match in re.finditer(r'filename="?([^"\s]+)"?', body, re.IGNORECASE):
        name = match.group(1)
        dot = name.rfind(".")
        if dot != -1:
            found.add(name[dot:].lower())
    return sorted(found)
