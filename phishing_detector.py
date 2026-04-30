#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║         PHISHING AWARENESS TOOL — Cyber Security Intern      ║
║         Checks URL safety: HTTPS, domain age, patterns       ║
╚══════════════════════════════════════════════════════════════╝
"""

import re
import ssl
import socket
import whois
import requests
from datetime import datetime
from urllib.parse import urlparse
import argparse
import json


# ──────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────

SUSPICIOUS_KEYWORDS = [
    "login", "signin", "verify", "account", "update", "secure",
    "banking", "paypal", "amazon", "google", "apple", "microsoft",
    "ebay", "netflix", "confirm", "password", "credential",
    "support", "helpdesk", "free", "prize", "winner", "click",
    "urgent", "alert", "suspended", "limited", "unusual",
]

SUSPICIOUS_TLDS = [
    ".tk", ".ml", ".ga", ".cf", ".gq", ".xyz", ".top",
    ".click", ".link", ".work", ".date", ".review",
]

TRUSTED_DOMAINS = [
    "google.com", "facebook.com", "amazon.com", "apple.com",
    "microsoft.com", "paypal.com", "twitter.com", "github.com",
    "youtube.com", "instagram.com",
]

# Weights for risk scoring (out of 100)
RISK_WEIGHTS = {
    "no_https":             20,
    "ip_address":           20,
    "suspicious_keyword":   10,   # per keyword, capped at 20
    "suspicious_tld":       15,
    "url_too_long":         10,
    "too_many_subdomains":  10,
    "hyphen_in_domain":     10,
    "at_symbol":            15,
    "double_slash_redirect": 10,
    "new_domain":           20,   # < 6 months old
    "young_domain":         10,   # < 1 year old
    "punycode":             15,
    "misleading_brand":     20,
    "port_in_url":          10,
    "ssl_invalid":          15,
}


# ──────────────────────────────────────────────────────────────
# ANALYSIS FUNCTIONS
# ──────────────────────────────────────────────────────────────

def check_https(parsed_url: urlparse) -> dict:
    """Check if the URL uses HTTPS."""
    is_https = parsed_url.scheme == "https"
    return {
        "check": "HTTPS Protocol",
        "passed": is_https,
        "risk": 0 if is_https else RISK_WEIGHTS["no_https"],
        "detail": "✅ Uses HTTPS (encrypted)" if is_https else "❌ Uses HTTP — traffic is unencrypted",
    }


def check_ip_address(parsed_url: urlparse) -> dict:
    """Detect if host is a raw IP address (red flag)."""
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    is_ip = bool(ip_pattern.match(parsed_url.hostname or ""))
    return {
        "check": "IP Address as Host",
        "passed": not is_ip,
        "risk": RISK_WEIGHTS["ip_address"] if is_ip else 0,
        "detail": "❌ URL uses a raw IP address — legitimate sites use domain names" if is_ip
                  else "✅ Uses a proper domain name",
    }


def check_suspicious_keywords(parsed_url: urlparse) -> dict:
    """Search for phishing-related keywords in URL."""
    full_url = parsed_url.geturl().lower()
    found = [kw for kw in SUSPICIOUS_KEYWORDS if kw in full_url]
    risk = min(len(found) * RISK_WEIGHTS["suspicious_keyword"], 20)
    return {
        "check": "Suspicious Keywords",
        "passed": len(found) == 0,
        "risk": risk,
        "detail": f"✅ No suspicious keywords found" if not found
                  else f"⚠️  Suspicious keywords detected: {', '.join(found)}",
    }


def check_tld(parsed_url: urlparse) -> dict:
    """Check for suspicious top-level domains."""
    hostname = parsed_url.hostname or ""
    bad_tld = next((tld for tld in SUSPICIOUS_TLDS if hostname.endswith(tld)), None)
    return {
        "check": "Top-Level Domain (TLD)",
        "passed": bad_tld is None,
        "risk": RISK_WEIGHTS["suspicious_tld"] if bad_tld else 0,
        "detail": f"❌ High-risk TLD detected: {bad_tld}" if bad_tld else "✅ TLD appears normal",
    }


def check_url_length(url: str) -> dict:
    """Long URLs are often used to hide the real destination."""
    is_long = len(url) > 75
    return {
        "check": "URL Length",
        "passed": not is_long,
        "risk": RISK_WEIGHTS["url_too_long"] if is_long else 0,
        "detail": f"⚠️  URL is suspiciously long ({len(url)} chars)" if is_long
                  else f"✅ URL length is normal ({len(url)} chars)",
    }


def check_subdomains(parsed_url: urlparse) -> dict:
    """Too many subdomains can be used to spoof trusted brands."""
    hostname = parsed_url.hostname or ""
    parts = hostname.split(".")
    subdomain_count = len(parts) - 2
    too_many = subdomain_count > 2
    return {
        "check": "Subdomain Depth",
        "passed": not too_many,
        "risk": RISK_WEIGHTS["too_many_subdomains"] if too_many else 0,
        "detail": f"⚠️  {subdomain_count} subdomains — could be impersonation" if too_many
                  else f"✅ Subdomain depth is normal ({max(subdomain_count, 0)} subdomains)",
    }


def check_hyphen(parsed_url: urlparse) -> dict:
    """Hyphens in domain names are often phishing indicators."""
    hostname = parsed_url.hostname or ""
    # Only check main domain, not subdomains
    main_domain = ".".join(hostname.split(".")[-2:])
    has_hyphen = "-" in main_domain
    return {
        "check": "Hyphens in Domain",
        "passed": not has_hyphen,
        "risk": RISK_WEIGHTS["hyphen_in_domain"] if has_hyphen else 0,
        "detail": f"⚠️  Hyphens in domain name: {main_domain}" if has_hyphen
                  else "✅ No hyphens in primary domain",
    }


def check_at_symbol(url: str) -> dict:
    """@ symbol in URL tricks browsers into ignoring everything before it."""
    has_at = "@" in url
    return {
        "check": "@ Symbol in URL",
        "passed": not has_at,
        "risk": RISK_WEIGHTS["at_symbol"] if has_at else 0,
        "detail": "❌ @ symbol detected — browser will ignore everything before it!" if has_at
                  else "✅ No @ symbol in URL",
    }


def check_double_slash_redirect(url: str) -> dict:
    """Double slash after first segment can indicate redirect tricks."""
    path = url.split("://", 1)[-1]
    has_redirect = "//" in path
    return {
        "check": "Double-Slash Redirect",
        "passed": not has_redirect,
        "risk": RISK_WEIGHTS["double_slash_redirect"] if has_redirect else 0,
        "detail": "⚠️  Double slash in path — possible redirect trick" if has_redirect
                  else "✅ No suspicious redirect patterns",
    }


def check_punycode(parsed_url: urlparse) -> dict:
    """Punycode (xn--) domains are used for homograph attacks."""
    hostname = parsed_url.hostname or ""
    has_punycode = "xn--" in hostname
    return {
        "check": "Punycode / Homograph Attack",
        "passed": not has_punycode,
        "risk": RISK_WEIGHTS["punycode"] if has_punycode else 0,
        "detail": "❌ Punycode detected — possible homograph attack (fake look-alike characters)" if has_punycode
                  else "✅ No punycode/homograph patterns",
    }


def check_port(parsed_url: urlparse) -> dict:
    """Non-standard ports in URLs are suspicious."""
    port = parsed_url.port
    standard_ports = {80, 443, None}
    has_unusual_port = port not in standard_ports
    return {
        "check": "Non-Standard Port",
        "passed": not has_unusual_port,
        "risk": RISK_WEIGHTS["port_in_url"] if has_unusual_port else 0,
        "detail": f"⚠️  Non-standard port in URL: {port}" if has_unusual_port
                  else "✅ Standard port (or none specified)",
    }


def check_misleading_brand(parsed_url: urlparse) -> dict:
    """Check if a trusted brand name appears in subdomain/path (not main domain)."""
    hostname = parsed_url.hostname or ""
    parts = hostname.split(".")
    main_domain = ".".join(parts[-2:])
    subdomains = ".".join(parts[:-2]).lower()
    path = (parsed_url.path or "").lower()

    for brand in TRUSTED_DOMAINS:
        brand_name = brand.split(".")[0]
        # Legitimate: brand appears as main domain
        if brand == main_domain:
            continue
        # Suspicious: brand appears in subdomain or path
        if brand_name in subdomains or brand_name in path:
            return {
                "check": "Brand Impersonation",
                "passed": False,
                "risk": RISK_WEIGHTS["misleading_brand"],
                "detail": f"❌ Brand '{brand_name}' appears in subdomain/path — possible impersonation!",
            }

    return {
        "check": "Brand Impersonation",
        "passed": True,
        "risk": 0,
        "detail": "✅ No brand impersonation patterns detected",
    }


def check_ssl_certificate(hostname: str) -> dict:
    """Attempt to verify the SSL certificate of the host."""
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                expiry_str = cert.get("notAfter", "")
                expiry = datetime.strptime(expiry_str, "%b %d %H:%M:%S %Y %Z") if expiry_str else None
                days_left = (expiry - datetime.utcnow()).days if expiry else None
                if days_left is not None and days_left < 15:
                    return {
                        "check": "SSL Certificate",
                        "passed": False,
                        "risk": RISK_WEIGHTS["ssl_invalid"],
                        "detail": f"⚠️  SSL cert expires in {days_left} days — nearly expired",
                    }
                return {
                    "check": "SSL Certificate",
                    "passed": True,
                    "risk": 0,
                    "detail": f"✅ Valid SSL certificate (expires: {expiry_str})",
                }
    except ssl.SSLError:
        return {
            "check": "SSL Certificate",
            "passed": False,
            "risk": RISK_WEIGHTS["ssl_invalid"],
            "detail": "❌ SSL certificate is INVALID or self-signed",
        }
    except Exception as e:
        return {
            "check": "SSL Certificate",
            "passed": None,
            "risk": 0,
            "detail": f"⚠️  Could not verify SSL: {e}",
        }


def check_domain_age(hostname: str) -> dict:
    """Query WHOIS to determine how old the domain is."""
    try:
        w = whois.whois(hostname)
        creation_date = w.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        if not creation_date:
            return {
                "check": "Domain Age (WHOIS)",
                "passed": None,
                "risk": 10,
                "detail": "⚠️  Could not determine domain creation date",
            }
        if isinstance(creation_date, str):
            creation_date = datetime.strptime(creation_date, "%Y-%m-%d")

        age_days = (datetime.utcnow() - creation_date).days
        age_months = age_days // 30

        if age_days < 180:
            return {
                "check": "Domain Age (WHOIS)",
                "passed": False,
                "risk": RISK_WEIGHTS["new_domain"],
                "detail": f"❌ Domain is only {age_months} month(s) old — very new, high phishing risk",
            }
        elif age_days < 365:
            return {
                "check": "Domain Age (WHOIS)",
                "passed": False,
                "risk": RISK_WEIGHTS["young_domain"],
                "detail": f"⚠️  Domain is {age_months} month(s) old — relatively young",
            }
        else:
            years = age_days // 365
            return {
                "check": "Domain Age (WHOIS)",
                "passed": True,
                "risk": 0,
                "detail": f"✅ Domain is {years} year(s) old — established domain",
            }
    except Exception as e:
        return {
            "check": "Domain Age (WHOIS)",
            "passed": None,
            "risk": 0,
            "detail": f"⚠️  WHOIS lookup failed: {e}",
        }


# ──────────────────────────────────────────────────────────────
# SCORING & REPORTING
# ──────────────────────────────────────────────────────────────

def calculate_risk_level(score: int) -> tuple[str, str]:
    if score >= 60:
        return "🔴 HIGH RISK", "This URL exhibits multiple phishing indicators. Do NOT visit it."
    elif score >= 30:
        return "🟡 MEDIUM RISK", "This URL has some suspicious traits. Proceed with caution."
    else:
        return "🟢 LOW RISK", "This URL appears relatively safe, but stay vigilant."


def print_banner():
    print("""
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║   🛡️  PHISHING AWARENESS TOOL  |  Cyber Security Intern Project  ║
║                                                                  ║
║   Analyzes URLs for phishing indicators:                         ║
║   • HTTPS & SSL validation                                       ║
║   • Domain age via WHOIS                                         ║
║   • Suspicious patterns & brand impersonation                    ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
""")


def print_report(url: str, results: list[dict], total_risk: int):
    risk_label, recommendation = calculate_risk_level(total_risk)

    print(f"\n  🌐 URL ANALYZED: {url}")
    print(f"  {'─' * 62}")
    print(f"  {'CHECK':<35} {'STATUS':<10} {'RISK PTS'}")
    print(f"  {'─' * 62}")

    for r in results:
        status = "PASS" if r["passed"] else ("WARN" if r["passed"] is None else "FAIL")
        color  = "✅" if r["passed"] else ("⚠️ " if r["passed"] is None else "❌")
        print(f"  {r['check']:<35} {color} {status:<6}  +{r['risk']}")

    print(f"  {'─' * 62}")
    print(f"\n  📋 DETAILS:")
    for r in results:
        print(f"     {r['detail']}")

    print(f"\n  {'═' * 62}")
    print(f"  TOTAL RISK SCORE : {total_risk} / 100+")
    print(f"  VERDICT          : {risk_label}")
    print(f"  RECOMMENDATION   : {recommendation}")
    print(f"  {'═' * 62}\n")


def export_json(url: str, results: list[dict], total_risk: int, filepath: str):
    risk_label, recommendation = calculate_risk_level(total_risk)
    report = {
        "url": url,
        "analyzed_at": datetime.utcnow().isoformat() + "Z",
        "total_risk_score": total_risk,
        "verdict": risk_label,
        "recommendation": recommendation,
        "checks": results,
    }
    with open(filepath, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  📁 Report saved to: {filepath}")


# ──────────────────────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ──────────────────────────────────────────────────────────────

def analyze_url(url: str) -> tuple[list[dict], int]:
    """Run all checks against the URL and return results + total risk score."""

    # Normalize: add scheme if missing
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)
    hostname = parsed.hostname or ""

    checks = [
        check_https(parsed),
        check_ip_address(parsed),
        check_suspicious_keywords(parsed),
        check_tld(parsed),
        check_url_length(url),
        check_subdomains(parsed),
        check_hyphen(parsed),
        check_at_symbol(url),
        check_double_slash_redirect(url),
        check_punycode(parsed),
        check_port(parsed),
        check_misleading_brand(parsed),
        check_ssl_certificate(hostname),
        check_domain_age(hostname),
    ]

    total_risk = sum(c["risk"] for c in checks)
    return checks, total_risk


def main():
    parser = argparse.ArgumentParser(
        description="Phishing Awareness Tool — analyze URLs for threats"
    )
    parser.add_argument("url", nargs="?", help="URL to analyze")
    parser.add_argument("--json", metavar="FILE", help="Export report as JSON")
    parser.add_argument("--batch", metavar="FILE",
                        help="Analyze multiple URLs from a text file (one per line)")
    args = parser.parse_args()

    print_banner()

    urls_to_check = []

    if args.batch:
        try:
            with open(args.batch) as f:
                urls_to_check = [line.strip() for line in f if line.strip()]
            print(f"  📂 Batch mode: {len(urls_to_check)} URLs loaded from {args.batch}\n")
        except FileNotFoundError:
            print(f"  ❌ Batch file not found: {args.batch}")
            return
    elif args.url:
        urls_to_check = [args.url]
    else:
        # Interactive mode
        print("  Enter a URL to analyze (or 'quit' to exit):")
        while True:
            try:
                user_input = input("\n  🔍 URL > ").strip()
                if user_input.lower() in ("quit", "exit", "q"):
                    print("\n  👋 Stay safe online!\n")
                    break
                if not user_input:
                    continue

                print("\n  ⏳ Analyzing...\n")
                results, risk = analyze_url(user_input)
                print_report(user_input, results, risk)

                if args.json:
                    export_json(user_input, results, risk, args.json)

            except KeyboardInterrupt:
                print("\n\n  👋 Stay safe online!\n")
                break
        return

    # Non-interactive mode
    for url in urls_to_check:
        print(f"\n  ⏳ Analyzing: {url}\n")
        results, risk = analyze_url(url)
        print_report(url, results, risk)

    if args.json and len(urls_to_check) == 1:
        export_json(urls_to_check[0], results, risk, args.json)


if __name__ == "__main__":
    main()
