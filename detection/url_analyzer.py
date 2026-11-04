
import re
import ipaddress
from urllib.parse import urlparse, unquote


# Common URL shortener domains
SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "shorturl.at",
    "ow.ly"
}


def extract_urls(text):
    """Extract URLs from email text."""

    pattern = r'https?://[^\s<>"\']+'

    urls = re.findall(pattern, text or "", re.IGNORECASE)

    # Remove common trailing punctuation
    return [
        url.rstrip(".,;:!?)]}")
        for url in urls
    ]


def analyze_url(url):
    """Analyze a URL for suspicious characteristics."""

    findings = []

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname

        if not hostname:
            return {
                "url": url,
                "suspicious": True,
                "findings": ["Invalid or missing hostname"]
            }

        hostname = hostname.lower()

        # Check for IP address instead of domain
        try:
            ipaddress.ip_address(hostname)
            findings.append("URL uses an IP address instead of a domain")
        except ValueError:
            pass

        # Check for URL shorteners
        if hostname in SHORTENERS:
            findings.append("URL uses a known shortening service")

        # Check for unusual URL length
        if len(url) > 150:
            findings.append("Unusually long URL")

        # Check for excessive subdomains
        if hostname.count(".") >= 4:
            findings.append("Unusually high number of subdomains")

        # Check for deceptive @ symbol in URL
        if "@" in parsed.netloc:
            findings.append("URL contains user information before hostname")

        # Check for suspicious keywords
        suspicious_words = [
            "login",
            "verify",
            "account",
            "secure",
            "password",
            "update",
            "confirm"
        ]

        decoded_url = unquote(url).lower()

        for word in suspicious_words:
            if word in decoded_url:
                findings.append(
                    f"URL contains potentially sensitive keyword: {word}"
                )

        # Check for non-standard port
        if parsed.port and parsed.port not in [80, 443]:
            findings.append("URL uses a non-standard port")

    except ValueError:
        findings.append("Malformed URL")

    return {
        "url": url,
        "suspicious": len(findings) > 0,
        "findings": findings
    }


def analyze_email_urls(email_text):
    """Extract and analyze all URLs in an email."""

    urls = extract_urls(email_text)

    results = [
        analyze_url(url)
        for url in urls
    ]

    return {
        "total_urls": len(urls),
        "suspicious_urls": sum(
            1 for result in results if result["suspicious"]
        ),
        "results": results
    }
