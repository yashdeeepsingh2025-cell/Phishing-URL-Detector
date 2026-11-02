
from urllib.parse import urlparse
import ipaddress

# Suspicious words commonly found in phishing URLs
SUSPICIOUS_WORDS = [
    "login",
    "verify",
    "update",
    "password",
    "account",
    "signin",
    "bank",
    "confirm",
    "secure"
]

# Common URL shortener domains
SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "ow.ly"
]


def analyze_url(url):

    score = 0
    warnings = []

    # Add a default scheme if missing
    if "://" not in url:
        url = "https://" + url

    try:
        parsed = urlparse(url)

        hostname = parsed.hostname

        if parsed.scheme not in ("http", "https"):
            return None, ["Unsupported URL scheme"]

        if not hostname:
            return None, ["Invalid URL or missing domain"]

    except ValueError:
        return None, ["Invalid URL format"]

    # 1. Check HTTPS
    if parsed.scheme != "https":
        score += 1
        warnings.append("Website does not use HTTPS")

    # 2. Check IP address
    try:
        ipaddress.ip_address(hostname)
        score += 2
        warnings.append("URL uses an IP address instead of a domain")
    except ValueError:
        pass

    # 3. Check suspicious keywords
    text_to_check = (
        hostname + parsed.path + parsed.query
    ).lower()

    if any(word in text_to_check for word in SUSPICIOUS_WORDS):
        score += 1
        warnings.append("Suspicious keyword detected")

    # 4. Check URL length
    if len(url) > 100:
        score += 1
        warnings.append("Unusually long URL")

    # 5. Check too many subdomains
    subdomains = hostname.split(".")

    if len(subdomains) > 4:
        score += 1
        warnings.append("Too many subdomains")

    # 6. Check special @ character
    if parsed.username is not None or parsed.password is not None:
        score += 2
        warnings.append("URL contains user information before the domain")

    # 7. Check punycode
    if any(part.startswith("xn--") for part in subdomains):
        score += 2
        warnings.append("Internationalized domain encoding detected")

    # 8. Check URL shorteners
    if hostname.lower() in SHORTENERS:
        score += 2
        warnings.append("URL shortening service detected")

    # Final risk classification
    if score >= 4:
        result = "HIGH RISK"
    elif score >= 2:
        result = "MEDIUM RISK"
    else:
        result = "LOW RISK"

    return (score, result), warnings


# Main program
print("=" * 45)
print("       PHISHING URL DETECTOR")
print("=" * 45)

while True:

    url = input("\nEnter URL (or q to quit): ").strip()

    if url.lower() == "q":
        print("Thank you for using Phishing Detector!")
        break

    if not url:
        print("Please enter a URL.")
        continue

    result, warnings = analyze_url(url)

    if result is None:
        print("\nInvalid URL:")
        for warning in warnings:
            print("-", warning)
        continue

    score, risk = result

    print("\n---------- SCAN RESULT ----------")
    print("Entered URL:", url)
    print("Risk Score:", score)
    print("Risk Level:", risk)

    if warnings:
        print("\nWarnings:")
        for warning in warnings:
            print("-", warning)
    else:
        print("No obvious suspicious signs detected.")

    print("--------------------------------")