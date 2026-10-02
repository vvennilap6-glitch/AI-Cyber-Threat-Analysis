import socket
import ipaddress
from urllib.parse import urlparse


def analyze_domain(target):
    target = target.strip()

    # Allow both domain names and URLs
    if "://" not in target:
        target = "https://" + target

    parsed = urlparse(target)
    domain = parsed.netloc.split(":")[0].lower()

    result = {
        "domain": domain,
        "ip_addresses": [],
        "is_ip": False,
        "suspicious_indicators": [],
        "risk_score": 0,
        "classification": "Likely Safe"
    }

    # Check if target itself is an IP
    try:
        ipaddress.ip_address(domain)
        result["is_ip"] = True
        result["ip_addresses"] = [domain]

        result["risk_score"] += 20
        result["suspicious_indicators"].append(
            "⚠️ Target is an IP address instead of a domain name"
        )

    except ValueError:

        # DNS lookup
        try:
            addresses = socket.getaddrinfo(
                domain,
                None
            )

            ips = sorted(
                set(
                    address[4][0]
                    for address in addresses
                )
            )

            result["ip_addresses"] = ips

        except socket.gaierror:

            result["risk_score"] += 30

            result["suspicious_indicators"].append(
                "🚨 Domain could not be resolved through DNS"
            )

    # Suspicious domain characteristics
    if len(domain) > 40:

        result["risk_score"] += 10

        result["suspicious_indicators"].append(
            "⚠️ Unusually long domain name"
        )

    suspicious_words = [
        "login",
        "verify",
        "secure",
        "account",
        "update",
        "password",
        "bank"
    ]

    detected_words = [
        word
        for word in suspicious_words
        if word in domain
    ]

    if detected_words:

        result["risk_score"] += min(
            len(detected_words) * 5,
            20
        )

        result["suspicious_indicators"].append(
            "⚠️ Suspicious keywords detected: "
            + ", ".join(detected_words)
        )

    # Final risk limit
    result["risk_score"] = min(
        result["risk_score"],
        100
    )

    if result["risk_score"] >= 60:

        result["classification"] = "Potentially Malicious"

    elif result["risk_score"] >= 30:

        result["classification"] = "Suspicious"

    else:

        result["classification"] = "Likely Safe"

    return result