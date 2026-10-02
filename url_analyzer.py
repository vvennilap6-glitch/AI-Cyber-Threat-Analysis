import re
from urllib.parse import urlparse

from model import predict_url


# =========================================================
# URL THREAT ANALYZER
# =========================================================

def analyze_url(url):

    # -----------------------------------------------------
    # INITIALIZATION
    # -----------------------------------------------------

    url = url.strip()

    if not url:
        raise ValueError("Please enter a URL.")

    # Add HTTPS if user enters only a domain
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    parsed = urlparse(url)

    if not parsed.netloc or not parsed.hostname:
        raise ValueError("Please enter a valid URL.")

    risk_score = 0
    findings = []

    hostname = parsed.hostname.lower()
    path = parsed.path.lower()


    # =====================================================
    # AI MODEL PREDICTION
    # =====================================================

    ai_result = "Unknown"
    ai_confidence = 0.0

    try:

        prediction = predict_url(url)

        if isinstance(prediction, dict):

            ai_result = prediction.get(
                "prediction",
                prediction.get(
                    "classification",
                    "Unknown"
                )
            )

            ai_confidence = float(
                prediction.get(
                    "confidence",
                    0.0
                )
            )

        elif isinstance(prediction, (tuple, list)):

            ai_result = str(prediction[0])

            if len(prediction) > 1:

                ai_confidence = float(
                    prediction[1]
                )

        else:

            ai_result = str(prediction)

    except Exception:

        findings.append(
            "⚠️ AI model prediction could not be completed."
        )


    # =====================================================
    # HTTP CHECK
    # =====================================================

    if parsed.scheme.lower() == "http":

        risk_score += 15

        findings.append(
            f"⚠️ Insecure HTTP link detected: {hostname}"
        )


    # =====================================================
    # IP ADDRESS CHECK
    # =====================================================

    ip_pattern = (
        r"^\d{1,3}"
        r"(?:\.\d{1,3}){3}$"
    )

    if re.match(ip_pattern, hostname):

        risk_score += 30

        findings.append(
            f"🚨 URL uses an IP address instead of a domain: "
            f"{hostname}"
        )


    # =====================================================
    # @ SYMBOL CHECK
    # =====================================================

    # @ in a URL can hide the real destination.
    # Example:
    # trusted-site.com@evil-site.com

    if "@" in parsed.netloc:

        risk_score += 40

        findings.append(
            "🚨 URL contains '@' symbol and may hide "
            "the actual destination"
        )


    # =====================================================
    # SUSPICIOUS DOMAIN TERMS
    # =====================================================

    suspicious_terms = [

        "login",
        "secure",
        "security",
        "verify",
        "account",
        "update",
        "confirm",
        "signin",
        "password",
        "banking"

    ]

    detected_terms = []

    for term in suspicious_terms:

        if term in hostname:

            detected_terms.append(term)

    if detected_terms:

        risk_score += min(
            len(detected_terms) * 3,
            10
        )

        findings.append(
            "⚠️ Security-related terms detected in domain: "
            + ", ".join(detected_terms)
        )


    # =====================================================
    # MULTIPLE SUBDOMAIN CHECK
    # =====================================================

    domain_parts = hostname.split(".")

    if len(domain_parts) >= 5:

        risk_score += 8

        findings.append(
            "⚠️ Multiple subdomains detected"
        )


    # =====================================================
    # LONG URL CHECK
    # =====================================================

    if len(url) > 150:

        risk_score += 5

        findings.append(
            "⚠️ Unusually long URL detected"
        )


    # =====================================================
    # SUSPICIOUS ENCODING / PATTERNS
    # =====================================================

    suspicious_patterns = [

        "%40",
        "%2f",
        "%2e",
        "--"

    ]

    for pattern in suspicious_patterns:

        if pattern in url.lower():

            risk_score += 5

            findings.append(
                f"⚠️ Suspicious URL pattern detected: {pattern}"
            )


    # =====================================================
    # ACCOUNT / AUTHENTICATION PATH CHECK
    # =====================================================

    account_paths = [

        "login",
        "signin",
        "account",
        "verify",
        "password",
        "session",
        "authenticate"

    ]

    for term in account_paths:

        if term in path:

            risk_score += 5

            findings.append(
                f"⚠️ Account or authentication-related "
                f"URL path detected: {term}"
            )

            break


    # =====================================================
    # AI SUPPORTING EVIDENCE
    # =====================================================

    ai_text = ai_result.lower()

    malicious_ai_labels = [

        "phishing",
        "malicious",
        "potentially malicious",
        "suspicious"

    ]

    ai_detected_malicious = any(
        label in ai_text
        for label in malicious_ai_labels
    )

    if ai_detected_malicious:

        # AI contributes to the risk score,
        # but rule-based checks remain important.

        if ai_confidence >= 95:

            risk_score += 25

        elif ai_confidence >= 80:

            risk_score += 15

        else:

            risk_score += 8

        findings.append(
            f"🤖 AI model detected phishing-like URL "
            f"characteristics ({ai_confidence:.2f}% confidence)."
        )


    # =====================================================
    # DANGEROUS COMBINATIONS
    # =====================================================

    has_at_symbol = "@" in parsed.netloc

    has_auth_path = any(
        term in path
        for term in account_paths
    )

    # @ symbol + authentication path is highly suspicious
    if has_at_symbol and has_auth_path:

        risk_score += 15

        findings.append(
            "🚨 URL combines destination obfuscation "
            "with an authentication-related path"
        )


    # IP address + HTTP is dangerous
    if (
        re.match(ip_pattern, hostname)
        and parsed.scheme.lower() == "http"
    ):

        risk_score += 15

        findings.append(
            "🚨 Insecure HTTP link points directly "
            "to an IP address"
        )


    # =====================================================
    # FINAL RISK LIMIT
    # =====================================================

    risk_score = min(
        risk_score,
        100
    )


    # =====================================================
    # CLASSIFICATION
    # =====================================================

    if risk_score >= 60:

        classification = (
            "Potentially Malicious"
        )

        recommendation = (
            "Do not click or open this link. "
            "Do not enter passwords, OTPs, or personal information."
        )

    elif risk_score >= 30:

        classification = (
            "Suspicious"
        )

        recommendation = (
            "Verify the sender and actual destination "
            "before opening or interacting with this link."
        )

    else:

        classification = (
            "Likely Legitimate"
        )

        recommendation = (
            "No major threat detected during this analysis. "
            "Continue to verify unfamiliar links before interacting with them."
        )


    # =====================================================
    # RETURN RESULT
    # =====================================================

    return {

        "classification": classification,

        "risk_score": risk_score,

        "ai_result": ai_result,

        "ai_confidence": ai_confidence,

        "findings": findings,

        "recommendation": recommendation,

        "url": url

    }