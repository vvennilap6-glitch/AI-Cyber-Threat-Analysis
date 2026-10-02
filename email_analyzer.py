import re
import ipaddress
from urllib.parse import urlparse

from model import predict_url


# =========================================================
# EMAIL THREAT ANALYZER
# =========================================================

def analyze_email(email_text):

    # =====================================================
    # INITIALIZATION
    # =====================================================

    email_text = str(email_text).strip()

    if not email_text:

        return {
            "classification": "Likely Safe",
            "risk_score": 0,
            "suspicious_keywords": [],
            "suspicious_urls": [],
            "findings": [],
            "recommendation": "No email content was provided."
        }

    email_lower = email_text.lower()

    risk_score = 0
    findings = []
    suspicious_keywords = []
    suspicious_urls = []


    # =====================================================
    # 1. SOCIAL ENGINEERING KEYWORDS
    # =====================================================

    urgency_keywords = [

        "urgent",
        "immediately",
        "act now",
        "within 24 hours",
        "last warning",
        "final warning"

    ]

    account_keywords = [

        "verify your account",
        "verify your identity",
        "account suspended",
        "account locked",
        "security alert",
        "confirm your account"

    ]

    credential_keywords = [

        "password",
        "username",
        "login credentials",
        "otp",
        "one time password"

    ]

    action_keywords = [

        "click here",
        "sign in",
        "login",
        "confirm"

    ]


    # =====================================================
    # DETECT KEYWORDS
    # =====================================================

    detected_urgency = [

        word
        for word in urgency_keywords
        if word in email_lower

    ]

    detected_account = [

        word
        for word in account_keywords
        if word in email_lower

    ]

    detected_credentials = [

        word
        for word in credential_keywords
        if word in email_lower

    ]

    detected_action = [

        word
        for word in action_keywords
        if word in email_lower

    ]


    # =====================================================
    # STORE DETECTED KEYWORDS
    # =====================================================

    suspicious_keywords.extend(
        detected_urgency
    )

    suspicious_keywords.extend(
        detected_account
    )

    suspicious_keywords.extend(
        detected_credentials
    )

    suspicious_keywords.extend(
        detected_action
    )


    # =====================================================
    # 2. SOCIAL ENGINEERING SCORING
    # =====================================================

    if detected_urgency:

        risk_score += 15

        findings.append(
            "⚠️ Urgency or pressure tactics detected"
        )


    if detected_account:

        risk_score += 10

        findings.append(
            "⚠️ Account-security related language detected"
        )


    if detected_credentials:

        risk_score += 20

        findings.append(
            "🚨 Possible request for sensitive credentials"
        )


    if detected_action:

        risk_score += 5

        findings.append(
            "⚠️ Request for user action detected"
        )


    # =====================================================
    # 3. URL EXTRACTION
    # =====================================================

    url_pattern = r"https?://[^\s<>\"']+"

    extracted_urls = re.findall(

        url_pattern,
        email_text,
        re.IGNORECASE

    )

    suspicious_urls = list(
        dict.fromkeys(extracted_urls)
    )


    # =====================================================
    # 4. URL ANALYSIS
    # =====================================================

    url_scores = []
    ai_only_suspicion_detected = False
    ai_only_confidence = 0.0


    for url in suspicious_urls:

        url_score = 0
        strong_url_indicator = False

        try:

            parsed = urlparse(url)

            hostname = (
                parsed.hostname or ""
            ).lower()

            path = (
                parsed.path or ""
            ).lower()


            if not hostname:
                continue


            # =================================================
            # HTTP CHECK
            # =================================================

            if parsed.scheme.lower() == "http":

                url_score += 15

                findings.append(
                    f"⚠️ Insecure HTTP link detected: "
                    f"{hostname}"
                )


            # =================================================
            # IP ADDRESS CHECK
            # =================================================

            is_ip_address = False

            try:

                ipaddress.ip_address(
                    hostname
                )

                is_ip_address = True

                url_score += 25

                strong_url_indicator = True

                findings.append(
                    f"🚨 URL uses an IP address instead of "
                    f"a domain: {hostname}"
                )

            except ValueError:

                pass


            # =================================================
            # @ URL DECEPTION
            # =================================================

            has_at_symbol = (
                parsed.username is not None
                or "@" in parsed.netloc
            )

            if has_at_symbol:

                url_score += 30

                strong_url_indicator = True

                findings.append(
                    "🚨 URL contains '@' symbol and may "
                    "hide the actual destination"
                )


            # =================================================
            # EXCESSIVE SUBDOMAINS
            # =================================================

            domain_parts = [

                part
                for part in hostname.split(".")
                if part

            ]

            if len(domain_parts) >= 5:

                url_score += 5

                findings.append(
                    "⚠️ Unusually complex subdomain "
                    "structure detected"
                )


            # =================================================
            # LONG HOSTNAME
            # =================================================

            if len(hostname) > 50:

                url_score += 5

                findings.append(
                    "⚠️ Unusually long hostname detected"
                )


            # =================================================
            # AUTHENTICATION PATH CHECK
            # =================================================

            authentication_terms = [

                "login",
                "signin",
                "verify",
                "verification",
                "authentication",
                "password"

            ]

            detected_path_terms = [

                term
                for term in authentication_terms
                if term in path

            ]

            if detected_path_terms:

                findings.append(
                    "⚠️ Account or authentication-related "
                    "URL path detected: "
                    + ", ".join(detected_path_terms)
                )


            # =================================================
            # DANGEROUS URL COMBINATIONS
            # =================================================

            if has_at_symbol and detected_path_terms:

                url_score += 15

                strong_url_indicator = True

                findings.append(
                    "🚨 URL combines destination obfuscation "
                    "with an authentication-related path"
                )


            if (
                is_ip_address
                and parsed.scheme.lower() == "http"
            ):

                url_score += 15

                strong_url_indicator = True

                findings.append(
                    "🚨 Insecure HTTP link points directly "
                    "to an IP address"
                )


            # =================================================
            # AI URL ANALYSIS
            # =================================================

            try:

                prediction = predict_url(url)

                ai_result = "Unknown"
                confidence = 0.0


                # Supports tuple output
                if isinstance(
                    prediction,
                    (tuple, list)
                ):

                    ai_result = str(
                        prediction[0]
                    )

                    if len(prediction) > 1:

                        confidence = float(
                            prediction[1]
                        )


                # Supports dictionary output
                elif isinstance(
                    prediction,
                    dict
                ):

                    ai_result = str(
                        prediction.get(
                            "prediction",
                            prediction.get(
                                "classification",
                                "Unknown"
                            )
                        )
                    )

                    confidence = float(
                        prediction.get(
                            "confidence",
                            0.0
                        )
                    )


                else:

                    ai_result = str(
                        prediction
                    )


                ai_text = ai_result.lower()

                malicious_labels = [

                    "potentially malicious",
                    "malicious",
                    "phishing",
                    "suspicious"

                ]

                ai_detected_malicious = any(

                    label in ai_text
                    for label in malicious_labels

                )


                if (
                    ai_detected_malicious
                    and confidence >= 95
                ):

                    if strong_url_indicator:

                        url_score += 10

                        findings.append(
                            f"🤖 AI model detected phishing-like "
                            f"URL characteristics "
                            f"({confidence:.2f}% confidence) "
                            f"and reinforced strong URL evidence."
                        )

                    else:

                        # AI alone receives a small score.
                        # This prevents the confusing situation:
                        # 0/100 risk + 99% phishing warning.

                        url_score += 5

                        ai_only_suspicion_detected = True

                        ai_only_confidence = max(
                            ai_only_confidence,
                            confidence
                        )

                        findings.append(
                            f"🤖 AI URL model flagged phishing-like "
                            f"characteristics "
                            f"({confidence:.2f}% confidence). "
                            f"No strong supporting email-level "
                            f"evidence was detected."
                        )


                elif (
                    ai_detected_malicious
                    and confidence >= 80
                ):

                    if strong_url_indicator:

                        url_score += 5

                        findings.append(
                            f"🤖 AI model detected suspicious "
                            f"URL characteristics "
                            f"({confidence:.2f}% confidence) "
                            f"and provided supporting evidence."
                        )

                    else:

                        ai_only_suspicion_detected = True

                        ai_only_confidence = max(
                            ai_only_confidence,
                            confidence
                        )

                        findings.append(
                            f"🤖 AI URL model reported suspicious "
                            f"characteristics "
                            f"({confidence:.2f}% confidence), "
                            f"but no strong supporting email-level "
                            f"evidence was detected."
                        )


            except Exception:

                findings.append(
                    "⚠️ AI URL analysis was unavailable"
                )


            # =================================================
            # STORE URL SCORE
            # =================================================

            url_scores.append(
                min(
                    url_score,
                    60
                )
            )


        except Exception:

            findings.append(
                "⚠️ One detected URL could not be fully analyzed"
            )


    # =====================================================
    # 5. ADD STRONGEST URL SCORE
    # =====================================================

    if url_scores:

        risk_score += max(
            url_scores
        )


    # =====================================================
    # 6. STRONG COMBINATIONS
    # =====================================================

    # Credential request + URL

    if (
        suspicious_urls
        and detected_credentials
    ):

        risk_score += 15

        findings.append(
            "🚨 Link is combined with a possible "
            "credential request"
        )


    # Urgency + URL

    if (
        suspicious_urls
        and detected_urgency
    ):

        risk_score += 10

        findings.append(
            "⚠️ Link is combined with urgency "
            "or pressure tactics"
        )


    # Account request + URL + user action

    if (
        suspicious_urls
        and detected_account
        and detected_action
    ):

        risk_score += 15

        findings.append(
            "🚨 Email combines an account-related "
            "request with a link and user action"
        )


    # =====================================================
    # 7. FALSE-POSITIVE PROTECTION
    # =====================================================

    strong_indicators = (

        bool(detected_credentials)
        or bool(detected_urgency)
        or any(
            score >= 25
            for score in url_scores
        )

    )


    # If AI is the only suspicious signal,
    # keep the email below the "Suspicious" threshold.

    if not strong_indicators:

        risk_score = min(
            risk_score,
            29
        )


    # =====================================================
    # 8. REMOVE DUPLICATES
    # =====================================================

    findings = list(
        dict.fromkeys(findings)
    )

    suspicious_keywords = list(
        dict.fromkeys(
            suspicious_keywords
        )
    )


    # =====================================================
    # 9. FINAL RISK SCORE
    # =====================================================

    risk_score = min(
        max(
            risk_score,
            0
        ),
        100
    )


    # =====================================================
    # 10. CLASSIFICATION
    # =====================================================

    if risk_score >= 60:

        classification = (
            "Potentially Malicious"
        )

    elif risk_score >= 30:

        classification = (
            "Suspicious"
        )

    else:

        classification = (
            "Likely Safe"
        )


    # =====================================================
    # 11. SECURITY RECOMMENDATION
    # =====================================================

    if classification == "Potentially Malicious":

        recommendation = (
            "Do not click links or provide personal "
            "information. Verify the message through "
            "an independent trusted channel."
        )

    elif classification == "Suspicious":

        recommendation = (
            "Verify the sender and destination links "
            "before taking any action."
        )

    else:

        if ai_only_suspicion_detected:

            recommendation = (
                "The AI URL model detected suspicious "
                "characteristics, but the email-level checks "
                "found insufficient supporting evidence for "
                "a malicious classification. Verify unfamiliar "
                "links before interacting with them."
            )

        else:

            recommendation = (
                "No strong phishing indicators were detected. "
                "Continue to use normal security precautions."
            )


    # =====================================================
    # 12. RETURN RESULT
    # =====================================================

    return {

        "classification": classification,

        "risk_score": risk_score,

        "suspicious_keywords":
            suspicious_keywords,

        "suspicious_urls":
            suspicious_urls,

        "findings":
            findings,

        "recommendation":
            recommendation

    }