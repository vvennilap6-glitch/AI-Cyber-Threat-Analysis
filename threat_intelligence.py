import hashlib


def generate_threat_intelligence(
    artifact_type,
    target,
    classification,
    risk_score,
    findings=None
):

    findings = findings or []

    try:
        risk_score = int(risk_score)
    except Exception:
        risk_score = 0


    # ==========================================
    # THREAT REPUTATION
    # ==========================================

    if risk_score >= 85:
        reputation = "Malicious"

    elif risk_score >= 60:
        reputation = "High Risk"

    elif risk_score >= 30:
        reputation = "Suspicious"

    else:
        reputation = "Clean"


    # ==========================================
    # THREAT CONFIDENCE
    # ==========================================

    if risk_score >= 85:
        confidence = 95

    elif risk_score >= 60:
        confidence = 85

    elif risk_score >= 30:
        confidence = 70

    else:
        confidence = 90


    # ==========================================
    # THREAT INDICATORS
    # ==========================================

    indicators = []

    for finding in findings:

        if finding:
            indicators.append(str(finding))


    # ==========================================
    # THREAT ID
    # ==========================================

    threat_id_source = (
        str(artifact_type)
        + str(target)
        + str(classification)
    )

    threat_id = hashlib.sha256(
        threat_id_source.encode()
    ).hexdigest()[:16]


    # ==========================================
    # SECURITY RECOMMENDATIONS
    # ==========================================

    recommendations = []

    if reputation == "Malicious":

        recommendations = [

            "Immediately block or restrict access to the artifact.",

            "Investigate related systems and users.",

            "Check for additional related threat activity.",

            "Preserve evidence for incident investigation."

        ]

    elif reputation == "High Risk":

        recommendations = [

            "Treat the artifact as a potential security threat.",

            "Restrict interaction with the artifact.",

            "Perform deeper security analysis.",

            "Monitor for suspicious activity."

        ]

    elif reputation == "Suspicious":

        recommendations = [

            "Perform additional investigation.",

            "Avoid interacting with suspicious artifacts.",

            "Monitor for related indicators.",

            "Review security findings carefully."

        ]

    else:

        recommendations = [

            "No immediate malicious indicators detected.",

            "Continue normal security monitoring.",

            "Perform additional analysis if new indicators appear."

        ]


    # ==========================================
    # RETURN INTELLIGENCE DATA
    # ==========================================

    intelligence = {

        "artifact_type": artifact_type,

        "target": target,

        "classification": classification,

        "risk_score": risk_score,

        "threat_reputation": reputation,

        "intelligence_confidence": confidence,

        "threat_indicators": indicators,

        "threat_id": threat_id,

        "recommendations": recommendations

    }


    return intelligence