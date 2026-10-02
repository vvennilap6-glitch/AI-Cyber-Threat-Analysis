def generate_incident_response(
    artifact_type=None,
    target=None,
    classification=None,
    risk_score=0,
    findings=None,
    correlations=None,
    **kwargs
):

    artifact_type = artifact_type or kwargs.get(
        "type",
        "Unknown"
    )

    target = target or kwargs.get(
        "artifact",
        "Unknown"
    )

    classification = classification or kwargs.get(
        "result",
        "Unknown"
    )

    findings = findings or []
    correlations = correlations or []

    try:
        risk_score = int(risk_score)
    except Exception:
        risk_score = 0


    # INCIDENT SEVERITY

    if risk_score >= 85:
        severity = "Critical"

    elif risk_score >= 60:
        severity = "High"

    elif risk_score >= 30:
        severity = "Medium"

    else:
        severity = "Low"


    # THREAT PRIORITY SCORE

    priority_score = risk_score

    if correlations:
        priority_score += 10

    if classification == "Potentially Malicious":
        priority_score += 10

    priority_score = min(
        priority_score,
        100
    )


    # INCIDENT SUMMARY

    incident_summary = (
        f"A {artifact_type} artifact was analyzed and "
        f"classified as '{classification}' with a "
        f"risk score of {risk_score}/100. "
        f"The incident severity has been assessed as "
        f"{severity}."
    )


    # IMMEDIATE ACTIONS

    if severity == "Critical":

        immediate_actions = [

            "Do not interact with the suspicious artifact.",

            "Immediately isolate affected systems if compromise is suspected.",

            "Block associated malicious domains, URLs or IP addresses.",

            "Preserve all available evidence for investigation.",

            "Notify the security administrator or incident response team."

        ]

    elif severity == "High":

        immediate_actions = [

            "Do not open or execute the suspicious artifact.",

            "Block suspicious URLs, domains or IP addresses.",

            "Investigate whether users interacted with the threat.",

            "Preserve evidence for further security analysis."

        ]

    elif severity == "Medium":

        immediate_actions = [

            "Treat the artifact as suspicious.",

            "Avoid interacting with suspicious links or files.",

            "Perform additional security analysis.",

            "Monitor systems for unusual activity."

        ]

    else:

        immediate_actions = [

            "Continue monitoring the artifact.",

            "Follow normal security precautions.",

            "Perform additional analysis if new indicators appear."

        ]


    # CONTAINMENT STEPS

    containment_steps = [

        "Restrict access to the suspicious artifact.",

        "Block related URLs, domains or IP addresses where applicable.",

        "Isolate affected devices if malicious activity is confirmed.",

        "Prevent further interaction until investigation is complete."

    ]


    # INVESTIGATION STEPS

    investigation_steps = [

        "Review all security findings.",

        "Analyze related threat artifacts.",

        "Check for repeated threat fingerprints.",

        "Review threat correlation results.",

        "Investigate possible user interaction with the artifact.",

        "Preserve relevant evidence for further analysis."

    ]


    # RETURN INCIDENT DATA

    return {

        "incident_severity": severity,

        "threat_priority_score": priority_score,

        "incident_summary": incident_summary,

        "affected_artifact": {

            "type": artifact_type,

            "target": target

        },

        "classification": classification,

        "risk_score": risk_score,

        "immediate_actions": immediate_actions,

        "containment_steps": containment_steps,

        "investigation_steps": investigation_steps,

        "security_findings": findings,

        "related_investigations": len(correlations)

    }