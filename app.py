import os
import tempfile
from io import BytesIO
from urllib.parse import urlparse

import streamlit as st

from url_analyzer import analyze_url
from file_analyzer import analyze_file
from email_analyzer import analyze_email
from qr_analyzer import analyze_qr
from domain_analyzer import analyze_domain

from threat_fingerprint import fingerprint_artifact
from threat_correlator import correlate_artifacts
from malware_intelligence import analyze_malware_intelligence
from incident_response import generate_incident_response
from incident_report import generate_incident_report
from threat_intelligence import generate_threat_intelligence
from ioc_extractor import extract_iocs, count_iocs, get_total_iocs
from ioc_investigator import investigate_iocs


# =========================================================
# PAGE CONFIGURATION
# =========================================================

st.set_page_config(
    page_title="AI Cyber Threat Analysis Platform",
    page_icon="🛡️",
    layout="wide"
)


# =========================================================
# SESSION STATE
# =========================================================

if "scan_history" not in st.session_state:
    st.session_state.scan_history = []


# =========================================================
# HELPER FUNCTIONS
# =========================================================

def add_to_history(
    artifact_type,
    target,
    result,
    risk_score,
    fingerprint,
    extra_data=None
):

    record = {
        "type": artifact_type,
        "target": target,
        "result": result,
        "risk_score": risk_score,
        "fingerprint": fingerprint
    }

    if extra_data:
        record.update(extra_data)

    st.session_state.scan_history.append(record)


def display_fingerprint(
    artifact_type,
    fingerprint
):

    st.subheader("🧬 Threat Fingerprint")

    st.write(
        f"**Artifact Type:** {artifact_type.upper()}"
    )

    st.code(
        fingerprint,
        language="text"
    )



def build_ioc_relationships(iocs, history=None):
    """
    Build local relationships between extracted IOCs and previously
    investigated artifacts. This is correlation logic only; it does
    not claim that a relationship proves malicious activity.
    """

    iocs = iocs or {}
    history = history or []

    urls = iocs.get("urls", [])
    domains = iocs.get("domains", [])
    ip_addresses = iocs.get("ip_addresses", [])
    hashes = iocs.get("hashes", {})

    md5 = hashes.get("md5", [])
    sha1 = hashes.get("sha1", [])
    sha256 = hashes.get("sha256", [])

    relationships = []

    # URL <-> Domain relationships.
    for url in urls:
        try:
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()

            for domain in domains:
                domain_lower = domain.lower()

                if host == domain_lower or host.endswith("." + domain_lower):
                    relationships.append({
                        "source": url,
                        "source_type": "URL",
                        "relationship": "contains domain",
                        "target": domain,
                        "target_type": "Domain",
                        "evidence": "The URL hostname matches the extracted domain."
                    })

            # URL <-> IP relationship when the URL hostname is an IP.
            for ip in ip_addresses:
                if host == ip:
                    relationships.append({
                        "source": url,
                        "source_type": "URL",
                        "relationship": "uses IP address",
                        "target": ip,
                        "target_type": "IP",
                        "evidence": "The URL hostname is the extracted IP address."
                    })

        except Exception:
            continue

    # Cross-correlate extracted IOCs with the existing investigation history.
    for record in history:
        target = str(record.get("target", ""))
        target_lower = target.lower()

        record_type = str(record.get("type", "Unknown"))
        record_fingerprint = str(record.get("fingerprint", ""))

        for url in urls:
            if target_lower == url.lower():
                relationships.append({
                    "source": url,
                    "source_type": "IOC URL",
                    "relationship": "matches investigation",
                    "target": target,
                    "target_type": record_type,
                    "evidence": (
                        f"The extracted URL exactly matches a previous "
                        f"{record_type} investigation."
                    )
                })

        for domain in domains:
            if target_lower == domain.lower():
                relationships.append({
                    "source": domain,
                    "source_type": "IOC Domain",
                    "relationship": "matches investigation",
                    "target": target,
                    "target_type": record_type,
                    "evidence": (
                        f"The extracted domain exactly matches a previous "
                        f"{record_type} investigation."
                    )
                })

        stored_sha256 = str(record.get("sha256", "")).lower()

        if stored_sha256:
            for hash_value in sha256:
                if stored_sha256 == hash_value.lower():
                    relationships.append({
                        "source": hash_value,
                        "source_type": "SHA-256",
                        "relationship": "matches file investigation",
                        "target": target,
                        "target_type": record_type,
                        "evidence": "The SHA-256 matches a previous file investigation."
                    })

        # Also correlate an IOC fingerprint if a history record explicitly
        # stores the same value as a target/fingerprint.
        for hash_value in md5 + sha1:
            if target_lower == hash_value.lower() or record_fingerprint.lower() == hash_value.lower():
                relationships.append({
                    "source": hash_value,
                    "source_type": "Hash",
                    "relationship": "matches investigation",
                    "target": target,
                    "target_type": record_type,
                    "evidence": "The extracted hash matches stored investigation data."
                })

    # Remove exact duplicate relationship rows.
    unique = []
    seen = set()

    for relationship in relationships:
        key = (
            relationship["source"],
            relationship["source_type"],
            relationship["relationship"],
            relationship["target"],
            relationship["target_type"]
        )

        if key not in seen:
            seen.add(key)
            unique.append(relationship)

    return unique


# =========================================================
# HEADER
# =========================================================

st.title("🛡️ AI Cyber Threat Analysis Platform")

st.write(
    "Analyze suspicious URLs, files, emails, QR codes and domains "
    "using AI-powered and rule-based security analysis."
)

st.markdown("---")


# =========================================================
# SIDEBAR
# =========================================================

st.sidebar.title("🔎 Threat Investigation")

st.sidebar.caption(
    "AI-powered security analysis and investigation tools"
)

st.sidebar.markdown("---")


analysis_type = st.sidebar.radio(
    "Select Analysis Type",
    [
        "🔗 URL Threat Scanner",
        "📁 File Threat Analyzer",
        "📧 Email Threat Analyzer",
        "📱 QR Threat Scanner",
        "🌐 Domain/IP Intelligence",
        "🦠 Malware Intelligence",
        "🔗 Threat Correlation",
        "🚨 Incident Response Center",
        "🧠 Threat Intelligence",
        "🔎 IOC Extraction & Investigation",
        "🕵️ IOC Investigation Dashboard",
        "🔗 IOC Relationship & Correlation",
        "🕸️ Threat Graph Visualization",
        "🛡️ Threat Intelligence Dashboard",
        "📊 Investigation Statistics",
        "📜 Scan History"
    ]
)

# =========================================================
# URL THREAT SCANNER
# =========================================================

if analysis_type == "🔗 URL Threat Scanner":

    st.header("🔗 URL Threat Scanner")

    st.write(
        "Analyze a URL using layered security checks "
        "and AI-based phishing detection."
    )

    url = st.text_input(
        "Enter a suspicious URL",
        placeholder="Example: https://example.com"
    )

    if st.button(
        "🔍 Analyze URL",
        use_container_width=True
    ):

        if not url.strip():

            st.warning(
                "⚠️ Please enter a URL."
            )

        else:

            try:

                result = analyze_url(url)

                classification = result[
                    "classification"
                ]

                risk_score = result[
                    "risk_score"
                ]

                if classification == "Potentially Malicious":

                    st.error(
                        "🚨 Potentially Malicious URL"
                    )

                elif classification == "Suspicious":

                    st.warning(
                        "⚠️ Suspicious URL"
                    )

                else:

                    st.success(
                        "✅ Likely Legitimate URL"
                    )


                col1, col2 = st.columns(2)

                with col1:

                    st.metric(
                        "AI Confidence",
                        f"{result['ai_confidence']:.2f}%"
                    )

                with col2:

                    st.metric(
                        "Risk Score",
                        f"{risk_score}/100"
                    )


                st.subheader(
                    "🔗 Analyzed URL"
                )

                st.code(
                    result["url"]
                )


                st.subheader(
                    "🤖 AI Analysis"
                )

                st.write(
                    f"**AI Classification:** "
                    f"{result['ai_result']}"
                )

                st.write(
                    f"**AI Confidence:** "
                    f"{result['ai_confidence']:.2f}%"
                )


                st.subheader(
                    "🔎 Security Findings"
                )

                if result["findings"]:

                    for finding in result["findings"]:

                        st.write(
                            finding
                        )

                else:

                    st.success(
                        "No obvious suspicious characteristics detected."
                    )


                st.subheader(
                    "🛡️ Security Recommendation"
                )

                st.info(
                    result["recommendation"]
                )


                fingerprint_data = fingerprint_artifact(

                    "URL",

                    {

                        "url": result["url"],

                        "classification": classification,

                        "risk_score": risk_score

                    }

                )

                fingerprint = fingerprint_data[
                    "fingerprint"
                ]

                display_fingerprint(
                    "URL",
                    fingerprint
                )


                add_to_history(

                    "URL",

                    result["url"],

                    classification,

                    risk_score,

                    fingerprint,

                    {

                        "findings": result.get(
                            "findings",
                            []
                        )

                    }

                )


            except Exception as error:

                st.error(
                    f"Error analyzing URL: {error}"
                )


# =========================================================
# FILE THREAT ANALYZER
# =========================================================

elif analysis_type == "📁 File Threat Analyzer":

    st.header("📁 File Threat Analyzer")

    st.write(
        "Upload a suspicious file for static security analysis."
    )

    st.info(
        "The uploaded file will not be executed."
    )


    uploaded_file = st.file_uploader(
        "Upload a suspicious file"
    )


    if uploaded_file is not None:

        if st.button(
            "🔍 Analyze File",
            use_container_width=True
        ):

            temp_path = None

            try:

                suffix = os.path.splitext(
                    uploaded_file.name
                )[1]


                with tempfile.NamedTemporaryFile(

                    delete=False,

                    suffix=suffix

                ) as temp_file:

                    temp_file.write(
                        uploaded_file.getbuffer()
                    )

                    temp_path = temp_file.name


                result = analyze_file(
                    temp_path
                )


                classification = result[
                    "classification"
                ]

                risk_score = result[
                    "risk_score"
                ]


                if classification == "Potentially Malicious":

                    st.error(
                        "🚨 Potentially Malicious File"
                    )

                elif classification == "Suspicious":

                    st.warning(
                        "⚠️ Suspicious File"
                    )

                else:

                    st.success(
                        "✅ Likely Safe File"
                    )


                col1, col2, col3 = st.columns(3)


                with col1:

                    st.metric(
                        "File Size",

                        f"{result['file_size']:,} bytes"
                    )


                with col2:

                    st.metric(
                        "Entropy",

                        result["entropy"]
                    )


                with col3:

                    st.metric(
                        "Risk Score",

                        f"{risk_score}/100"
                    )


                st.subheader(
                    "📄 File Information"
                )


                st.write(
                    f"**File Name:** "
                    f"{uploaded_file.name}"
                )


                st.write(
                    f"**Extension:** "
                    f"{result['extension']}"
                )


                st.write(
                    f"**SHA-256:** "
                    f"`{result['sha256']}`"
                )


                st.subheader(
                    "🔎 Security Findings"
                )


                if result["reasons"]:

                    for reason in result["reasons"]:

                        st.write(
                            reason
                        )

                else:

                    st.success(
                        "No obvious suspicious characteristics detected."
                    )


                st.subheader(
                    "🛡️ Security Recommendation"
                )


                if classification == "Potentially Malicious":

                    st.error(

                        "🚫 Do not open or execute this file. "
                        "Further malware analysis is recommended."

                    )


                elif classification == "Suspicious":

                    st.warning(

                        "⚠️ Treat this file with caution. "
                        "Additional security analysis is recommended."

                    )


                else:

                    st.success(

                        "No major threat detected during this analysis."

                    )


                fingerprint_data = fingerprint_artifact(

                    "FILE",

                    {

                        "sha256": result["sha256"],

                        "file_name": uploaded_file.name

                    }

                )


                fingerprint = fingerprint_data[
                    "fingerprint"
                ]


                display_fingerprint(
                    "FILE",
                    fingerprint
                )


                file_content = ""

                try:

                    uploaded_file.seek(0)

                    raw_content = uploaded_file.read(
                        2 * 1024 * 1024
                    )

                    file_content = raw_content.decode(
                        "utf-8",
                        errors="ignore"
                    )

                    uploaded_file.seek(0)

                except Exception:

                    file_content = ""


                add_to_history(

                    "FILE",

                    uploaded_file.name,

                    classification,

                    risk_score,

                    fingerprint,

                    {

                        "sha256": result["sha256"],

                        "file_name": uploaded_file.name,

                        "file_type": result["extension"],

                        "findings": result["reasons"],

                        "file_content": file_content

                    }

                )


            except Exception as error:

                st.error(
                    f"Error analyzing file: {error}"
                )


            finally:

                if (

                    temp_path

                    and

                    os.path.exists(temp_path)

                ):

                    os.remove(
                        temp_path
                    )


# =========================================================
# EMAIL THREAT ANALYZER
# =========================================================

elif analysis_type == "📧 Email Threat Analyzer":

    st.header("📧 Email Threat Analyzer")

    st.write(
        "Analyze suspicious email content for phishing "
        "and social engineering indicators."
    )


    email_text = st.text_area(

        "Paste suspicious email content",

        height=250

    )


    if st.button(

        "🔍 Analyze Email",

        use_container_width=True

    ):

        if not email_text.strip():

            st.warning(
                "⚠️ Please enter email content."
            )

        else:

            try:

                result = analyze_email(
                    email_text
                )


                classification = result[
                    "classification"
                ]

                risk_score = result[
                    "risk_score"
                ]


                if classification == "Potentially Malicious":

                    st.error(
                        "🚨 Potentially Malicious Email"
                    )

                elif classification == "Suspicious":

                    st.warning(
                        "⚠️ Suspicious Email"
                    )

                else:

                    st.success(
                        "✅ Likely Safe Email"
                    )


                col1, col2 = st.columns(2)


                with col1:

                    st.metric(
                        "Risk Score",

                        f"{risk_score}/100"
                    )


                with col2:

                    suspicious_urls = result.get(
                        "suspicious_urls",
                        []
                    )

                    st.metric(
                        "Suspicious URLs",

                        len(suspicious_urls)
                    )


                st.subheader(
                    "🔎 Security Findings"
                )


                findings = result.get(
                    "findings",
                    []
                )


                if findings:

                    for finding in findings:

                        st.write(
                            finding
                        )


                suspicious_keywords = result.get(
                    "suspicious_keywords",
                    []
                )


                if suspicious_keywords:

                    st.subheader(
                        "⚠️ Suspicious Keywords"
                    )

                    st.write(
                        ", ".join(
                            suspicious_keywords
                        )
                    )


                detected_urls = result.get(
                    "detected_urls",
                    []
                )


                if detected_urls:

                    st.subheader(
                        "🔗 Detected URLs"
                    )

                    for detected_url in detected_urls:

                        st.code(
                            detected_url
                        )


                st.subheader(
                    "🛡️ Security Recommendation"
                )


                st.info(
                    result.get(

                        "recommendation",

                        "Verify the sender before interacting "
                        "with suspicious content."

                    )
                )


                fingerprint_data = fingerprint_artifact(

                    "EMAIL",

                    {

                        "email_content": email_text

                    }

                )


                fingerprint = fingerprint_data[
                    "fingerprint"
                ]


                display_fingerprint(
                    "EMAIL",
                    fingerprint
                )


                add_to_history(

                    "EMAIL",

                    "Email Message",

                    classification,

                    risk_score,

                    fingerprint,

                    {

                        "email_text": email_text,

                        "suspicious_urls": suspicious_urls,

                        "findings": findings

                    }

                )


            except Exception as error:

                st.error(
                    f"Error analyzing email: {error}"
                )


# =========================================================
# QR THREAT SCANNER
# =========================================================

elif analysis_type == "📱 QR Threat Scanner":

    st.header("📱 QR Threat Scanner")

    st.write(
        "Upload an image containing a QR code "
        "for threat analysis."
    )


    qr_file = st.file_uploader(

        "Upload QR Code Image",

        type=[
            "png",
            "jpg",
            "jpeg"
        ]

    )


    if qr_file is not None:

        if st.button(

            "🔍 Scan QR Code",

            use_container_width=True

        ):

            temp_path = None

            try:

                suffix = os.path.splitext(
                    qr_file.name
                )[1]


                with tempfile.NamedTemporaryFile(

                    delete=False,

                    suffix=suffix

                ) as temp_file:

                    temp_file.write(
                        qr_file.getbuffer()
                    )

                    temp_path = temp_file.name


                qr_result = analyze_qr(
                    temp_path
                )


                if not qr_result[
                    "detected"
                ]:

                    st.warning(
                        qr_result["message"]
                    )


                else:

                    st.success(
                        qr_result["message"]
                    )


                    qr_data = qr_result[
                        "data"
                    ]


                    st.subheader(
                        "📦 QR Content"
                    )

                    st.code(
                        qr_data
                    )


                    fingerprint_data = fingerprint_artifact(

                        "QR",

                        {

                            "data": qr_data

                        }

                    )


                    fingerprint = fingerprint_data[
                        "fingerprint"
                    ]


                    display_fingerprint(
                        "QR",
                        fingerprint
                    )


                    if qr_data.startswith(

                        (
                            "http://",
                            "https://"
                        )

                    ):

                        st.subheader(
                            "🔗 URL Threat Analysis"
                        )


                        url_result = analyze_url(
                            qr_data
                        )


                        classification = url_result[
                            "classification"
                        ]

                        risk_score = url_result[
                            "risk_score"
                        ]


                        if classification == "Potentially Malicious":

                            st.error(
                                "🚨 Potentially Malicious URL"
                            )

                        elif classification == "Suspicious":

                            st.warning(
                                "⚠️ Suspicious URL"
                            )

                        else:

                            st.success(
                                "✅ Likely Legitimate URL"
                            )


                        col1, col2 = st.columns(2)


                        with col1:

                            st.metric(

                                "AI Confidence",

                                f"{url_result['ai_confidence']:.2f}%"

                            )


                        with col2:

                            st.metric(

                                "Risk Score",

                                f"{risk_score}/100"

                            )


                        st.subheader(
                            "🔎 Security Findings"
                        )


                        for finding in url_result[
                            "findings"
                        ]:

                            st.write(
                                finding
                            )


                        st.subheader(
                            "🛡️ Security Recommendation"
                        )

                        st.info(
                            url_result[
                                "recommendation"
                            ]
                        )


                        add_to_history(

                            "QR",

                            qr_data,

                            classification,

                            risk_score,

                            fingerprint,

                            {

                                "data": qr_data,

                                "findings": url_result.get(
                                    "findings",
                                    []
                                )

                            }

                        )


                    else:

                        add_to_history(

                            "QR",

                            qr_data,

                            "QR Content Detected",

                            0,

                            fingerprint,

                            {

                                "data": qr_data,

                                "findings": []

                            }

                        )


            except Exception as error:

                st.error(
                    f"Error scanning QR code: {error}"
                )


            finally:

                if (

                    temp_path

                    and

                    os.path.exists(temp_path)

                ):

                    os.remove(
                        temp_path
                    )


# =========================================================
# DOMAIN/IP INTELLIGENCE
# =========================================================

elif analysis_type == "🌐 Domain/IP Intelligence":

    st.header("🌐 Domain/IP Intelligence")

    st.write(
        "Investigate a domain name or IP address using "
        "DNS resolution and security indicators."
    )


    target = st.text_input(
        "Enter a domain or IP address"
    )


    if st.button(

        "🔍 Investigate Target",

        use_container_width=True

    ):

        if not target.strip():

            st.warning(
                "⚠️ Please enter a domain or IP address."
            )

        else:

            try:

                result = analyze_domain(
                    target
                )


                classification = result.get(
                    "classification",
                    "Unknown"
                )

                risk_score = result.get(
                    "risk_score",
                    0
                )


                if classification == "Potentially Malicious":

                    st.error(
                        "🚨 Potentially Malicious Target"
                    )

                elif classification == "Suspicious":

                    st.warning(
                        "⚠️ Suspicious Target"
                    )

                else:

                    st.success(
                        "✅ Likely Safe Target"
                    )


                col1, col2, col3 = st.columns(3)


                with col1:

                    st.metric(

                        "Risk Score",

                        f"{risk_score}/100"

                    )


                with col2:

                    st.metric(

                        "Target Type",

                        result.get(
                            "target_type",
                            "Unknown"
                        )

                    )


                with col3:

                    resolved_ips = result.get(
                        "resolved_ips",
                        []
                    )

                    st.metric(
                        "Resolved IPs",
                        len(resolved_ips)
                    )


                if resolved_ips:

                    st.subheader(
                        "🌐 Resolved IP Addresses"
                    )


                    for ip in resolved_ips:

                        st.code(
                            ip
                        )


                findings = result.get(
                    "findings",
                    []
                )


                if findings:

                    st.subheader(
                        "🔎 Security Findings"
                    )


                    for finding in findings:

                        st.write(
                            finding
                        )


                recommendation = result.get(
                    "recommendation",
                    ""
                )


                if recommendation:

                    st.subheader(
                        "🛡️ Security Recommendation"
                    )

                    st.info(
                        recommendation
                    )


                fingerprint_data = fingerprint_artifact(

                    "DOMAIN",

                    {

                        "target": target

                    }

                )


                fingerprint = fingerprint_data[
                    "fingerprint"
                ]


                display_fingerprint(
                    "DOMAIN/IP",
                    fingerprint
                )


                add_to_history(

                    "DOMAIN",

                    target,

                    classification,

                    risk_score,

                    fingerprint,

                    {

                        "resolved_ips": resolved_ips,

                        "findings": findings

                    }

                )


            except Exception as error:

                st.error(
                    f"Error investigating target: {error}"
                )


# =========================================================
# MALWARE INTELLIGENCE
# =========================================================

elif analysis_type == "🦠 Malware Intelligence":

    st.header("🦠 Malware Intelligence")

    st.write(
        "Analyze previously identified file security indicators "
        "to identify possible malware behavior and threat levels."
    )


    file_records = [

        record

        for record in st.session_state.scan_history

        if record.get("type") == "FILE"

    ]


    if not file_records:

        st.info(
            "ℹ️ No file investigations found yet."
        )

        st.write(
            "First analyze a file using the "
            "**📁 File Threat Analyzer**."
        )


    else:

        file_names = [

            record.get(
                "target",
                "Unknown File"
            )

            for record in file_records

        ]


        selected_file = st.selectbox(

            "Select an analyzed file",

            file_names

        )


        selected_record = next(

            record

            for record in file_records

            if record.get("target") == selected_file

        )


        if st.button(

            "🧠 Analyze Malware Intelligence",

            use_container_width=True

        ):


            intelligence = analyze_malware_intelligence(

                file_name=selected_record.get(

                    "file_name",

                    selected_record.get(
                        "target",
                        ""
                    )

                ),

                file_type=selected_record.get(

                    "file_type",

                    ""

                ),

                findings=selected_record.get(

                    "findings",

                    []

                ),

                risk_score=selected_record.get(

                    "risk_score",

                    0

                ),

                sha256=selected_record.get(

                    "sha256",

                    ""

                ),

                file_content=selected_record.get(

                    "file_content",

                    ""

                )

            )


            st.subheader(
                "🧠 Malware Intelligence Result"
            )


            threat_level = intelligence[
                "threat_level"
            ]


            if threat_level == "High":

                st.error(
                    "🚨 HIGH THREAT LEVEL"
                )

            elif threat_level == "Medium":

                st.warning(
                    "⚠️ MEDIUM THREAT LEVEL"
                )

            else:

                st.success(
                    "✅ LOW THREAT LEVEL"
                )


            col1, col2 = st.columns(2)


            with col1:

                st.metric(
                    "Threat Level",
                    threat_level
                )


            with col2:

                st.metric(
                    "Intelligence Confidence",
                    f"{intelligence['confidence']}%"
                )


            st.subheader(
                "🦠 Possible Malware Types"
            )


            malware_types = intelligence[
                "possible_malware_types"
            ]


            if malware_types:

                for malware_type in malware_types:

                    st.warning(
                        f"⚠️ Possible {malware_type}"
                    )

            else:

                st.success(
                    "No specific malware family indicators detected."
                )


            st.subheader(
                "🔎 Malware Intelligence Findings"
            )


            for finding in intelligence[
                "intelligence_findings"
            ]:

                st.write(
                    finding
                )


            if intelligence.get(
                "sha256"
            ):

                st.subheader(
                    "🔐 File SHA-256"
                )

                st.code(
                    intelligence["sha256"]
                )


            st.subheader(
                "🛡️ Security Recommendation"
            )


            if threat_level == "High":

                st.error(

                    "🚫 Do not execute this file. "
                    "Isolate the file and perform additional "
                    "malware investigation."

                )


            elif threat_level == "Medium":

                st.warning(

                    "⚠️ Treat this file as suspicious and "
                    "perform additional analysis before opening it."

                )


            else:

                st.success(

                    "✅ No strong malware indicators were detected "
                    "from the available static intelligence."

                )


# =========================================================
# THREAT CORRELATION
# =========================================================

elif analysis_type == "🔗 Threat Correlation":

    st.header("🔗 Threat Correlation Engine")

    st.write(
        "Identify relationships between previously "
        "analyzed threat artifacts."
    )


    history = st.session_state.scan_history


    if len(history) < 2:

        st.info(
            "Analyze at least two artifacts to detect relationships."
        )


    else:

        correlations = correlate_artifacts(
            history
        )


        st.metric(

            "🔎 Correlations Detected",

            len(correlations)

        )


        if not correlations:

            st.success(
                "✅ No direct correlations were found "
                "between the investigations."
            )


            st.write(

                "Correlation checks shared domains, repeated "
                "targets, and repeated threat fingerprints."

            )


        else:

            st.subheader(
                "🚨 Related Investigations"
            )


            for index, correlation in enumerate(

                correlations,

                start=1

            ):

                st.subheader(
                    f"🔗 Correlation #{index}"
                )


                st.write(

                    f"**Relationship:** "
                    f"{correlation['type']}"

                )


                st.write(

                    f"**Reason:** "
                    f"{correlation['reason']}"

                )


                first = correlation[
                    "first"
                ]

                second = correlation[
                    "second"
                ]


                col1, col2 = st.columns(2)


                with col1:

                    st.write(
                        "**Investigation 1**"
                    )

                    st.write(
                        f"Type: `{first.get('type')}`"
                    )

                    st.write(
                        f"Target: `{first.get('target')}`"
                    )

                    st.write(
                        f"Risk: "
                        f"`{first.get('risk_score')}/100`"
                    )


                with col2:

                    st.write(
                        "**Investigation 2**"
                    )

                    st.write(
                        f"Type: `{second.get('type')}`"
                    )

                    st.write(
                        f"Target: `{second.get('target')}`"
                    )

                    st.write(
                        f"Risk: "
                        f"`{second.get('risk_score')}/100`"
                    )


                st.markdown("---")


# =========================================================
# INCIDENT RESPONSE CENTER
# =========================================================

elif analysis_type == "🚨 Incident Response Center":

    st.header("🚨 Automated Incident Response Center")

    st.write(
        "Automatically generate incident severity, priority, "
        "recommended actions and investigation steps based on "
        "previous threat investigations."
    )


    history = st.session_state.scan_history


    if not history:

        st.info(
            "ℹ️ No investigations are available yet."
        )

        st.write(
            "First analyze a URL, file, email, QR code or domain."
        )


    else:

        investigation_options = []

        for index, record in enumerate(history):

            artifact_type = record.get(
                "type",
                "Unknown"
            )

            target = record.get(
                "target",
                "Unknown"
            )

            investigation_options.append(
                f"{index + 1}. {artifact_type} - {target}"
            )


        selected_investigation = st.selectbox(

            "Select Investigation",

            investigation_options

        )


        selected_index = investigation_options.index(
            selected_investigation
        )

        selected_record = history[
            selected_index
        ]


        st.markdown("---")

        st.subheader(
            "🔍 Selected Investigation"
        )


        st.write(
            f"**Artifact Type:** "
            f"{selected_record.get('type', 'Unknown')}"
        )

        st.write(
            f"**Classification:** "
            f"{selected_record.get('result', 'Unknown')}"
        )

        st.write(
            f"**Risk Score:** "
            f"{selected_record.get('risk_score', 0)}/100"
        )

        st.code(
            str(
                selected_record.get(
                    "target",
                    "Unknown"
                )
            ),
            language="text"
        )


        if st.button(

            "🚨 Generate Incident Response",

            use_container_width=True

        ):

            correlations = []

            try:

                if len(history) >= 2:

                    all_correlations = correlate_artifacts(
                        history
                    )

                    for correlation in all_correlations:

                        first = correlation.get(
                            "first",
                            {}
                        )

                        second = correlation.get(
                            "second",
                            {}
                        )

                        if (

                            first.get(
                                "target"
                            )

                            ==

                            selected_record.get(
                                "target"
                            )

                            or

                            second.get(
                                "target"
                            )

                            ==

                            selected_record.get(
                                "target"
                            )

                        ):

                            correlations.append(
                                correlation
                            )

            except Exception:

                correlations = []


            incident = generate_incident_response(

                artifact_type=selected_record.get(
                    "type",
                    "Unknown"
                ),

                target=selected_record.get(
                    "target",
                    "Unknown"
                ),

                classification=selected_record.get(
                    "result",
                    "Unknown"
                ),

                risk_score=selected_record.get(
                    "risk_score",
                    0
                ),

                findings=selected_record.get(
                    "findings",
                    []
                ),

                correlations=correlations

            )


            severity = incident.get(

                "incident_severity",

                "Unknown"

            )


            priority_score = incident.get(

                "threat_priority_score",

                0

            )


            st.markdown("---")

            st.subheader(
                "🚨 Incident Severity"
            )


            if severity == "Critical":

                st.error(
                    "🔴 CRITICAL SEVERITY INCIDENT"
                )

            elif severity == "High":

                st.error(
                    "🟠 HIGH SEVERITY INCIDENT"
                )

            elif severity == "Medium":

                st.warning(
                    "🟡 MEDIUM SEVERITY INCIDENT"
                )

            else:

                st.success(
                    "🟢 LOW SEVERITY INCIDENT"
                )


            col1, col2 = st.columns(2)


            with col1:

                st.metric(
                    "🎯 Threat Priority Score",
                    priority_score
                )


            with col2:

                st.metric(
                    "🚨 Incident Severity",
                    severity
                )


            st.subheader(
                "📋 Incident Summary"
            )

            st.write(
                incident.get(
                    "incident_summary",
                    "No incident summary available."
                )
            )


            st.subheader(
                "🎯 Affected Artifact"
            )

            affected_artifact = incident.get(
                "affected_artifact",
                {}
            )


            st.write(
                f"**Type:** "
                f"{affected_artifact.get('type', 'Unknown')}"
            )

            st.write(
                f"**Target:** "
                f"{affected_artifact.get('target', 'Unknown')}"
            )

            st.write(
                f"**Classification:** "
                f"{incident.get('classification', 'Unknown')}"
            )

            st.write(
                f"**Risk Score:** "
                f"{incident.get('risk_score', 0)}/100"
            )

            st.write(
                "**Threat Fingerprint:**"
            )

            st.code(
                str(
                    selected_record.get(
                        "fingerprint",
                        "Not Available"
                    )
                ),
                language="text"
            )


            st.subheader(
                "⚡ Recommended Immediate Actions"
            )

            for index, action in enumerate(

                incident.get(
                    "immediate_actions",
                    []
                ),

                start=1

            ):

                st.write(
                    f"{index}. {action}"
                )


            st.subheader(
                "🛡️ Containment Steps"
            )

            for index, step in enumerate(

                incident.get(
                    "containment_steps",
                    []
                ),

                start=1

            ):

                st.write(
                    f"{index}. {step}"
                )


            st.subheader(
                "🔎 Investigation Steps"
            )

            for index, step in enumerate(

                incident.get(
                    "investigation_steps",
                    []
                ),

                start=1

            ):

                st.write(
                    f"{index}. {step}"
                )


            findings = incident.get(
                "security_findings",
                []
            )


            if findings:

                st.subheader(
                    "🔎 Security Findings"
                )

                for finding in findings:

                    st.write(
                        finding
                    )


            st.markdown("---")

            st.subheader(
                "📄 Security Incident Report"
            )

            st.write(
                "Generate and download the complete security incident report as a PDF."
            )

            try:

                report_data = dict(
                    incident
                )

                report_data["affected_artifact"] = {
                    "type": affected_artifact.get(
                        "type",
                        "Unknown"
                    ),
                    "target": affected_artifact.get(
                        "target",
                        "Unknown"
                    )
                }

                report_data["security_findings"] = findings

                pdf_buffer = BytesIO()

                generate_incident_report(
                    report_data,
                    pdf_buffer
                )

                pdf_buffer.seek(
                    0
                )

                safe_artifact_type = str(
                    selected_record.get(
                        "type",
                        "Incident"
                    )
                ).lower()

                st.download_button(

                    label="⬇️ Download Security Incident Report (PDF)",

                    data=pdf_buffer.getvalue(),

                    file_name=(
                        f"security_incident_report_"
                        f"{safe_artifact_type}.pdf"
                    ),

                    mime="application/pdf",

                    use_container_width=True

                )

                st.success(
                    "✅ Incident response generated successfully. "
                    "Your PDF report is ready to download."
                )

            except Exception as error:

                st.error(
                    f"Error generating PDF report: {error}"
                )


# =========================================================
# THREAT INTELLIGENCE
# =========================================================

elif analysis_type == "🧠 Threat Intelligence":

    st.header("🧠 Threat Intelligence")

    st.write(
        "Generate threat reputation, confidence, indicators "
        "and security recommendations from previous investigations."
    )

    history = st.session_state.scan_history

    if not history:

        st.info(
            "ℹ️ No investigations are available yet."
        )

        st.write(
            "First analyze a URL, file, email, QR code or domain."
        )

    else:

        investigation_options = []

        for index, record in enumerate(history):

            artifact_type = record.get(
                "type",
                "Unknown"
            )

            target = record.get(
                "target",
                "Unknown"
            )

            investigation_options.append(
                f"{index + 1}. {artifact_type} - {target}"
            )


        selected_investigation = st.selectbox(

            "Select Investigation",

            investigation_options

        )


        selected_index = investigation_options.index(
            selected_investigation
        )

        selected_record = history[
            selected_index
        ]


        st.markdown("---")

        st.subheader(
            "🔍 Selected Threat Artifact"
        )


        st.write(
            f"**Artifact Type:** "
            f"{selected_record.get('type', 'Unknown')}"
        )

        st.write(
            f"**Target:** "
            f"{selected_record.get('target', 'Unknown')}"
        )

        st.write(
            f"**Classification:** "
            f"{selected_record.get('result', 'Unknown')}"
        )

        st.write(
            f"**Risk Score:** "
            f"{selected_record.get('risk_score', 0)}/100"
        )


        if st.button(

            "🧠 Generate Threat Intelligence",

            use_container_width=True

        ):

            try:

                intelligence = generate_threat_intelligence(

                    artifact_type=selected_record.get(
                        "type",
                        "Unknown"
                    ),

                    target=selected_record.get(
                        "target",
                        "Unknown"
                    ),

                    classification=selected_record.get(
                        "result",
                        "Unknown"
                    ),

                    risk_score=selected_record.get(
                        "risk_score",
                        0
                    ),

                    findings=selected_record.get(
                        "findings",
                        []
                    )

                )


                threat_reputation = intelligence.get(
                    "threat_reputation",
                    "Unknown"
                )

                intelligence_confidence = intelligence.get(
                    "intelligence_confidence",
                    0
                )


                st.markdown("---")

                st.subheader(
                    "🚨 Threat Reputation"
                )


                if threat_reputation == "Malicious":

                    st.error(
                        "🔴 MALICIOUS THREAT"
                    )

                elif threat_reputation == "High Risk":

                    st.error(
                        "🟠 HIGH RISK THREAT"
                    )

                elif threat_reputation == "Suspicious":

                    st.warning(
                        "🟡 SUSPICIOUS THREAT"
                    )

                else:

                    st.success(
                        "🟢 CLEAN / LOW RISK"
                    )


                col1, col2 = st.columns(2)


                with col1:

                    st.metric(
                        "🛡️ Threat Reputation",
                        threat_reputation
                    )


                with col2:

                    st.metric(
                        "🎯 Intelligence Confidence",
                        f"{intelligence_confidence}%"
                    )


                st.subheader(
                    "🆔 Threat Intelligence ID"
                )

                st.code(
                    intelligence.get(
                        "threat_id",
                        "Not Available"
                    ),
                    language="text"
                )


                st.subheader(
                    "🔎 Threat Indicators"
                )

                indicators = intelligence.get(
                    "threat_indicators",
                    []
                )

                for indicator in indicators:

                    st.write(
                        f"• {indicator}"
                    )


                st.subheader(
                    "🛡️ Security Recommendations"
                )

                recommendations = intelligence.get(
                    "recommendations",
                    []
                )

                for index, recommendation in enumerate(

                    recommendations,

                    start=1

                ):

                    st.write(
                        f"{index}. {recommendation}"
                    )


                st.success(
                    "✅ Threat intelligence generated successfully."
                )


            except Exception as error:

                st.error(
                    f"Error generating threat intelligence: {error}"
                )


# =========================================================
# IOC EXTRACTION & INVESTIGATION
# =========================================================

elif analysis_type == "🔎 IOC Extraction & Investigation":

    st.header("🔎 IOC Extraction & Investigation")

    st.write(
        "Extract Indicators of Compromise (IOCs) from suspicious text "
        "and investigate the detected URLs and domains."
    )

    ioc_text = st.text_area(
        "Paste suspicious email, log, message or threat report",
        height=250,
        placeholder=(
            "Example: Suspicious login at https://secure-login.example.com "
            "from 192.168.1.25. SHA-256: "
            "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
        )
    )

    if st.button(
        "🔍 Extract IOCs",
        use_container_width=True
    ):

        if not ioc_text.strip():

            st.warning("⚠️ Please paste some text to analyze.")

        else:

            try:

                iocs = extract_iocs(ioc_text)
                counts = count_iocs(iocs)
                total_iocs = get_total_iocs(iocs)

                st.session_state["last_iocs"] = iocs

                st.markdown("---")
                st.subheader("📊 IOC Summary")

                col1, col2, col3, col4 = st.columns(4)

                col1.metric("🔗 URLs", counts["urls"])
                col2.metric("🌐 Domains", counts["domains"])
                col3.metric("📍 IP Addresses", counts["ip_addresses"])
                col4.metric("🔐 Total IOCs", total_iocs)

                st.subheader("🔗 Detected URLs")

                if iocs["urls"]:
                    for detected_url in iocs["urls"]:
                        st.code(detected_url, language="text")

                    st.subheader("🧪 URL Investigation")

                    selected_url = st.selectbox(
                        "Select a detected URL",
                        iocs["urls"]
                    )

                    if st.button(
                        "🛡️ Analyze Selected URL",
                        use_container_width=True
                    ):
                        url_result = analyze_url(selected_url)

                        classification = url_result.get(
                            "classification", "Unknown"
                        )
                        risk_score = url_result.get(
                            "risk_score", 0
                        )

                        if classification == "Potentially Malicious":
                            st.error("🚨 Potentially Malicious URL")
                        elif classification == "Suspicious":
                            st.warning("⚠️ Suspicious URL")
                        else:
                            st.success("✅ Likely Legitimate URL")

                        col1, col2 = st.columns(2)

                        with col1:
                            st.metric(
                                "AI Confidence",
                                f"{url_result.get('ai_confidence', 0):.2f}%"
                            )

                        with col2:
                            st.metric(
                                "Risk Score",
                                f"{risk_score}/100"
                            )

                        findings = url_result.get("findings", [])

                        if findings:
                            st.subheader("🔎 URL Security Findings")
                            for finding in findings:
                                st.write(finding)

                        st.info(
                            url_result.get(
                                "recommendation",
                                "Perform additional security analysis."
                            )
                        )

                else:
                    st.success("No URLs were detected.")

                st.subheader("🌐 Detected Domains")

                if iocs["domains"]:
                    for domain in iocs["domains"]:
                        st.code(domain, language="text")

                    st.subheader("🧪 Domain Investigation")

                    selected_domain = st.selectbox(
                        "Select a detected domain",
                        iocs["domains"]
                    )

                    if st.button(
                        "🛡️ Analyze Selected Domain",
                        use_container_width=True
                    ):
                        domain_result = analyze_domain(selected_domain)

                        classification = domain_result.get(
                            "classification", "Unknown"
                        )
                        risk_score = domain_result.get(
                            "risk_score", 0
                        )

                        if classification == "Potentially Malicious":
                            st.error("🚨 Potentially Malicious Domain")
                        elif classification == "Suspicious":
                            st.warning("⚠️ Suspicious Domain")
                        else:
                            st.success("✅ Likely Safe Domain")

                        col1, col2 = st.columns(2)

                        with col1:
                            st.metric(
                                "Risk Score",
                                f"{risk_score}/100"
                            )

                        with col2:
                            st.metric(
                                "Resolved IPs",
                                len(domain_result.get("resolved_ips", []))
                            )

                        findings = domain_result.get("findings", [])

                        if findings:
                            st.subheader("🔎 Domain Security Findings")
                            for finding in findings:
                                st.write(finding)

                else:
                    st.success("No domains were detected.")

                st.subheader("📍 Detected IP Addresses")

                if iocs["ip_addresses"]:
                    for ip_address in iocs["ip_addresses"]:
                        st.code(ip_address, language="text")
                else:
                    st.success("No IPv4 addresses were detected.")

                st.subheader("🔐 Detected File Hashes")

                hash_data = iocs.get("hashes", {})

                for hash_type, hashes in hash_data.items():
                    if hashes:
                        st.write(f"**{hash_type.upper()} Hashes**")
                        for hash_value in hashes:
                            st.code(hash_value, language="text")

                if not any(hash_data.values()):
                    st.success("No file hashes were detected.")

                st.success(
                    f"✅ IOC extraction completed. {total_iocs} IOC(s) detected."
                )

            except Exception as error:
                st.error(f"Error extracting IOCs: {error}")


# =========================================================
# IOC INVESTIGATION DASHBOARD
# =========================================================

elif analysis_type == "🕵️ IOC Investigation Dashboard":

    st.header("🕵️ IOC Investigation Dashboard")

    st.write(
        "Investigate previously extracted Indicators of Compromise "
        "(IOCs) and organize them into an investigation overview."
    )

    iocs = st.session_state.get("last_iocs", {})

    if not iocs:
        st.info(
            "ℹ️ No extracted IOCs are available yet."
        )

        st.write(
            "First use **🔎 IOC Extraction & Investigation**, "
            "paste suspicious text and click **🔍 Extract IOCs**."
        )

    else:

        try:
            investigation = investigate_iocs(iocs)

            total_iocs = investigation.get(
                "total_iocs",
                0
            )

            investigation_status = investigation.get(
                "investigation_status",
                "Unknown"
            )

            investigation_priority = investigation.get(
                "investigation_priority",
                "Unknown"
            )

            st.markdown("---")
            st.subheader("📊 Investigation Overview")

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "🔐 Total IOCs",
                    total_iocs
                )

            with col2:
                st.metric(
                    "📋 Investigation Status",
                    investigation_status
                )

            with col3:
                st.metric(
                    "🎯 Priority",
                    investigation_priority
                )

            st.markdown("---")

            st.subheader("🔗 URL Indicators")

            urls = investigation.get("urls", [])

            if urls:
                for url in urls:
                    st.code(
                        url,
                        language="text"
                    )
            else:
                st.success(
                    "No URL indicators were extracted."
                )

            st.subheader("🌐 Domain Indicators")

            domains = investigation.get("domains", [])

            if domains:
                for domain in domains:
                    st.code(
                        domain,
                        language="text"
                    )
            else:
                st.success(
                    "No domain indicators were extracted."
                )

            st.subheader("📍 IP Address Indicators")

            ip_addresses = investigation.get(
                "ip_addresses",
                []
            )

            if ip_addresses:
                for ip_address in ip_addresses:
                    st.code(
                        ip_address,
                        language="text"
                    )
            else:
                st.success(
                    "No IPv4 indicators were extracted."
                )

            st.subheader("🔐 File Hash Indicators")

            hash_sections = [
                ("MD5", investigation.get("md5", [])),
                ("SHA-1", investigation.get("sha1", [])),
                ("SHA-256", investigation.get("sha256", []))
            ]

            hashes_found = False

            for hash_name, hash_values in hash_sections:

                if hash_values:
                    hashes_found = True

                    st.write(
                        f"**{hash_name}**"
                    )

                    for hash_value in hash_values:
                        st.code(
                            hash_value,
                            language="text"
                        )

            if not hashes_found:
                st.success(
                    "No file hash indicators were extracted."
                )

            st.markdown("---")

            st.subheader("🔎 Investigation Findings")

            findings = investigation.get(
                "findings",
                []
            )

            for finding in findings:
                st.write(
                    f"• {finding}"
                )

            st.markdown("---")

            st.subheader("🧭 Investigation Guidance")

            if investigation_priority == "High":
                st.error(
                    "🚨 High IOC activity detected. "
                    "Prioritize investigation of the identified "
                    "indicators and preserve relevant evidence."
                )

            elif investigation_priority == "Medium":
                st.warning(
                    "⚠️ Multiple indicators were detected. "
                    "Continue investigation and correlate the "
                    "indicators with other threat artifacts."
                )

            else:
                st.info(
                    "ℹ️ Continue investigating the extracted "
                    "indicators and correlate them with other "
                    "available security evidence."
                )

        except Exception as error:

            st.error(
                f"Error investigating IOCs: {error}"
            )


# =========================================================
# IOC RELATIONSHIP & CORRELATION
# =========================================================

elif analysis_type == "🔗 IOC Relationship & Correlation":

    st.header("🔗 IOC Relationship & Correlation")

    st.write(
        "Correlate extracted URLs, domains, IP addresses and hashes "
        "with each other and with previous investigations."
    )

    iocs = st.session_state.get("last_iocs", {})
    history = st.session_state.scan_history

    if not iocs:
        st.info(
            "ℹ️ No extracted IOCs are available yet."
        )

        st.write(
            "First use **🔎 IOC Extraction & Investigation**, "
            "paste suspicious text and click **🔍 Extract IOCs**."
        )

    else:

        try:

            relationships = build_ioc_relationships(
                iocs,
                history
            )

            urls = iocs.get("urls", [])
            domains = iocs.get("domains", [])
            ip_addresses = iocs.get("ip_addresses", [])
            hashes = iocs.get("hashes", {})

            total_relationships = len(relationships)

            st.markdown("---")
            st.subheader("📊 Relationship Overview")

            col1, col2, col3, col4 = st.columns(4)

            with col1:
                st.metric(
                    "🔗 URLs",
                    len(urls)
                )

            with col2:
                st.metric(
                    "🌐 Domains",
                    len(domains)
                )

            with col3:
                st.metric(
                    "📍 IP Addresses",
                    len(ip_addresses)
                )

            with col4:
                st.metric(
                    "🧩 Relationships",
                    total_relationships
                )

            st.markdown("---")

            if not relationships:

                st.info(
                    "ℹ️ No direct IOC relationships were found "
                    "from the extracted indicators and available "
                    "investigation history."
                )

            else:

                st.subheader("🕸️ IOC Relationship Map")

                for index, relationship in enumerate(
                    relationships,
                    start=1
                ):

                    st.markdown(
                        f"### 🔗 Relationship #{index}"
                    )

                    col1, col2, col3 = st.columns(3)

                    with col1:
                        st.write(
                            f"**Source**\n\n"
                            f"`{relationship['source']}`"
                        )
                        st.caption(
                            relationship["source_type"]
                        )

                    with col2:
                        st.write(
                            f"**Relationship**\n\n"
                            f"**{relationship['relationship']}**"
                        )

                    with col3:
                        st.write(
                            f"**Target**\n\n"
                            f"`{relationship['target']}`"
                        )
                        st.caption(
                            relationship["target_type"]
                        )

                    st.info(
                        f"Evidence: {relationship['evidence']}"
                    )

                    st.markdown("---")

            st.subheader("🧭 Correlation Summary")

            url_domain_links = sum(
                1
                for relationship in relationships
                if relationship["relationship"] == "contains domain"
            )

            url_ip_links = sum(
                1
                for relationship in relationships
                if relationship["relationship"] == "uses IP address"
            )

            history_links = sum(
                1
                for relationship in relationships
                if relationship["relationship"]
                in (
                    "matches investigation",
                    "matches file investigation"
                )
            )

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "URL ↔ Domain",
                    url_domain_links
                )

            with col2:
                st.metric(
                    "URL ↔ IP",
                    url_ip_links
                )

            with col3:
                st.metric(
                    "History Matches",
                    history_links
                )

            st.caption(
                "Correlation indicates a data relationship between "
                "indicators. It does not by itself prove that an IOC "
                "is malicious."
            )

        except Exception as error:

            st.error(
                f"Error correlating IOCs: {error}"
            )


# =========================================================
# THREAT GRAPH VISUALIZATION
# =========================================================

elif analysis_type == "🕸️ Threat Graph Visualization":

    st.header("🕸️ Threat Graph Visualization")

    st.write(
        "Visualize relationships between extracted indicators and "
        "previous investigation records. The graph represents "
        "data relationships and does not by itself prove malicious activity."
    )

    iocs = st.session_state.get("last_iocs", {})
    history = st.session_state.scan_history

    if not iocs:
        st.info(
            "ℹ️ No extracted IOCs are available yet."
        )

        st.write(
            "First use **🔎 IOC Extraction & Investigation**, "
            "paste suspicious text and click **🔍 Extract IOCs**."
        )

    else:

        try:

            relationships = build_ioc_relationships(
                iocs,
                history
            )

            urls = iocs.get("urls", [])
            domains = iocs.get("domains", [])
            ip_addresses = iocs.get("ip_addresses", [])
            hashes = iocs.get("hashes", {})

            total_indicators = (
                len(urls)
                + len(domains)
                + len(ip_addresses)
                + len(hashes.get("md5", []))
                + len(hashes.get("sha1", []))
                + len(hashes.get("sha256", []))
            )

            col1, col2, col3 = st.columns(3)

            with col1:
                st.metric(
                    "🧩 Indicators",
                    total_indicators
                )

            with col2:
                st.metric(
                    "🔗 Relationships",
                    len(relationships)
                )

            with col3:
                st.metric(
                    "🗂️ History Records",
                    len(history)
                )

            st.markdown("---")
            st.subheader("🕸️ Investigation Graph")

            graph = build_ioc_graph(
                iocs,
                relationships
            )

            st.graphviz_chart(
                graph,
                use_container_width=True
            )

            st.caption(
                "Graph nodes represent extracted indicators. "
                "Edges represent detected local relationships or matches "
                "with previous investigation records."
            )

            if relationships:
                st.subheader("🔎 Graph Relationships")

                for index, relationship in enumerate(
                    relationships,
                    start=1
                ):
                    st.write(
                        f"**{index}.** "
                        f"`{relationship['source']}` "
                        f"→ **{relationship['relationship']}** → "
                        f"`{relationship['target']}`"
                    )
            else:
                st.info(
                    "No direct relationships were detected. "
                    "The graph still displays the extracted indicators "
                    "as independent investigation evidence."
                )

        except Exception as error:

            st.error(
                f"Error generating threat graph: {error}"
            )


# =========================================================
# THREAT INTELLIGENCE DASHBOARD
# =========================================================

elif analysis_type == "🛡️ Threat Intelligence Dashboard":

    st.header("🛡️ Threat Intelligence Dashboard")

    st.write(
        "A centralized overview of your previous threat investigations, "
        "risk levels and investigation activity."
    )

    history = st.session_state.scan_history

    if not history:

        st.info(
            "ℹ️ No investigations are available yet. "
            "Analyze a URL, file, email, QR code or domain first."
        )

    else:

        total_investigations = len(history)

        high_risk = sum(
            1 for record in history
            if record.get("risk_score", 0) >= 60
        )

        suspicious = sum(
            1 for record in history
            if 30 <= record.get("risk_score", 0) < 60
        )

        average_risk = sum(
            record.get("risk_score", 0)
            for record in history
        ) / total_investigations

        col1, col2, col3, col4 = st.columns(4)

        col1.metric(
            "🔢 Total Investigations",
            total_investigations
        )

        col2.metric(
            "🚨 High Risk",
            high_risk
        )

        col3.metric(
            "⚠️ Suspicious",
            suspicious
        )

        col4.metric(
            "📊 Average Risk",
            f"{average_risk:.1f}/100"
        )

        st.markdown("---")


        most_dangerous = max(
            history,
            key=lambda record: record.get("risk_score", 0)
        )

        st.subheader("🎯 Highest-Risk Investigation")

        danger_col1, danger_col2, danger_col3 = st.columns(3)

        danger_col1.write(
            f"**Type:** {most_dangerous.get('type', 'Unknown')}"
        )

        danger_col2.write(
            f"**Risk Score:** {most_dangerous.get('risk_score', 0)}/100"
        )

        danger_col3.write(
            f"**Result:** {most_dangerous.get('result', 'Unknown')}"
        )

        st.code(
            str(most_dangerous.get("target", "Unknown")),
            language="text"
        )

        st.markdown("---")


        st.subheader("📈 Risk Distribution")

        risk_distribution = {
            "Likely Safe": 0,
            "Suspicious": 0,
            "High Risk": 0
        }

        for record in history:

            score = record.get("risk_score", 0)

            if score >= 60:
                risk_distribution["High Risk"] += 1

            elif score >= 30:
                risk_distribution["Suspicious"] += 1

            else:
                risk_distribution["Likely Safe"] += 1

        st.bar_chart(
            risk_distribution
        )


        st.subheader("🧩 Investigation Type Breakdown")

        type_counts = {}

        for record in history:

            artifact_type = record.get(
                "type",
                "Unknown"
            )

            type_counts[artifact_type] = (
                type_counts.get(
                    artifact_type,
                    0
                ) + 1
            )

        st.bar_chart(
            type_counts
        )


        st.subheader("🔗 Threat Relationship Summary")

        correlations = correlate_artifacts(
            history
        )

        if correlations:

            st.warning(
                f"⚠️ {len(correlations)} related investigation "
                "relationship(s) detected."
            )

        else:

            st.success(
                "✅ No direct relationships were found between "
                "the current investigations."
            )


# =========================================================
# INVESTIGATION STATISTICS
# =========================================================

elif analysis_type == "📊 Investigation Statistics":

    st.header("📈 Investigation Statistics")

    history = st.session_state.scan_history

    if not history:

        st.info(
            "No investigations available yet."
        )

    else:

        total = len(
            history
        )


        malicious = sum(

            1

            for record in history

            if record.get("result")

            == "Potentially Malicious"

        )


        suspicious = sum(

            1

            for record in history

            if record.get("result")

            == "Suspicious"

        )


        average_risk = (

            sum(

                record.get(
                    "risk_score",
                    0
                )

                for record in history

            )

            /

            total

        )


        col1, col2, col3, col4 = st.columns(4)


        with col1:

            st.metric(
                "🔢 Total Investigations",
                total
            )


        with col2:

            st.metric(
                "🚨 Malicious",
                malicious
            )


        with col3:

            st.metric(
                "⚠️ Suspicious",
                suspicious
            )


        with col4:

            st.metric(
                "📊 Average Risk",
                f"{average_risk:.1f}/100"
            )


        st.subheader(
            "🧩 Investigation Breakdown"
        )


        url_count = sum(

            1

            for record in history

            if record.get("type") == "URL"

        )


        file_count = sum(

            1

            for record in history

            if record.get("type") == "FILE"

        )


        email_count = sum(

            1

            for record in history

            if record.get("type") == "EMAIL"

        )


        qr_count = sum(

            1

            for record in history

            if record.get("type") == "QR"

        )


        domain_count = sum(

            1

            for record in history

            if record.get("type") == "DOMAIN"

        )


        col1, col2, col3, col4, col5 = st.columns(5)


        with col1:

            st.metric(
                "🔗 URLs",
                url_count
            )


        with col2:

            st.metric(
                "📁 Files",
                file_count
            )


        with col3:

            st.metric(
                "📧 Emails",
                email_count
            )


        with col4:

            st.metric(
                "📱 QR Codes",
                qr_count
            )


        with col5:

            st.metric(
                "🌐 Domains/IPs",
                domain_count
            )


# =========================================================
# SCAN HISTORY
# =========================================================

elif analysis_type == "📜 Scan History":

    st.header("📜 Investigation History")

    history = st.session_state.scan_history

    if not history:

        st.info(
            "No investigations have been performed yet."
        )

    else:

        display_data = []

        for record in history:

            display_data.append({

                "Type": record.get(
                    "type"
                ),

                "Target": record.get(
                    "target"
                ),

                "Result": record.get(
                    "result"
                ),

                "Risk Score":

                    f"{record.get('risk_score', 0)}/100",

                "Fingerprint":

                    str(

                        record.get(
                            "fingerprint",
                            ""
                        )

                    )[:16].upper()

            })


        st.dataframe(

            display_data,

            use_container_width=True,

            hide_index=True

        )


        if st.button(

            "🗑️ Clear Investigation History",

            use_container_width=True

        ):

            st.session_state.scan_history = []

            st.rerun()


# =========================================================
# FOOTER
# =========================================================

st.markdown("---")

st.caption(

    "🛡️ AI Cyber Threat Analysis Platform | "
    "URL • File • Email • QR • Domain/IP • "
    "Malware Intelligence • Threat Correlation • "
    "IOC Correlation • Threat Graph • Incident Response • "
    "Threat Intelligence • Threat Intelligence Dashboard"

)