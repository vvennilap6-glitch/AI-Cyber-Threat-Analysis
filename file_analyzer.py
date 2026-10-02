import hashlib
import math
import os
import re
import zipfile
from pathlib import Path


# ============================================================
# SHA-256
# ============================================================

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as file:
        while True:
            chunk = file.read(8192)

            if not chunk:
                break

            sha256.update(chunk)

    return sha256.hexdigest()


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(file_path):
    with open(file_path, "rb") as file:
        data = file.read()

    if not data:
        return 0.0

    frequency = [0] * 256

    for byte in data:
        frequency[byte] += 1

    entropy = 0.0
    data_length = len(data)

    for count in frequency:
        if count == 0:
            continue

        probability = count / data_length
        entropy -= probability * math.log2(probability)

    return entropy


# ============================================================
# FILE TYPE DETECTION
# ============================================================

def detect_file_type(file_path):
    extension = Path(file_path).suffix.lower()

    signatures = {
        b"\x4d\x5a": "Windows PE executable",
        b"\x7fELF": "Linux ELF executable",
        b"%PDF": "PDF document",
        b"\x89PNG": "PNG image",
        b"\xff\xd8\xff": "JPEG image",
        b"PK\x03\x04": "ZIP-based archive/document",
    }

    try:
        with open(file_path, "rb") as file:
            header = file.read(16)
    except Exception:
        return "Unknown"

    detected_type = "Unknown"

    for signature, file_type in signatures.items():
        if header.startswith(signature):
            detected_type = file_type
            break

    if detected_type == "ZIP-based archive/document":
        try:
            with zipfile.ZipFile(file_path, "r") as archive:
                names = archive.namelist()

                if "[Content_Types].xml" in names:

                    if any(name.startswith("word/") for name in names):
                        detected_type = "Microsoft Word document"

                    elif any(name.startswith("xl/") for name in names):
                        detected_type = "Microsoft Excel document"

                    elif any(name.startswith("ppt/") for name in names):
                        detected_type = "Microsoft PowerPoint document"

        except zipfile.BadZipFile:
            pass

    if detected_type == "Unknown" and extension:
        detected_type = f"File with {extension} extension"

    return detected_type


# ============================================================
# ARCHIVE / OFFICE DOCUMENT ANALYSIS
# ============================================================

def analyze_archive_contents(file_path):
    findings = []
    embedded_files = []
    urls = []

    try:
        with zipfile.ZipFile(file_path, "r") as archive:

            names = archive.namelist()

            embedded_files = [
                name for name in names
                if not name.endswith("/")
            ]

            suspicious_extensions = (
                ".exe",
                ".dll",
                ".scr",
                ".bat",
                ".cmd",
                ".ps1",
                ".vbs",
                ".js",
                ".jar",
                ".msi",
                ".hta"
            )

            for name in names:

                lower_name = name.lower()

                if lower_name.endswith(suspicious_extensions):
                    findings.append(
                        f"🚨 Suspicious executable/script found "
                        f"inside archive: {name}"
                    )

                try:
                    if not name.endswith("/"):
                        data = archive.read(name)

                        text = data.decode(
                            "utf-8",
                            errors="ignore"
                        )

                        found_urls = re.findall(
                            r"https?://[^\s<>'\"]+",
                            text,
                            re.IGNORECASE
                        )

                        urls.extend(found_urls)

                except Exception:
                    continue

            if any(
                "vbaProject" in name
                or "vbaproject" in name.lower()
                for name in names
            ):
                findings.append(
                    "🚨 VBA macro project detected"
                )

            if any(
                "external" in name.lower()
                and name.lower().endswith(".xml.rels")
                for name in names
            ):
                findings.append(
                    "⚠️ External relationship data detected"
                )

    except zipfile.BadZipFile:
        pass

    except Exception:
        pass

    return {
        "embedded_files": embedded_files,
        "urls": list(set(urls)),
        "findings": list(set(findings))
    }


# ============================================================
# TEXT / SCRIPT ANALYSIS
# ============================================================

def analyze_text_content(file_path):
    findings = []

    text_extensions = {
        ".txt",
        ".py",
        ".js",
        ".html",
        ".htm",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".psm1",
        ".php",
        ".sh",
        ".json",
        ".xml",
        ".csv"
    }

    extension = Path(file_path).suffix.lower()

    if extension not in text_extensions:
        return findings

    try:
        with open(
            file_path,
            "r",
            encoding="utf-8",
            errors="ignore"
        ) as file:
            content = file.read()

    except Exception:
        return findings

    patterns = {
        "PowerShell command":
            r"\bpowershell(?:\.exe)?\b",

        "Command shell execution":
            r"\bcmd\.exe\b|\bcommand\.com\b",

        "Process execution":
            r"\bsubprocess\.",

        "Dynamic code execution":
            r"\beval\s*\(|\bexec\s*\(",

        "Base64 encoding/decoding":
            r"\bbase64\b|\bb64decode\b|\bb64encode\b",

        "Suspicious download function":
            r"\burllib\.request\b|\brequests\.get\s*\(",

        "Possible IP address":
            r"\b(?:\d{1,3}\.){3}\d{1,3}\b",

        "Obfuscated hexadecimal string":
            r"\\x[0-9a-fA-F]{2}",

        "JavaScript execution":
            r"\bjavascript\s*:|\.js\b"
    }

    for name, pattern in patterns.items():

        if re.search(
            pattern,
            content,
            re.IGNORECASE
        ):
            findings.append(name)

    return findings


# ============================================================
# FILE NAME ANALYSIS
# ============================================================

def analyze_filename(file_name):
    findings = []

    lower_name = file_name.lower()

    suspicious_extensions = [
        ".exe",
        ".dll",
        ".scr",
        ".bat",
        ".cmd",
        ".ps1",
        ".vbs",
        ".js",
        ".jar",
        ".msi",
        ".hta"
    ]

    extension = Path(lower_name).suffix

    if extension in suspicious_extensions:
        findings.append(
            f"🚨 Potentially executable file type: {extension}"
        )

    dangerous_double_extensions = [
        ".pdf.exe",
        ".jpg.exe",
        ".jpeg.exe",
        ".png.exe",
        ".doc.exe",
        ".docx.exe",
        ".xls.exe",
        ".xlsx.exe"
    ]

    if any(
        lower_name.endswith(pattern)
        for pattern in dangerous_double_extensions
    ):
        findings.append(
            "🚨 Suspicious double file extension detected"
        )

    if lower_name.startswith("."):
        findings.append(
            "⚠️ Hidden-style filename detected"
        )

    return findings


# ============================================================
# MAIN FILE ANALYZER
# ============================================================

def analyze_file(file_path):

    file_name = os.path.basename(file_path)
    file_size = os.path.getsize(file_path)

    extension = (
        Path(file_name).suffix.lower()
        if Path(file_name).suffix
        else "No extension"
    )

    sha256 = calculate_sha256(file_path)
    entropy = calculate_entropy(file_path)
    file_type = detect_file_type(file_path)

    findings = []

    # --------------------------------------------------------
    # Filename analysis
    # --------------------------------------------------------

    findings.extend(
        analyze_filename(file_name)
    )

    # --------------------------------------------------------
    # File type analysis
    # --------------------------------------------------------

    if file_type == "Windows PE executable":
        findings.append(
            "🚨 Windows executable format detected"
        )

    elif file_type == "Linux ELF executable":
        findings.append(
            "🚨 Linux executable format detected"
        )

    # --------------------------------------------------------
    # Entropy analysis
    # --------------------------------------------------------

    entropy_warning = False

    if entropy >= 7.8:

        entropy_warning = True

        if extension not in {
            ".docx",
            ".xlsx",
            ".pptx",
            ".zip",
            ".jar"
        }:
            findings.append(
                "⚠️ Very high file entropy detected"
            )

    # --------------------------------------------------------
    # Large file analysis
    # --------------------------------------------------------

    if file_size > 100 * 1024 * 1024:
        findings.append(
            "⚠️ Unusually large file detected"
        )

    # --------------------------------------------------------
    # Text analysis
    # --------------------------------------------------------

    findings.extend(
        analyze_text_content(file_path)
    )

    # --------------------------------------------------------
    # Archive / Office analysis
    # --------------------------------------------------------

    archive_result = {
        "embedded_files": [],
        "urls": [],
        "findings": []
    }

    if file_type in {
        "ZIP-based archive/document",
        "Microsoft Word document",
        "Microsoft Excel document",
        "Microsoft PowerPoint document"
    }:

        archive_result = analyze_archive_contents(
            file_path
        )

        findings.extend(
            archive_result["findings"]
        )

    # --------------------------------------------------------
    # Risk scoring
    # --------------------------------------------------------

    risk_score = 0

    # Strong indicators
    for finding in findings:

        finding_lower = finding.lower()

        if "windows executable format" in finding_lower:
            risk_score += 40

        elif "linux executable format" in finding_lower:
            risk_score += 40

        elif "potentially executable file type" in finding_lower:
            risk_score += 35

        elif "double file extension" in finding_lower:
            risk_score += 40

        elif "executable/script found inside archive" in finding_lower:
            risk_score += 40

        elif "vba macro project detected" in finding_lower:
            risk_score += 35

        elif "powershell command" in finding_lower:
            risk_score += 25

        elif "command shell execution" in finding_lower:
            risk_score += 25

        elif "process execution" in finding_lower:
            risk_score += 20

        elif "dynamic code execution" in finding_lower:
            risk_score += 20

        elif "suspicious download function" in finding_lower:
            risk_score += 20

        elif "base64 encoding/decoding" in finding_lower:
            risk_score += 10

        elif "possible ip address" in finding_lower:
            risk_score += 10

        elif "obfuscated hexadecimal string" in finding_lower:
            risk_score += 15

        elif "javascript execution" in finding_lower:
            risk_score += 15

        elif "hidden-style filename" in finding_lower:
            risk_score += 10

        elif "unusually large file" in finding_lower:
            risk_score += 10

        elif "external relationship data" in finding_lower:
            risk_score += 10

        elif "very high file entropy" in finding_lower:
            risk_score += 10

    risk_score = min(
        risk_score,
        100
    )

    # --------------------------------------------------------
    # Classification
    # --------------------------------------------------------

    if risk_score >= 60:
        classification = "Potentially Malicious"

    elif risk_score >= 30:
        classification = "Suspicious"

    else:
        classification = "Likely Safe"

    # --------------------------------------------------------
    # Recommendation
    # --------------------------------------------------------

    if classification == "Potentially Malicious":

        recommendation = (
            "🚨 Do not open or execute this file. "
            "Further malware analysis is recommended."
        )

    elif classification == "Suspicious":

        recommendation = (
            "⚠️ Treat this file with caution. "
            "Additional security analysis is recommended."
        )

    else:

        recommendation = (
            "✅ No major threat indicators were detected "
            "during this analysis."
        )

    # --------------------------------------------------------
    # Clean finding list
    # --------------------------------------------------------

    final_findings = list(dict.fromkeys(findings))

    if not final_findings:
        final_findings = [
            "No obvious suspicious characteristics detected."
        ]

    return {
        "file_name": file_name,
        "file_size": file_size,
        "extension": extension,
        "file_type": file_type,
        "sha256": sha256,
        "entropy": round(entropy, 2),
        "risk_score": risk_score,
        "classification": classification,
        "recommendation": recommendation,
        "reasons": final_findings,
        "suspicious_patterns": final_findings,
        "embedded_files": archive_result["embedded_files"],
        "embedded_urls": archive_result["urls"]
    }