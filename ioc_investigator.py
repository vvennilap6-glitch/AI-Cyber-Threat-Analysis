def investigate_iocs(iocs):
    """
    Analyze extracted IOCs and generate an investigation summary.
    """

    iocs = iocs or {}

    urls = iocs.get("urls", [])
    domains = iocs.get("domains", [])
    ip_addresses = iocs.get("ip_addresses", [])
    hashes = iocs.get("hashes", {})

    md5 = hashes.get("md5", [])
    sha1 = hashes.get("sha1", [])
    sha256 = hashes.get("sha256", [])

    total_iocs = (
        len(urls)
        + len(domains)
        + len(ip_addresses)
        + len(md5)
        + len(sha1)
        + len(sha256)
    )

    findings = []

    # URL investigation
    if urls:
        findings.append(
            f"{len(urls)} URL indicator(s) require investigation."
        )

    # Domain investigation
    if domains:
        findings.append(
            f"{len(domains)} domain indicator(s) were identified."
        )

    # IP investigation
    if ip_addresses:
        findings.append(
            f"{len(ip_addresses)} IPv4 indicator(s) were identified."
        )

    # Hash investigation
    if md5:
        findings.append(
            f"{len(md5)} MD5 hash indicator(s) were identified."
        )

    if sha1:
        findings.append(
            f"{len(sha1)} SHA-1 hash indicator(s) were identified."
        )

    if sha256:
        findings.append(
            f"{len(sha256)} SHA-256 hash indicator(s) were identified."
        )

    if total_iocs == 0:
        investigation_status = "No IOCs Detected"
        investigation_priority = "Low"
    elif total_iocs <= 2:
        investigation_status = "Initial Investigation"
        investigation_priority = "Low"
    elif total_iocs <= 5:
        investigation_status = "Investigation Required"
        investigation_priority = "Medium"
    else:
        investigation_status = "High IOC Activity"
        investigation_priority = "High"

    if not findings:
        findings.append(
            "No indicators were available for investigation."
        )

    return {
        "total_iocs": total_iocs,
        "investigation_status": investigation_status,
        "investigation_priority": investigation_priority,
        "urls": urls,
        "domains": domains,
        "ip_addresses": ip_addresses,
        "md5": md5,
        "sha1": sha1,
        "sha256": sha256,
        "findings": findings
    }