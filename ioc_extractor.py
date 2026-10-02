import re


def extract_iocs(text):
    """
    Extract Indicators of Compromise (IOCs) from text.

    Extracts:
    - URLs
    - Domains
    - IPv4 addresses
    - MD5 hashes
    - SHA-1 hashes
    - SHA-256 hashes
    """

    if not text:
        return {
            "urls": [],
            "domains": [],
            "ip_addresses": [],
            "hashes": {
                "md5": [],
                "sha1": [],
                "sha256": []
            }
        }

    text = str(text)

    # -----------------------------
    # URL extraction
    # -----------------------------
    url_pattern = r"https?://[^\s<>'\"`]+"

    urls = re.findall(url_pattern, text)

    # Remove common punctuation accidentally captured at the end
    urls = [
        url.rstrip(".,;:!?)]}")
        for url in urls
    ]

    # Remove duplicates
    urls = list(dict.fromkeys(urls))

    # -----------------------------
    # IPv4 extraction
    # -----------------------------
    ip_pattern = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"

    possible_ips = re.findall(ip_pattern, text)

    ip_addresses = []

    for ip in possible_ips:
        parts = ip.split(".")

        if all(0 <= int(part) <= 255 for part in parts):
            ip_addresses.append(ip)

    ip_addresses = list(dict.fromkeys(ip_addresses))

    # -----------------------------
    # Domain extraction
    # -----------------------------
    domain_pattern = (
        r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}"
        r"[a-zA-Z0-9])?\.)+"
        r"[a-zA-Z]{2,}\b"
    )

    possible_domains = re.findall(domain_pattern, text)

    domains = []

    for domain in possible_domains:
        domain = domain.lower()

        # Ignore domains already represented by IP addresses
        if domain not in domains:
            domains.append(domain)

    # -----------------------------
    # Hash extraction
    # -----------------------------

    md5_pattern = r"\b[a-fA-F0-9]{32}\b"
    sha1_pattern = r"\b[a-fA-F0-9]{40}\b"
    sha256_pattern = r"\b[a-fA-F0-9]{64}\b"

    md5_hashes = list(dict.fromkeys(
        re.findall(md5_pattern, text)
    ))

    sha1_hashes = list(dict.fromkeys(
        re.findall(sha1_pattern, text)
    ))

    sha256_hashes = list(dict.fromkeys(
        re.findall(sha256_pattern, text)
    ))

    return {
        "urls": urls,
        "domains": domains,
        "ip_addresses": ip_addresses,
        "hashes": {
            "md5": md5_hashes,
            "sha1": sha1_hashes,
            "sha256": sha256_hashes
        }
    }


def count_iocs(iocs):
    """
    Count all extracted IOC types.
    """

    return {
        "urls": len(iocs.get("urls", [])),
        "domains": len(iocs.get("domains", [])),
        "ip_addresses": len(iocs.get("ip_addresses", [])),
        "md5": len(iocs.get("hashes", {}).get("md5", [])),
        "sha1": len(iocs.get("hashes", {}).get("sha1", [])),
        "sha256": len(iocs.get("hashes", {}).get("sha256", []))
    }


def get_total_iocs(iocs):
    """
    Return total number of extracted IOCs.
    """

    counts = count_iocs(iocs)

    return sum(counts.values())