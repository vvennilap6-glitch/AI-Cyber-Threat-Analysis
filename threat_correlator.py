import re
from urllib.parse import urlparse


def extract_domains(text):
    if not text:
        return []

    urls = re.findall(
        r"https?://[^\s<>\"']+",
        str(text),
        re.IGNORECASE
    )

    domains = []

    for url in urls:
        try:
            domain = (
                urlparse(url)
                .netloc
                .split(":")[0]
                .lower()
                .rstrip(".")
            )

            if domain:
                domains.append(domain)

        except Exception:
            pass

    return list(set(domains))


def normalize_target(target):
    if not target:
        return ""

    value = str(target).strip().lower()

    if value in {
        "email message",
        "qr code",
        "file",
        "domain investigation"
    }:
        return ""

    if "://" not in value:
        value = "https://" + value

    try:
        return (
            urlparse(value)
            .netloc
            .split(":")[0]
            .lower()
            .rstrip(".")
        )
    except Exception:
        return ""


def extract_artifact_domains(artifact):
    domains = set()

    target_domain = normalize_target(
        artifact.get("target", "")
    )

    if target_domain:
        domains.add(target_domain)

    for key in (
        "email_text",
        "text",
        "data",
        "content",
        "message"
    ):
        for domain in extract_domains(
            artifact.get(key, "")
        ):
            domains.add(domain)

    suspicious_urls = artifact.get(
        "suspicious_urls",
        []
    )

    if isinstance(suspicious_urls, list):
        for url in suspicious_urls:
            domain = normalize_target(url)

            if domain:
                domains.add(domain)

    return domains


def correlate_artifacts(history):

    correlations = []
    seen_pairs = set()

    for i in range(len(history)):

        for j in range(i + 1, len(history)):

            first = history[i]
            second = history[j]

            # Ignore exact duplicate investigations.
            if (
                first.get("type") == second.get("type")
                and first.get("target") == second.get("target")
                and first.get("fingerprint") == second.get("fingerprint")
            ):
                continue

            # Create a unique pair identifier.
            pair_id = tuple(sorted([
                str(first.get("fingerprint", "")),
                str(second.get("fingerprint", ""))
            ]))

            # Skip a relationship that has already been recorded.
            if pair_id in seen_pairs:
                continue

            # Check for shared domains.
            shared_domains = (
                extract_artifact_domains(first)
                &
                extract_artifact_domains(second)
            )

            if shared_domains:

                correlations.append({
                    "type": "Shared Domain",
                    "first": first,
                    "second": second,
                    "shared_domains": sorted(shared_domains),
                    "reason": (
                        "The same domain appeared across "
                        "multiple threat investigations."
                    )
                })

                seen_pairs.add(pair_id)
                continue

            # Check for same fingerprint.
            first_fp = first.get(
                "fingerprint",
                ""
            )

            second_fp = second.get(
                "fingerprint",
                ""
            )

            if (
                first_fp
                and second_fp
                and first_fp == second_fp
            ):

                correlations.append({
                    "type": "Same Fingerprint",
                    "first": first,
                    "second": second,
                    "shared_domains": [],
                    "reason": (
                        "Different investigations produced "
                        "the same threat fingerprint."
                    )
                })

                seen_pairs.add(pair_id)

    return correlations