import hashlib
import json


def generate_fingerprint(data):
    """
    Generate a unique SHA-256 fingerprint
    from threat analysis data.
    """

    if isinstance(data, dict):
        fingerprint_data = json.dumps(
            data,
            sort_keys=True,
            default=str
        )
    else:
        fingerprint_data = str(data)

    fingerprint = hashlib.sha256(
        fingerprint_data.encode("utf-8")
    ).hexdigest()

    return fingerprint


def generate_short_fingerprint(data):
    """
    Generate a shorter fingerprint for display.
    """

    full_fingerprint = generate_fingerprint(data)

    return full_fingerprint[:16].upper()


def fingerprint_artifact(artifact_type, artifact_data):
    """
    Create a threat fingerprint for an analyzed artifact.
    """

    fingerprint = generate_fingerprint({
        "artifact_type": artifact_type,
        "artifact_data": artifact_data
    })

    short_fingerprint = fingerprint[:16].upper()

    return {
        "artifact_type": artifact_type,
        "fingerprint": fingerprint,
        "short_fingerprint": short_fingerprint
    }