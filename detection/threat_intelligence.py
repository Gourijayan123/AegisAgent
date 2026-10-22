"""Threat-intelligence enrichment with a safe offline fallback."""


def lookup_ip_reputation(ip_address):
    """Return the current reputation for an IP address.

    This project currently performs no external reputation lookup, so the
    report explicitly records that the reputation is unknown.
    """
    del ip_address
    return {"reputation": "Unknown"}
