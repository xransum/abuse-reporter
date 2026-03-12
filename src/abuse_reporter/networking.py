"""Network utilities: WHOIS lookups, IP info, and reverse DNS."""

import socket
import sys

import requests
import whois
from requests.exceptions import RequestException


def get_whois_info(
    ip_addr: str,
    retry: int = 0,
    max_retries: int = 3,
) -> whois.WhoisEntry | None:
    """Retrieve WHOIS information for an IP address.

    Args:
        ip_addr: The IP address to query.
        retry: Current retry attempt number (used internally).
        max_retries: Maximum number of retry attempts before giving up.

    Returns:
        A WhoisEntry on success, or None if all attempts fail.
    """
    try:
        return whois.whois(ip_addr)
    except Exception as exc:  # noqa: BLE001 - whois raises bare Exception
        if retry < max_retries:
            return get_whois_info(ip_addr, retry + 1, max_retries)
        print(f"Failed to get WHOIS info for {ip_addr}: {exc}", file=sys.stderr)
        return None


def get_ip_info(ip_addr: str) -> dict[str, str] | None:
    """Fetch IP metadata from the ipinfo.io API.

    Args:
        ip_addr: The IP address to look up.

    Returns:
        A dictionary of IP metadata on success, or None on failure.
    """
    try:
        response = requests.get(
            f"https://ipinfo.io/{ip_addr}/json",
            timeout=10,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/58.0.3029.110 Safari/537.3"
                )
            },
        )
        response.raise_for_status()
        return response.json()  # type: ignore[no-any-return]
    except RequestException as exc:
        print(f"Failed to get IP info for {ip_addr}: {exc}", file=sys.stderr)
        return None


def get_hostname_from_ip(ip_addr: str) -> str:
    """Perform a reverse DNS lookup for an IP address.

    Args:
        ip_addr: The IP address to look up.

    Returns:
        The resolved hostname, or ``"Unknown"`` if the lookup fails.
    """
    try:
        hostname, *_ = socket.gethostbyaddr(ip_addr)
        return hostname
    except socket.herror:
        return "Unknown"
